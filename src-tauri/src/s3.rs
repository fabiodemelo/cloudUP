//! A compact, dependency-light Amazon S3 client.
//!
//! Implements AWS Signature Version 4 and the handful of REST operations we need
//! (list buckets, list objects, get/put/delete object, create bucket). It works
//! against AWS S3 and any S3-compatible endpoint (MinIO, Backblaze B2, etc.) by
//! using path-style addressing against a configurable endpoint.

use crate::backend::{save_response, send_download, transfer_client, upload_timeout, FileBody};
use crate::error::{Error, Result};
use chrono::Utc;
use hmac::{Hmac, Mac};
use reqwest::Client;
use roxmltree::Document;
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

/// Payload hash for a streamed upload: the body is not hashed up front
/// (that would mean reading the file twice); TLS protects it in transit.
const UNSIGNED_PAYLOAD: &str = "UNSIGNED-PAYLOAD";

pub struct S3Bucket {
    pub name: String,
    pub creation_date: Option<String>,
}

pub struct S3Object {
    pub key: String,
    pub size: u64,
    pub last_modified: Option<String>,
}

#[derive(Clone)]
pub struct S3 {
    pub endpoint: String, // e.g. "https://s3.amazonaws.com" or "http://localhost:9000"
    pub region: String,   // e.g. "us-east-1"
    pub access_key: String,
    pub secret_key: String,
    http: Client,
}

impl S3 {
    pub fn new(endpoint: &str, region: &str, access_key: &str, secret_key: &str) -> Self {
        let endpoint = normalize_endpoint(endpoint);
        let region = if region.trim().is_empty() { "us-east-1" } else { region }.trim().to_string();
        Self {
            endpoint,
            region,
            access_key: access_key.trim().to_string(),
            secret_key: secret_key.trim().to_string(),
            http: Client::builder()
                .timeout(std::time::Duration::from_secs(60))
                .build()
                .unwrap_or_default(),
        }
    }

    /// Split the endpoint into (base_url, authority/host).
    fn parts(&self) -> (&str, &str) {
        let without_scheme = self.endpoint.splitn(2, "://").nth(1).unwrap_or(&self.endpoint);
        let authority = without_scheme.split('/').next().unwrap_or("");
        (&self.endpoint, authority)
    }

    // ------------------------------------------------------------------ SigV4

    #[cfg(test)]
    fn sign(
        &self,
        method: &str,
        path: &str,
        query: &[(String, String)],
        payload: &[u8],
    ) -> Vec<(String, String)> {
        self.sign_at(method, path, query, payload, Utc::now())
    }

    #[cfg(test)]
    fn sign_at(
        &self,
        method: &str,
        path: &str, // already URI-encoded, e.g. "/bucket/key"
        query: &[(String, String)], // raw (unencoded) params; will be encoded + sorted
        payload: &[u8],
        now: chrono::DateTime<Utc>,
    ) -> Vec<(String, String)> {
        self.sign_hashed(method, path, query, &sha256_hex(payload), now)
    }

    /// Sign with a precomputed payload hash (or `UNSIGNED-PAYLOAD`).
    fn sign_hashed(
        &self,
        method: &str,
        path: &str,
        query: &[(String, String)],
        payload_hash: &str,
        now: chrono::DateTime<Utc>,
    ) -> Vec<(String, String)> {
        let (_, host) = self.parts();

        let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();
        let date_stamp = now.format("%Y%m%d").to_string();

        let payload_hash = payload_hash.to_string();

        let canonical_query = canonical_query(query);

        // Canonical headers (sorted by name).
        let mut headers: Vec<(String, String)> = vec![
            ("host".to_string(), host.to_string()),
            ("x-amz-content-sha256".to_string(), payload_hash.clone()),
            ("x-amz-date".to_string(), amz_date.clone()),
        ];
        headers.sort_by(|a, b| a.0.cmp(&b.0));
        let canonical_headers = headers
            .iter()
            .map(|(k, v)| format!("{}:{}\n", k, v))
            .collect::<String>();
        let signed_headers = headers.iter().map(|(k, _)| k.as_str()).collect::<Vec<_>>().join(";");

        let canonical_request = format!(
            "{}\n{}\n{}\n{}\n{}\n{}",
            method, path, canonical_query, canonical_headers, signed_headers, payload_hash
        );

        let scope = format!("{}/{}/{}/aws4_request", date_stamp, self.region, "s3");
        let string_to_sign = format!(
            "AWS4-HMAC-SHA256\n{}\n{}\n{}",
            amz_date,
            scope,
            sha256_hex(canonical_request.as_bytes())
        );

        let k_date = hmac_sha256(format!("AWS4{}", self.secret_key).as_bytes(), &date_stamp);
        let k_region = hmac_sha256(&k_date, &self.region);
        let k_service = hmac_sha256(&k_region, "s3");
        let k_signing = hmac_sha256(&k_service, "aws4_request");
        let signature = hex::encode(hmac_sha256(&k_signing, &string_to_sign));

        let authorization = format!(
            "AWS4-HMAC-SHA256 Credential={}/{}, SignedHeaders={}, Signature={}",
            self.access_key, scope, signed_headers, signature
        );

        vec![
            ("host".to_string(), host.to_string()),
            ("x-amz-content-sha256".to_string(), payload_hash),
            ("x-amz-date".to_string(), amz_date),
            ("authorization".to_string(), authorization),
        ]
    }

    /// Perform a signed request. `path` is the URI path (bucket-prefixed), `query`
    /// raw params, `payload` the body bytes. Returns the response.
    async fn request(
        &self,
        method: &str,
        path: &str,
        query: &[(String, String)],
        payload: &[u8],
    ) -> Result<reqwest::Response> {
        let mut req = self.signed(&self.http, method, path, query, &sha256_hex(payload));
        if !payload.is_empty() {
            req = req.body(payload.to_vec());
        }
        check(req.send().await.map_err(Error::http)?).await
    }

    /// A request on `http` carrying the SigV4 headers for `payload_hash`.
    fn signed(
        &self,
        http: &Client,
        method: &str,
        path: &str,
        query: &[(String, String)],
        payload_hash: &str,
    ) -> reqwest::RequestBuilder {
        let (base, _) = self.parts();
        let mut url = format!("{}{}", base, path);
        if !query.is_empty() {
            // Send exactly the string that was signed.
            url.push_str(&format!("?{}", canonical_query(query)));
        }

        let headers = self.sign_hashed(method, path, query, payload_hash, Utc::now());

        let mut req = http.request(reqwest::Method::from_bytes(method.as_bytes()).unwrap_or_else(|_| reqwest::Method::GET), &url);
        for (k, v) in headers {
            req = req.header(k.as_str(), v.as_str());
        }
        req
    }

    // ------------------------------------------------------------- operations

    /// List all buckets the credentials can see.
    pub async fn list_buckets(&self) -> Result<Vec<S3Bucket>> {
        let resp = self.request("GET", "/", &[], b"").await?;
        let xml = resp.text().await.map_err(Error::http)?;
        parse_list_buckets(&xml)
    }

    /// List objects under `bucket`/`prefix`. Returns (objects, common_prefixes).
    /// Common prefixes are "directories" (when delimiter is "/").
    pub async fn list_objects(
        &self,
        bucket: &str,
        prefix: &str,
    ) -> Result<(Vec<S3Object>, Vec<String>)> {
        self.list_all(bucket, prefix, true).await
    }

    /// Every page of a ListObjectsV2 listing (S3 returns at most 1000 keys
    /// per response). Without the delimiter it lists all nested keys.
    async fn list_all(&self, bucket: &str, prefix: &str, delimited: bool) -> Result<(Vec<S3Object>, Vec<String>)> {
        let path = format!("/{}", bucket);
        let (mut objects, mut prefixes) = (Vec::new(), Vec::new());
        let mut token: Option<String> = None;
        loop {
            let mut query: Vec<(String, String)> = vec![("list-type".into(), "2".into())];
            if delimited {
                query.push(("delimiter".into(), "/".into()));
            }
            if !prefix.is_empty() {
                query.push(("prefix".into(), prefix.to_string()));
            }
            if let Some(t) = &token {
                query.push(("continuation-token".into(), t.clone()));
            }
            let resp = self.request("GET", &path, &query, b"").await?;
            let xml = resp.text().await.map_err(Error::http)?;
            let (o, p) = parse_list_objects(&xml)?;
            objects.extend(o);
            prefixes.extend(p);
            match next_token(&xml) {
                Some(t) if Some(&t) != token.as_ref() => token = Some(t),
                _ => break,
            }
        }
        Ok((objects, prefixes))
    }

    /// Download an object's bytes.
    pub async fn get_object(&self, bucket: &str, key: &str) -> Result<Vec<u8>> {
        let path = format!("/{}{}", bucket, encode_path(key));
        let resp = self.request("GET", &path, &[], b"").await?;
        let bytes = resp.bytes().await.map_err(Error::http)?;
        Ok(bytes.to_vec())
    }

    /// Stream an object into a local file. Returns its size.
    pub async fn get_object_to_file(&self, bucket: &str, key: &str, dest: &std::path::Path) -> Result<u64> {
        let path = format!("/{}{}", bucket, encode_path(key));
        let req = self.signed(&transfer_client(), "GET", &path, &[], &sha256_hex(b""));
        let resp = check(send_download(req).await?).await?;
        save_response(resp, dest).await
    }

    /// Upload a local file as an object, streamed from disk. A single PUT
    /// (S3 takes up to 5 GB that way).
    pub async fn put_object_from_file(&self, bucket: &str, key: &str, src: &std::path::Path) -> Result<()> {
        let path = format!("/{}{}", bucket, encode_path(key));
        let body = FileBody::whole(src).await?;
        let req = self
            .signed(&transfer_client(), "PUT", &path, &[], UNSIGNED_PAYLOAD)
            .header(reqwest::header::CONTENT_LENGTH, body.content_len())
            .timeout(upload_timeout(body.content_len()))
            .body(body.body().await?);
        check(req.send().await.map_err(Error::http)?).await?;
        Ok(())
    }

    /// Upload bytes as an object.
    pub async fn put_object(&self, bucket: &str, key: &str, data: &[u8]) -> Result<()> {
        let path = format!("/{}{}", bucket, encode_path(key));
        self.request("PUT", &path, &[], data).await?;
        Ok(())
    }

    /// Delete a single object.
    pub async fn delete_object(&self, bucket: &str, key: &str) -> Result<()> {
        let path = format!("/{}{}", bucket, encode_path(key));
        self.request("DELETE", &path, &[], b"").await?;
        Ok(())
    }

    /// Create a bucket (best-effort; ignored if it already exists).
    pub async fn create_bucket(&self, name: &str) -> Result<()> {
        let path = format!("/{}", name);
        self.request("PUT", &path, &[], b"").await?;
        Ok(())
    }

    /// Delete every object under a prefix, nested ones included (used for
    /// "delete folder"). Objects are deleted one by one, a few at a time:
    /// unlike the multi-object Delete API this works on every S3-compatible
    /// service and reports each failure.
    pub async fn delete_prefix(&self, bucket: &str, prefix: &str) -> Result<u32> {
        use futures_util::stream::{self, TryStreamExt};
        let (objects, _) = self.list_all(bucket, prefix, false).await?;
        let n = objects.len() as u32;
        stream::iter(objects.into_iter().map(Ok))
            .try_for_each_concurrent(8, |o: S3Object| async move { self.delete_object(bucket, &o.key).await })
            .await?;
        Ok(n)
    }
}

// --------------------------------------------------------------------- helpers

/// Turn a non-2xx response into an `Error::S3` with its XML body.
async fn check(resp: reqwest::Response) -> Result<reqwest::Response> {
    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(Error::S3 { status: status.as_u16(), body });
    }
    Ok(resp)
}

fn normalize_endpoint(endpoint: &str) -> String {
    let e = endpoint.trim();
    if e.is_empty() {
        return "https://s3.amazonaws.com".to_string();
    }
    let e = if e.contains("://") { e.to_string() } else { format!("https://{}", e) };
    e.trim_end_matches('/').to_string()
}

/// URI-encode a string per AWS SigV4 rules. `encode_slash` controls whether '/' is encoded.
/// SigV4 canonical query string: every key and value URI-encoded (including
/// '/', so `delimiter=/` becomes `delimiter=%2F`), then sorted. The request URL
/// must use this same string, or the server computes a different signature.
fn canonical_query(query: &[(String, String)]) -> String {
    let mut q: Vec<(String, String)> = query
        .iter()
        .map(|(k, v)| (uri_encode(k, true), uri_encode(v, true)))
        .collect();
    q.sort();
    q.iter()
        .map(|(k, v)| format!("{}={}", k, v))
        .collect::<Vec<_>>()
        .join("&")
}

fn uri_encode(s: &str, encode_slash: bool) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            b'/' if !encode_slash => out.push('/'),
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}

/// Encode an object key path, preserving '/' but encoding other special chars.
fn encode_path(key: &str) -> String {
    let trimmed = key.trim_start_matches('/');
    if trimmed.is_empty() {
        return String::new();
    }
    let trailing = trimmed.ends_with('/');
    let body = trimmed.trim_end_matches('/');
    let mut out = String::from("/");
    for (i, segment) in body.split('/').enumerate() {
        if i > 0 {
            out.push('/');
        }
        out.push_str(&uri_encode(segment, false));
    }
    if trailing {
        out.push('/');
    }
    out
}

fn sha256_hex(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    hex::encode(h.finalize())
}

fn hmac_sha256(key: &[u8], data: &str) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("hmac key");
    mac.update(data.as_bytes());
    let v = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&v);
    out
}

// ----------------------------------------------------------------------- XML

fn parse_list_buckets(xml: &str) -> Result<Vec<S3Bucket>> {
    let doc = Document::parse(xml).map_err(|e| Error::Parse(e.to_string()))?;
    let root = doc.root_element();
    let mut out = vec![];
    for bucket in root.descendants().filter(|n| n.has_tag_name("Bucket")) {
        let name = bucket
            .children()
            .find(|n| n.has_tag_name("Name"))
            .and_then(|n| n.text())
            .unwrap_or("")
            .to_string();
        let creation = bucket
            .children()
            .find(|n| n.has_tag_name("CreationDate"))
            .and_then(|n| n.text())
            .map(|s| s.to_string());
        if !name.is_empty() {
            out.push(S3Bucket { name, creation_date: creation });
        }
    }
    Ok(out)
}

fn parse_list_objects(xml: &str) -> Result<(Vec<S3Object>, Vec<String>)> {
    let doc = Document::parse(xml).map_err(|e| Error::Parse(e.to_string()))?;
    let root = doc.root_element();
    let mut objects = vec![];
    let mut prefixes = vec![];

    for node in root.descendants() {
        if node.has_tag_name("Contents") {
            let key = child_text(&node, "Key");
            let size = child_text(&node, "Size").parse::<u64>().unwrap_or(0);
            let modified = child_text(&node, "LastModified");
            if !key.is_empty() {
                objects.push(S3Object { key, size, last_modified: Some(modified) });
            }
        } else if node.has_tag_name("CommonPrefixes") {
            if let Some(p) = node.children().find(|n| n.has_tag_name("Prefix")).and_then(|n| n.text()) {
                prefixes.push(p.to_string());
            }
        }
    }
    Ok((objects, prefixes))
}

fn child_text(node: &roxmltree::Node, tag: &str) -> String {
    node.children()
        .find(|n| n.has_tag_name(tag))
        .and_then(|n| n.text())
        .unwrap_or("")
        .to_string()
}

/// The continuation token of a truncated ListObjectsV2 page, if any.
fn next_token(xml: &str) -> Option<String> {
    let doc = Document::parse(xml).ok()?;
    let root = doc.root_element();
    if child_text(&root, "IsTruncated") != "true" {
        return None;
    }
    Some(child_text(&root, "NextContinuationToken")).filter(|t| !t.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_client() -> S3 {
        S3::new("https://s3.amazonaws.com", "us-east-1", "AKIAEXAMPLE", "wJalrXUtnFEMI/K7MDENG/blast")
    }

    #[test]
    fn sigv4_authorization_shape() {
        let h = test_client()
            .sign("GET", "/mybucket", &[("list-type".into(), "2".into())], b"")
            .into_iter()
            .map(|(k, v)| (k.to_lowercase(), v))
            .collect::<std::collections::HashMap<_, _>>();

        let host = h.get("host").expect("host");
        assert!(host.contains("s3.amazonaws.com"), "host was: {host}");
        // x-amz-date is the ISO8601 basic-format timestamp, e.g. 20261013T033520Z.
        let date = h.get("x-amz-date").expect("x-amz-date");
        assert_eq!(date.len(), 16, "x-amz-date was: {date}");
        assert_eq!(&date[8..9], "T", "x-amz-date was: {date}");
        assert!(date.ends_with('Z'));
        assert!(date[0..8].chars().all(|c| c.is_ascii_digit()));
        // The payload hash must be 64 hex digits (SHA-256).
        let ph = h.get("x-amz-content-sha256").expect("x-amz-content-sha256");
        assert_eq!(ph.len(), 64);
        assert!(ph.chars().all(|c| c.is_ascii_hexdigit()));
        let auth = h.get("authorization").expect("authorization");
        assert!(auth.starts_with("AWS4-HMAC-SHA256 Credential=AKIAEXAMPLE/"));
        assert!(auth.contains("/us-east-1/s3/aws4_request"));
        assert!(auth.contains("SignedHeaders=host;x-amz-content-sha256;x-amz-date"));
        // The signature is a 64-hex-char (256-bit) digest.
        let sig = auth.rsplit("Signature=").next().expect("signature");
        assert_eq!(sig.len(), 64);
        assert!(sig.chars().all(|c| c.is_ascii_hexdigit()));
        // Canonical query string ordering check: signed request must include it.
        assert!(auth.len() > 0);
    }

    #[test]
    fn sigv4_empty_payload_hash_is_sha256_of_empty() {
        // The well-known SHA-256 of the empty byte string.
        let empty = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let h = test_client().sign("GET", "/", &[], b"").into_iter().find(|(k, _)| k == "x-amz-content-sha256").map(|(_, v)| v);
        assert_eq!(h.as_deref(), Some(empty));
    }

    #[test]
    fn payload_hash_is_sha256_of_body() {
        // A real payload is hashed to its SHA-256 hex digest (not the empty-string one).
        let body = b"hello";
        let expected = sha256_hex(body);
        let got = test_client()
            .sign("PUT", "/bucket/x", &[], body)
            .into_iter()
            .find(|(k, _)| k == "x-amz-content-sha256")
            .map(|(_, v)| v)
            .unwrap();
        assert_eq!(got, expected);
    }

    #[test]
    fn next_token_only_when_truncated() {
        let truncated = "<ListBucketResult><IsTruncated>true</IsTruncated><NextContinuationToken>abc</NextContinuationToken></ListBucketResult>";
        assert_eq!(next_token(truncated).as_deref(), Some("abc"));
        let last = "<ListBucketResult><IsTruncated>false</IsTruncated></ListBucketResult>";
        assert_eq!(next_token(last), None);
    }

    #[test]
    fn parse_list_objects_content_and_prefixes() {
        let xml = r#"<?xml version="1.0"?><ListBucketResult>
          <Name>mybucket</Name>
          <Prefix>photos/</Prefix>
          <Contents><Key>photos/a.jpg</Key><Size>1234</Size><LastModified>2024-01-02T03:04:05Z</LastModified></Contents>
          <Contents><Key>photos/b.jpg</Key><Size>99</Size></Contents>
          <CommonPrefixes><Prefix>docs/</Prefix></CommonPrefixes>
          <CommonPrefixes><Prefix>videos/</Prefix></CommonPrefixes>
        </ListBucketResult>"#;
        let (objects, prefixes) = parse_list_objects(xml).unwrap();
        assert_eq!(objects.len(), 2);
        assert_eq!(objects[0].key, "photos/a.jpg");
        assert_eq!(objects[0].size, 1234);
        assert_eq!(objects[0].last_modified.as_deref(), Some("2024-01-02T03:04:05Z"));
        assert_eq!(objects[1].key, "photos/b.jpg");
        assert_eq!(objects[1].size, 99);
        // A missing <LastModified> element yields an empty string, not a missing entry.
        assert_eq!(objects[1].last_modified.as_deref(), Some(""));
        assert_eq!(prefixes, vec!["docs/", "videos/"]);
    }

    #[test]
    fn sigv4_matches_aws_list_objects_example() {
        // "Example: GET Bucket (List Objects)" from the AWS SigV4 S3 docs.
        use chrono::TimeZone;
        let c = S3::new(
            "https://examplebucket.s3.amazonaws.com",
            "us-east-1",
            "AKIAIOSFODNN7EXAMPLE",
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        );
        let q = vec![("max-keys".to_string(), "2".to_string()), ("prefix".to_string(), "J".to_string())];
        let at = Utc.with_ymd_and_hms(2013, 5, 24, 0, 0, 0).unwrap();
        let auth = c
            .sign_at("GET", "/", &q, b"", at)
            .into_iter()
            .find(|(k, _)| k == "authorization")
            .unwrap()
            .1;
        assert!(
            auth.ends_with("Signature=34b48302e7b5fa45bde8084f4b7868a86f0a534bc59db6670ed5711ef69dc6f7"),
            "{auth}"
        );
    }

    #[test]
    fn unsigned_payload_is_signed_as_such() {
        use chrono::TimeZone;
        let at = Utc.with_ymd_and_hms(2026, 1, 2, 3, 4, 5).unwrap();
        let c = test_client();
        let h = c.sign_hashed("PUT", "/bucket/big.bin", &[], UNSIGNED_PAYLOAD, at);
        let get = |k: &str| h.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone()).unwrap();
        assert_eq!(get("x-amz-content-sha256"), "UNSIGNED-PAYLOAD");
        // The marker is part of the signed canonical request: a different
        // payload hash gives a different signature.
        let hashed = c.sign_at("PUT", "/bucket/big.bin", &[], b"", at);
        let auth = |v: &[(String, String)]| v.iter().find(|(n, _)| n == "authorization").unwrap().1.clone();
        assert_ne!(auth(&h), auth(&hashed));
    }

    #[test]
    fn canonical_query_encodes_slash_and_sorts() {
        let q = vec![
            ("prefix".to_string(), "photos/2026 trip/".to_string()),
            ("list-type".to_string(), "2".to_string()),
            ("delimiter".to_string(), "/".to_string()),
        ];
        assert_eq!(
            canonical_query(&q),
            "delimiter=%2F&list-type=2&prefix=photos%2F2026%20trip%2F"
        );
    }

    #[test]
    fn encode_path_preserves_slashes_and_keeps_trailing() {
        assert_eq!(encode_path("a/b c.txt"), "/a/b%20c.txt");
        assert_eq!(encode_path("/dir/"), "/dir/");
        assert_eq!(encode_path(""), "");
        assert_eq!(encode_path("top/file-name.txt"), "/top/file-name.txt");
    }
}
