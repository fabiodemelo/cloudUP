//! A compact, dependency-light Amazon S3 client.
//!
//! Implements AWS Signature Version 4 and the handful of REST operations we need
//! (list buckets, list objects, get/put/delete object, create bucket). It works
//! against AWS S3 and any S3-compatible endpoint (MinIO, Backblaze B2, etc.) by
//! using path-style addressing against a configurable endpoint.

use crate::error::{Error, Result};
use chrono::Utc;
use hmac::{Hmac, Mac};
use reqwest::Client;
use roxmltree::Document;
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

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
            secret_key: secret_key.to_string(),
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

    fn sign(
        &self,
        method: &str,
        path: &str, // already URI-encoded, e.g. "/bucket/key"
        query: &[(String, String)], // raw (unencoded) params; will be encoded + sorted
        payload: &[u8],
    ) -> Vec<(String, String)> {
        let (_, host) = self.parts();

        let now = Utc::now();
        let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();
        let date_stamp = now.format("%Y%m%d").to_string();

        let payload_hash = sha256_hex(payload);

        // Canonical query string: encode then sort.
        let mut q: Vec<(String, String)> = query
            .iter()
            .map(|(k, v)| (uri_encode(k, false), uri_encode(v, false)))
            .collect();
        q.sort();
        let canonical_query = q
            .iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect::<Vec<_>>()
            .join("&");

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
        let (base, _) = self.parts();
        let mut url = format!("{}{}", base, path);
        if !query.is_empty() {
            let mut q: Vec<(String, String)> = query
                .iter()
                .map(|(k, v)| (uri_encode(k, false), uri_encode(v, true)))
                .collect();
            q.sort();
            let qs = q
                .iter()
                .map(|(k, v)| format!("{}={}", k, v))
                .collect::<Vec<_>>()
                .join("&");
            url.push_str(&format!("?{}", qs));
        }

        let headers = self.sign(method, path, query, payload);

        let mut req = self.http.request(reqwest::Method::from_bytes(method.as_bytes()).unwrap_or_else(|_| reqwest::Method::GET), &url);
        for (k, v) in headers {
            req = req.header(k.as_str(), v.as_str());
        }
        if !payload.is_empty() {
            req = req.body(payload.to_vec());
        }

        let resp = req.send().await.map_err(|e| Error::Http(e.to_string()))?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(Error::S3 { status: status.as_u16(), body });
        }
        Ok(resp)
    }

    // ------------------------------------------------------------- operations

    /// List all buckets the credentials can see.
    pub async fn list_buckets(&self) -> Result<Vec<S3Bucket>> {
        let resp = self.request("GET", "/", &[], b"").await?;
        let xml = resp.text().await.map_err(|e| Error::Http(e.to_string()))?;
        parse_list_buckets(&xml)
    }

    /// List objects under `bucket`/`prefix`. Returns (objects, common_prefixes).
    /// Common prefixes are "directories" (when delimiter is "/").
    pub async fn list_objects(
        &self,
        bucket: &str,
        prefix: &str,
    ) -> Result<(Vec<S3Object>, Vec<String>)> {
        let path = format!("/{}", bucket);
        let mut query: Vec<(String, String)> = vec![
            ("list-type".into(), "2".into()),
            ("delimiter".into(), "/".into()),
        ];
        if !prefix.is_empty() {
            query.push(("prefix".into(), prefix.to_string()));
        }
        let resp = self.request("GET", &path, &query, b"").await?;
        let xml = resp.text().await.map_err(|e| Error::Http(e.to_string()))?;
        parse_list_objects(&xml)
    }

    /// Download an object's bytes.
    pub async fn get_object(&self, bucket: &str, key: &str) -> Result<Vec<u8>> {
        let path = format!("/{}{}", bucket, encode_path(key));
        let resp = self.request("GET", &path, &[], b"").await?;
        let bytes = resp.bytes().await.map_err(|e| Error::Http(e.to_string()))?;
        Ok(bytes.to_vec())
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

    /// Delete all objects under a prefix (used for "delete folder").
    pub async fn delete_prefix(&self, bucket: &str, prefix: &str) -> Result<u32> {
        let mut deleted = 0u32;
        loop {
            let (objects, _) = self.list_objects(bucket, prefix).await?;
            if objects.is_empty() {
                break;
            }
            let body = format!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?><Delete>{}<Quiet>true</Quiet></Delete>",
                objects
                    .iter()
                    .map(|o| format!("<Object><Key>{}</Key></Object>", xml_escape(&o.key)))
                    .collect::<Vec<_>>()
                    .join("")
            );
            let path = format!("/{}", bucket);
            match self
                .request("POST", &path, &[("delete".into(), "".into())], body.as_bytes())
                .await
            {
                Ok(r) => {
                    let xml = r.text().await.unwrap_or_default();
                    deleted += count_deleted(&xml);
                }
                Err(_) => break,
            }
        }
        Ok(deleted)
    }
}

// --------------------------------------------------------------------- helpers

fn normalize_endpoint(endpoint: &str) -> String {
    let e = endpoint.trim();
    if e.is_empty() {
        return "https://s3.amazonaws.com".to_string();
    }
    let e = if e.contains("://") { e.to_string() } else { format!("https://{}", e) };
    e.trim_end_matches('/').to_string()
}

/// URI-encode a string per AWS SigV4 rules. `encode_slash` controls whether '/' is encoded.
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

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
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

fn count_deleted(xml: &str) -> u32 {
    Document::parse(xml)
        .map(|doc| {
            doc.root_element()
                .descendants()
                .filter(|n| n.has_tag_name("Deleted"))
                .count() as u32
        })
        .unwrap_or(0)
}
