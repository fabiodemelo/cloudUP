//! Shared error type for the backend.

use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("HTTP error: {0}")]
    Http(String),

    #[error("{}", s3_summary(*status, body))]
    S3 { status: u16, body: String },

    #[error("WebDAV error (status {status}): {body}")]
    Webdav { status: u16, body: String },

    #[error("{provider} API error (status {status}): {body}")]
    Api { provider: String, status: u16, body: String },

    #[error("parse error: {0}")]
    Parse(String),

    #[error("not implemented for this connection type yet")]
    NotImplemented,

    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, Error>;

impl Error {
    /// A network error without its URL: URLs can carry credentials or
    /// tokens (query strings, signed links) that must not reach the UI or logs.
    pub fn http(e: reqwest::Error) -> Self {
        Error::Http(e.without_url().to_string())
    }
}

impl From<Error> for String {
    fn from(e: Error) -> Self {
        e.to_string()
    }
}

/// Turn an S3 XML error body into a short, readable message with a hint for
/// the common setup mistakes, e.g. "InvalidAccessKeyId (403): ...".
fn s3_summary(status: u16, body: &str) -> String {
    let tag = |t: &str| {
        let open = format!("<{t}>");
        let close = format!("</{t}>");
        body.find(&open)
            .and_then(|i| body[i + open.len()..].find(&close).map(|j| body[i + open.len()..i + open.len() + j].trim().to_string()))
            .filter(|s| !s.is_empty())
    };
    let Some(code) = tag("Code") else {
        return format!("S3 error (status {status}): {body}");
    };
    let hint = match code.as_str() {
        "InvalidAccessKeyId" => "the Access Key ID is not recognised by this endpoint. Use an S3/Spaces access key (not an API token) issued for the same provider and region",
        "SignatureDoesNotMatch" => "the Secret Access Key does not match the Access Key ID",
        "NoSuchBucket" => "that bucket does not exist at this endpoint. Check the bucket name and region",
        "AccessDenied" => "the key is valid but not allowed to access this bucket",
        "PermanentRedirect" | "AuthorizationHeaderMalformed" => "the bucket lives in a different region. Check the endpoint and region",
        _ => "",
    };
    let mut out = format!("{code} ({status})");
    if let Some(m) = tag("Message") { out.push_str(": "); out.push_str(&m); }
    if !hint.is_empty() { out.push_str(" — "); out.push_str(hint); }
    out
}
