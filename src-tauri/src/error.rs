//! Shared error type for the backend.

use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("HTTP error: {0}")]
    Http(String),

    #[error("S3 error (status {status}): {body}")]
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

impl From<Error> for String {
    fn from(e: Error) -> Self {
        e.to_string()
    }
}
