use std::fmt;
use std::time::Duration;

use serde::Serialize;

/// Response shape shared by every target (HTTP, DNS, ...).
///
/// `size`, `words` and `lines` are derived from the body for HTTP. Other
/// transports can use [`Response::from_parts`] when a body is not meaningful.
#[derive(Debug, Clone)]
pub struct Response {
    pub status: u16,
    pub size: usize,
    pub words: usize,
    pub lines: usize,
    pub body: String,
    pub elapsed: Duration,
}

impl Response {
    pub fn from_body(status: u16, body: impl Into<String>, elapsed: Duration) -> Self {
        let body = body.into();
        let size = body.len();
        let words = body.split_whitespace().count();
        let lines = if body.is_empty() {
            0
        } else {
            body.lines().count()
        };
        Self {
            status,
            size,
            words,
            lines,
            body,
            elapsed,
        }
    }

    pub fn from_parts(
        status: u16,
        size: usize,
        words: usize,
        lines: usize,
        elapsed: Duration,
    ) -> Self {
        Self {
            status,
            size,
            words,
            lines,
            body: String::new(),
            elapsed,
        }
    }
}

/// Calibration baseline signature. A response is represented only by the
/// fields calibration compares, never by the body itself.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub struct Signature {
    pub status: u16,
    pub size: usize,
    pub words: usize,
    pub lines: usize,
}

impl From<&Response> for Signature {
    fn from(response: &Response) -> Self {
        Self {
            status: response.status,
            size: response.size,
            words: response.words,
            lines: response.lines,
        }
    }
}

/// The result of one successful exchange. `info` carries transport metadata
/// (for HTTP: `url`, `final_url`, `method`) and is flattened into the JSONL
/// result event.
#[derive(Debug, Clone)]
pub struct ExecResult {
    pub response: Response,
    pub info: serde_json::Value,
}

#[derive(Debug, Clone)]
pub struct EngineError {
    pub message: String,
    pub retryable: bool,
    pub timed_out: bool,
}

impl EngineError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            retryable: false,
            timed_out: false,
        }
    }

    pub fn retryable(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            retryable: true,
            timed_out: false,
        }
    }

    pub fn non_retryable(message: impl Into<String>) -> Self {
        Self::new(message)
    }

    pub fn timeout() -> Self {
        Self {
            message: "request timed out".to_string(),
            retryable: true,
            timed_out: true,
        }
    }
}

impl fmt::Display for EngineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for EngineError {}

impl From<std::io::Error> for EngineError {
    fn from(err: std::io::Error) -> Self {
        Self::new(err.to_string())
    }
}
