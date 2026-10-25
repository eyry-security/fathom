#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

#[derive(Debug, Clone)]
pub struct Request {
    pub method: String,
    pub path: String,
    pub headers: HashMap<String, String>,
    pub body: String,
}

#[derive(Debug, Clone)]
pub struct TestResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: String,
    pub delay: Option<Duration>,
}

impl TestResponse {
    pub fn ok(body: impl Into<String>) -> Self {
        Self {
            status: 200,
            headers: Vec::new(),
            body: body.into(),
            delay: None,
        }
    }

    pub fn status(status: u16, body: impl Into<String>) -> Self {
        Self {
            status,
            headers: Vec::new(),
            body: body.into(),
            delay: None,
        }
    }
}

pub type Handler = Arc<dyn Fn(&Request) -> TestResponse + Send + Sync + 'static>;

pub struct FixtureServer {
    base_url: String,
    handle: tokio::task::JoinHandle<()>,
}

impl FixtureServer {
    pub async fn start(handler: Handler) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            loop {
                let Ok((socket, _)) = listener.accept().await else {
                    break;
                };
                let handler = handler.clone();
                tokio::spawn(async move {
                    let _ = serve_connection(socket, handler).await;
                });
            }
        });
        Self {
            base_url: format!("http://{address}"),
            handle,
        }
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }
}

impl Drop for FixtureServer {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

async fn serve_connection(mut socket: TcpStream, handler: Handler) -> std::io::Result<()> {
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 8192];

    loop {
        let header_end = loop {
            if let Some(index) = find_header_end(&buffer) {
                break index;
            }
            let read = socket.read(&mut chunk).await?;
            if read == 0 {
                return Ok(());
            }
            buffer.extend_from_slice(&chunk[..read]);
            if buffer.len() > 4 * 1024 * 1024 {
                return Ok(());
            }
        };

        let head = String::from_utf8_lossy(&buffer[..header_end]).into_owned();
        let mut lines = head.lines();
        let request_line = lines.next().unwrap_or_default();
        let mut request_parts = request_line.split_whitespace();
        let method = request_parts.next().unwrap_or("GET").to_string();
        let path = request_parts.next().unwrap_or("/").to_string();

        let mut headers = HashMap::new();
        let mut content_length = 0usize;
        for line in lines {
            let Some((name, value)) = line.split_once(':') else {
                continue;
            };
            let name = name.trim().to_ascii_lowercase();
            let value = value.trim().to_string();
            if name == "content-length" {
                content_length = value.parse().unwrap_or(0);
            }
            headers.insert(name, value);
        }

        let body_start = header_end + 4;
        while buffer.len() < body_start + content_length {
            let read = socket.read(&mut chunk).await?;
            if read == 0 {
                return Ok(());
            }
            buffer.extend_from_slice(&chunk[..read]);
        }
        let body =
            String::from_utf8_lossy(&buffer[body_start..body_start + content_length]).into_owned();
        buffer.drain(..body_start + content_length);

        let request = Request {
            method,
            path,
            headers,
            body,
        };
        let response = handler(&request);
        if let Some(delay) = response.delay {
            tokio::time::sleep(delay).await;
        }

        let reason = match response.status {
            200 => "OK",
            301 => "Moved Permanently",
            302 => "Found",
            307 => "Temporary Redirect",
            308 => "Permanent Redirect",
            404 => "Not Found",
            500 => "Internal Server Error",
            _ => "Response",
        };
        let mut output = format!(
            "HTTP/1.1 {} {}\r\nContent-Length: {}\r\nConnection: keep-alive\r\n",
            response.status,
            reason,
            response.body.len()
        );
        for (name, value) in &response.headers {
            output.push_str(name);
            output.push_str(": ");
            output.push_str(value);
            output.push_str("\r\n");
        }
        output.push_str("\r\n");
        output.push_str(&response.body);
        socket.write_all(output.as_bytes()).await?;
        socket.flush().await?;
    }
}

fn find_header_end(buffer: &[u8]) -> Option<usize> {
    buffer.windows(4).position(|window| window == b"\r\n\r\n")
}
