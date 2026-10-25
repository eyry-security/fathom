//! HTTP mode for the shared engine.
//!
//! Templates may contain `FUZZ`/`FUZZ2` in the URL, method, header names,
//! header values, cookie header and body. `HttpTarget` implements the core
//! `Target` trait, so HTTP mode gets the same scheduler, retries, rate limit,
//! calibration and matchers as any other transport.

use std::time::Instant;

use reqwest::Client;
use reqwest::Proxy;
use reqwest::header::{HeaderName, HeaderValue};
use serde_json::json;

use crate::engine::Target;
use crate::types::{EngineError, ExecResult, Response};
use crate::wordlist::{WordSet, substitute};

#[derive(Debug, Clone, Default)]
pub struct HttpOptions {
    pub follow_redirects: bool,
    pub insecure: bool,
    pub proxy: Option<String>,
    pub user_agent: Option<String>,
}

pub fn build_client(options: &HttpOptions) -> Result<Client, EngineError> {
    let mut builder = Client::builder()
        .redirect(if options.follow_redirects {
            reqwest::redirect::Policy::limited(10)
        } else {
            reqwest::redirect::Policy::none()
        })
        .danger_accept_invalid_certs(options.insecure)
        .user_agent(
            options
                .user_agent
                .clone()
                .unwrap_or_else(|| concat!("fathom/", env!("CARGO_PKG_VERSION")).to_string()),
        );

    if let Some(proxy) = &options.proxy {
        let proxy = Proxy::all(proxy)
            .map_err(|err| EngineError::non_retryable(format!("invalid proxy: {err}")))?;
        builder = builder.proxy(proxy);
    }

    builder
        .build()
        .map_err(|err| EngineError::non_retryable(format!("failed to build HTTP client: {err}")))
}

#[derive(Debug, Clone)]
pub struct HttpTemplate {
    pub url: String,
    pub method: String,
    pub headers: Vec<(String, String)>,
    pub cookie: Option<String>,
    pub body: Option<String>,
}

impl HttpTemplate {
    pub fn render(&self, words: &WordSet) -> RenderedRequest {
        RenderedRequest {
            url: substitute(&self.url, words),
            method: substitute(&self.method, words).to_uppercase(),
            headers: self
                .headers
                .iter()
                .map(|(name, value)| (substitute(name, words), substitute(value, words)))
                .collect(),
            cookie: self.cookie.as_ref().map(|value| substitute(value, words)),
            body: self.body.as_ref().map(|value| substitute(value, words)),
        }
    }

    /// Template used to fuzz inside a discovered directory URL.
    pub fn for_recursion_base(&self, base: &str) -> Self {
        let mut template = self.clone();
        template.url = if base.ends_with('/') {
            format!("{base}FUZZ")
        } else {
            format!("{base}/FUZZ")
        };
        template
    }
}

#[derive(Debug, Clone)]
pub struct RenderedRequest {
    pub url: String,
    pub method: String,
    pub headers: Vec<(String, String)>,
    pub cookie: Option<String>,
    pub body: Option<String>,
}

pub struct HttpTarget {
    client: Client,
    template: HttpTemplate,
}

impl HttpTarget {
    pub fn new(client: Client, template: HttpTemplate) -> Self {
        Self { client, template }
    }

    pub fn template(&self) -> &HttpTemplate {
        &self.template
    }
}

impl Target for HttpTarget {
    async fn execute(&self, words: &WordSet) -> Result<ExecResult, EngineError> {
        let rendered = self.template.render(words);
        let method = reqwest::Method::from_bytes(rendered.method.as_bytes()).map_err(|err| {
            EngineError::non_retryable(format!("invalid method `{}`: {err}", rendered.method))
        })?;

        let mut request = self.client.request(method, &rendered.url);
        for (name, value) in &rendered.headers {
            let name = HeaderName::from_bytes(name.as_bytes()).map_err(|err| {
                EngineError::non_retryable(format!("invalid header name `{name}`: {err}"))
            })?;
            let value = HeaderValue::from_str(value).map_err(|err| {
                EngineError::non_retryable(format!("invalid header value: {err}"))
            })?;
            request = request.header(name, value);
        }
        if let Some(cookie) = &rendered.cookie {
            let value = HeaderValue::from_str(cookie).map_err(|err| {
                EngineError::non_retryable(format!("invalid cookie value: {err}"))
            })?;
            request = request.header(reqwest::header::COOKIE, value);
        }
        if let Some(body) = &rendered.body {
            request = request.body(body.clone());
        }

        let started = Instant::now();
        let response = request.send().await.map_err(reqwest_error)?;
        let status = response.status().as_u16();
        let final_url = response.url().to_string();
        let bytes = response.bytes().await.map_err(reqwest_error)?;
        let elapsed = started.elapsed();
        let body = String::from_utf8_lossy(&bytes).into_owned();

        Ok(ExecResult {
            response: Response::from_body(status, body, elapsed),
            info: json!({
                "url": rendered.url,
                "final_url": final_url,
                "method": rendered.method,
            }),
        })
    }
}

fn reqwest_error(error: reqwest::Error) -> EngineError {
    let retryable = !error.is_builder();
    EngineError {
        message: error.to_string(),
        retryable,
        timed_out: error.is_timeout(),
    }
}

/// Returns the base URL to queue for recursion when a kept result ends in a
/// directory path, or `None` when the depth cap is reached.
pub fn recursion_base(info: &serde_json::Value, depth: usize, max_depth: usize) -> Option<String> {
    if depth >= max_depth {
        return None;
    }
    let url = info
        .get("final_url")
        .or_else(|| info.get("url"))?
        .as_str()?;
    let without_fragment = url.split('#').next().unwrap_or(url);
    let without_query = without_fragment
        .split('?')
        .next()
        .unwrap_or(without_fragment);
    if without_query.ends_with('/') {
        Some(without_query.to_string())
    } else {
        None
    }
}
