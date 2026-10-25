//! Event output.
//!
//! JSONL contract (one JSON object per line, UTF-8):
//!
//! ```json
//! {"type":"result","input":{"FUZZ":"admin","FUZZ2":"example"},"url":"http://127.0.0.1:8080/admin","final_url":"http://127.0.0.1:8080/admin","method":"GET","status":200,"size":123,"words":4,"lines":2,"duration_ms":7}
//! {"type":"stats","requests":100,"errors":0,"kept":4,"filtered":96,"elapsed_ms":812,"rps":123.15}
//! ```
//!
//! * `type` is `result` or `stats`.
//! * `input` maps each used keyword (`FUZZ`, and `FUZZ2` when a second list is
//!   present) to its value.
//! * Transport metadata from the target is flattened next to `input`; HTTP
//!   targets add `url`, `final_url` and `method`.
//! * `status`, `size` (body bytes), `words`, `lines`, `duration_ms` describe
//!   the response.
//! * Exactly one `stats` object is written as the trailer. `requests` counts
//!   attempts (including retries), `errors` counts failed attempts.
//!
//! Only kept results produce `result` events.

use std::io::Write;
use std::time::Duration;

use serde::Serialize;

use crate::engine::RunReport;
use crate::types::ExecResult;
use crate::wordlist::{FUZZ, FUZZ2, WordSet};

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Event {
    Result {
        input: serde_json::Value,
        #[serde(flatten)]
        info: serde_json::Value,
        status: u16,
        size: usize,
        words: usize,
        lines: usize,
        duration_ms: u64,
    },
    Stats {
        requests: u64,
        errors: u64,
        kept: u64,
        filtered: u64,
        elapsed_ms: u64,
        rps: f64,
    },
}

impl Event {
    pub fn result(words: &WordSet, result: &ExecResult) -> Self {
        let response = &result.response;
        Self::Result {
            input: input_value(words),
            info: result.info.clone(),
            status: response.status,
            size: response.size,
            words: response.words,
            lines: response.lines,
            duration_ms: millis(response.elapsed),
        }
    }

    pub fn stats(report: &RunReport) -> Self {
        Self::Stats {
            requests: report.stats.requests,
            errors: report.stats.errors,
            kept: report.stats.kept,
            filtered: report.stats.filtered,
            elapsed_ms: millis(report.elapsed),
            rps: report.rps,
        }
    }
}

fn input_value(words: &WordSet) -> serde_json::Value {
    let mut map = serde_json::Map::new();
    map.insert(
        FUZZ.to_string(),
        serde_json::Value::String(words.first.clone()),
    );
    if let Some(second) = &words.second {
        map.insert(FUZZ2.to_string(), serde_json::Value::String(second.clone()));
    }
    serde_json::Value::Object(map)
}

fn millis(duration: Duration) -> u64 {
    duration.as_millis().min(u128::from(u64::MAX)) as u64
}

pub fn event_line(event: &Event) -> String {
    serde_json::to_string(event).expect("event serialization cannot fail")
}

pub fn write_event<W: Write>(writer: &mut W, event: &Event) -> std::io::Result<()> {
    serde_json::to_writer(&mut *writer, event).map_err(std::io::Error::other)?;
    writer.write_all(b"\n")?;
    writer.flush()
}

pub struct JsonlWriter<W: Write> {
    writer: W,
}

impl<W: Write> JsonlWriter<W> {
    pub fn new(writer: W) -> Self {
        Self { writer }
    }

    pub fn write(&mut self, event: &Event) -> std::io::Result<()> {
        write_event(&mut self.writer, event)
    }

    pub fn flush(&mut self) -> std::io::Result<()> {
        self.writer.flush()
    }
}

#[derive(Debug, Default)]
pub struct HumanTable {
    header_printed: bool,
}

impl HumanTable {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn print(&mut self, event: &Event) {
        match event {
            Event::Result {
                input,
                info,
                status,
                size,
                words,
                lines,
                duration_ms,
            } => {
                if !self.header_printed {
                    println!(
                        "{:<6} {:<8} {:<6} {:<6} {:<8} TARGET",
                        "STATUS", "SIZE", "WORDS", "LINES", "TIME(ms)"
                    );
                    self.header_printed = true;
                }
                let target = info
                    .get("url")
                    .and_then(|value| value.as_str())
                    .map(str::to_string)
                    .unwrap_or_else(|| input_label(input));
                println!(
                    "{:<6} {:<8} {:<6} {:<6} {:<8} {}",
                    status, size, words, lines, duration_ms, target
                );
            }
            Event::Stats {
                requests,
                errors,
                kept,
                filtered,
                elapsed_ms,
                rps,
            } => {
                println!(
                    "[stats] requests={requests} errors={errors} kept={kept} filtered={filtered} elapsed_ms={elapsed_ms} rps={rps:.2}"
                );
            }
        }
    }
}

fn input_label(input: &serde_json::Value) -> String {
    input
        .as_object()
        .map(|map| {
            map.iter()
                .map(|(key, value)| format!("{key}={}", value.as_str().unwrap_or_default()))
                .collect::<Vec<_>>()
                .join("&")
        })
        .unwrap_or_default()
}
