//! ffuf-style matchers and filters.
//!
//! A response is kept when **all configured matcher groups pass** and **no
//! configured filter group hits**. Within a group (for example several status
//! codes, or several regexes) values are OR-ed.

use std::time::Duration;

use regex::Regex;

use crate::types::Response;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimeRange {
    pub min_ms: u64,
    pub max_ms: u64,
}

impl TimeRange {
    pub fn new(min_ms: u64, max_ms: u64) -> Self {
        Self { min_ms, max_ms }
    }

    pub fn contains(&self, elapsed: Duration) -> bool {
        let millis = elapsed.as_millis().min(u128::from(u64::MAX)) as u64;
        millis >= self.min_ms && millis <= self.max_ms
    }

    /// Accepts `100`, `100-`, `-100`, `100-250` (milliseconds).
    pub fn parse(value: &str) -> Result<Self, String> {
        let value = value.trim();
        if value.is_empty() {
            return Err("time range cannot be empty".to_string());
        }
        match value.split_once('-') {
            Some((min, max)) => {
                let min_ms = if min.trim().is_empty() {
                    0
                } else {
                    min.trim()
                        .parse::<u64>()
                        .map_err(|_| format!("invalid time range `{value}`"))?
                };
                let max_ms = if max.trim().is_empty() {
                    u64::MAX
                } else {
                    max.trim()
                        .parse::<u64>()
                        .map_err(|_| format!("invalid time range `{value}`"))?
                };
                if min_ms > max_ms {
                    return Err(format!("time range `{value}` has min greater than max"));
                }
                Ok(Self { min_ms, max_ms })
            }
            None => {
                let millis = value
                    .parse::<u64>()
                    .map_err(|_| format!("invalid time range `{value}`"))?;
                Ok(Self {
                    min_ms: millis,
                    max_ms: millis,
                })
            }
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct Criteria {
    pub status: Vec<u16>,
    pub size: Vec<usize>,
    pub words: Vec<usize>,
    pub lines: Vec<usize>,
    pub regex: Vec<Regex>,
    pub time_ms: Option<TimeRange>,
}

impl Criteria {
    pub fn is_empty(&self) -> bool {
        self.status.is_empty()
            && self.size.is_empty()
            && self.words.is_empty()
            && self.lines.is_empty()
            && self.regex.is_empty()
            && self.time_ms.is_none()
    }

    /// True when every configured matcher group passes.
    pub fn matches_all(&self, response: &Response) -> bool {
        (self.status.is_empty() || self.status.contains(&response.status))
            && (self.size.is_empty() || self.size.contains(&response.size))
            && (self.words.is_empty() || self.words.contains(&response.words))
            && (self.lines.is_empty() || self.lines.contains(&response.lines))
            && (self.regex.is_empty()
                || self
                    .regex
                    .iter()
                    .any(|regex| regex.is_match(&response.body)))
            && self
                .time_ms
                .map(|range| range.contains(response.elapsed))
                .unwrap_or(true)
    }

    /// True when at least one configured filter group hits.
    pub fn any_hit(&self, response: &Response) -> bool {
        (!self.status.is_empty() && self.status.contains(&response.status))
            || (!self.size.is_empty() && self.size.contains(&response.size))
            || (!self.words.is_empty() && self.words.contains(&response.words))
            || (!self.lines.is_empty() && self.lines.contains(&response.lines))
            || (!self.regex.is_empty()
                && self
                    .regex
                    .iter()
                    .any(|regex| regex.is_match(&response.body)))
            || self
                .time_ms
                .map(|range| range.contains(response.elapsed))
                .unwrap_or(false)
    }
}

#[derive(Debug, Clone, Default)]
pub struct Selector {
    pub matchers: Criteria,
    pub filters: Criteria,
}

impl Selector {
    pub fn keep(&self, response: &Response) -> bool {
        self.matchers.matches_all(response) && !self.filters.any_hit(response)
    }
}

pub fn compile_regexes(patterns: &[String]) -> Result<Vec<Regex>, regex::Error> {
    patterns.iter().map(|pattern| Regex::new(pattern)).collect()
}
