//! DNS brute-force mode for the shared engine.
//!
//! `DnsTarget` turns one word into `<word>.<domain>` and resolves the
//! configured record types through hickory-dns. It implements the core
//! [`Target`] trait, so DNS mode uses the same scheduler, rate limiter,
//! per-request timeout, retries and circuit breaker as HTTP mode.

use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::RwLock;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use futures::future::join_all;
use hickory_resolver::TokioAsyncResolver;
use hickory_resolver::config::{
    NameServerConfig, NameServerConfigGroup, Protocol, ResolverConfig, ResolverOpts,
};
use hickory_resolver::error::{ResolveError, ResolveErrorKind};
use hickory_resolver::proto::op::ResponseCode;
use hickory_resolver::proto::rr::{Name, RData, RecordType};
use rand::Rng;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::calibration::Calibration;
use crate::engine::{Engine, Target};
use crate::matcher::Selector;
use crate::output::Event;
use crate::types::{EngineError, ExecResult, Response};
use crate::wordlist::WordSet;

/// Stable identity of one answer. TTL is deliberately excluded: a wildcard
/// record whose TTL changes between probes is still the same answer.
pub type AnswerKey = (String, String);

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DnsAnswer {
    #[serde(rename = "type")]
    pub record_type: String,
    pub value: String,
    pub ttl: u32,
}

impl DnsAnswer {
    pub fn key(&self) -> AnswerKey {
        (self.record_type.clone(), self.value.clone())
    }
}

/// Payload carried under the `dns` key of a result event.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DnsPayload {
    pub host: String,
    pub domain: String,
    pub record_types: Vec<String>,
    pub rcode: String,
    pub wildcard: bool,
    pub answers: Vec<DnsAnswer>,
}

impl DnsPayload {
    pub fn answer_keys(&self) -> impl Iterator<Item = AnswerKey> + '_ {
        self.answers.iter().map(DnsAnswer::key)
    }
}

pub fn default_record_types(cname: bool) -> Vec<RecordType> {
    let mut record_types = vec![RecordType::A, RecordType::AAAA];
    if cname {
        record_types.push(RecordType::CNAME);
    }
    record_types
}

/// Build all configured resolvers. An empty list uses the system resolver.
/// Each explicit entry becomes its own UDP resolver so the target can rotate
/// between them deterministically.
pub fn build_resolvers(specs: &[String]) -> Result<Vec<TokioAsyncResolver>, EngineError> {
    if specs.is_empty() {
        return Ok(vec![system_resolver()?]);
    }

    let mut resolvers = Vec::with_capacity(specs.len());
    for spec in specs {
        let address = parse_resolver(spec)?;
        let mut name_servers = NameServerConfigGroup::with_capacity(1);
        name_servers.push(NameServerConfig::new(address, Protocol::Udp));

        let config = ResolverConfig::from_parts(None, Vec::new(), name_servers);
        let mut options = ResolverOpts::default();
        options.attempts = 1;
        options.num_concurrent_reqs = 1;
        options.preserve_intermediates = false;
        options.use_hosts_file = false;
        resolvers.push(TokioAsyncResolver::tokio(config, options));
    }
    Ok(resolvers)
}

fn system_resolver() -> Result<TokioAsyncResolver, EngineError> {
    TokioAsyncResolver::tokio_from_system_conf()
        .map_err(|err| EngineError::non_retryable(format!("cannot read system resolver: {err}")))
}

fn parse_resolver(spec: &str) -> Result<SocketAddr, EngineError> {
    let spec = spec.trim();
    if let Ok(address) = SocketAddr::from_str(spec) {
        return Ok(address);
    }
    if let Ok(ip) = IpAddr::from_str(spec) {
        return Ok(SocketAddr::new(ip, 53));
    }
    Err(EngineError::non_retryable(format!(
        "invalid resolver `{spec}` (expected IP or IP:PORT)"
    )))
}

/// Union of answer identities returned by random non-existent names at the
/// level being brute-forced. A result is wildcard traffic when all of its
/// answer identities are present here (subset or equal).
#[derive(Debug, Clone, Default)]
pub struct WildcardSet {
    answers: HashSet<AnswerKey>,
}

impl WildcardSet {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_empty(&self) -> bool {
        self.answers.is_empty()
    }

    pub fn len(&self) -> usize {
        self.answers.len()
    }

    pub fn extend_answers<'a, I>(&mut self, answers: I)
    where
        I: IntoIterator<Item = &'a DnsAnswer>,
    {
        self.answers.extend(answers.into_iter().map(DnsAnswer::key));
    }

    pub fn contains(&self, answer: &DnsAnswer) -> bool {
        self.answers.contains(&answer.key())
    }

    /// True when every answer identity is part of the wildcard set. TTLs are
    /// ignored, and a result with an extra/distinct record is not a match.
    pub fn matches(&self, answers: &[DnsAnswer]) -> bool {
        !self.answers.is_empty()
            && !answers.is_empty()
            && answers.iter().all(|answer| self.contains(answer))
    }

    pub fn answers(&self) -> &HashSet<AnswerKey> {
        &self.answers
    }
}

pub struct DnsTarget {
    resolvers: Vec<TokioAsyncResolver>,
    next_resolver: AtomicUsize,
    domain: String,
    record_types: Vec<RecordType>,
    wildcards: RwLock<WildcardSet>,
    show_wildcards: bool,
}

impl DnsTarget {
    pub fn new(
        resolvers: Vec<TokioAsyncResolver>,
        domain: impl Into<String>,
        record_types: Vec<RecordType>,
    ) -> Self {
        assert!(!resolvers.is_empty(), "at least one resolver is required");
        Self {
            resolvers,
            next_resolver: AtomicUsize::new(0),
            domain: domain.into().trim_end_matches('.').to_string(),
            record_types,
            wildcards: RwLock::new(WildcardSet::default()),
            show_wildcards: false,
        }
    }

    pub fn domain(&self) -> &str {
        &self.domain
    }

    pub fn record_types(&self) -> &[RecordType] {
        &self.record_types
    }

    pub fn set_show_wildcards(&mut self, show: bool) {
        self.show_wildcards = show;
    }

    pub fn show_wildcards(&self) -> bool {
        self.show_wildcards
    }

    pub fn set_wildcards(&self, wildcards: WildcardSet) {
        *self
            .wildcards
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = wildcards;
    }

    pub fn wildcards(&self) -> WildcardSet {
        self.wildcards
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    /// Probe random non-existent names at `<random>.<domain>` (the level being
    /// brute-forced) and union every answer they return. Probes use the same
    /// engine scheduler and rate caps as the main run but are not counted in
    /// its statistics.
    pub async fn detect_wildcards(&self, engine: &Engine, probes: usize) -> WildcardSet {
        let mut wildcards = WildcardSet::new();
        if probes == 0 {
            return wildcards;
        }

        let probe_words = (0..probes).map(|_| Ok(WordSet::single(random_label())));
        let _ = engine
            .run(
                probe_words,
                self,
                &Selector::default(),
                &Calibration::default(),
                |event| {
                    if let Event::Result { info, .. } = &event {
                        if let Some(payload) = payload_from_info(info) {
                            wildcards.extend_answers(payload.answers.iter());
                        }
                    }
                },
            )
            .await;
        wildcards
    }

    fn resolver(&self) -> &TokioAsyncResolver {
        let index = self.next_resolver.fetch_add(1, Ordering::Relaxed) % self.resolvers.len();
        &self.resolvers[index]
    }

    fn host(&self, words: &WordSet) -> String {
        let label = words.first.trim_end_matches('.');
        format!("{label}.{}", self.domain)
    }
}

impl Target for DnsTarget {
    async fn execute(&self, words: &WordSet) -> Result<ExecResult, EngineError> {
        let host = self.host(words);
        let name = Name::from_ascii(format!("{host}.")).map_err(|err| {
            EngineError::non_retryable(format!("invalid DNS name `{host}`: {err}"))
        })?;
        let resolver = self.resolver().clone();
        let started = Instant::now();

        let lookups = self.record_types.iter().copied().map(|record_type| {
            let resolver = resolver.clone();
            let name = name.clone();
            async move {
                let result = resolver.lookup(name, record_type).await;
                (record_type, result)
            }
        });
        let outcomes = join_all(lookups).await;
        let elapsed = started.elapsed();

        let mut answers = Vec::new();
        let mut saw_answer = false;
        let mut saw_nxdomain = false;
        let mut rcode = ResponseCode::NoError;

        for (requested, outcome) in outcomes {
            match outcome {
                Ok(lookup) => {
                    if rcode == ResponseCode::NXDomain {
                        rcode = ResponseCode::NoError;
                    }
                    for record in lookup.record_iter() {
                        let Some(data) = record.data() else {
                            continue;
                        };
                        let Some(value) = rdata_value(data) else {
                            continue;
                        };
                        saw_answer = true;
                        answers.push(DnsAnswer {
                            record_type: record.record_type().to_string(),
                            value,
                            ttl: record.ttl(),
                        });
                    }
                    if !saw_answer && requested == RecordType::A {
                        // A valid NOERROR/NODATA response still means the name
                        // exists; leave rcode as NOERROR.
                    }
                }
                Err(error) => match error.kind() {
                    ResolveErrorKind::NoRecordsFound { response_code, .. } => {
                        if *response_code == ResponseCode::NXDomain {
                            saw_nxdomain = true;
                        } else if *response_code != ResponseCode::NoError {
                            rcode = *response_code;
                        }
                    }
                    _ => return Err(resolve_error(error)),
                },
            }
        }

        if !saw_answer && saw_nxdomain && rcode == ResponseCode::NoError {
            rcode = ResponseCode::NXDomain;
        }

        answers.sort_by(|a, b| {
            a.record_type
                .cmp(&b.record_type)
                .then_with(|| a.value.cmp(&b.value))
        });
        answers.dedup();

        let body = answers
            .iter()
            .map(|answer| format!("{} {} {}", answer.record_type, answer.value, answer.ttl))
            .collect::<Vec<_>>()
            .join("\n");
        let wildcard = self
            .wildcards
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .matches(&answers);
        let payload = DnsPayload {
            host,
            domain: self.domain.clone(),
            record_types: self.record_types.iter().map(ToString::to_string).collect(),
            rcode: rcode_label(rcode).to_string(),
            wildcard,
            answers,
        };

        Ok(ExecResult {
            response: Response::from_body(u16::from(rcode), body, elapsed),
            info: json!({ "dns": payload }),
        })
    }

    fn keep_result(&self, _words: &WordSet, result: &ExecResult) -> bool {
        let Some(payload) = payload_from_info(&result.info) else {
            return true;
        };
        if payload.answers.is_empty() {
            return false;
        }
        if self.show_wildcards {
            return true;
        }
        !self
            .wildcards
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .matches(&payload.answers)
    }
}

fn random_label() -> String {
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let mut rng = rand::thread_rng();
    (0..18)
        .map(|_| ALPHABET[rng.gen_range(0..ALPHABET.len())] as char)
        .collect()
}

fn rdata_value(data: &RData) -> Option<String> {
    match data {
        RData::A(address) => Some(address.0.to_string()),
        RData::AAAA(address) => Some(address.0.to_string()),
        RData::CNAME(name) => Some(
            name.0
                .to_string()
                .trim_end_matches('.')
                .to_ascii_lowercase(),
        ),
        _ => None,
    }
}

fn resolve_error(error: ResolveError) -> EngineError {
    match error.kind() {
        ResolveErrorKind::Timeout => EngineError::timeout(),
        ResolveErrorKind::Io(_) | ResolveErrorKind::NoConnections => {
            EngineError::retryable(error.to_string())
        }
        _ => EngineError::non_retryable(error.to_string()),
    }
}

fn rcode_label(rcode: ResponseCode) -> &'static str {
    match rcode {
        ResponseCode::NoError => "NOERROR",
        ResponseCode::FormErr => "FORMERR",
        ResponseCode::ServFail => "SERVFAIL",
        ResponseCode::NXDomain => "NXDOMAIN",
        ResponseCode::NotImp => "NOTIMP",
        ResponseCode::Refused => "REFUSED",
        _ => "OTHER",
    }
}

pub fn payload_from_info(info: &serde_json::Value) -> Option<DnsPayload> {
    info.get("dns")
        .cloned()
        .and_then(|value| serde_json::from_value(value).ok())
}

/// Translate a discovered host into one line of Vedette input: a bare host, or
/// `host:port` when a port is supplied.
pub fn handoff_line(host: &str, port: Option<u16>) -> String {
    match port {
        Some(port) => format!("{host}:{port}"),
        None => host.to_string(),
    }
}

/// Write one Vedette-compatible host line (including the trailing newline).
pub fn write_handoff_line<W: std::io::Write>(
    writer: &mut W,
    host: &str,
    port: Option<u16>,
) -> std::io::Result<()> {
    writeln!(writer, "{}", handoff_line(host, port))
}
