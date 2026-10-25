//! Transport-agnostic scheduling engine.
//!
//! A [`Target`] renders one [`WordSet`] into a request and returns a
//! [`Response`]. Everything else (concurrency, rate limiting, timeouts,
//! retries, circuit breaking, calibration and keeping decisions) lives here so
//! HTTP and DNS modes share the same scheduler.

use std::collections::VecDeque;
use std::future::Future;
use std::time::{Duration, Instant};

use futures::{StreamExt, stream};
use rand::Rng;
use tokio::sync::Mutex;
use tokio::time::{Instant as TokioInstant, sleep};

use crate::calibration::Calibration;
use crate::matcher::Selector;
use crate::output::Event;
use crate::types::{EngineError, ExecResult};
use crate::wordlist::WordSet;

pub trait Target {
    fn execute(&self, words: &WordSet) -> impl Future<Output = Result<ExecResult, EngineError>>;
}

#[derive(Debug, Clone)]
pub struct CircuitBreakerConfig {
    pub window: usize,
    pub error_threshold: f64,
    pub min_samples: usize,
    pub cooldown: Duration,
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            window: 50,
            error_threshold: 0.5,
            min_samples: 20,
            cooldown: Duration::from_secs(5),
        }
    }
}

#[derive(Debug, Clone)]
pub struct EngineConfig {
    pub concurrency: usize,
    pub rate_limit: Option<f64>,
    pub timeout: Duration,
    pub retries: u32,
    pub retry_base_delay: Duration,
    pub circuit_breaker: Option<CircuitBreakerConfig>,
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            concurrency: 40,
            rate_limit: None,
            timeout: Duration::from_secs(10),
            retries: 2,
            retry_base_delay: Duration::from_millis(100),
            circuit_breaker: None,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct RunStats {
    pub requests: u64,
    pub errors: u64,
    pub kept: u64,
    pub filtered: u64,
}

impl RunStats {
    pub fn merge(&mut self, other: &RunStats) {
        self.requests += other.requests;
        self.errors += other.errors;
        self.kept += other.kept;
        self.filtered += other.filtered;
    }
}

#[derive(Debug, Clone, Default)]
pub struct RunReport {
    pub stats: RunStats,
    pub elapsed: Duration,
    pub rps: f64,
}

pub struct Engine {
    config: EngineConfig,
    limiter: Option<RateLimiter>,
    breaker: Option<CircuitBreaker>,
}

impl Engine {
    pub fn new(config: EngineConfig) -> Self {
        let limiter = config
            .rate_limit
            .filter(|rate| rate.is_finite() && *rate > 0.0)
            .map(RateLimiter::new);
        let breaker = config.circuit_breaker.clone().map(CircuitBreaker::new);
        Self {
            config,
            limiter,
            breaker,
        }
    }

    pub fn config(&self) -> &EngineConfig {
        &self.config
    }

    /// Probe the target with random entries and return the baseline. Probes
    /// use the same rate limit, timeout, retry and circuit-breaker policy, but
    /// are not included in run statistics.
    pub async fn calibrate<T: Target>(&self, target: &T, probes: usize) -> Calibration {
        let mut calibration = Calibration::new(probes > 0, Vec::new());
        for _ in 0..probes {
            let words = random_words();
            let report = self.perform(target, &words).await;
            if let Ok(result) = report.result {
                calibration.add_response(&result.response);
            }
        }
        calibration
    }

    /// Run a streaming wordlist through the target. Result events are emitted
    /// in completion order; the caller writes the final stats trailer.
    pub async fn run<I, T, C>(
        &self,
        words: I,
        target: &T,
        selector: &Selector,
        calibration: &Calibration,
        mut emit: C,
    ) -> Result<RunReport, EngineError>
    where
        I: Iterator<Item = std::io::Result<WordSet>>,
        T: Target,
        C: FnMut(Event),
    {
        let started = Instant::now();
        let mut stats = RunStats::default();
        let concurrency = self.config.concurrency.max(1);

        let mut pending = stream::iter(words)
            .map(|item| async move {
                match item {
                    Ok(words) => {
                        let report = self.perform(target, &words).await;
                        WorkItem::Done(words, report)
                    }
                    Err(err) => WorkItem::WordlistError(err),
                }
            })
            .buffer_unordered(concurrency);

        while let Some(item) = pending.next().await {
            match item {
                WorkItem::WordlistError(err) => {
                    return Err(EngineError::new(format!("wordlist read failed: {err}")));
                }
                WorkItem::Done(words, report) => {
                    stats.requests += u64::from(report.attempts);
                    stats.errors += u64::from(report.failed);
                    if let Ok(result) = report.result {
                        let keep = selector.keep(&result.response)
                            && !calibration.matches(&result.response);
                        if keep {
                            stats.kept += 1;
                            emit(Event::result(&words, &result));
                        } else {
                            stats.filtered += 1;
                        }
                    }
                }
            }
        }

        let elapsed = started.elapsed();
        let rps = if elapsed.as_secs_f64() > 0.0 {
            stats.requests as f64 / elapsed.as_secs_f64()
        } else {
            0.0
        };
        Ok(RunReport {
            stats,
            elapsed,
            rps,
        })
    }

    async fn perform<T: Target>(&self, target: &T, words: &WordSet) -> AttemptReport {
        let max_attempts = self.config.retries.saturating_add(1);
        let mut failed = 0u32;
        let mut last_error = None;

        for attempt in 0..max_attempts {
            if let Some(limiter) = &self.limiter {
                limiter.acquire().await;
            }
            if let Some(breaker) = &self.breaker {
                breaker.acquire().await;
            }

            let result =
                match tokio::time::timeout(self.config.timeout, target.execute(words)).await {
                    Ok(result) => result,
                    Err(_) => Err(EngineError::timeout()),
                };

            match result {
                Ok(result) => {
                    if let Some(breaker) = &self.breaker {
                        breaker.record(true).await;
                    }
                    return AttemptReport {
                        result: Ok(result),
                        attempts: attempt + 1,
                        failed,
                    };
                }
                Err(error) => {
                    failed += 1;
                    if let Some(breaker) = &self.breaker {
                        breaker.record(false).await;
                    }
                    let retryable = error.retryable;
                    last_error = Some(error);
                    if attempt + 1 < max_attempts && retryable {
                        let delay = {
                            let base = self
                                .config
                                .retry_base_delay
                                .as_millis()
                                .max(1)
                                .min(u128::from(u64::MAX))
                                as u64;
                            let exponent = 1u64 << attempt.min(20);
                            let backoff = base.saturating_mul(exponent);
                            let jitter = rand::thread_rng().gen_range(0..=base);
                            Duration::from_millis(backoff.saturating_add(jitter))
                        };
                        sleep(delay).await;
                    } else {
                        break;
                    }
                }
            }
        }

        AttemptReport {
            result: Err(last_error.unwrap_or_else(|| EngineError::new("request failed"))),
            attempts: failed.max(1),
            failed,
        }
    }
}

enum WorkItem {
    WordlistError(std::io::Error),
    Done(WordSet, AttemptReport),
}

struct AttemptReport {
    result: Result<ExecResult, EngineError>,
    attempts: u32,
    failed: u32,
}

fn random_words() -> WordSet {
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let mut rng = rand::thread_rng();
    let first_length = rng.gen_range(8..=12);
    let second_length = rng.gen_range(8..=12);
    let mut generate = |length: usize| {
        (0..length)
            .map(|_| ALPHABET[rng.gen_range(0..ALPHABET.len())] as char)
            .collect::<String>()
    };
    let first = generate(first_length);
    let second = generate(second_length);
    WordSet {
        first,
        second: Some(second),
    }
}

struct RateLimiter {
    interval: Duration,
    next: Mutex<Instant>,
}

impl RateLimiter {
    fn new(requests_per_second: f64) -> Self {
        Self {
            interval: Duration::from_secs_f64(1.0 / requests_per_second),
            next: Mutex::new(Instant::now()),
        }
    }

    async fn acquire(&self) {
        let wait = {
            let mut next = self.next.lock().await;
            let now = Instant::now();
            let slot = if *next > now { *next } else { now };
            *next = slot + self.interval;
            slot.saturating_duration_since(now)
        };
        if !wait.is_zero() {
            sleep(wait).await;
        }
    }
}

struct CircuitBreaker {
    config: CircuitBreakerConfig,
    state: Mutex<BreakerState>,
}

struct BreakerState {
    outcomes: VecDeque<bool>,
    open_until: Option<TokioInstant>,
}

impl CircuitBreaker {
    fn new(config: CircuitBreakerConfig) -> Self {
        Self {
            config,
            state: Mutex::new(BreakerState {
                outcomes: VecDeque::new(),
                open_until: None,
            }),
        }
    }

    async fn acquire(&self) {
        loop {
            let wait = {
                let mut state = self.state.lock().await;
                let now = TokioInstant::now();
                if let Some(until) = state.open_until {
                    if until > now {
                        Some(until - now)
                    } else {
                        state.open_until = None;
                        state.outcomes.clear();
                        None
                    }
                } else {
                    let min_samples = self.config.min_samples.max(1);
                    let errors = state.outcomes.iter().filter(|ok| !**ok).count();
                    let rate = if state.outcomes.is_empty() {
                        0.0
                    } else {
                        errors as f64 / state.outcomes.len() as f64
                    };
                    if state.outcomes.len() >= min_samples && rate >= self.config.error_threshold {
                        state.open_until = Some(now + self.config.cooldown);
                        state.outcomes.clear();
                        Some(self.config.cooldown)
                    } else {
                        None
                    }
                }
            };

            match wait {
                Some(duration) if !duration.is_zero() => sleep(duration).await,
                Some(_) => {}
                None => return,
            }
        }
    }

    async fn record(&self, success: bool) {
        let mut state = self.state.lock().await;
        if state.open_until.is_some() {
            return;
        }
        state.outcomes.push_back(success);
        let window = self.config.window.max(1);
        while state.outcomes.len() > window {
            state.outcomes.pop_front();
        }
    }
}
