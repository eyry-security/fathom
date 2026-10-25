use std::collections::{HashSet, VecDeque};
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand, ValueEnum};
use fathom::http_mode::recursion_base;
use fathom::{
    Calibration, CircuitBreakerConfig, Criteria, Engine, EngineConfig, Event, HttpOptions,
    HttpTarget, HttpTemplate, HumanTable, JsonlWriter, Mode, RunReport, RunStats, Selector,
    TimeRange, WordlistSpec, build_client, compile_regexes, expand_extensions,
};

const DEFAULT_MATCH_STATUSES: &str = "200-299,301,302,307,401,403,405,500";

#[derive(Parser)]
#[command(
    name = "fathom",
    version,
    about = "Rust fuzzing engine for the Eyry suite (HTTP now, DNS next)"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Fuzz an HTTP template containing FUZZ / FUZZ2.
    Http(HttpArgs),
}

#[derive(Args)]
struct HttpArgs {
    /// URL template; FUZZ / FUZZ2 may appear anywhere.
    #[arg(short = 'u', long = "url", value_name = "URL")]
    url: String,

    /// One wordlist, or two for FUZZ + FUZZ2.
    #[arg(
        short = 'w',
        long = "wordlist",
        value_name = "FILE",
        num_args = 1..=2,
        required = true
    )]
    wordlists: Vec<PathBuf>,

    /// Pairing mode when two wordlists are supplied.
    #[arg(long = "mode", value_enum, default_value_t = ModeArg::Clusterbomb)]
    mode: ModeArg,

    /// HTTP method template.
    #[arg(short = 'X', long = "method", default_value = "GET")]
    method: String,

    /// Header template, `Name: Value`; repeatable.
    #[arg(short = 'H', long = "header", value_name = "HEADER")]
    headers: Vec<String>,

    /// Cookie header template.
    #[arg(short = 'b', long = "cookie", value_name = "COOKIE")]
    cookie: Option<String>,

    /// Request body template.
    #[arg(short = 'd', long = "data", value_name = "BODY")]
    body: Option<String>,

    /// Follow redirects.
    #[arg(short = 'r', long = "follow-redirects")]
    follow_redirects: bool,

    /// Skip TLS certificate verification.
    #[arg(short = 'k', long = "insecure")]
    insecure: bool,

    /// Proxy URL (HTTP/HTTPS proxy environment variables also work).
    #[arg(short = 'x', long = "proxy", value_name = "URL")]
    proxy: Option<String>,

    /// Concurrent requests (default: 40).
    #[arg(short = 't', long = "concurrency", default_value_t = 40)]
    concurrency: usize,

    /// Global requests/sec cap (default: none).
    #[arg(long = "rate", visible_alias = "rate-limit", value_name = "RPS")]
    rate: Option<f64>,

    /// Per-request timeout in seconds.
    #[arg(long = "timeout", default_value_t = 10.0)]
    timeout: f64,

    /// Retry count per request (capped at 10).
    #[arg(long = "retries", default_value_t = 2)]
    retries: u32,

    /// Pause new work when the rolling error rate reaches this ratio (0, 1].
    #[arg(long = "error-threshold", value_name = "RATIO")]
    error_threshold: Option<f64>,

    /// Rolling error window size.
    #[arg(long = "error-window", default_value_t = 50)]
    error_window: usize,

    /// Minimum samples before the circuit breaker can open.
    #[arg(long = "error-min-samples", default_value_t = 20)]
    error_min_samples: usize,

    /// Circuit-breaker pause duration in seconds.
    #[arg(long = "error-cooldown", default_value_t = 5.0)]
    error_cooldown: f64,

    /// Calibrate with random entries and auto-filter matching baselines.
    #[arg(short = 'a', long = "calibrate")]
    calibrate: bool,

    /// Number of random calibration probes.
    #[arg(long = "calibration-requests", default_value_t = 3)]
    calibration_requests: usize,

    /// Queue discovered directory paths (URLs ending in `/`) for fuzzing.
    #[arg(long = "recursion")]
    recursion: bool,

    /// Maximum recursion depth.
    #[arg(long = "recursion-depth", default_value_t = 2)]
    recursion_depth: usize,

    /// Append each extension to every FUZZ entry.
    #[arg(short = 'e', long = "extensions", value_delimiter = ',')]
    extensions: Vec<String>,

    /// Matcher status codes/ranges (default: 200-299,301,302,307,401,403,405,500).
    #[arg(long = "match-status", value_delimiter = ',')]
    match_status: Vec<String>,

    /// Matcher body sizes in bytes.
    #[arg(long = "match-size", value_delimiter = ',')]
    match_size: Vec<String>,

    /// Matcher word counts.
    #[arg(long = "match-words", value_delimiter = ',')]
    match_words: Vec<String>,

    /// Matcher line counts.
    #[arg(long = "match-lines", value_delimiter = ',')]
    match_lines: Vec<String>,

    /// Matcher body regex; repeatable.
    #[arg(long = "match-regex")]
    match_regex: Vec<String>,

    /// Matcher response-time range in milliseconds, e.g. `100-500`.
    #[arg(long = "match-time")]
    match_time: Option<String>,

    /// Filter status codes/ranges.
    #[arg(long = "filter-status", value_delimiter = ',')]
    filter_status: Vec<String>,

    /// Filter body sizes in bytes.
    #[arg(long = "filter-size", value_delimiter = ',')]
    filter_size: Vec<String>,

    /// Filter word counts.
    #[arg(long = "filter-words", value_delimiter = ',')]
    filter_words: Vec<String>,

    /// Filter line counts.
    #[arg(long = "filter-lines", value_delimiter = ',')]
    filter_lines: Vec<String>,

    /// Filter body regex; repeatable.
    #[arg(long = "filter-regex")]
    filter_regex: Vec<String>,

    /// Filter response-time range in milliseconds, e.g. `100-500`.
    #[arg(long = "filter-time")]
    filter_time: Option<String>,

    /// Write JSONL events plus the stats trailer to this file.
    #[arg(short = 'o', long = "output", value_name = "FILE")]
    output: Option<PathBuf>,

    /// Terminal output format.
    #[arg(long = "format", value_enum, default_value_t = OutputFormat::Human)]
    format: OutputFormat,
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
enum ModeArg {
    Pitchfork,
    Clusterbomb,
}

impl From<ModeArg> for Mode {
    fn from(value: ModeArg) -> Self {
        match value {
            ModeArg::Pitchfork => Mode::Pitchfork,
            ModeArg::Clusterbomb => Mode::Clusterbomb,
        }
    }
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
enum OutputFormat {
    Human,
    Jsonl,
}

#[tokio::main]
async fn main() {
    if let Err(error) = cli().await {
        eprintln!("error: {error:#}");
        std::process::exit(1);
    }
}

async fn cli() -> Result<()> {
    match Cli::parse().command {
        Command::Http(args) => run_http(args).await,
    }
}

async fn run_http(args: HttpArgs) -> Result<()> {
    if args.concurrency == 0 {
        bail!("--concurrency must be at least 1");
    }
    if !args.timeout.is_finite() || args.timeout <= 0.0 {
        bail!("--timeout must be greater than 0");
    }
    if let Some(rate) = args.rate {
        if !rate.is_finite() || rate <= 0.0 {
            bail!("--rate must be greater than 0");
        }
    }

    let mut headers = Vec::with_capacity(args.headers.len());
    for raw in &args.headers {
        let (name, value) = raw
            .split_once(':')
            .with_context(|| format!("header `{raw}` is missing `:`"))?;
        headers.push((name.trim().to_string(), value.trim_start().to_string()));
    }

    let template = HttpTemplate {
        url: args.url.clone(),
        method: args.method.clone(),
        headers,
        cookie: args.cookie.clone(),
        body: args.body.clone(),
    };

    let match_statuses = if args.match_status.is_empty() {
        vec![DEFAULT_MATCH_STATUSES.to_string()]
    } else {
        args.match_status.clone()
    };
    let selector = Selector {
        matchers: Criteria {
            status: parse_statuses(&match_statuses)?,
            size: parse_numbers(&args.match_size)?,
            words: parse_numbers(&args.match_words)?,
            lines: parse_numbers(&args.match_lines)?,
            regex: compile_regexes(&args.match_regex).context("invalid --match-regex")?,
            time_ms: args
                .match_time
                .as_deref()
                .map(TimeRange::parse)
                .transpose()
                .map_err(anyhow::Error::msg)?,
        },
        filters: Criteria {
            status: parse_statuses(&args.filter_status)?,
            size: parse_numbers(&args.filter_size)?,
            words: parse_numbers(&args.filter_words)?,
            lines: parse_numbers(&args.filter_lines)?,
            regex: compile_regexes(&args.filter_regex).context("invalid --filter-regex")?,
            time_ms: args
                .filter_time
                .as_deref()
                .map(TimeRange::parse)
                .transpose()
                .map_err(anyhow::Error::msg)?,
        },
    };

    let circuit_breaker = match args.error_threshold {
        Some(threshold) => {
            if !threshold.is_finite() || threshold <= 0.0 || threshold > 1.0 {
                bail!("--error-threshold must be in (0, 1]");
            }
            if !args.error_cooldown.is_finite() || args.error_cooldown <= 0.0 {
                bail!("--error-cooldown must be greater than 0");
            }
            Some(CircuitBreakerConfig {
                window: args.error_window.max(1),
                error_threshold: threshold,
                min_samples: args.error_min_samples.max(1),
                cooldown: Duration::from_secs_f64(args.error_cooldown),
            })
        }
        None => None,
    };

    let engine = Engine::new(EngineConfig {
        concurrency: args.concurrency,
        rate_limit: args.rate,
        timeout: Duration::from_secs_f64(args.timeout),
        retries: args.retries.min(10),
        retry_base_delay: Duration::from_millis(100),
        circuit_breaker,
    });

    let client = build_client(&HttpOptions {
        follow_redirects: args.follow_redirects,
        insecure: args.insecure,
        proxy: args.proxy.clone(),
        user_agent: None,
    })?;

    let spec = WordlistSpec::new(
        args.wordlists[0].clone(),
        args.wordlists.get(1).cloned(),
        args.mode.into(),
    );
    let extensions: Vec<String> = args
        .extensions
        .iter()
        .map(|extension| extension.trim().to_string())
        .filter(|extension| !extension.is_empty())
        .collect();

    let mut sinks: Vec<JsonlWriter<Box<dyn Write>>> = Vec::new();
    if args.format == OutputFormat::Jsonl {
        sinks.push(JsonlWriter::new(Box::new(
            BufWriter::new(std::io::stdout()),
        )));
    }
    if let Some(path) = &args.output {
        let file = File::create(path)
            .with_context(|| format!("cannot create output file {}", path.display()))?;
        sinks.push(JsonlWriter::new(Box::new(BufWriter::new(file))));
    }
    let mut human = (args.format == OutputFormat::Human).then(HumanTable::new);

    let mut queue: VecDeque<(HttpTemplate, usize)> = VecDeque::new();
    queue.push_back((template, 0));
    let mut visited: HashSet<String> = HashSet::new();
    let mut aggregate = RunStats::default();
    let overall_start = Instant::now();

    while let Some((current_template, depth)) = queue.pop_front() {
        if !visited.insert(current_template.url.clone()) {
            continue;
        }

        let target = HttpTarget::new(client.clone(), current_template.clone());
        let calibration = if args.calibrate {
            engine.calibrate(&target, args.calibration_requests).await
        } else {
            Calibration::default()
        };

        let words = spec
            .iter()
            .with_context(|| format!("cannot open wordlist {}", spec.first.display()))?;
        let words = expand_extensions(words, extensions.clone());

        let mut recursions = Vec::new();
        let mut output_error: Option<anyhow::Error> = None;

        let report = engine
            .run(words, &target, &selector, &calibration, |event| {
                if output_error.is_some() {
                    return;
                }
                if let Event::Result { info, .. } = &event {
                    if args.recursion {
                        if let Some(base) = recursion_base(info, depth, args.recursion_depth) {
                            recursions
                                .push((current_template.for_recursion_base(&base), depth + 1));
                        }
                    }
                }
                if let Some(table) = &mut human {
                    table.print(&event);
                }
                for sink in &mut sinks {
                    if let Err(error) = sink.write(&event) {
                        output_error = Some(anyhow::Error::new(error));
                        break;
                    }
                }
            })
            .await?;

        if let Some(error) = output_error {
            return Err(error).context("cannot write output");
        }

        aggregate.merge(&report.stats);
        if args.recursion {
            for item in recursions {
                if !visited.contains(&item.0.url) {
                    queue.push_back(item);
                }
            }
        }
    }

    let elapsed = overall_start.elapsed();
    let rps = if elapsed.as_secs_f64() > 0.0 {
        aggregate.requests as f64 / elapsed.as_secs_f64()
    } else {
        0.0
    };
    let stats = Event::stats(&RunReport {
        stats: aggregate,
        elapsed,
        rps,
    });
    if let Some(table) = &mut human {
        table.print(&stats);
    }
    for sink in &mut sinks {
        sink.write(&stats)?;
        sink.flush()?;
    }

    Ok(())
}

fn parse_statuses(values: &[String]) -> Result<Vec<u16>> {
    let mut statuses = Vec::new();
    for value in values {
        for part in value.split(',') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            if part.eq_ignore_ascii_case("all") {
                return Ok(Vec::new());
            }
            if let Some((start, end)) = part.split_once('-') {
                let start: u16 = start
                    .trim()
                    .parse()
                    .with_context(|| format!("invalid status range `{part}`"))?;
                let end: u16 = end
                    .trim()
                    .parse()
                    .with_context(|| format!("invalid status range `{part}`"))?;
                if start > end {
                    bail!("invalid status range `{part}`: start is greater than end");
                }
                statuses.extend(start..=end);
            } else {
                statuses.push(
                    part.parse()
                        .with_context(|| format!("invalid status code `{part}`"))?,
                );
            }
        }
    }
    statuses.sort_unstable();
    statuses.dedup();
    Ok(statuses)
}

fn parse_numbers(values: &[String]) -> Result<Vec<usize>> {
    let mut numbers = Vec::new();
    for value in values {
        for part in value.split(',') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            numbers.push(
                part.parse()
                    .with_context(|| format!("invalid number `{part}`"))?,
            );
        }
    }
    numbers.sort_unstable();
    numbers.dedup();
    Ok(numbers)
}
