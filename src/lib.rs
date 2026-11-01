//! fathom — one fuzzing engine, HTTP today and DNS next.
//!
//! The core (`wordlist`, `engine`, `calibration`, `matcher`, `output`) has no
//! HTTP assumptions. HTTP support is the `http_mode` target plus the `http`
//! binary subcommand.

pub mod calibration;
pub mod dns_mode;
pub mod engine;
pub mod http_mode;
pub mod matcher;
pub mod output;
pub mod types;
pub mod wordlist;

pub use calibration::Calibration;
pub use dns_mode::{
    AnswerKey, DnsAnswer, DnsPayload, DnsRunStats, DnsTarget, DnsTypeStats, DnsTypeTotals,
    WildcardSet, build_resolvers, default_record_types, handoff_line, payload_from_info,
    write_handoff_line,
};
pub use engine::{CircuitBreakerConfig, Engine, EngineConfig, RunReport, RunStats, Target};
pub use http_mode::{HttpOptions, HttpTarget, HttpTemplate, build_client};
pub use matcher::{Criteria, Selector, TimeRange, compile_regexes};
pub use output::{Event, HumanTable, JsonlWriter, event_line, write_event};
pub use types::{EngineError, ExecResult, Response, Signature};
pub use wordlist::{
    ExtensionIter, FUZZ, FUZZ2, Mode, WordSet, WordlistIter, WordlistSpec, expand_extensions,
    substitute,
};
