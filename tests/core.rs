mod common;

use std::fs;
use std::io::Write;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use common::{FixtureServer, TestResponse};
use fathom::{
    Calibration, Criteria, Engine, EngineConfig, Event, HttpOptions, HttpTarget, HttpTemplate,
    Mode, Selector, TimeRange, WordSet, WordlistSpec, build_client, event_line, expand_extensions,
    substitute, write_event,
};
use serde_json::json;

#[test]
fn substitution_single_and_multi_position() {
    let single = WordSet::single("admin");
    assert_eq!(
        substitute("http://127.0.0.1/FUZZ/FUZZ", &single),
        "http://127.0.0.1/admin/admin"
    );

    let pair = WordSet::pair("admin", "example");
    assert_eq!(
        substitute("http://FUZZ.FUZZ2/FUZZ?peer=FUZZ2", &pair),
        "http://admin.example/admin?peer=example"
    );
}

fn write_wordlist(contents: &str) -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("words.txt");
    let mut file = fs::File::create(&path).unwrap();
    file.write_all(contents.as_bytes()).unwrap();
    (dir, path)
}

#[test]
fn pitchfork_pairs_lines() {
    let (_dir_a, first) = write_wordlist("a\nb\nc\n");
    let (_dir_b, second) = write_wordlist("1\n2\n");
    let spec = WordlistSpec::new(first, Some(second), Mode::Pitchfork);
    let words: Vec<_> = spec.iter().unwrap().map(|item| item.unwrap()).collect();
    assert_eq!(words.len(), 2);
    assert_eq!(words[0], WordSet::pair("a", "1"));
    assert_eq!(words[1], WordSet::pair("b", "2"));
}

#[test]
fn clusterbomb_is_cartesian() {
    let (_dir_a, first) = write_wordlist("a\nb\nc\n");
    let (_dir_b, second) = write_wordlist("1\n2\n");
    let spec = WordlistSpec::new(first, Some(second), Mode::Clusterbomb);
    let words: Vec<_> = spec.iter().unwrap().map(|item| item.unwrap()).collect();
    assert_eq!(words.len(), 6);
    assert_eq!(words[0], WordSet::pair("a", "1"));
    assert_eq!(words[5], WordSet::pair("c", "2"));
}

#[test]
fn mode_parses_from_str() {
    assert_eq!(Mode::from_str("pitchfork").unwrap(), Mode::Pitchfork);
    assert_eq!(Mode::from_str("clusterbomb").unwrap(), Mode::Clusterbomb);
    assert!(Mode::from_str("bogus").is_err());
}

#[test]
fn extensions_expand_each_entry() {
    let (_dir, first) = write_wordlist("admin\nlogin\n");
    let spec = WordlistSpec::new(first, None, Mode::Clusterbomb);
    let words: Vec<_> = expand_extensions(
        spec.iter().unwrap(),
        vec![".php".to_string(), ".html".to_string()],
    )
    .map(|item| item.unwrap().first)
    .collect();
    assert_eq!(
        words,
        vec![
            "admin",
            "admin.php",
            "admin.html",
            "login",
            "login.php",
            "login.html"
        ]
    );
}

fn response() -> fathom::Response {
    let mut response = fathom::Response::from_body(200, "hello world", Duration::from_millis(50));
    response.elapsed = Duration::from_millis(50);
    response
}

#[test]
fn every_matcher_type_has_a_case() {
    let response = response();
    let cases = [
        (
            Criteria {
                status: vec![200],
                ..Criteria::default()
            },
            Criteria {
                status: vec![201],
                ..Criteria::default()
            },
        ),
        (
            Criteria {
                size: vec![11],
                ..Criteria::default()
            },
            Criteria {
                size: vec![12],
                ..Criteria::default()
            },
        ),
        (
            Criteria {
                words: vec![2],
                ..Criteria::default()
            },
            Criteria {
                words: vec![3],
                ..Criteria::default()
            },
        ),
        (
            Criteria {
                lines: vec![1],
                ..Criteria::default()
            },
            Criteria {
                lines: vec![2],
                ..Criteria::default()
            },
        ),
    ];

    for (matching, non_matching) in cases {
        let keep = Selector {
            matchers: matching.clone(),
            filters: Criteria::default(),
        };
        let drop = Selector {
            matchers: non_matching,
            filters: Criteria::default(),
        };
        assert!(keep.keep(&response));
        assert!(!drop.keep(&response));
    }

    let regex_matching = Selector {
        matchers: Criteria {
            regex: fathom::compile_regexes(&["hello".to_string()]).unwrap(),
            ..Criteria::default()
        },
        filters: Criteria::default(),
    };
    let regex_failing = Selector {
        matchers: Criteria {
            regex: fathom::compile_regexes(&["nope".to_string()]).unwrap(),
            ..Criteria::default()
        },
        filters: Criteria::default(),
    };
    assert!(regex_matching.keep(&response));
    assert!(!regex_failing.keep(&response));

    let time_matching = Selector {
        matchers: Criteria {
            time_ms: Some(TimeRange::new(40, 60)),
            ..Criteria::default()
        },
        filters: Criteria::default(),
    };
    let time_failing = Selector {
        matchers: Criteria {
            time_ms: Some(TimeRange::new(60, 100)),
            ..Criteria::default()
        },
        filters: Criteria::default(),
    };
    assert!(time_matching.keep(&response));
    assert!(!time_failing.keep(&response));
}

#[test]
fn every_filter_type_has_a_case() {
    let response = response();
    let filters = [
        Criteria {
            status: vec![200],
            ..Criteria::default()
        },
        Criteria {
            size: vec![11],
            ..Criteria::default()
        },
        Criteria {
            words: vec![2],
            ..Criteria::default()
        },
        Criteria {
            lines: vec![1],
            ..Criteria::default()
        },
        Criteria {
            regex: fathom::compile_regexes(&["hello".to_string()]).unwrap(),
            ..Criteria::default()
        },
        Criteria {
            time_ms: Some(TimeRange::new(40, 60)),
            ..Criteria::default()
        },
    ];

    for filter in filters {
        let selector = Selector {
            matchers: Criteria::default(),
            filters: filter.clone(),
        };
        assert!(!selector.keep(&response), "filter should hit: {filter:?}");

        let non_hitting = match filter {
            Criteria { status, .. } if !status.is_empty() => Criteria {
                status: vec![201],
                ..Criteria::default()
            },
            Criteria { size, .. } if !size.is_empty() => Criteria {
                size: vec![999],
                ..Criteria::default()
            },
            Criteria { words, .. } if !words.is_empty() => Criteria {
                words: vec![999],
                ..Criteria::default()
            },
            Criteria { lines, .. } if !lines.is_empty() => Criteria {
                lines: vec![999],
                ..Criteria::default()
            },
            Criteria { regex, .. } if !regex.is_empty() => Criteria {
                regex: fathom::compile_regexes(&["absent".to_string()]).unwrap(),
                ..Criteria::default()
            },
            _ => Criteria {
                time_ms: Some(TimeRange::new(60, 100)),
                ..Criteria::default()
            },
        };
        let selector = Selector {
            matchers: Criteria::default(),
            filters: non_hitting,
        };
        assert!(selector.keep(&response));
    }
}

#[test]
fn jsonl_result_and_stats_golden() {
    let words = WordSet::pair("admin", "example");
    let result = fathom::ExecResult {
        response: fathom::Response::from_body(200, "hello world", Duration::from_millis(7)),
        info: json!({
            "url": "http://127.0.0.1:9/admin",
            "final_url": "http://127.0.0.1:9/admin",
            "method": "GET"
        }),
    };
    let result_event = Event::result(&words, &result);
    let result_value: serde_json::Value = serde_json::from_str(&event_line(&result_event)).unwrap();
    assert_eq!(
        result_value,
        json!({
            "type": "result",
            "input": {"FUZZ": "admin", "FUZZ2": "example"},
            "url": "http://127.0.0.1:9/admin",
            "final_url": "http://127.0.0.1:9/admin",
            "method": "GET",
            "status": 200,
            "size": 11,
            "words": 2,
            "lines": 1,
            "duration_ms": 7
        })
    );

    let stats = fathom::RunReport {
        stats: fathom::RunStats {
            requests: 100,
            errors: 2,
            kept: 4,
            filtered: 94,
        },
        elapsed: Duration::from_millis(812),
        rps: 123.15,
    };
    let stats_event = Event::stats(&stats);
    let mut encoded = Vec::new();
    write_event(&mut encoded, &stats_event).unwrap();
    let text = String::from_utf8(encoded).unwrap();
    assert!(text.ends_with('\n'));
    let stats_value: serde_json::Value = serde_json::from_str(text.trim_end()).unwrap();
    assert_eq!(
        stats_value,
        json!({
            "type": "stats",
            "requests": 100,
            "errors": 2,
            "kept": 4,
            "filtered": 94,
            "elapsed_ms": 812,
            "rps": 123.15
        })
    );
}

#[tokio::test]
async fn calibration_filters_baseline_and_keeps_real_path() {
    let server = FixtureServer::start(Arc::new(|request: &common::Request| {
        if request.path == "/real" {
            TestResponse::ok("a genuinely different real page")
        } else {
            TestResponse::ok("same baseline page for everything")
        }
    }))
    .await;

    let (_dir, wordlist) = write_wordlist("alpha\nbeta\nreal\n");
    let spec = WordlistSpec::new(wordlist, None, Mode::Clusterbomb);
    let client = build_client(&HttpOptions::default()).unwrap();
    let target = HttpTarget::new(
        client,
        HttpTemplate {
            url: format!("{}/FUZZ", server.base_url()),
            method: "GET".to_string(),
            headers: Vec::new(),
            cookie: None,
            body: None,
        },
    );
    let engine = Engine::new(EngineConfig {
        concurrency: 4,
        retries: 0,
        timeout: Duration::from_secs(2),
        ..EngineConfig::default()
    });

    let calibration = engine.calibrate(&target, 3).await;
    assert!(calibration.enabled);
    assert_eq!(calibration.signatures.len(), 1);

    let mut events = Vec::new();
    let report = engine
        .run(
            spec.iter().unwrap(),
            &target,
            &Selector::default(),
            &calibration,
            |event| events.push(event),
        )
        .await
        .unwrap();

    assert_eq!(report.stats.requests, 3);
    assert_eq!(report.stats.errors, 0);
    assert_eq!(report.stats.kept, 1);
    assert_eq!(report.stats.filtered, 2);
    assert_eq!(events.len(), 1);
    match &events[0] {
        Event::Result { input, .. } => {
            assert_eq!(input.get("FUZZ").unwrap(), "real");
        }
        Event::Stats { .. } => panic!("run should only emit result events"),
    }
}

#[tokio::test]
async fn calibration_can_be_disabled() {
    let server = FixtureServer::start(Arc::new(|_request: &common::Request| {
        TestResponse::ok("same body")
    }))
    .await;
    let (_dir, wordlist) = write_wordlist("one\ntwo\n");
    let spec = WordlistSpec::new(wordlist, None, Mode::Clusterbomb);
    let client = build_client(&HttpOptions::default()).unwrap();
    let target = HttpTarget::new(
        client,
        HttpTemplate {
            url: format!("{}/FUZZ", server.base_url()),
            method: "GET".to_string(),
            headers: Vec::new(),
            cookie: None,
            body: None,
        },
    );
    let engine = Engine::new(EngineConfig {
        concurrency: 2,
        retries: 0,
        timeout: Duration::from_secs(2),
        ..EngineConfig::default()
    });
    let report = engine
        .run(
            spec.iter().unwrap(),
            &target,
            &Selector::default(),
            &Calibration::default(),
            |_| {},
        )
        .await
        .unwrap();
    assert_eq!(report.stats.kept, 2);
    assert_eq!(report.stats.filtered, 0);
}
