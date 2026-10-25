mod common;

use std::fs::File;
use std::io::{BufWriter, Write};
use std::sync::Arc;
use std::time::Duration;

use common::{FixtureServer, TestResponse};
use fathom::{
    Calibration, Engine, EngineConfig, Event, HttpOptions, HttpTarget, HttpTemplate, Selector,
    WordlistSpec, build_client,
};

#[tokio::test]
async fn ten_thousand_requests_complete_without_error_blowup() {
    let server = FixtureServer::start(Arc::new(|_request: &common::Request| {
        TestResponse::ok("ok")
    }))
    .await;

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("perf.txt");
    let file = File::create(&path).unwrap();
    let mut writer = BufWriter::new(file);
    for index in 0..10_000 {
        writeln!(writer, "entry{index}").unwrap();
    }
    writer.flush().unwrap();

    let spec = WordlistSpec::new(path, None, fathom::Mode::Clusterbomb);
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
        concurrency: 64,
        rate_limit: None,
        timeout: Duration::from_secs(5),
        retries: 0,
        retry_base_delay: Duration::from_millis(10),
        circuit_breaker: None,
    });

    let mut kept = 0u64;
    let report = engine
        .run(
            spec.iter().unwrap(),
            &target,
            &Selector::default(),
            &Calibration::default(),
            |event| {
                if matches!(event, Event::Result { .. }) {
                    kept += 1;
                }
            },
        )
        .await
        .unwrap();

    println!(
        "perf smoke: requests={} errors={} kept={} elapsed={:.3}s rps={:.1}",
        report.stats.requests,
        report.stats.errors,
        report.stats.kept,
        report.elapsed.as_secs_f64(),
        report.rps
    );

    assert_eq!(report.stats.requests, 10_000);
    assert_eq!(report.stats.errors, 0);
    assert_eq!(report.stats.kept, 10_000);
    assert_eq!(kept, 10_000);
}
