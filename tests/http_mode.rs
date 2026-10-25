mod common;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use common::{FixtureServer, Request, TestResponse};
use fathom::{
    HttpOptions, HttpTarget, HttpTemplate, Target, WordSet, build_client, http_mode::recursion_base,
};
use serde_json::json;

#[test]
fn template_substitutes_every_field() {
    let template = HttpTemplate {
        url: "http://FUZZ.FUZZ2/FUZZ".to_string(),
        method: "FUZZ2".to_string(),
        headers: vec![("X-Fuzz".to_string(), "FUZZ".to_string())],
        cookie: Some("session=FUZZ2".to_string()),
        body: Some("user=FUZZ&peer=FUZZ2".to_string()),
    };
    let rendered = template.render(&WordSet::pair("admin", "patch"));
    assert_eq!(rendered.url, "http://admin.patch/admin");
    assert_eq!(rendered.method, "PATCH");
    assert_eq!(
        rendered.headers,
        vec![("X-Fuzz".to_string(), "admin".to_string())]
    );
    assert_eq!(rendered.cookie.as_deref(), Some("session=patch"));
    assert_eq!(rendered.body.as_deref(), Some("user=admin&peer=patch"));
}

#[tokio::test]
async fn http_target_sends_method_headers_cookie_and_body() {
    let seen: Arc<Mutex<Vec<Request>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_handler = seen.clone();
    let server = FixtureServer::start(Arc::new(move |request: &Request| {
        seen_handler.lock().unwrap().push(request.clone());
        TestResponse::ok("created")
    }))
    .await;

    let client = build_client(&HttpOptions::default()).unwrap();
    let target = HttpTarget::new(
        client,
        HttpTemplate {
            url: format!("{}/api/FUZZ", server.base_url()),
            method: "POST".to_string(),
            headers: vec![("X-Token".to_string(), "FUZZ".to_string())],
            cookie: Some("sid=FUZZ".to_string()),
            body: Some("payload=FUZZ".to_string()),
        },
    );

    let result = target.execute(&WordSet::single("admin")).await.unwrap();
    assert_eq!(result.response.status, 200);
    assert_eq!(result.response.body, "created");
    assert_eq!(
        result.info["url"],
        format!("{}/api/admin", server.base_url())
    );
    assert_eq!(result.info["method"], "POST");

    let requests = seen.lock().unwrap();
    assert_eq!(requests.len(), 1);
    let request = &requests[0];
    assert_eq!(request.method, "POST");
    assert_eq!(request.path, "/api/admin");
    assert_eq!(
        request.headers.get("x-token").map(String::as_str),
        Some("admin")
    );
    assert_eq!(
        request.headers.get("cookie").map(String::as_str),
        Some("sid=admin")
    );
    assert_eq!(request.body, "payload=admin");
}

#[test]
fn recursion_helpers_respect_depth_and_directory_paths() {
    let info = json!({
        "url": "http://127.0.0.1:8080/dir/",
        "final_url": "http://127.0.0.1:8080/dir/"
    });
    assert_eq!(
        recursion_base(&info, 0, 2).as_deref(),
        Some("http://127.0.0.1:8080/dir/")
    );
    assert_eq!(recursion_base(&info, 2, 2), None);

    let file_info = json!({"url": "http://127.0.0.1:8080/admin.php"});
    assert_eq!(recursion_base(&file_info, 0, 2), None);

    let template = HttpTemplate {
        url: "http://127.0.0.1:8080/FUZZ".to_string(),
        method: "GET".to_string(),
        headers: Vec::new(),
        cookie: None,
        body: None,
    };
    let nested = template.for_recursion_base("http://127.0.0.1:8080/dir/");
    assert_eq!(nested.url, "http://127.0.0.1:8080/dir/FUZZ");
}

#[tokio::test]
async fn request_timeout_is_enforced_by_engine() {
    let server = FixtureServer::start(Arc::new(|_request: &Request| TestResponse {
        status: 200,
        headers: Vec::new(),
        body: "slow".to_string(),
        delay: Some(Duration::from_millis(200)),
    }))
    .await;

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
    let engine = fathom::Engine::new(fathom::EngineConfig {
        concurrency: 1,
        retries: 0,
        timeout: Duration::from_millis(50),
        ..fathom::EngineConfig::default()
    });
    let mut words = Vec::new();
    words.push(Ok(WordSet::single("slow")));
    let report = engine
        .run(
            words.into_iter(),
            &target,
            &fathom::Selector::default(),
            &fathom::Calibration::default(),
            |_| {},
        )
        .await
        .unwrap();
    assert_eq!(report.stats.requests, 1);
    assert_eq!(report.stats.errors, 1);
    assert_eq!(report.stats.kept, 0);
}
