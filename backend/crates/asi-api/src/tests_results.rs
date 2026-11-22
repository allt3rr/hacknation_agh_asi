//! Testy API wyników (`wyniki-i-ochrona-danych`): stronicowanie, redakcja, odsłonięcie, eksport/import,
//! korekty, sygnatury i DefectDojo.

use crate::scans::ScanService;
use crate::tests::{add_user, body, call, cookie_pair, login_as, prepared, PASSWORD};
use crate::tests_vuln::{dd_config, mock_dd};
use crate::{router, AppState};
use asi_core::rbac;
use asi_scanner::config::ScanConfig;
use asi_scanner::nmap::{AnyRunner, FakeRunner};
use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use serde_json::{json, Value};
use sqlx::PgPool;
use std::path::PathBuf;
use tower::ServiceExt;

const SECRET: &str = "tajny-123";

async fn state(db: &PgPool) -> AppState {
    let dir = PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/../../signatures"));
    let svc = ScanService::new(
        Ok(ScanConfig::default()),
        AnyRunner::Fake(FakeRunner::default()),
        dir,
    );
    prepared(db).await.with_scans(svc)
}

async fn as_role(st: &AppState, db: &PgPool, name: &str, role: &str) -> String {
    add_user(db, name, role).await;
    cookie_pair(&login_as(st, name, PASSWORD).await)
}

async fn raw(
    st: &AppState,
    method: &str,
    uri: &str,
    cookie: &str,
    data: String,
) -> axum::response::Response {
    let req = Request::builder()
        .method(method)
        .uri(uri)
        .header(header::COOKIE, cookie)
        .body(Body::from(data))
        .unwrap();
    router(st.clone()).oneshot(req).await.unwrap()
}

async fn text(res: axum::response::Response) -> String {
    String::from_utf8(
        axum::body::to_bytes(res.into_body(), 1 << 24)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap()
}

async fn import_json(st: &AppState, cookie: &str, items: Value) -> String {
    let res = raw(
        st,
        "POST",
        "/api/v1/results/import?format=json",
        cookie,
        items.to_string(),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
    body(res).await["run_id"].as_str().unwrap().to_string()
}

fn wordpress_row(ip: &str, title: &str) -> Value {
    json!({
        "ip": ip, "port": 80, "proto": "tcp", "state": "open", "service": "http", "product": "Apache",
        "raw_product": "Apache", "raw_service": "http",
        "http": { "status": 200, "title": title, "final_url": "", "redirects": [], "blocked_redirects": [],
                  "headers": { "server": "Apache" }, "cookies": [], "tls": null },
        "technologies": [{ "signature_id": "wordpress", "name": "WordPress", "category": "cms",
                           "version": "6.4.2", "confidence": 72, "evidence": ["body"] }],
        "seen_at": "2026-11-21T10:00:00Z"
    })
}

#[sqlx::test(migrator = "asi_db::MIGRATOR")]
async fn paging_totals_and_dashboard(db: PgPool) {
    let st = state(&db).await;
    let editor = as_role(&st, &db, "ed", rbac::EDITOR).await;
    let viewer = as_role(&st, &db, "vi", rbac::VIEWER).await;
    let empty = body(call(&st, "GET", "/api/v1/dashboard", Some(&viewer), None).await).await;
    assert_eq!(empty["scans_total"], 0);
    sqlx::query(
        "INSERT INTO scan_runs (kind, status, finished_at) VALUES ('scan', 'done', now() - interval '1 day'),
         ('scan', 'partial', now() - interval '1 day'), ('scan', 'failed', now() - interval '1 day')",
    )
    .execute(&db)
    .await
    .unwrap();
    let items: Vec<Value> = (0..250)
        .map(|i| json!({ "ip": format!("10.0.{}.{}", i / 200, i % 200 + 1), "port": 22, "proto": "tcp" }))
        .collect();
    let run = import_json(&st, &editor, Value::Array(items)).await;

    let page = body(
        call(
            &st,
            "GET",
            &format!("/api/v1/runs/{run}/observations?limit=100&offset=200"),
            Some(&viewer),
            None,
        )
        .await,
    )
    .await;
    assert_eq!(
        (
            page["total"].as_i64(),
            page["items"].as_array().unwrap().len()
        ),
        (Some(250), 50)
    );
    let changes = body(
        call(
            &st,
            "GET",
            &format!("/api/v1/runs/{run}/changes?limit=50"),
            Some(&viewer),
            None,
        )
        .await,
    )
    .await;
    assert_eq!(
        (
            changes["total"].as_i64(),
            changes["items"].as_array().unwrap().len()
        ),
        (Some(250), 50)
    );

    let dash = body(call(&st, "GET", "/api/v1/dashboard", Some(&viewer), None).await).await;
    assert_eq!(dash["changes_total"], 250, "licznik nie jest obcięty");
    assert_eq!(dash["services"], 250);
    assert_eq!(dash["latest_run"]["kind"], "import");
    assert_eq!(dash["scans_total"], 2, "tylko done/partial, bez importów");
}

#[sqlx::test(migrator = "asi_db::MIGRATOR")]
async fn secrets_are_redacted_and_reveal_is_audited(db: PgPool) {
    let st = state(&db).await;
    let admin = cookie_pair(&login_as(&st, "admin", "fixture-password").await);
    let viewer = as_role(&st, &db, "vi", rbac::VIEWER).await;
    let analyst = as_role(&st, &db, "an", rbac::ANALYST).await;
    let obs = json!([{ "ip": "10.0.0.1", "port": 80, "proto": "tcp",
        "http": { "url": "http://10.0.0.1:80/", "status": 200,
                  "headers": { "server": "nginx", "x-auth-token": SECRET },
                  "cookies": [format!("PHPSESSID={SECRET}; Path=/; HttpOnly")] } }]);
    let run = import_json(&st, &admin, obs).await;

    let page = text(
        call(
            &st,
            "GET",
            &format!("/api/v1/runs/{run}/observations"),
            Some(&viewer),
            None,
        )
        .await,
    )
    .await;
    assert!(!page.contains(SECRET), "{page}");
    assert!(page.contains("PHPSESSID") && page.contains("HttpOnly"));
    let export = text(
        call(
            &st,
            "GET",
            &format!("/api/v1/runs/{run}/export?format=json"),
            Some(&viewer),
            None,
        )
        .await,
    )
    .await;
    assert!(!export.contains(SECRET));

    let id = serde_json::from_str::<Value>(&page).unwrap()["items"][0]["id"]
        .as_str()
        .unwrap()
        .to_string();
    let path = format!("/api/v1/observations/{id}/secrets");
    assert_eq!(
        call(&st, "GET", &path, Some(&analyst), None).await.status(),
        StatusCode::FORBIDDEN
    );
    let revealed = text(call(&st, "GET", &path, Some(&admin), None).await).await;
    assert!(revealed.contains(SECRET));
    let audit = text(
        call(
            &st,
            "GET",
            "/api/v1/admin/audit?limit=500",
            Some(&admin),
            None,
        )
        .await,
    )
    .await;
    assert!(audit.contains("results.reveal") && !audit.contains(SECRET));
}

#[sqlx::test(migrator = "asi_db::MIGRATOR")]
async fn csv_export_is_spreadsheet_safe_and_round_trips(db: PgPool) {
    let st = state(&db).await;
    let editor = as_role(&st, &db, "ed", rbac::EDITOR).await;
    let run = import_json(
        &st,
        &editor,
        json!([wordpress_row("10.0.0.5", "=HYPERLINK(\"http://x\")")]),
    )
    .await;

    let safe = text(
        call(
            &st,
            "GET",
            &format!("/api/v1/runs/{run}/export?format=csv"),
            Some(&editor),
            None,
        )
        .await,
    )
    .await;
    assert!(safe.contains("'=HYPERLINK"), "{safe}");
    let raw_csv = text(
        call(
            &st,
            "GET",
            &format!("/api/v1/runs/{run}/export?format=csv&profile=raw"),
            Some(&editor),
            None,
        )
        .await,
    )
    .await;
    assert!(!raw_csv.contains("'=HYPERLINK"));

    let res = raw(
        &st,
        "POST",
        "/api/v1/results/import?format=csv",
        &editor,
        raw_csv,
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
    let run2 = body(res).await["run_id"].as_str().unwrap().to_string();
    let page = body(
        call(
            &st,
            "GET",
            &format!("/api/v1/runs/{run2}/observations"),
            Some(&editor),
            None,
        )
        .await,
    )
    .await;
    let o = &page["items"][0];
    assert_eq!(
        (o["port"].as_u64(), o["product"].as_str()),
        (Some(80), Some("Apache"))
    );
    assert_eq!(
        (o["http"]["status"].as_u64(), o["http"]["title"].as_str()),
        (Some(200), Some("=HYPERLINK(\"http://x\")"))
    );
    assert_eq!(o["technologies"][0]["name"], "WordPress");
    assert_eq!(o["technologies"][0]["version"], "6.4.2");

    let pending: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM scan_chunks")
        .fetch_one(&db)
        .await
        .unwrap();
    assert_eq!(pending, 0, "import nie tworzy zaległości");
}

#[sqlx::test(migrator = "asi_db::MIGRATOR")]
async fn overrides_survive_next_run_with_history(db: PgPool) {
    let st = state(&db).await;
    let editor = as_role(&st, &db, "ed", rbac::EDITOR).await;
    let analyst = as_role(&st, &db, "an", rbac::ANALYST).await;
    let viewer = as_role(&st, &db, "vi", rbac::VIEWER).await;
    import_json(
        &st,
        &editor,
        json!([{ "ip": "10.0.0.1", "port": 80, "proto": "tcp", "product": "nginx" }]),
    )
    .await;

    let put = |field: &str, value: &str| {
        (
            "/api/v1/overrides".to_string(),
            json!({ "key": "10.0.0.1:80/tcp", "field": field, "value": value, "reason": "weryfikacja" }),
        )
    };
    for (field, value) in [
        ("status", "false_positive"),
        ("product", "nginx-custom"),
        ("owner", "dział A"),
        ("owner", "dział B"),
    ] {
        let (path, b) = put(field, value);
        assert_eq!(
            call(&st, "PUT", &path, Some(&analyst), Some(b))
                .await
                .status(),
            StatusCode::OK,
            "{field}"
        );
    }
    let (path, b) = put("ip", "1.2.3.4");
    assert_eq!(
        call(&st, "PUT", &path, Some(&analyst), Some(b))
            .await
            .status(),
        StatusCode::BAD_REQUEST
    );
    let (path, b) = put("status", "zamkniete");
    assert_eq!(
        call(&st, "PUT", &path, Some(&analyst), Some(b))
            .await
            .status(),
        StatusCode::BAD_REQUEST
    );
    let (path, b) = put("note", "x");
    assert_eq!(
        call(&st, "PUT", &path, Some(&viewer), Some(b))
            .await
            .status(),
        StatusCode::FORBIDDEN
    );

    // kolejny przebieg z tym samym pomiarem
    let run = import_json(
        &st,
        &editor,
        json!([{ "ip": "10.0.0.1", "port": 80, "proto": "tcp", "product": "nginx" }]),
    )
    .await;
    let page = body(
        call(
            &st,
            "GET",
            &format!("/api/v1/runs/{run}/observations"),
            Some(&viewer),
            None,
        )
        .await,
    )
    .await;
    let o = &page["items"][0];
    assert_eq!(
        (o["product"].as_str(), o["raw_product"].as_str()),
        (Some("nginx-custom"), Some("nginx"))
    );
    assert_eq!(
        (o["status"].as_str(), o["owner"].as_str()),
        (Some("false_positive"), Some("dział B"))
    );
    let csv = text(
        call(
            &st,
            "GET",
            &format!("/api/v1/runs/{run}/export?format=csv"),
            Some(&viewer),
            None,
        )
        .await,
    )
    .await;
    assert!(csv.contains("nginx-custom") && csv.contains("false_positive"));

    let hist = body(
        call(
            &st,
            "GET",
            "/api/v1/overrides?key=10.0.0.1:80/tcp",
            Some(&viewer),
            None,
        )
        .await,
    )
    .await;
    let owners: Vec<&Value> = hist
        .as_array()
        .unwrap()
        .iter()
        .filter(|h| h["field"] == "owner")
        .collect();
    assert_eq!(owners.len(), 2);
    assert!(owners.iter().filter(|h| !h["revoked_at"].is_null()).count() == 1);
    assert!(owners.iter().all(|h| h["author"] == "an"));
}

#[sqlx::test(migrator = "asi_db::MIGRATOR")]
async fn signatures_api_validates_and_respects_roles(db: PgPool) {
    let st = state(&db).await;
    let editor = as_role(&st, &db, "ed", rbac::EDITOR).await;
    let analyst = as_role(&st, &db, "an", rbac::ANALYST).await;
    let sig = |path: &str| json!({ "yaml": format!("- id: moja\n  name: Moja\n  category: application\n  rules:\n    - type: path\n      path: \"{path}\"\n") });

    let res = call(
        &st,
        "POST",
        "/api/v1/signatures",
        Some(&editor),
        Some(sig("//evil.example/")),
    )
    .await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        call(
            &st,
            "POST",
            "/api/v1/signatures",
            Some(&analyst),
            Some(sig("/panel"))
        )
        .await
        .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        call(
            &st,
            "POST",
            "/api/v1/signatures",
            Some(&editor),
            Some(sig("/panel"))
        )
        .await
        .status(),
        StatusCode::OK
    );
    assert_eq!(
        call(
            &st,
            "POST",
            "/api/v1/signatures",
            Some(&editor),
            Some(sig("/panel"))
        )
        .await
        .status(),
        StatusCode::CONFLICT
    );
    assert_eq!(
        call(
            &st,
            "PUT",
            "/api/v1/signatures/moja",
            Some(&analyst),
            Some(sig("/panel2"))
        )
        .await
        .status(),
        StatusCode::OK
    );

    let list = body(call(&st, "GET", "/api/v1/signatures", Some(&analyst), None).await).await;
    assert!(list["builtin"].as_array().unwrap().len() >= 20);
    let custom = &list["custom"][0];
    assert_eq!(
        (custom["slug"].as_str(), custom["version"].as_i64()),
        (Some("moja"), Some(2))
    );
    assert!(custom["yaml"].as_str().unwrap().contains("/panel2"));

    assert_eq!(
        call(
            &st,
            "DELETE",
            "/api/v1/signatures/moja",
            Some(&analyst),
            None
        )
        .await
        .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        call(
            &st,
            "DELETE",
            "/api/v1/signatures/moja",
            Some(&editor),
            None
        )
        .await
        .status(),
        StatusCode::NO_CONTENT
    );
}

#[sqlx::test(migrator = "asi_db::MIGRATOR")]
async fn builtin_signature_can_be_overridden_and_restored(db: PgPool) {
    let st = state(&db).await;
    let editor = as_role(&st, &db, "ed", rbac::EDITOR).await;
    let viewer = as_role(&st, &db, "vi", rbac::VIEWER).await;
    let list = body(call(&st, "GET", "/api/v1/signatures", Some(&viewer), None).await).await;
    let builtin = list["builtin"].as_array().unwrap();
    assert!(builtin
        .iter()
        .all(|s| !s["yaml"].as_str().unwrap().is_empty()));

    let id = builtin[0]["id"].as_str().unwrap().to_string();
    let confidence = |set: &asi_fingerprint::SignatureSet| {
        set.signatures()
            .iter()
            .find(|s| s.id == id)
            .unwrap()
            .confidence
    };
    let original = confidence(&crate::scans::load_signatures(&st, &st.scans).await.unwrap());
    let changed = if original == 1 { 2 } else { 1 };
    let mut sigs =
        asi_fingerprint::SignatureSet::parse_yaml(builtin[0]["yaml"].as_str().unwrap()).unwrap();
    sigs[0].confidence = changed;
    let yaml = serde_saphyr::to_string(&sigs).unwrap();

    let res = call(
        &st,
        "POST",
        "/api/v1/signatures",
        Some(&editor),
        Some(json!({ "yaml": yaml })),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(
        confidence(&crate::scans::load_signatures(&st, &st.scans).await.unwrap()),
        changed
    );

    let res = call(
        &st,
        "DELETE",
        &format!("/api/v1/signatures/{id}"),
        Some(&editor),
        None,
    )
    .await;
    assert_eq!(res.status(), StatusCode::NO_CONTENT);
    assert_eq!(
        confidence(&crate::scans::load_signatures(&st, &st.scans).await.unwrap()),
        original
    );
}

#[sqlx::test(migrator = "asi_db::MIGRATOR")]
async fn defectdojo_export_is_redacted(db: PgPool) {
    let (port, dd) = mock_dd().await;
    let st = state(&db).await.with_defectdojo(Some(dd_config(port)));
    let editor = as_role(&st, &db, "ed", rbac::EDITOR).await;
    let analyst = as_role(&st, &db, "an", rbac::ANALYST).await;
    let mut row = wordpress_row("10.0.0.7", "Blog");
    row["http"]["cookies"] = json!([{ "name": "wordpress_logged_in", "attributes": ["HttpOnly"] }]);
    let run = import_json(&st, &editor, json!([row])).await;
    let res = call(
        &st,
        "POST",
        &format!("/api/v1/runs/{run}/defectdojo"),
        Some(&analyst),
        None,
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
    assert!(body(res).await["findings"].as_u64().unwrap() >= 1);
    let d = dd.lock().unwrap();
    let payload = &d.imports[0].1;
    assert!(payload.contains("WordPress na 10.0.0.7:80"));
    assert!(!payload.contains(SECRET));
}
