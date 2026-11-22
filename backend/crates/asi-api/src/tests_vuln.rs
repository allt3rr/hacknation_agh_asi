//! Testy sprawdzania podatności (`vulnerability-assessment`) i DefectDojo per IP
//! (`defectdojo-integration`) z atrapami NVD i DefectDojo.

use crate::defectdojo::DefectDojo;
use crate::scans::ScanService;
use crate::tests::{add_user, body, call, cookie_pair, login_as, prepared, PASSWORD};
use crate::AppState;
use asi_core::rbac;
use asi_scanner::config::{ScanConfig, VulnConfig, VulnMode};
use asi_scanner::nmap::{AnyRunner, FakeRunner};
use axum::extract::Query;
use axum::http::StatusCode;
use serde_json::{json, Value};
use sqlx::PgPool;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

const NVD_FIXTURE: &str = include_str!("../../asi-vuln/tests/fixtures/nvd_apache_2.4.49.json");

/// Stan atrapy DefectDojo: engagementy, importy (engagement, ciało multipart) i nagłówki.
#[derive(Default)]
pub(crate) struct Dd {
    pub engagements: Vec<Value>,
    pub imports: Vec<(u64, String)>,
    pub auth: Vec<String>,
    /// Engagement o nazwie zawierającej ten tekst kończy się błędem 500.
    pub fail_name: Option<String>,
}

pub(crate) async fn mock_dd() -> (u16, Arc<Mutex<Dd>>) {
    let dd: Arc<Mutex<Dd>> = Arc::default();
    let (get_dd, post_dd, imp_dd) = (dd.clone(), dd.clone(), dd.clone());
    let app = axum::Router::new()
        .route(
            "/api/v2/engagements/",
            axum::routing::get(move |Query(q): Query<HashMap<String, String>>| {
                let dd = get_dd.clone();
                async move {
                    let dd = dd.lock().unwrap();
                    // jak w DefectDojo: `name` = „zawiera”, `status` i `product` = równe
                    let results: Vec<Value> = dd
                        .engagements
                        .iter()
                        .filter(|e| {
                            q.get("name")
                                .is_none_or(|n| e["name"].as_str().unwrap().contains(n.as_str()))
                                && q.get("status").is_none_or(|s| e["status"] == s.as_str())
                                && q.get("product").is_none_or(|p| {
                                    e["product"].as_u64().map(|n| n.to_string()).as_ref() == Some(p)
                                })
                        })
                        .cloned()
                        .collect();
                    axum::Json(json!({ "count": results.len(), "results": results }))
                }
            })
            .post(move |axum::Json(mut e): axum::Json<Value>| {
                let dd = post_dd.clone();
                async move {
                    let mut dd = dd.lock().unwrap();
                    if dd
                        .fail_name
                        .as_deref()
                        .is_some_and(|f| e["name"].as_str().unwrap().contains(f))
                    {
                        return (StatusCode::INTERNAL_SERVER_ERROR, axum::Json(json!({})));
                    }
                    e["id"] = json!(100 + dd.engagements.len());
                    dd.engagements.push(e.clone());
                    (StatusCode::CREATED, axum::Json(e))
                }
            }),
        )
        .route(
            "/api/v2/import-scan/",
            axum::routing::post(move |headers: axum::http::HeaderMap, b: String| {
                let dd = imp_dd.clone();
                async move {
                    let marker = "name=\"engagement\"\r\n\r\n";
                    let at = b.find(marker).expect("brak pola engagement") + marker.len();
                    let id: u64 = b[at..].split("\r\n").next().unwrap().parse().unwrap();
                    let mut dd = dd.lock().unwrap();
                    let auth = headers
                        .get("authorization")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("")
                        .to_string();
                    dd.auth.push(auth);
                    dd.imports.push((id, b));
                    axum::Json(json!({ "test": 1 }))
                }
            }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (port, dd)
}

pub(crate) fn dd_config(port: u16) -> DefectDojo {
    DefectDojo {
        url: format!("http://127.0.0.1:{port}"),
        token: "tok-dd".into(),
        product: 3,
    }
}

/// Atrapa NVD: zwraca fixture Apache 2.4.49 (albo 503, gdy `down`), liczy zapytania.
async fn mock_nvd(down: bool) -> (String, Arc<AtomicUsize>) {
    let calls = Arc::new(AtomicUsize::new(0));
    let c = calls.clone();
    let app = axum::Router::new().route(
        "/cves",
        axum::routing::get(move || {
            c.fetch_add(1, Ordering::SeqCst);
            async move {
                if down {
                    (StatusCode::SERVICE_UNAVAILABLE, String::new())
                } else {
                    (StatusCode::OK, NVD_FIXTURE.to_string())
                }
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (format!("http://127.0.0.1:{port}/cves"), calls)
}

fn config(nvd_url: &str, mode: VulnMode) -> ScanConfig {
    ScanConfig {
        recheck_missing: false,
        vuln: VulnConfig {
            mode,
            nvd_url: nvd_url.into(),
            ..Default::default()
        },
        ..Default::default()
    }
}

async fn state_with(db: &PgPool, cfg: ScanConfig, runner: FakeRunner) -> AppState {
    let dir = PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/../../signatures"));
    prepared(db)
        .await
        .with_scans(ScanService::new(Ok(cfg), AnyRunner::Fake(runner), dir))
}

async fn as_role(st: &AppState, db: &PgPool, name: &str, role: &str) -> String {
    add_user(db, name, role).await;
    cookie_pair(&login_as(st, name, PASSWORD).await)
}

/// Import zwykłych obserwacji (przebieg opublikowany jako `done`).
async fn import(st: &AppState, cookie: &str, items: Value) -> String {
    let res = call(
        st,
        "POST",
        "/api/v1/results/import?format=json",
        Some(cookie),
        Some(items),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
    body(res).await["run_id"].as_str().unwrap().to_string()
}

fn apache(ip: &str) -> Value {
    json!({ "ip": ip, "port": 80, "proto": "tcp", "state": "open", "service": "http",
            "product": "Apache httpd", "version": "2.4.49" })
}

async fn wait_state(st: &AppState, cookie: &str, run: &str, want: &[&str]) -> Value {
    for _ in 0..200 {
        let r = body(
            call(
                st,
                "GET",
                &format!("/api/v1/runs/{run}"),
                Some(cookie),
                None,
            )
            .await,
        )
        .await;
        if want.contains(&r["vuln_state"].as_str().unwrap_or("")) {
            return r;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    panic!("stan sprawdzania nie osiągnął {want:?}");
}

#[sqlx::test(migrator = "asi_db::MIGRATOR")]
async fn check_classifies_cves_and_respects_permissions(db: PgPool) {
    let (nvd, calls) = mock_nvd(false).await;
    let st = state_with(&db, config(&nvd, VulnMode::Ask), FakeRunner::default()).await;
    let editor = as_role(&st, &db, "ed", rbac::EDITOR).await;
    let analyst = as_role(&st, &db, "an", rbac::ANALYST).await;
    let viewer = as_role(&st, &db, "vi", rbac::VIEWER).await;
    let ssh = json!({ "ip": "10.0.0.2", "port": 22, "proto": "tcp", "service": "ssh" });
    let run = import(
        &st,
        &editor,
        json!([apache("10.0.0.1"), apache("10.0.0.3"), ssh]),
    )
    .await;
    let check = format!("/api/v1/runs/{run}/vuln-check");

    for path in [check.clone(), format!("{check}/skip")] {
        assert_eq!(
            call(&st, "POST", &path, Some(&viewer), None).await.status(),
            StatusCode::FORBIDDEN
        );
    }
    let missing = format!("/api/v1/runs/{}/vuln-check", uuid::Uuid::new_v4());
    assert_eq!(
        call(&st, "POST", &missing, Some(&analyst), None)
            .await
            .status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        call(&st, "POST", &check, Some(&analyst), None)
            .await
            .status(),
        StatusCode::ACCEPTED
    );
    let r = wait_state(&st, &analyst, &run, &["done", "failed"]).await;
    assert_eq!(r["vuln_state"], "done", "{r}");
    assert_eq!(r["vuln_summary"]["unidentified"], 1, "ssh bez wersji");
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "jedno zapytanie na unikalny CPE"
    );

    let list = format!("/api/v1/runs/{run}/vulnerabilities");
    let all = body(call(&st, "GET", &list, Some(&viewer), None).await).await;
    assert_eq!(all["total"], 6, "3 CVE × 2 usługi");
    assert_eq!(all["summary"]["by_severity"]["Critical"], 2);
    assert_eq!(all["summary"]["by_severity"]["Info"], 2);
    let first = &all["items"][0];
    assert_eq!(first["cve_id"], "CVE-2021-42013");
    assert_eq!(first["cvss_score"], 9.8);
    assert_eq!(first["evidence"], "version_match");
    assert_eq!(first["version"], "2.4.49");

    let crit = body(
        call(
            &st,
            "GET",
            &format!("{list}?severity=Critical&ip=10.0.0.3"),
            Some(&viewer),
            None,
        )
        .await,
    )
    .await;
    assert_eq!(crit["total"], 1);
    assert_eq!(crit["items"][0]["ip"], "10.0.0.3");
    assert_eq!(
        call(
            &st,
            "GET",
            &format!("{list}?severity=Groźna"),
            Some(&viewer),
            None
        )
        .await
        .status(),
        StatusCode::BAD_REQUEST
    );

    // korekta analityka `false_positive` ukrywa podatności usługi
    let res = call(
        &st,
        "PUT",
        "/api/v1/overrides",
        Some(&analyst),
        Some(json!({ "key": "10.0.0.3:80/tcp", "field": "status", "value": "false_positive" })),
    )
    .await;
    assert!(res.status().is_success(), "{}", res.status());
    let all = body(call(&st, "GET", &list, Some(&viewer), None).await).await;
    assert_eq!(all["total"], 3);
    assert!(all["items"]
        .as_array()
        .unwrap()
        .iter()
        .all(|v| v["ip"] == "10.0.0.1"));

    // ponowne uruchomienie korzysta z cache; odrzucenie decyzji po zakończeniu
    assert_eq!(
        call(&st, "POST", &check, Some(&analyst), None)
            .await
            .status(),
        StatusCode::ACCEPTED
    );
    wait_state(&st, &analyst, &run, &["done"]).await;
    assert_eq!(calls.load(Ordering::SeqCst), 1, "cache CVE");
    assert_eq!(
        call(&st, "POST", &format!("{check}/skip"), Some(&analyst), None)
            .await
            .status(),
        StatusCode::NO_CONTENT
    );
    wait_state(&st, &analyst, &run, &["skipped"]).await;

    let actions: Vec<String> =
        sqlx::query_scalar("SELECT action FROM audit_log WHERE action LIKE 'vuln.%' ORDER BY id")
            .fetch_all(&db)
            .await
            .unwrap();
    assert!(actions.contains(&"vuln.check.start".to_string()));
    assert!(actions.contains(&"vuln.check.finish".to_string()));
    assert!(actions.contains(&"vuln.check.skip".to_string()));
}

#[sqlx::test(migrator = "asi_db::MIGRATOR")]
async fn nvd_down_fails_check_but_keeps_run(db: PgPool) {
    let (nvd, _) = mock_nvd(true).await;
    let mut cfg = config(&nvd, VulnMode::Ask);
    cfg.vuln.cache_hours = 0;
    let st = state_with(&db, cfg, FakeRunner::default()).await;
    let editor = as_role(&st, &db, "ed", rbac::EDITOR).await;
    let run = import(&st, &editor, json!([apache("10.0.0.1")])).await;
    // atrapa odpowiada 503: klient ponawia z backoffem, więc czekamy dłużej na `failed`
    let path = format!("/api/v1/runs/{run}/vuln-check");
    assert_eq!(
        call(&st, "POST", &path, Some(&editor), None).await.status(),
        StatusCode::ACCEPTED
    );
    assert_eq!(
        call(&st, "POST", &path, Some(&editor), None).await.status(),
        StatusCode::CONFLICT,
        "drugie sprawdzanie w trakcie"
    );
    let mut r = Value::Null;
    for _ in 0..1200 {
        r = body(
            call(
                &st,
                "GET",
                &format!("/api/v1/runs/{run}"),
                Some(&editor),
                None,
            )
            .await,
        )
        .await;
        if r["vuln_state"] != "running" {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert_eq!(r["vuln_state"], "failed", "{r}");
    assert!(r["vuln_reason"].as_str().unwrap().contains("NVD"), "{r}");
    assert_eq!(r["status"], "done", "wynik przebiegu nienaruszony");
}

async fn start_scan(st: &AppState, cookie: &str, body_json: Option<Value>) -> String {
    let res = call(st, "POST", "/api/v1/runs", Some(cookie), body_json).await;
    assert_eq!(res.status(), StatusCode::ACCEPTED);
    body(res).await["run_id"].as_str().unwrap().to_string()
}

#[sqlx::test(migrator = "asi_db::MIGRATOR")]
async fn mode_after_scan(db: PgPool) {
    let (nvd, calls) = mock_nvd(false).await;
    let fake = FakeRunner {
        open_port: 22,
        ..Default::default()
    };
    let st = state_with(&db, config(&nvd, VulnMode::Ask), fake).await;
    let admin = cookie_pair(&login_as(&st, "admin", "fixture-password").await);
    call(
        &st,
        "POST",
        "/api/v1/targets",
        Some(&admin),
        Some(json!({ "text": "10.0.0.1" })),
    )
    .await;

    let run = start_scan(&st, &admin, None).await;
    wait_state(&st, &admin, &run, &["pending_decision"]).await;

    let run = start_scan(&st, &admin, Some(json!({ "vuln_check": "off" }))).await;
    // `none` jest też stanem początkowym: poczekaj na zakończenie skanu
    for _ in 0..200 {
        let r = body(
            call(
                &st,
                "GET",
                &format!("/api/v1/runs/{run}"),
                Some(&admin),
                None,
            )
            .await,
        )
        .await;
        if r["status"] != "running" {
            assert_eq!(r["vuln_state"], "none");
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }

    let run = start_scan(&st, &admin, Some(json!({ "vuln_check": "auto" }))).await;
    let r = wait_state(&st, &admin, &run, &["done", "failed"]).await;
    assert_eq!(r["vuln_state"], "done", "{r}");
    assert_eq!(r["vuln_summary"]["unidentified"], 1);
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "usługa bez wersji nie wymaga NVD"
    );

    let res = call(
        &st,
        "POST",
        "/api/v1/runs",
        Some(&admin),
        Some(json!({ "vuln_check": "zawsze" })),
    )
    .await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
}

#[sqlx::test(migrator = "asi_db::MIGRATOR")]
async fn defectdojo_engagement_per_ip(db: PgPool) {
    let (nvd, _) = mock_nvd(false).await;
    let (port, dd) = mock_dd().await;
    let st = state_with(&db, config(&nvd, VulnMode::Ask), FakeRunner::default()).await;
    let editor = as_role(&st, &db, "ed", rbac::EDITOR).await;
    let analyst = as_role(&st, &db, "an", rbac::ANALYST).await;
    let viewer = as_role(&st, &db, "vi", rbac::VIEWER).await;
    let wp = |ip: &str| {
        json!({ "ip": ip, "port": 80, "proto": "tcp", "raw_product": "Apache", "raw_service": "http",
                "technologies": [{ "signature_id": "wordpress", "name": "WordPress", "category": "cms",
                                   "version": "6.4.2", "confidence": 72, "evidence": ["body"] }] })
    };
    // istnieje: aktywny engagement dla .1 i zamknięty dla .12 (nazwa „zawiera” ASI 10.0.0.1)
    dd.lock().unwrap().engagements = vec![
        json!({ "id": 7, "name": "ASI 10.0.0.1", "status": "In Progress", "product": 3 }),
        json!({ "id": 8, "name": "ASI 10.0.0.12", "status": "Completed", "product": 3 }),
        json!({ "id": 9, "name": "ASI 10.0.0.12", "status": "In Progress", "product": 4 }),
    ];
    let run = import(
        &st,
        &editor,
        json!([wp("10.0.0.1"), wp("10.0.0.12"), wp("10.0.0.13")]),
    )
    .await;
    let path = format!("/api/v1/runs/{run}/defectdojo");

    assert_eq!(
        call(&st, "POST", &path, Some(&analyst), None)
            .await
            .status(),
        StatusCode::CONFLICT,
        "brak konfiguracji"
    );
    let st = st.with_defectdojo(Some(dd_config(port)));
    assert_eq!(
        call(&st, "POST", &path, Some(&viewer), None).await.status(),
        StatusCode::FORBIDDEN
    );
    let res = call(&st, "POST", &path, Some(&analyst), None).await;
    assert_eq!(res.status(), StatusCode::OK);
    let out = body(res).await;
    let eng = out["engagements"].as_array().unwrap();
    assert_eq!(eng.len(), 3, "{out}");
    assert_eq!(
        eng[0],
        json!({ "ip": "10.0.0.1", "engagement_id": 7, "created": false })
    );
    assert_eq!(eng[1]["ip"], "10.0.0.12");
    assert_eq!(
        eng[1]["created"], true,
        "zamknięty i z innego produktu nie są używane"
    );
    assert_eq!(eng[2]["created"], true);
    assert!(out["findings"].as_u64().unwrap() >= 3);

    {
        let d = dd.lock().unwrap();
        assert_eq!(d.imports.len(), 3, "osobny import dla każdego IP");
        assert!(d.auth.iter().all(|a| a == "Token tok-dd"));
        let to7 = &d.imports.iter().find(|(id, _)| *id == 7).unwrap().1;
        assert!(to7.contains("Generic Findings Import"));
        assert!(to7.contains("WordPress na 10.0.0.1:80"));
        assert!(!to7.contains("10.0.0.13"), "findingi tylko swojego IP");
        let created: Vec<&Value> = d
            .engagements
            .iter()
            .filter(|e| e["id"].as_u64() >= Some(100))
            .collect();
        assert_eq!(created.len(), 2);
        assert!(created
            .iter()
            .all(|e| e["status"] == "In Progress" && e["product"] == 3));
    }

    // druga wysyłka trafia do tych samych engagementów
    let out = body(call(&st, "POST", &path, Some(&analyst), None).await).await;
    assert!(
        out["engagements"]
            .as_array()
            .unwrap()
            .iter()
            .all(|e| e["created"] == false),
        "{out}"
    );
    assert_eq!(dd.lock().unwrap().engagements.len(), 5);

    // podatności po sprawdzeniu trafiają do engagementu IP
    let run = import(&st, &editor, json!([apache("10.0.0.1")])).await;
    let n = dd.lock().unwrap().imports.len();
    assert_eq!(
        call(
            &st,
            "POST",
            &format!("/api/v1/runs/{run}/vuln-check"),
            Some(&analyst),
            None
        )
        .await
        .status(),
        StatusCode::ACCEPTED
    );
    wait_state(&st, &analyst, &run, &["done"]).await;
    let mut cve_import = None;
    for _ in 0..100 {
        if let Some(i) = dd.lock().unwrap().imports.get(n) {
            cve_import = Some(i.clone());
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    let (id, payload) = cve_import.expect("brak wysyłki CVE po sprawdzeniu");
    assert_eq!(id, 7);
    assert!(payload.contains("CVE-2021-42013"));
    assert!(payload.contains("\"cvssv3_score\":9.8"));
    assert!(payload.contains("\"verified\":false"));

    // błąd jednego IP nie przerywa pozostałych; gdy wszystkie zawodzą → 502
    dd.lock().unwrap().fail_name = Some("10.0.0.13".into());
    dd.lock()
        .unwrap()
        .engagements
        .retain(|e| e["name"] != "ASI 10.0.0.13");
    let run = import(&st, &editor, json!([wp("10.0.0.1"), wp("10.0.0.13")])).await;
    let path = format!("/api/v1/runs/{run}/defectdojo");
    let out = body(call(&st, "POST", &path, Some(&analyst), None).await).await;
    assert_eq!(out["engagements"].as_array().unwrap().len(), 1, "{out}");
    assert_eq!(out["failed"][0]["ip"], "10.0.0.13");
    let st = st.with_defectdojo(Some(dd_config(1)));
    assert_eq!(
        call(&st, "POST", &path, Some(&analyst), None)
            .await
            .status(),
        StatusCode::BAD_GATEWAY
    );
    let exports: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM audit_log WHERE action = 'defectdojo.export'")
            .fetch_one(&db)
            .await
            .unwrap();
    assert_eq!(exports, 3);
}

/// Usługa skanu z atrapą nmap odpowiadającą portem `port` (nowy port = nowa usługa = finding).
fn scans(nvd: &str, port: u16) -> ScanService {
    let dir = PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/../../signatures"));
    let fake = FakeRunner {
        open_port: port,
        ..Default::default()
    };
    ScanService::new(Ok(config(nvd, VulnMode::Ask)), AnyRunner::Fake(fake), dir)
}

async fn wait_scan_done(st: &AppState, cookie: &str, run: &str) {
    for _ in 0..200 {
        let r = body(
            call(
                st,
                "GET",
                &format!("/api/v1/runs/{run}"),
                Some(cookie),
                None,
            )
            .await,
        )
        .await;
        if r["status"] != "running" {
            assert_eq!(r["status"], "done", "{r}");
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    panic!("skan nie zakończył się");
}

/// Wynik wysyłki zapisany w przebiegu (`dd_export`), gdy już jest.
async fn wait_dd_export(st: &AppState, cookie: &str, run: &str) -> Value {
    for _ in 0..100 {
        let path = format!("/api/v1/runs/{run}");
        let r = body(call(st, "GET", &path, Some(cookie), None).await).await;
        if !r["dd_export"].is_null() {
            return r["dd_export"].clone();
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    panic!("brak zapisanego wyniku wysyłki do DefectDojo");
}

async fn wait_imports(dd: &Arc<Mutex<Dd>>, n: usize) -> usize {
    for _ in 0..100 {
        if dd.lock().unwrap().imports.len() >= n {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    dd.lock().unwrap().imports.len()
}

#[sqlx::test(migrator = "asi_db::MIGRATOR")]
async fn defectdojo_push_waits_for_cve_decision(db: PgPool) {
    let (nvd, _) = mock_nvd(false).await;
    let (port, dd) = mock_dd().await;
    let fake = FakeRunner {
        open_port: 22,
        ..Default::default()
    };
    let st = state_with(&db, config(&nvd, VulnMode::Ask), fake)
        .await
        .with_defectdojo(Some(dd_config(port)));
    let admin = cookie_pair(&login_as(&st, "admin", "fixture-password").await);
    let targets = json!({ "text": "10.0.0.1
10.0.0.2" });
    call(&st, "POST", "/api/v1/targets", Some(&admin), Some(targets)).await;

    // off: bez sprawdzania CVE samo info idzie od razu, osobno dla każdego IP
    let run = start_scan(&st, &admin, Some(json!({ "vuln_check": "off" }))).await;
    wait_scan_done(&st, &admin, &run).await;
    assert_eq!(wait_imports(&dd, 2).await, 2);
    let export = wait_dd_export(&st, &admin, &run).await;
    assert_eq!(export["content"], "inventory");
    assert_eq!(export["engagements"], 2);
    assert!(export["error"].is_null());
    assert!(export["at"].is_string(), "{export}");
    {
        let d = dd.lock().unwrap();
        assert!(d
            .imports
            .iter()
            .all(|(_, b)| b.contains("Generic Findings Import")));
        let names: Vec<&str> = d
            .engagements
            .iter()
            .map(|e| e["name"].as_str().unwrap())
            .collect();
        assert_eq!(names, vec!["ASI 10.0.0.1", "ASI 10.0.0.2"]);
    }

    // ask: przed decyzją nic nie jest wysyłane; po odrzuceniu — samo info
    let st = st.with_scans(scans(&nvd, 23));
    let run = start_scan(&st, &admin, None).await;
    wait_state(&st, &admin, &run, &["pending_decision"]).await;
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    assert_eq!(
        dd.lock().unwrap().imports.len(),
        2,
        "wysyłka czeka na decyzję o CVE"
    );
    let skip = format!("/api/v1/runs/{run}/vuln-check/skip");
    assert_eq!(
        call(&st, "POST", &skip, Some(&admin), None).await.status(),
        StatusCode::NO_CONTENT
    );
    assert_eq!(wait_imports(&dd, 4).await, 4);
    assert_eq!(
        dd.lock().unwrap().engagements.len(),
        2,
        "te same engagementy"
    );

    // ask + akceptacja: wysyłka dopiero po zakończeniu sprawdzania
    let st = st.with_scans(scans(&nvd, 24));
    let run = start_scan(&st, &admin, None).await;
    wait_state(&st, &admin, &run, &["pending_decision"]).await;
    assert_eq!(dd.lock().unwrap().imports.len(), 4);
    let check = format!("/api/v1/runs/{run}/vuln-check");
    assert_eq!(
        call(&st, "POST", &check, Some(&admin), None).await.status(),
        StatusCode::ACCEPTED
    );
    wait_state(&st, &admin, &run, &["done"]).await;
    assert_eq!(wait_imports(&dd, 6).await, 6);
    assert_eq!(wait_dd_export(&st, &admin, &run).await["content"], "all");

    // DefectDojo niedostępne: skan nadal kończy się sukcesem (nowy port = jest co wysłać)
    let st = st
        .with_scans(scans(&nvd, 25))
        .with_defectdojo(Some(dd_config(1)));
    let run = start_scan(&st, &admin, Some(json!({ "vuln_check": "off" }))).await;
    wait_scan_done(&st, &admin, &run).await;
    let export = wait_dd_export(&st, &admin, &run).await;
    assert!(
        export["error"].as_str().unwrap().contains("DefectDojo"),
        "{export}"
    );
}
