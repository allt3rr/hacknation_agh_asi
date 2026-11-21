//! Testy API przebiegów (`skaner-bezpieczny`) z atrapą nmap (`FakeRunner`).

use crate::scans::ScanService;
use crate::tests::{add_user, body, call, cookie_pair, login_as, prepared, PASSWORD};
use crate::AppState;
use asi_core::rbac;
use asi_scanner::config::{ScanConfig, WindowConfig};
use asi_scanner::nmap::{AnyRunner, FakeRunner};
use axum::http::StatusCode;
use chrono::NaiveDateTime;
use serde_json::{json, Value};
use sqlx::PgPool;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

fn signatures_dir() -> PathBuf {
    PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/../../../signatures"))
}

fn cfg() -> ScanConfig {
    ScanConfig {
        recheck_missing: false,
        chunk_size: 2,
        min_chunk: 1,
        ..Default::default()
    }
}

fn service(cfg: Result<ScanConfig, String>, fake: FakeRunner) -> ScanService {
    ScanService::new(cfg, AnyRunner::Fake(fake), signatures_dir())
}

async fn setup(db: &PgPool, svc: ScanService) -> (AppState, String) {
    let st = prepared(db).await.with_scans(svc);
    let admin = cookie_pair(&login_as(&st, "admin", "admin").await);
    let add = json!({ "text": "10.0.0.1 10.0.0.2 10.0.0.3" });
    assert_eq!(
        call(&st, "POST", "/api/v1/targets", Some(&admin), Some(add))
            .await
            .status(),
        StatusCode::OK
    );
    (st, admin)
}

async fn wait_finished(st: &AppState, cookie: &str, id: &str) -> Value {
    for _ in 0..200 {
        let run =
            body(call(st, "GET", &format!("/api/v1/runs/{id}"), Some(cookie), None).await).await;
        if run["status"] != "running" {
            return run;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("przebieg {id} nie zakończył się");
}

async fn start(st: &AppState, cookie: &str) -> (StatusCode, Value) {
    let res = call(st, "POST", "/api/v1/runs", Some(cookie), None).await;
    (res.status(), body(res).await)
}

#[sqlx::test(migrator = "asi_db::MIGRATOR")]
async fn run_completes_with_observations_and_permissions(db: PgPool) {
    let fake = FakeRunner {
        open_port: 22,
        ..Default::default()
    };
    let (st, admin) = setup(&db, service(Ok(cfg()), fake)).await;
    add_user(&db, "vi", rbac::VIEWER).await;
    let viewer = cookie_pair(&login_as(&st, "vi", PASSWORD).await);
    assert_eq!(start(&st, &viewer).await.0, StatusCode::FORBIDDEN);

    let (status, started) = start(&st, &admin).await;
    assert_eq!(status, StatusCode::ACCEPTED);
    let id = started["run_id"].as_str().unwrap().to_string();
    let run = wait_finished(&st, &viewer, &id).await;
    assert_eq!(run["status"], "done");
    assert_eq!(run["coverage"]["scanned"], 3);
    assert_eq!(run["coverage"]["services"], 3);

    let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM observations WHERE run_id = $1::uuid")
        .bind(&id)
        .fetch_one(&db)
        .await
        .unwrap();
    assert_eq!(n, 3);
    let list = body(call(&st, "GET", "/api/v1/runs", Some(&viewer), None).await).await;
    assert_eq!(list.as_array().unwrap().len(), 1);
}

#[sqlx::test(migrator = "asi_db::MIGRATOR")]
async fn failing_nmap_gives_failed_and_retries_next_time(db: PgPool) {
    let fake = FakeRunner {
        fail: true,
        ..Default::default()
    };
    let (st, admin) = setup(&db, service(Ok(cfg()), fake)).await;
    let id = start(&st, &admin).await.1["run_id"]
        .as_str()
        .unwrap()
        .to_string();
    let run = wait_finished(&st, &admin, &id).await;
    assert_eq!(run["status"], "failed");
    assert_eq!(run["coverage"]["scanned"], 0);
    assert_eq!(run["coverage"]["failed"], 3);
    let failed: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM scan_chunks WHERE run_id = $1::uuid AND status = 'failed'",
    )
    .bind(&id)
    .fetch_one(&db)
    .await
    .unwrap();
    assert!(failed > 0);
}

#[sqlx::test(migrator = "asi_db::MIGRATOR")]
async fn second_start_conflicts_and_cancel_stops(db: PgPool) {
    let fake = FakeRunner {
        delay: Duration::from_secs(5),
        ..Default::default()
    };
    let (st, admin) = setup(&db, service(Ok(cfg()), fake)).await;
    add_user(&db, "an", rbac::ANALYST).await;
    let analyst = cookie_pair(&login_as(&st, "an", PASSWORD).await);

    let id = start(&st, &admin).await.1["run_id"]
        .as_str()
        .unwrap()
        .to_string();
    let (status, err) = start(&st, &analyst).await;
    assert_eq!(status, StatusCode::CONFLICT, "{err}");

    let res = call(
        &st,
        "POST",
        &format!("/api/v1/runs/{id}/cancel"),
        Some(&analyst),
        None,
    )
    .await;
    assert_eq!(res.status(), StatusCode::NO_CONTENT);
    let run = wait_finished(&st, &admin, &id).await;
    assert_eq!(run["status"], "cancelled");
    let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM observations")
        .fetch_one(&db)
        .await
        .unwrap();
    assert_eq!(n, 0, "anulowany przebieg nie publikuje wyniku");
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(
        start(&st, &admin).await.0,
        StatusCode::ACCEPTED,
        "slot zwolniony"
    );
}

#[sqlx::test(migrator = "asi_db::MIGRATOR")]
async fn windows_and_bad_config_refuse_start(db: PgPool) {
    let mut night = cfg();
    night.schedule.windows = vec![WindowConfig {
        start: "22:00".into(),
        end: "06:00".into(),
        days: vec![],
    }];
    let noon = NaiveDateTime::parse_from_str("2026-11-21 12:00", "%Y-%m-%d %H:%M").unwrap();
    let svc = service(Ok(night), FakeRunner::default()).with_clock(Arc::new(move || noon));
    let (st, admin) = setup(&db, svc).await;
    let (status, err) = start(&st, &admin).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert!(err["error"].as_str().unwrap().contains("oknem"), "{err}");
    let runs: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM scan_runs")
        .fetch_one(&db)
        .await
        .unwrap();
    assert_eq!(runs, 0);

    let bad = ScanConfig::from_toml(
        "[schedule]\n[[schedule.windows]]\nstart = \"25:00\"\nend = \"06:00\"\n",
    )
    .map_err(|e| format!("{e:#}"));
    let st = st.with_scans(service(bad, FakeRunner::default()));
    let (status, err) = start(&st, &admin).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert!(
        err["error"].as_str().unwrap().contains("konfiguracja"),
        "{err}"
    );
}

#[sqlx::test(migrator = "asi_db::MIGRATOR")]
async fn window_deadline_gives_partial_and_resume_goes_first(db: PgPool) {
    let mut c = cfg();
    c.chunk_size = 1;
    c.concurrency = 1;
    c.schedule.windows = vec![WindowConfig {
        start: "00:00".into(),
        end: "23:59".into(),
        days: vec![],
    }];
    // okno kończy się 300 ms po „teraz”
    let svc = service(
        Ok(c.clone()),
        FakeRunner {
            delay: Duration::from_millis(200),
            ..Default::default()
        },
    )
    .with_clock(Arc::new(|| {
        NaiveDateTime::parse_from_str("2026-11-21 23:58:59.700", "%Y-%m-%d %H:%M:%S%.3f").unwrap()
    }));
    let (st, admin) = setup(&db, svc).await;
    let id = start(&st, &admin).await.1["run_id"]
        .as_str()
        .unwrap()
        .to_string();
    let run = wait_finished(&st, &admin, &id).await;
    assert_eq!(run["status"], "partial", "{run}");
    assert_eq!(run["reason"], "koniec okna czasowego");
    let pending: Vec<Vec<String>> = sqlx::query_scalar(
        "SELECT targets FROM scan_chunks WHERE run_id = $1::uuid AND status = 'pending'",
    )
    .bind(&id)
    .fetch_all(&db)
    .await
    .unwrap();
    let pending: Vec<String> = pending.concat();
    assert!(!pending.is_empty());

    // wykluczony zaległy cel nie jest wznawiany; reszta zaległych idzie na początek
    let excluded = pending[0].clone();
    sqlx::query("UPDATE targets SET excluded = true WHERE value = $1")
        .bind(&excluded)
        .execute(&db)
        .await
        .unwrap();
    let attempts = asi_db::runs::resume_targets(&db).await.unwrap();
    assert!(attempts.contains_key(&excluded), "zaległość zapisana");
    let st = st.with_scans(service(Ok(cfg()), FakeRunner::default()));
    let id = start(&st, &admin).await.1["run_id"]
        .as_str()
        .unwrap()
        .to_string();
    let run = wait_finished(&st, &admin, &id).await;
    assert_eq!(run["status"], "done");
    let scanned: Vec<String> =
        sqlx::query_scalar("SELECT host(ip) FROM observations WHERE run_id = $1::uuid")
            .bind(&id)
            .fetch_all(&db)
            .await
            .unwrap();
    assert!(!scanned.contains(&excluded));
    let profile: Value =
        sqlx::query_scalar("SELECT profile_snapshot FROM scan_runs WHERE id = $1::uuid")
            .bind(&id)
            .fetch_one(&db)
            .await
            .unwrap();
    assert_eq!(
        profile["resumed"].as_u64().unwrap() as usize,
        pending.len() - 1
    );
}

#[sqlx::test(migrator = "asi_db::MIGRATOR")]
async fn schedule_is_editable_validated_and_used_by_start(db: PgPool) {
    let noon = NaiveDateTime::parse_from_str("2026-11-21 12:00", "%Y-%m-%d %H:%M").unwrap();
    let svc = service(Ok(cfg()), FakeRunner::default()).with_clock(Arc::new(move || noon));
    let (st, admin) = setup(&db, svc).await;
    add_user(&db, "viewer1", rbac::VIEWER).await;
    let viewer = cookie_pair(&login_as(&st, "viewer1", PASSWORD).await);

    let night = json!({ "enabled": true, "every_hours": 12,
        "windows": [{ "start": "22:00", "end": "06:00", "days": ["mon", "fri"] }] });

    // odczyt dla każdej roli, zapis tylko z scans.configure
    let res = call(&st, "GET", "/api/v1/schedule", Some(&viewer), None).await;
    assert_eq!(res.status(), StatusCode::OK);
    let res = call(&st, "PUT", "/api/v1/schedule", Some(&viewer), Some(night.clone())).await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);

    // błędne okno i częstotliwość są odrzucane
    let bad_window = json!({ "enabled": true, "every_hours": 12, "windows": [{ "start": "25:00", "end": "06:00" }] });
    let res = call(&st, "PUT", "/api/v1/schedule", Some(&admin), Some(bad_window)).await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let bad_every = json!({ "enabled": true, "every_hours": 0, "windows": [] });
    let res = call(&st, "PUT", "/api/v1/schedule", Some(&admin), Some(bad_every)).await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);

    // zapis: widoczny w odczycie, w bazie, w dzienniku audytu i od razu w polityce startu (południe poza oknem)
    let res = call(&st, "PUT", "/api/v1/schedule", Some(&admin), Some(night.clone())).await;
    assert_eq!(res.status(), StatusCode::NO_CONTENT);
    let saved = body(call(&st, "GET", "/api/v1/schedule", Some(&viewer), None).await).await;
    assert_eq!(saved, night);
    let stored: Value = sqlx::query_scalar("SELECT value FROM scan_schedule").fetch_one(&db).await.unwrap();
    assert_eq!(stored, night);
    let audited: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM audit_log WHERE action = 'schedule.update'")
        .fetch_one(&db)
        .await
        .unwrap();
    assert_eq!(audited, 1);
    let (status, err) = start(&st, &admin).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert!(err["error"].as_str().unwrap().contains("oknem"), "{err}");

    // po restarcie (nowa usługa z plikiem bez okien) harmonogram wraca z bazy
    let st2 = st.with_scans(service(Ok(cfg()), FakeRunner::default()));
    assert!(st2.scans.schedule().windows.is_empty());
    crate::scans::load_saved_schedule(&st2).await;
    assert_eq!(serde_json::to_value(st2.scans.schedule()).unwrap(), night);
}
