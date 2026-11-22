//! Testy API przebiegów (`skaner-bezpieczny`) z atrapą nmap (`FakeRunner`).

use crate::scans::ScanService;
use crate::tests::{add_user, body, call, cookie_pair, login_as, prepared, PASSWORD};
use crate::AppState;
use asi_core::rbac;
use asi_scanner::config::ScanConfig;
use asi_scanner::nmap::{AnyRunner, FakeRunner};
use axum::http::StatusCode;
use serde_json::{json, Value};
use sqlx::PgPool;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use time::PrimitiveDateTime;

fn signatures_dir() -> PathBuf {
    PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/../../signatures"))
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
    let admin = cookie_pair(&login_as(&st, "admin", "fixture-password").await);
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

fn at(text: &str) -> PrimitiveDateTime {
    PrimitiveDateTime::parse(
        text,
        time::macros::format_description!("[year]-[month]-[day] [hour]:[minute]"),
    )
    .unwrap()
}

/// Tworzy pozycję harmonogramu przez API i zwraca ją z bazy.
async fn add_schedule(
    st: &AppState,
    cookie: &str,
    db: &PgPool,
    windows: Value,
) -> asi_db::schedule::ScheduleView {
    let ids: Vec<String> = target_ids(db).await.into_iter().map(|t| t.0).collect();
    let entry = json!({ "name": "noc", "every_hours": 1, "windows": windows, "target_ids": ids, "vuln_check": "off" });
    let res = call(st, "POST", "/api/v1/schedules", Some(cookie), Some(entry)).await;
    assert_eq!(res.status(), StatusCode::CREATED);
    let id: uuid::Uuid = body(res).await["id"].as_str().unwrap().parse().unwrap();
    asi_db::schedule::get(db, id).await.unwrap().unwrap()
}

#[sqlx::test(migrator = "asi_db::MIGRATOR")]
async fn windows_limit_schedule_not_manual_start(db: PgPool) {
    let noon = at("2026-11-21 12:00");
    let svc = service(Ok(cfg()), FakeRunner::default()).with_clock(Arc::new(move || Some(noon)));
    let (st, admin) = setup(&db, svc).await;
    let night = add_schedule(
        &st,
        &admin,
        &db,
        json!([{ "start": "22:00", "end": "06:00", "days": [] }]),
    )
    .await;

    // pozycja poza swoim oknem nie startuje
    let err = crate::scans::start_run(&st, None, Some(&night.target_ids), None, Some(&night))
        .await
        .unwrap_err();
    assert!(
        matches!(&err, crate::scans::StartError::Refused(m) if m.contains("oknem")),
        "{err:?}"
    );
    assert_eq!(crate::scans::run_due(&st).await.unwrap(), None);

    // ręczny start o tej samej porze działa i nie ma terminu
    let (status, started) = start(&st, &admin).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{started}");
    let run = wait_finished(&st, &admin, started["run_id"].as_str().unwrap()).await;
    assert_eq!(run["status"], "done", "{run}");

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
    // okno pozycji kończy się 300 ms po „teraz”
    let svc = service(
        Ok(c.clone()),
        FakeRunner {
            delay: Duration::from_millis(200),
            ..Default::default()
        },
    )
    .with_clock(Arc::new(|| {
        PrimitiveDateTime::parse(
            "2026-11-21 23:58:59.700",
            time::macros::format_description!(
                "[year]-[month]-[day] [hour]:[minute]:[second].[subsecond]"
            ),
        )
        .ok()
    }));
    let (st, admin) = setup(&db, svc).await;
    let entry = add_schedule(
        &st,
        &admin,
        &db,
        json!([{ "start": "00:00", "end": "23:59", "days": [] }]),
    )
    .await;
    let id = crate::scans::run_due(&st)
        .await
        .unwrap()
        .expect("należna pozycja startuje")
        .to_string();
    let run = wait_finished(&st, &admin, &id).await;
    assert_eq!(run["schedule_id"], json!(entry.id), "{run}");
    assert_eq!(run["schedule_name"], "noc");
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
async fn schedules_crud_validation_rbac_and_audit(db: PgPool) {
    let (st, admin) = setup(&db, service(Ok(cfg()), FakeRunner::default())).await;
    add_user(&db, "viewer1", rbac::VIEWER).await;
    add_user(&db, "editor1", rbac::EDITOR).await;
    let viewer = cookie_pair(&login_as(&st, "viewer1", PASSWORD).await);
    let editor = cookie_pair(&login_as(&st, "editor1", PASSWORD).await);
    let ids: Vec<String> = target_ids(&db).await.into_iter().map(|t| t.0).collect();
    let entry = |every: i64, windows: Value, targets: &[String]| {
        json!({ "name": "DMZ nocą", "enabled": true, "every_hours": every, "windows": windows,
                "target_ids": targets, "vuln_check": "auto" })
    };
    let night = json!([{ "start": "22:00", "end": "06:00", "days": ["mon", "fri"] }]);
    let post = |cookie: &str, b: Value| {
        let (st, cookie) = (st.clone(), cookie.to_string());
        async move { call(&st, "POST", "/api/v1/schedules", Some(&cookie), Some(b)).await }
    };

    // viewer czyta, ale nie zapisuje
    let res = call(&st, "GET", "/api/v1/schedules", Some(&viewer), None).await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(body(res).await, json!([]));
    let res = post(&viewer, entry(24, night.clone(), &ids[..2])).await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);

    // walidacja: okno, częstotliwość, pusta i nieznana lista celów
    for bad in [
        entry(24, json!([{ "start": "25:00", "end": "06:00" }]), &ids[..2]),
        entry(0, night.clone(), &ids[..2]),
        entry(24, night.clone(), &[]),
        entry(24, night.clone(), &[uuid::Uuid::new_v4().to_string()]),
    ] {
        let res = post(&editor, bad.clone()).await;
        assert_eq!(res.status(), StatusCode::BAD_REQUEST, "{bad}");
    }
    let res = call(&st, "GET", "/api/v1/schedules", Some(&viewer), None).await;
    assert_eq!(body(res).await, json!([]));

    // utworzenie, edycja, usunięcie celu, usunięcie pozycji
    let res = post(&editor, entry(24, night.clone(), &ids[..2])).await;
    assert_eq!(res.status(), StatusCode::CREATED);
    let created = body(res).await;
    let id = created["id"].as_str().unwrap().to_string();
    assert_eq!(created["windows"], night);
    assert_eq!(created["vuln_check"], "auto");
    let res = call(
        &st,
        "PUT",
        &format!("/api/v1/schedules/{id}"),
        Some(&editor),
        Some(entry(12, night.clone(), &ids[..2])),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(body(res).await["every_hours"], 12);
    let res = call(
        &st,
        "PUT",
        &format!("/api/v1/schedules/{}", uuid::Uuid::new_v4()),
        Some(&editor),
        Some(entry(12, night.clone(), &ids[..2])),
    )
    .await;
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
    let res = call(
        &st,
        "DELETE",
        &format!("/api/v1/targets/{}", ids[0]),
        Some(&admin),
        None,
    )
    .await;
    assert!(res.status().is_success(), "{}", res.status());
    let list = body(call(&st, "GET", "/api/v1/schedules", Some(&viewer), None).await).await;
    assert_eq!(list[0]["missing_targets"], 1);
    let res = call(
        &st,
        "DELETE",
        &format!("/api/v1/schedules/{id}"),
        Some(&viewer),
        None,
    )
    .await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
    let res = call(
        &st,
        "DELETE",
        &format!("/api/v1/schedules/{id}"),
        Some(&editor),
        None,
    )
    .await;
    assert_eq!(res.status(), StatusCode::NO_CONTENT);
    let res = call(
        &st,
        "DELETE",
        &format!("/api/v1/schedules/{id}"),
        Some(&editor),
        None,
    )
    .await;
    assert_eq!(res.status(), StatusCode::NOT_FOUND);

    let audited: Vec<String> = sqlx::query_scalar(
        "SELECT action FROM audit_log WHERE entity = 'scan_schedule' AND entity_id = $1 ORDER BY id",
    )
    .bind(&id)
    .fetch_all(&db)
    .await
    .unwrap();
    assert_eq!(
        audited,
        ["schedule.create", "schedule.update", "schedule.delete"]
    );
    // stary endpoint nie istnieje
    let res = call(&st, "GET", "/api/v1/schedule", Some(&viewer), None).await;
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
}

async fn target_ids(db: &PgPool) -> Vec<(String, String)> {
    sqlx::query_as("SELECT id::text, value FROM targets ORDER BY value")
        .fetch_all(db)
        .await
        .unwrap()
}

async fn start_with(st: &AppState, cookie: &str, ids: Value) -> (StatusCode, Value) {
    let res = call(
        st,
        "POST",
        "/api/v1/runs",
        Some(cookie),
        Some(json!({ "target_ids": ids })),
    )
    .await;
    (res.status(), body(res).await)
}

#[sqlx::test(migrator = "asi_db::MIGRATOR")]
async fn selected_targets_only_and_others_keep_state(db: PgPool) {
    let fake = FakeRunner {
        open_port: 22,
        ..Default::default()
    };
    let (st, admin) = setup(&db, service(Ok(cfg()), fake)).await;
    let ids = target_ids(&db).await; // 10.0.0.1, 10.0.0.2, 10.0.0.3

    let (status, started) = start_with(&st, &admin, json!([ids[0].0, ids[1].0])).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{started}");
    let id = started["run_id"].as_str().unwrap().to_string();
    let run = wait_finished(&st, &admin, &id).await;
    assert_eq!(run["status"], "done");
    assert_eq!(run["coverage"]["scanned"], 2);
    let ips: Vec<String> = sqlx::query_scalar(
        "SELECT DISTINCT host(ip) FROM observations WHERE run_id = $1::uuid ORDER BY 1",
    )
    .bind(&id)
    .fetch_all(&db)
    .await
    .unwrap();
    assert_eq!(ips, ["10.0.0.1", "10.0.0.2"]);
    let selected: Option<i64> = sqlx::query_scalar(
        "SELECT (details->>'selected')::bigint FROM audit_log WHERE action = 'run.start' ORDER BY id DESC LIMIT 1",
    )
    .fetch_one(&db)
    .await
    .unwrap();
    assert_eq!(selected, Some(2));

    // pełny przebieg (bez body), potem tylko 10.0.0.1: 10.0.0.3 nie dostaje zmian
    let full = start(&st, &admin).await.1["run_id"]
        .as_str()
        .unwrap()
        .to_string();
    wait_finished(&st, &admin, &full).await;
    let only = start_with(&st, &admin, json!([ids[0].0])).await.1["run_id"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(
        wait_finished(&st, &admin, &only).await["coverage"]["scanned"],
        1
    );
    let changes = body(
        call(
            &st,
            "GET",
            &format!("/api/v1/runs/{only}/changes"),
            Some(&admin),
            None,
        )
        .await,
    )
    .await;
    assert!(
        changes["items"]
            .as_array()
            .unwrap()
            .iter()
            .all(|c| c["ip"] != "10.0.0.3"),
        "{changes}"
    );
}

#[sqlx::test(migrator = "asi_db::MIGRATOR")]
async fn selection_is_validated(db: PgPool) {
    let (st, admin) = setup(&db, service(Ok(cfg()), FakeRunner::default())).await;
    let ids = target_ids(&db).await;
    add_user(&db, "vi", rbac::VIEWER).await;
    let viewer = cookie_pair(&login_as(&st, "vi", PASSWORD).await);

    assert_eq!(
        start_with(&st, &viewer, json!([ids[0].0])).await.0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        start_with(&st, &admin, json!([])).await.0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        start_with(&st, &admin, json!(["00000000-0000-0000-0000-000000000000"]))
            .await
            .0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        start_with(&st, &admin, json!(["nie-uuid"])).await.0,
        StatusCode::BAD_REQUEST
    );

    sqlx::query("UPDATE targets SET excluded = true WHERE id = $1::uuid")
        .bind(&ids[2].0)
        .execute(&db)
        .await
        .unwrap();
    assert_eq!(
        start_with(&st, &admin, json!([ids[2].0])).await.0,
        StatusCode::CONFLICT
    );
    let runs: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM scan_runs")
        .fetch_one(&db)
        .await
        .unwrap();
    assert_eq!(runs, 0, "odrzucony start nie tworzy przebiegu");
}
