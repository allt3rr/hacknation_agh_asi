//! Testy publikacji wyniku (`results::publish`) na PostgreSQL.

use crate::results::{publish, PublishInput, PublishOutcome};
use crate::runs::{get_run, reserve_scan};
use crate::MIGRATOR;
use asi_core::model::{HttpInfo, Observation};
use asi_crypto::FieldCrypto;
use serde_json::json;
use sqlx::PgPool;
use std::collections::{HashMap, HashSet};
use uuid::Uuid;

fn crypto() -> FieldCrypto {
    FieldCrypto::from_base64(&FieldCrypto::generate_key()).unwrap()
}

fn obs(ip: &str, port: u16, product: &str) -> Observation {
    let mut o = Observation::new(ip.into(), port, "tcp".into());
    o.product = Some(product.into());
    o
}

struct Run<'a> {
    observations: Vec<Observation>,
    scanned: Vec<&'a str>,
    resolved: Vec<(&'a str, &'a str)>,
    failed: Vec<Vec<String>>,
    pending: Vec<String>,
}

impl<'a> Run<'a> {
    fn new(observations: Vec<Observation>, scanned: &[&'a str]) -> Self {
        Self {
            observations,
            scanned: scanned.to_vec(),
            resolved: vec![],
            failed: vec![],
            pending: vec![],
        }
    }
}

async fn run_and_publish(db: &PgPool, c: &FieldCrypto, r: Run<'_>) -> (Uuid, PublishOutcome) {
    let id = reserve_scan(db, "test", None, &json!({}))
        .await
        .unwrap()
        .unwrap();
    let live: HashSet<String> = r.observations.iter().map(|o| o.ip.clone()).collect();
    let scanned: HashSet<String> = r.scanned.iter().map(|s| s.to_string()).collect();
    let resolved: Vec<(String, String)> = r
        .resolved
        .iter()
        .map(|(d, i)| (d.to_string(), i.to_string()))
        .collect();
    let failed: Vec<(Vec<String>, String)> = r
        .failed
        .iter()
        .map(|t| (t.clone(), "błąd".to_string()))
        .collect();
    let input = PublishInput {
        observations: &r.observations,
        live: &live,
        scanned: &scanned,
        resolved: &resolved,
        failed: &failed,
        pending: &r.pending,
        attempts: &HashMap::new(),
        max_attempts: 3,
        inactive_after: 2,
        planned: scanned.len(),
        status: "done",
        reason: None,
        coverage: json!({}),
    };
    let out = publish(db, c, id, "test", &input).await.unwrap();
    (id, out)
}

async fn count(db: &PgPool, sql: &str) -> i64 {
    sqlx::query_scalar(sql).fetch_one(db).await.unwrap()
}

#[sqlx::test(migrator = "MIGRATOR")]
async fn second_publish_and_lost_lease_write_nothing(db: PgPool) {
    let c = crypto();
    let (id, out) = run_and_publish(
        &db,
        &c,
        Run::new(vec![obs("10.0.0.1", 80, "nginx")], &["10.0.0.1"]),
    )
    .await;
    assert_eq!(out, PublishOutcome::Published { changes: 1 });
    assert_eq!(get_run(&db, id).await.unwrap().unwrap().status, "done");

    let input_obs = vec![obs("10.0.0.1", 80, "nginx")];
    let live: HashSet<String> = ["10.0.0.1".to_string()].into();
    let input = PublishInput {
        observations: &input_obs,
        live: &live,
        scanned: &live,
        resolved: &[],
        failed: &[],
        pending: &[],
        attempts: &HashMap::new(),
        max_attempts: 3,
        inactive_after: 2,
        planned: 1,
        status: "done",
        reason: None,
        coverage: json!({}),
    };
    assert_eq!(
        publish(&db, &c, id, "test", &input).await.unwrap(),
        PublishOutcome::LeaseLost
    );
    assert_eq!(count(&db, "SELECT COUNT(*) FROM observations").await, 1);
    assert_eq!(count(&db, "SELECT COUNT(*) FROM changes").await, 1);

    // dzierżawa przejęta przed publikacją
    let other = reserve_scan(&db, "proc-a", None, &json!({}))
        .await
        .unwrap()
        .unwrap();
    sqlx::query("UPDATE scan_runs SET lease_owner = 'proc-b' WHERE id = $1")
        .bind(other)
        .execute(&db)
        .await
        .unwrap();
    assert_eq!(
        publish(&db, &c, other, "proc-a", &input).await.unwrap(),
        PublishOutcome::LeaseLost
    );
    assert_eq!(count(&db, "SELECT COUNT(*) FROM observations").await, 1);
}

#[sqlx::test(migrator = "MIGRATOR")]
async fn changes_between_runs(db: PgPool) {
    let c = crypto();
    let first = vec![
        obs("10.0.0.1", 80, "nginx"),
        obs("10.0.0.1", 22, "OpenSSH"),
        obs("10.0.0.2", 80, "IIS"),
    ];
    run_and_publish(&db, &c, Run::new(first, &["10.0.0.1", "10.0.0.2"])).await;

    let second = vec![obs("10.0.0.1", 80, "Apache"), obs("10.0.0.1", 443, "nginx")];
    let (id, _) = run_and_publish(&db, &c, Run::new(second, &["10.0.0.1"])).await;
    let rows: Vec<(String, String)> =
        sqlx::query_as("SELECT kind, entity_key FROM changes WHERE run_id = $1 ORDER BY 2, 1")
            .bind(id)
            .fetch_all(&db)
            .await
            .unwrap();
    assert!(rows.contains(&("changed".into(), "10.0.0.1:80/tcp".into())));
    assert!(rows.contains(&("new".into(), "10.0.0.1:443/tcp".into())));
    assert!(rows.contains(&("gone".into(), "10.0.0.1:22/tcp".into())));
    assert!(
        !rows.iter().any(|(_, k)| k.starts_with("10.0.0.2")),
        "10.0.0.2 nie był skanowany"
    );

    // usługa „gone” nie wraca jako zmiana w kolejnym przebiegu
    let third = vec![obs("10.0.0.1", 80, "Apache"), obs("10.0.0.1", 443, "nginx")];
    let (id, out) = run_and_publish(&db, &c, Run::new(third, &["10.0.0.1"])).await;
    assert_eq!(out, PublishOutcome::Published { changes: 0 }, "{id}");
}

#[sqlx::test(migrator = "MIGRATOR")]
async fn silent_domain_becomes_unstable_then_inactive(db: PgPool) {
    let c = crypto();
    let mut o = obs("10.0.0.9", 80, "nginx");
    o.hostname = Some("app.lab".into());
    let mut first = Run::new(vec![o], &["app.lab"]);
    first.resolved = vec![("app.lab", "10.0.0.9")];
    run_and_publish(&db, &c, first).await;
    let state = || async {
        sqlx::query_scalar::<_, String>("SELECT state FROM assets WHERE ip = '10.0.0.9'")
            .fetch_one(&db)
            .await
            .unwrap()
    };
    assert_eq!(state().await, "active");

    run_and_publish(&db, &c, Run::new(vec![], &["app.lab"])).await;
    assert_eq!(state().await, "unstable");
    let (id, _) = run_and_publish(&db, &c, Run::new(vec![], &["app.lab"])).await;
    assert_eq!(state().await, "inactive");
    let kinds: Vec<String> = sqlx::query_scalar("SELECT kind FROM changes WHERE run_id = $1")
        .bind(id)
        .fetch_all(&db)
        .await
        .unwrap();
    assert_eq!(kinds, vec!["host_inactive"]);

    let mut back = obs("10.0.0.9", 80, "nginx");
    back.hostname = Some("app.lab".into());
    let (id, _) = run_and_publish(&db, &c, Run::new(vec![back], &["app.lab"])).await;
    let kinds: Vec<String> = sqlx::query_scalar("SELECT kind FROM changes WHERE run_id = $1")
        .bind(id)
        .fetch_all(&db)
        .await
        .unwrap();
    assert_eq!(kinds, vec!["host_returned"]);
}

#[sqlx::test(migrator = "MIGRATOR")]
async fn cookie_values_are_only_encrypted(db: PgPool) {
    let c = crypto();
    let mut o = obs("10.0.0.1", 80, "nginx");
    o.http = Some(HttpInfo {
        url: "http://10.0.0.1:80/".into(),
        status: 200,
        cookies: vec!["PHPSESSID=tajny-token-123; Path=/; HttpOnly".into()],
        ..Default::default()
    });
    run_and_publish(&db, &c, Run::new(vec![o], &["10.0.0.1"])).await;

    let meta: serde_json::Value = sqlx::query_scalar("SELECT cookies_meta FROM http_info")
        .fetch_one(&db)
        .await
        .unwrap();
    assert_eq!(
        meta,
        json!([{ "name": "PHPSESSID", "attributes": ["Path=/", "HttpOnly"] }])
    );
    let names: Vec<String> = sqlx::query_scalar("SELECT cookie_names FROM observations")
        .fetch_one(&db)
        .await
        .unwrap();
    assert_eq!(names, vec!["PHPSESSID"]);
    let leaked = count(
        &db,
        "SELECT COUNT(*) FROM (SELECT encode(data_enc, 'escape') AS t FROM observations
                               UNION ALL SELECT encode(cookies_enc, 'escape') FROM http_info
                               UNION ALL SELECT cookies_meta::text FROM http_info) x WHERE t LIKE '%tajny-token%'",
    )
    .await;
    assert_eq!(leaked, 0);
}

#[sqlx::test(migrator = "MIGRATOR")]
async fn failed_chunks_count_attempts_and_get_abandoned(db: PgPool) {
    let c = crypto();
    let mut r = Run::new(vec![], &[]);
    r.failed = vec![vec!["10.0.0.5".into()]];
    r.pending = vec!["10.0.0.6".into()];
    let (id, _) = run_and_publish(&db, &c, r).await;
    let rows: Vec<(String, i32)> =
        sqlx::query_as("SELECT status, attempt FROM scan_chunks WHERE run_id = $1 ORDER BY status")
            .bind(id)
            .fetch_all(&db)
            .await
            .unwrap();
    assert_eq!(rows, vec![("failed".into(), 1), ("pending".into(), 0)]);
}
