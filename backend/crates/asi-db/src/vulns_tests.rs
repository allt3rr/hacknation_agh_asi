//! Testy stanu sprawdzania i zapisu podatności na PostgreSQL.

use crate::runs::{get_run, reserve_scan};
use crate::vulns::{self, Transition};
use crate::MIGRATOR;
use asi_core::vuln::Vulnerability;
use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;

fn vuln(ip: &str, cve: &str, score: Option<f64>) -> Vulnerability {
    Vulnerability {
        ip: ip.into(),
        port: 80,
        proto: "tcp".into(),
        cve_id: cve.into(),
        cvss_score: score,
        cvss_vector: score.map(|_| "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H".into()),
        severity: asi_core::vuln::severity_from_cvss(score).into(),
        evidence: "version_match".into(),
        component: "http_server".into(),
        version: "2.4.49".into(),
        description: "opis".into(),
        published: Some("2021-10-05".into()),
    }
}

async fn published_run(db: &PgPool) -> Uuid {
    let id = reserve_scan(db, "t", None, &json!({}))
        .await
        .unwrap()
        .unwrap();
    sqlx::query("UPDATE scan_runs SET status = 'done' WHERE id = $1")
        .bind(id)
        .execute(db)
        .await
        .unwrap();
    id
}

#[sqlx::test(migrator = "MIGRATOR")]
async fn state_transitions(db: PgPool) {
    let id = published_run(&db).await;
    let running = reserve_scan(&db, "t", None, &json!({}))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        vulns::begin(&db, running).await.unwrap(),
        Transition::NotPublished
    );
    assert_eq!(
        vulns::begin(&db, Uuid::new_v4()).await.unwrap(),
        Transition::NotFound
    );

    vulns::set_initial(&db, id, "pending_decision")
        .await
        .unwrap();
    assert_eq!(
        get_run(&db, id).await.unwrap().unwrap().vuln_state,
        "pending_decision"
    );
    assert_eq!(vulns::begin(&db, id).await.unwrap(), Transition::Done);
    assert_eq!(vulns::begin(&db, id).await.unwrap(), Transition::Busy);
    assert_eq!(vulns::skip(&db, id).await.unwrap(), Transition::Busy);
    vulns::set_initial(&db, id, "none").await.unwrap();
    assert_eq!(
        get_run(&db, id).await.unwrap().unwrap().vuln_state,
        "running"
    );

    assert_eq!(vulns::recover_orphans(&db).await.unwrap(), 1);
    let run = get_run(&db, id).await.unwrap().unwrap();
    assert_eq!(run.vuln_state, "failed");
    assert!(run.vuln_reason.is_some());
    assert_eq!(vulns::skip(&db, id).await.unwrap(), Transition::Done);
    assert_eq!(
        get_run(&db, id).await.unwrap().unwrap().vuln_state,
        "skipped"
    );
}

#[sqlx::test(migrator = "MIGRATOR")]
async fn store_confirm_and_list(db: PgPool) {
    let id = published_run(&db).await;
    let items = vec![
        vuln("10.0.0.1", "CVE-2021-41773", Some(7.5)),
        vuln("10.0.0.1", "CVE-2021-42013", Some(9.8)),
        vuln("10.0.0.2", "CVE-2099-0001", None),
    ];
    vulns::replace(&db, id, &items).await.unwrap();
    let all = vulns::list(&db, id, None, None).await.unwrap();
    assert_eq!(all[0].cve_id, "CVE-2021-42013", "najwyższy CVSS najpierw");
    assert_eq!(all[2].severity, "Info");
    assert_eq!(all[0], items[1]);

    // potwierdzenie podnosi dowód (ocena NVD zostaje), CVE spoza NVD jest dodawane
    let mut known = vuln("10.0.0.1", "CVE-2021-41773", Some(1.0));
    known.description = "z szablonu".into();
    let extra = vuln("10.0.0.3", "CVE-2020-1938", Some(9.8));
    let n = vulns::confirm(&db, id, &[known, extra]).await.unwrap();
    assert_eq!(n, 2);
    let high = vulns::list(&db, id, Some("High"), None).await.unwrap();
    assert_eq!(high.len(), 1);
    assert_eq!(high[0].evidence, "confirmed");
    assert_eq!(high[0].cvss_score, Some(7.5), "ocena NVD zachowana");
    assert_eq!(high[0].description, "opis");
    let added = vulns::list(&db, id, None, Some("10.0.0.3")).await.unwrap();
    assert_eq!(added[0].evidence, "confirmed");
    for evidence in ["version_backport", "version_conditional"] {
        let mut v = vuln("10.0.0.4", "CVE-2099-0002", None);
        v.evidence = evidence.into();
        vulns::replace(&db, id, &[v]).await.expect(evidence);
    }
    vulns::replace(&db, id, &items).await.unwrap();
    assert_eq!(
        vulns::list(&db, id, None, Some("10.0.0.2"))
            .await
            .unwrap()
            .len(),
        1
    );

    // ponowne sprawdzanie zastępuje wynik
    vulns::replace(&db, id, &items[..1]).await.unwrap();
    assert_eq!(vulns::list(&db, id, None, None).await.unwrap().len(), 1);
}

#[sqlx::test(migrator = "MIGRATOR")]
async fn cve_cache_respects_age(db: PgPool) {
    let cpe = "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*";
    assert!(vulns::cache_get(&db, cpe, 24).await.unwrap().is_none());
    vulns::cache_put(&db, cpe, &json!([{ "id": "CVE-1" }]))
        .await
        .unwrap();
    assert_eq!(
        vulns::cache_get(&db, cpe, 24).await.unwrap(),
        Some(json!([{ "id": "CVE-1" }]))
    );
    assert!(vulns::cache_get(&db, cpe, 0).await.unwrap().is_none());
}
