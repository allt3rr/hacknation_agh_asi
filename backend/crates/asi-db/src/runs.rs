//! Przebiegi skanu: atomowa rezerwacja z dzierżawą, odzyskanie osieroconych, anulowanie,
//! zaległości z poprzedniego przebiegu i odczyt.

use anyhow::Result;
use serde::Serialize;
use serde_json::Value;
use sqlx::PgPool;
use std::collections::HashMap;
use time::OffsetDateTime;
use uuid::Uuid;

/// Dzierżawa przedłużana co `HEARTBEAT_SECS`; po `LEASE_SECS` bez odnowienia przebieg jest osierocony.
pub const LEASE_SECS: i32 = 60;
// co sekundę: heartbeat zapisuje też postęp skanu widoczny w UI (jedno UPDATE wiersza na sekundę)
pub const HEARTBEAT_SECS: u64 = 1;

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct RunView {
    pub id: Uuid,
    pub kind: String,
    pub status: String,
    pub reason: Option<String>,
    pub coverage: Value,
    #[serde(with = "time::serde::rfc3339::option")]
    pub started_at: Option<OffsetDateTime>,
    #[serde(with = "time::serde::rfc3339::option")]
    pub finished_at: Option<OffsetDateTime>,
    pub duration_ms: Option<i64>,
    pub hosts_total: i32,
    pub hosts_done: i32,
    pub triggered_by: Option<Uuid>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

const RUN_COLUMNS: &str =
    "id, kind, status, reason, coverage, started_at, finished_at, duration_ms,
                           hosts_total, hosts_done, triggered_by, created_at";

/// Oznacza przebiegi z wygasłą dzierżawą jako `failed` („utracona dzierżawa”).
pub async fn recover_orphans(db: &PgPool) -> Result<u64> {
    let res = sqlx::query(
        "UPDATE scan_runs SET status = 'failed', reason = 'utracona dzierżawa', finished_at = now(),
                lease_owner = NULL
         WHERE status = 'running' AND lease_until < now()",
    )
    .execute(db)
    .await?;
    Ok(res.rows_affected())
}

/// Rezerwuje skan. `None`, gdy w bazie trwa już inny skan z ważną dzierżawą.
pub async fn reserve_scan(
    db: &PgPool,
    owner: &str,
    triggered_by: Option<Uuid>,
    profile: &Value,
) -> Result<Option<Uuid>> {
    recover_orphans(db).await?;
    let res = sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO scan_runs (kind, status, lease_owner, lease_until, started_at, triggered_by, profile_snapshot)
         VALUES ('scan', 'running', $1, now() + make_interval(secs => $2), now(), $3, $4)
         RETURNING id",
    )
    .bind(owner)
    .bind(LEASE_SECS as f64)
    .bind(triggered_by)
    .bind(profile)
    .fetch_one(db)
    .await;
    match res {
        Ok(id) => Ok(Some(id)),
        Err(sqlx::Error::Database(e)) if e.is_unique_violation() => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// Przedłuża dzierżawę i zapisuje postęp (`hosts_done` przycięte do `hosts_total`).
/// `false` = przebieg anulowany albo przejęty: właściciel ma przerwać pracę.
pub async fn heartbeat(
    db: &PgPool,
    run_id: Uuid,
    owner: &str,
    hosts_total: i32,
    hosts_done: i32,
) -> Result<bool> {
    let res = sqlx::query(
        "UPDATE scan_runs SET lease_until = now() + make_interval(secs => $3),
                hosts_total = $4, hosts_done = LEAST($5, $4)
         WHERE id = $1 AND lease_owner = $2 AND status = 'running'",
    )
    .bind(run_id)
    .bind(owner)
    .bind(LEASE_SECS as f64)
    .bind(hosts_total)
    .bind(hosts_done)
    .execute(db)
    .await?;
    Ok(res.rows_affected() == 1)
}

pub async fn cancel(db: &PgPool, run_id: Uuid) -> Result<bool> {
    let res = sqlx::query(
        "UPDATE scan_runs SET status = 'cancelled', reason = 'anulowano', finished_at = now(), lease_owner = NULL
         WHERE id = $1 AND status = 'running'",
    )
    .bind(run_id)
    .execute(db)
    .await?;
    Ok(res.rows_affected() == 1)
}

/// Kończy przebieg błędem przed publikacją (np. brak celów, błąd skanera), jeśli nadal ma dzierżawę.
pub async fn finish_failed(db: &PgPool, run_id: Uuid, owner: &str, reason: &str) -> Result<()> {
    sqlx::query(
        "UPDATE scan_runs SET status = 'failed', reason = $3, finished_at = now(), lease_owner = NULL,
                duration_ms = (EXTRACT(EPOCH FROM now() - started_at) * 1000)::bigint
         WHERE id = $1 AND lease_owner = $2 AND status = 'running'",
    )
    .bind(run_id)
    .bind(owner)
    .bind(reason)
    .execute(db)
    .await?;
    Ok(())
}

/// Zaległe i nieudane podgrupy z ostatniego zakończonego skanu (import pomijany): cel → liczba prób.
pub async fn resume_targets(db: &PgPool) -> Result<HashMap<String, i32>> {
    let rows: Vec<(Vec<String>, i32)> = sqlx::query_as(
        "SELECT c.targets, c.attempt FROM scan_chunks c
         WHERE c.status IN ('pending', 'failed') AND c.run_id = (
             SELECT id FROM scan_runs WHERE kind = 'scan' AND status <> 'running'
             ORDER BY created_at DESC LIMIT 1)",
    )
    .fetch_all(db)
    .await?;
    let mut out = HashMap::new();
    for (targets, attempt) in rows {
        for t in targets {
            let e = out.entry(t).or_insert(attempt);
            *e = (*e).max(attempt);
        }
    }
    Ok(out)
}

/// Kiedy zakończył się ostatni skan (bez importów) i czy zostawił zaległości.
pub async fn last_scan(db: &PgPool) -> Result<Option<(OffsetDateTime, String)>> {
    Ok(sqlx::query_as(
        "SELECT COALESCE(started_at, created_at), status FROM scan_runs
         WHERE kind = 'scan' AND status <> 'running' ORDER BY created_at DESC LIMIT 1",
    )
    .fetch_optional(db)
    .await?)
}

pub async fn list_runs(db: &PgPool, limit: i64) -> Result<Vec<RunView>> {
    Ok(sqlx::query_as::<_, RunView>(&format!(
        "SELECT {RUN_COLUMNS} FROM scan_runs ORDER BY created_at DESC LIMIT $1"
    ))
    .bind(limit)
    .fetch_all(db)
    .await?)
}

pub async fn get_run(db: &PgPool, id: Uuid) -> Result<Option<RunView>> {
    Ok(sqlx::query_as::<_, RunView>(&format!(
        "SELECT {RUN_COLUMNS} FROM scan_runs WHERE id = $1"
    ))
    .bind(id)
    .fetch_optional(db)
    .await?)
}

/// Przebieg importu: własna historia (`kind = 'import'`), nie blokuje skanów i nie wpływa na zaległości.
pub async fn reserve_import(
    db: &PgPool,
    owner: &str,
    triggered_by: Option<Uuid>,
    profile: &Value,
) -> Result<Uuid> {
    Ok(sqlx::query_scalar(
        "INSERT INTO scan_runs (kind, status, lease_owner, lease_until, started_at, triggered_by, profile_snapshot)
         VALUES ('import', 'running', $1, now() + make_interval(secs => $2), now(), $3, $4)
         RETURNING id",
    )
    .bind(owner)
    .bind(LEASE_SECS as f64)
    .bind(triggered_by)
    .bind(profile)
    .fetch_one(db)
    .await?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MIGRATOR;
    use serde_json::json;

    #[sqlx::test(migrator = "MIGRATOR")]
    async fn only_one_concurrent_reservation(db: PgPool) {
        let profile = json!({});
        let (a, b) = tokio::join!(
            reserve_scan(&db, "proc-a", None, &profile),
            reserve_scan(&db, "proc-b", None, &profile)
        );
        let granted = [a.unwrap(), b.unwrap()]
            .iter()
            .filter(|r| r.is_some())
            .count();
        assert_eq!(granted, 1);
    }

    #[sqlx::test(migrator = "MIGRATOR")]
    async fn orphan_is_failed_and_slot_reused(db: PgPool) {
        let first = reserve_scan(&db, "a", None, &json!({}))
            .await
            .unwrap()
            .unwrap();
        assert!(reserve_scan(&db, "b", None, &json!({}))
            .await
            .unwrap()
            .is_none());
        assert!(heartbeat(&db, first, "a", 0, 0).await.unwrap());

        sqlx::query("UPDATE scan_runs SET lease_until = now() - interval '1 second'")
            .execute(&db)
            .await
            .unwrap();
        let second = reserve_scan(&db, "b", None, &json!({}))
            .await
            .unwrap()
            .unwrap();
        let old = get_run(&db, first).await.unwrap().unwrap();
        assert_eq!(
            (old.status.as_str(), old.reason.as_deref()),
            ("failed", Some("utracona dzierżawa"))
        );
        assert!(
            !heartbeat(&db, first, "a", 0, 0).await.unwrap(),
            "stary właściciel traci dzierżawę"
        );

        assert!(cancel(&db, second).await.unwrap());
        assert!(!heartbeat(&db, second, "b", 0, 0).await.unwrap());
        assert_eq!(
            get_run(&db, second).await.unwrap().unwrap().status,
            "cancelled"
        );
    }

    #[sqlx::test(migrator = "MIGRATOR")]
    async fn heartbeat_records_progress(db: PgPool) {
        let run = reserve_scan(&db, "a", None, &json!({}))
            .await
            .unwrap()
            .unwrap();
        assert!(heartbeat(&db, run, "a", 10, 4).await.unwrap());
        let r = get_run(&db, run).await.unwrap().unwrap();
        assert_eq!((r.hosts_total, r.hosts_done), (10, 4));

        assert!(heartbeat(&db, run, "a", 10, 99).await.unwrap());
        assert_eq!(get_run(&db, run).await.unwrap().unwrap().hosts_done, 10);

        assert!(!heartbeat(&db, run, "obcy", 20, 0).await.unwrap());
        let r = get_run(&db, run).await.unwrap().unwrap();
        assert_eq!((r.hosts_total, r.hosts_done), (10, 10));
    }

    #[sqlx::test(migrator = "MIGRATOR")]
    async fn resume_skips_imports(db: PgPool) {
        let run = reserve_scan(&db, "a", None, &json!({}))
            .await
            .unwrap()
            .unwrap();
        sqlx::query("INSERT INTO scan_chunks (run_id, stage, targets, status, attempt) VALUES ($1, 'ports', '{10.0.0.1,10.0.0.2}', 'pending', 0), ($1, 'ports', '{10.0.0.3}', 'failed', 2)")
            .bind(run)
            .execute(&db)
            .await
            .unwrap();
        sqlx::query("UPDATE scan_runs SET status = 'partial' WHERE id = $1")
            .bind(run)
            .execute(&db)
            .await
            .unwrap();
        sqlx::query("INSERT INTO scan_runs (kind, status) VALUES ('import', 'done')")
            .execute(&db)
            .await
            .unwrap();

        let resume = resume_targets(&db).await.unwrap();
        assert_eq!(resume.len(), 3);
        assert_eq!(resume["10.0.0.3"], 2);
        assert_eq!(last_scan(&db).await.unwrap().unwrap().1, "partial");
    }
}
