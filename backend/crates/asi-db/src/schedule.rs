//! Pozycje harmonogramu skanów. Walidację (okna, zakresy, cele) robi warstwa API.

use anyhow::Result;
use serde::Serialize;
use serde_json::Value;
use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

/// Pozycja z danymi do terminu: ostatni zakończony przebieg tej pozycji i liczba usuniętych celów.
#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct ScheduleView {
    pub id: Uuid,
    pub name: String,
    pub enabled: bool,
    pub every_hours: i32,
    pub windows: Value,
    pub target_ids: Vec<Uuid>,
    pub vuln_check: String,
    #[serde(with = "time::serde::rfc3339::option")]
    pub last_run_at: Option<OffsetDateTime>,
    pub last_status: Option<String>,
    pub missing_targets: i32,
}

pub struct ScheduleInput<'a> {
    pub name: &'a str,
    pub enabled: bool,
    pub every_hours: i32,
    pub windows: &'a Value,
    pub target_ids: &'a [Uuid],
    pub vuln_check: &'a str,
}

// shortcut: powiązanie przebiegu z pozycją przez profile_snapshot bez indeksu; przy tysiącach przebiegów dodać kolumnę scan_runs.schedule_id.
const SELECT: &str = "SELECT s.id, s.name, s.enabled, s.every_hours, s.windows, s.target_ids, s.vuln_check,
        last.at AS last_run_at, last.status AS last_status,
        (cardinality(s.target_ids) - (SELECT count(*) FROM targets t WHERE t.id = ANY(s.target_ids)))::int AS missing_targets
    FROM scan_schedules s
    LEFT JOIN LATERAL (
        SELECT COALESCE(r.started_at, r.created_at) AS at, r.status FROM scan_runs r
        WHERE r.kind = 'scan' AND r.status <> 'running' AND r.profile_snapshot->>'schedule_id' = s.id::text
        ORDER BY r.created_at DESC LIMIT 1
    ) last ON true";

pub async fn list(db: &PgPool) -> Result<Vec<ScheduleView>> {
    Ok(
        sqlx::query_as(&format!("{SELECT} ORDER BY s.created_at, s.id"))
            .fetch_all(db)
            .await?,
    )
}

pub async fn get(db: &PgPool, id: Uuid) -> Result<Option<ScheduleView>> {
    Ok(sqlx::query_as(&format!("{SELECT} WHERE s.id = $1"))
        .bind(id)
        .fetch_optional(db)
        .await?)
}

pub async fn create(db: &PgPool, input: &ScheduleInput<'_>, user: Uuid) -> Result<Uuid> {
    Ok(sqlx::query_scalar(
        "INSERT INTO scan_schedules (name, enabled, every_hours, windows, target_ids, vuln_check, created_by, updated_by)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $7) RETURNING id",
    )
    .bind(input.name)
    .bind(input.enabled)
    .bind(input.every_hours)
    .bind(input.windows)
    .bind(input.target_ids)
    .bind(input.vuln_check)
    .bind(user)
    .fetch_one(db)
    .await?)
}

/// `false`, gdy pozycji nie ma.
pub async fn update(db: &PgPool, id: Uuid, input: &ScheduleInput<'_>, user: Uuid) -> Result<bool> {
    let res = sqlx::query(
        "UPDATE scan_schedules SET name = $2, enabled = $3, every_hours = $4, windows = $5, target_ids = $6,
             vuln_check = $7, updated_by = $8, updated_at = now()
         WHERE id = $1",
    )
    .bind(id)
    .bind(input.name)
    .bind(input.enabled)
    .bind(input.every_hours)
    .bind(input.windows)
    .bind(input.target_ids)
    .bind(input.vuln_check)
    .bind(user)
    .execute(db)
    .await?;
    Ok(res.rows_affected() == 1)
}

/// `false`, gdy pozycji nie ma. Przebiegi pozycji zostają (wskazują ją tylko w profilu).
pub async fn delete(db: &PgPool, id: Uuid) -> Result<bool> {
    let res = sqlx::query("DELETE FROM scan_schedules WHERE id = $1")
        .bind(id)
        .execute(db)
        .await?;
    Ok(res.rows_affected() == 1)
}

/// Te z `ids`, które nadal są w tabeli celów (usunięty cel nie blokuje pozycji).
pub async fn existing_targets(db: &PgPool, ids: &[Uuid]) -> Result<Vec<Uuid>> {
    Ok(
        sqlx::query_scalar("SELECT id FROM targets WHERE id = ANY($1)")
            .bind(ids)
            .fetch_all(db)
            .await?,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::migrate::Migrator;
    use std::borrow::Cow;

    /// Baza po 0006 z zapisanym starym harmonogramem → po 0007 jedna pozycja z niewykluczonymi celami.
    #[sqlx::test(migrations = false)]
    async fn migration_converts_saved_schedule(db: PgPool) {
        let early = Migrator {
            migrations: Cow::Owned(
                crate::MIGRATOR
                    .migrations
                    .iter()
                    .filter(|m| m.version < 7)
                    .cloned()
                    .collect(),
            ),
            ..Migrator::DEFAULT
        };
        early.run(&db).await.unwrap();
        sqlx::query(
            "INSERT INTO targets (kind, value, source, excluded) VALUES
             ('ip', '10.0.0.1', 'manual', false), ('ip', '10.0.0.2', 'manual', false),
             ('ip', '10.0.0.3', 'manual', false), ('ip', '10.0.0.4', 'manual', true)",
        )
        .execute(&db)
        .await
        .unwrap();
        let old = serde_json::json!({ "enabled": true, "every_hours": 24,
            "windows": [{ "start": "22:00", "end": "06:00", "days": [] }] });
        sqlx::query("INSERT INTO scan_schedule (value) VALUES ($1)")
            .bind(&old)
            .execute(&db)
            .await
            .unwrap();

        crate::MIGRATOR.run(&db).await.unwrap();
        let all = list(&db).await.unwrap();
        assert_eq!(all.len(), 1);
        let s = &all[0];
        assert_eq!(
            (s.name.as_str(), s.enabled, s.every_hours),
            ("Harmonogram", true, 24)
        );
        assert_eq!(s.windows, old["windows"]);
        assert_eq!((s.target_ids.len(), s.vuln_check.as_str()), (3, "ask"));
        assert_eq!((s.last_run_at, s.missing_targets), (None, 0));
    }

    #[sqlx::test(migrator = "crate::MIGRATOR")]
    async fn crud_and_missing_targets(db: PgPool) {
        let ids: Vec<Uuid> = sqlx::query_scalar(
            "INSERT INTO targets (kind, value, source) VALUES ('ip', '10.0.0.1', 'manual'), ('ip', '10.0.0.2', 'manual') RETURNING id",
        )
        .fetch_all(&db)
        .await
        .unwrap();
        let user: Uuid = sqlx::query_scalar(
            "INSERT INTO users (username, password_hash) VALUES ('u', 'x') RETURNING id",
        )
        .fetch_one(&db)
        .await
        .unwrap();
        let windows = serde_json::json!([]);
        let mut input = ScheduleInput {
            name: "DMZ",
            enabled: true,
            every_hours: 24,
            windows: &windows,
            target_ids: &ids,
            vuln_check: "off",
        };
        let id = create(&db, &input, user).await.unwrap();
        input.every_hours = 12;
        assert!(update(&db, id, &input, user).await.unwrap());
        assert_eq!(get(&db, id).await.unwrap().unwrap().every_hours, 12);

        sqlx::query("DELETE FROM targets WHERE id = $1")
            .bind(ids[0])
            .execute(&db)
            .await
            .unwrap();
        assert_eq!(get(&db, id).await.unwrap().unwrap().missing_targets, 1);
        assert_eq!(existing_targets(&db, &ids).await.unwrap(), vec![ids[1]]);

        assert!(delete(&db, id).await.unwrap());
        assert!(!delete(&db, id).await.unwrap());
        assert!(!update(&db, id, &input, user).await.unwrap());
    }
}
