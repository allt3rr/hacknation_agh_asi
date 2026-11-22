//! Dziennik audytu. Nigdy nie zapisuj tu haseł ani tokenów.

use anyhow::Result;
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

pub struct Entry<'a> {
    pub user_id: Option<Uuid>,
    pub username: Option<&'a str>,
    pub action: &'a str,
    pub entity: Option<&'a str>,
    pub entity_id: Option<String>,
    pub ip: Option<String>,
    pub details: Value,
}

pub async fn record<'c>(db: impl sqlx::PgExecutor<'c>, entry: Entry<'_>) -> Result<()> {
    sqlx::query("INSERT INTO audit_log (user_id, username, action, entity, entity_id, ip, details) VALUES ($1, $2, $3, $4, $5, $6::inet, $7)")
        .bind(entry.user_id)
        .bind(entry.username)
        .bind(entry.action)
        .bind(entry.entity)
        .bind(entry.entity_id)
        .bind(entry.ip)
        .bind(entry.details)
        .execute(db)
        .await?;
    Ok(())
}

#[derive(Debug, serde::Serialize, sqlx::FromRow)]
pub struct AuditRow {
    pub id: i64,
    pub user_id: Option<Uuid>,
    pub username: Option<String>,
    pub action: String,
    pub entity: Option<String>,
    pub entity_id: Option<String>,
    pub details: Value,
    pub ip: Option<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub at: time::OffsetDateTime,
}

/// Najnowsze wpisy; `before` = id, od którego (wyłącznie) czytać starsze.
pub async fn list(db: &PgPool, limit: i64, before: Option<i64>) -> Result<Vec<AuditRow>> {
    Ok(sqlx::query_as::<_, AuditRow>(
        "SELECT id, user_id, username, action, entity, entity_id, details, host(ip) AS ip, at
         FROM audit_log WHERE ($2::bigint IS NULL OR id < $2)
         ORDER BY id DESC LIMIT $1",
    )
    .bind(limit)
    .bind(before)
    .fetch_all(db)
    .await?)
}
