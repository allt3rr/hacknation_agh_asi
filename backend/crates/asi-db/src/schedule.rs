//! Zapisany harmonogram skanów (jeden wiersz JSON). Walidację robi warstwa API.

use anyhow::Result;
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

pub async fn load(db: &PgPool) -> Result<Option<Value>> {
    Ok(sqlx::query_scalar("SELECT value FROM scan_schedule WHERE id")
        .fetch_optional(db)
        .await?)
}

pub async fn save(db: &PgPool, value: &Value, user: Uuid) -> Result<()> {
    sqlx::query(
        "INSERT INTO scan_schedule (id, value, updated_by, updated_at) VALUES (true, $1, $2, now())
         ON CONFLICT (id) DO UPDATE SET value = excluded.value, updated_by = excluded.updated_by, updated_at = now()",
    )
    .bind(value)
    .bind(user)
    .execute(db)
    .await?;
    Ok(())
}
