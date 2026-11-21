//! Własne sygnatury dodane przez użytkowników (treść YAML).

use super::{new_id, now, Db};
use anyhow::Result;
use serde::Serialize;

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct SignatureRow {
    pub id: String,
    pub name: String,
    pub yaml: String,
    pub enabled: i64,
    pub created_by: String,
    pub created_at: String,
}

pub async fn list_signatures(db: &Db) -> Result<Vec<SignatureRow>> {
    let rows = sqlx::query_as::<_, SignatureRow>("SELECT * FROM signatures ORDER BY name")
        .fetch_all(db)
        .await?;
    Ok(rows)
}

pub async fn insert_signature(db: &Db, name: &str, yaml: &str, user: &str) -> Result<String> {
    let id = new_id();
    sqlx::query(
        "INSERT INTO signatures (id, name, yaml, enabled, created_by, created_at)
         VALUES (?, ?, ?, 1, ?, ?)",
    )
    .bind(&id)
    .bind(name)
    .bind(yaml)
    .bind(user)
    .bind(now())
    .execute(db)
    .await?;
    Ok(id)
}

pub async fn delete_signature(db: &Db, id: &str) -> Result<bool> {
    let res = sqlx::query("DELETE FROM signatures WHERE id = ?").bind(id).execute(db).await?;
    Ok(res.rows_affected() > 0)
}
