//! Własne sygnatury (tabela `rules`): wersjonowane, wyłączane zamiast usuwania.

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct RuleRow {
    pub slug: String,
    pub version: i32,
    pub yaml: String,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
}

/// Najnowsza wersja każdej sygnatury.
pub async fn list(db: &PgPool) -> Result<Vec<RuleRow>> {
    Ok(sqlx::query_as::<_, RuleRow>(
        "SELECT DISTINCT ON (slug) slug, version, yaml, enabled, created_at FROM rules ORDER BY slug, version DESC",
    )
    .fetch_all(db)
    .await?)
}

/// `false`, gdy sygnatura o tym `slug` już istnieje.
pub async fn create(db: &PgPool, slug: &str, yaml: &str, author: Uuid) -> Result<bool> {
    let res = sqlx::query(
        "INSERT INTO rules (slug, version, yaml, author) SELECT $1, 1, $2, $3
         WHERE NOT EXISTS (SELECT 1 FROM rules WHERE slug = $1)",
    )
    .bind(slug)
    .bind(yaml)
    .bind(author)
    .execute(db)
    .await?;
    Ok(res.rows_affected() == 1)
}

/// Nowa wersja istniejącej sygnatury (włączona). `false`, gdy nie istnieje.
pub async fn new_version(db: &PgPool, slug: &str, yaml: &str, author: Uuid) -> Result<bool> {
    let mut tx = db.begin().await?;
    let current: Option<i32> = sqlx::query_scalar("SELECT MAX(version) FROM rules WHERE slug = $1")
        .bind(slug)
        .fetch_one(&mut *tx)
        .await?;
    let Some(current) = current else {
        return Ok(false);
    };
    sqlx::query("UPDATE rules SET enabled = false WHERE slug = $1")
        .bind(slug)
        .execute(&mut *tx)
        .await?;
    sqlx::query("INSERT INTO rules (slug, version, yaml, author) VALUES ($1, $2, $3, $4)")
        .bind(slug)
        .bind(current + 1)
        .bind(yaml)
        .bind(author)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(true)
}

pub async fn disable(db: &PgPool, slug: &str) -> Result<bool> {
    let res = sqlx::query("UPDATE rules SET enabled = false WHERE slug = $1 AND enabled")
        .bind(slug)
        .execute(db)
        .await?;
    Ok(res.rows_affected() > 0)
}
