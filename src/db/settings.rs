//! Ustawienia zapisane z interfejsu (klucz -> JSON).

use super::Db;
use anyhow::Result;

pub async fn load_setting(db: &Db, key: &str) -> Result<Option<String>> {
    let value = sqlx::query_scalar("SELECT value FROM settings WHERE key = ?")
        .bind(key)
        .fetch_optional(db)
        .await?;
    Ok(value)
}

pub async fn save_setting(db: &Db, key: &str, value: &str) -> Result<()> {
    sqlx::query("INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value")
        .bind(key)
        .bind(value)
        .execute(db)
        .await?;
    Ok(())
}
