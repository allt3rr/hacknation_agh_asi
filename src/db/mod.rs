//! Warstwa danych: SQLite przez sqlx.
//! Kolumny z sufiksem `_enc` są szyfrowane po stronie aplikacji (patrz `crypto.rs`).

pub mod crypto;

mod annotations;
mod changes;
mod hosts;
mod observations;
mod runs;
mod signatures;
mod targets;
mod users;

pub use annotations::*;
pub use changes::*;
pub use hosts::*;
pub use observations::*;
pub use runs::*;
pub use signatures::*;
pub use targets::*;
pub use users::*;

use anyhow::Result;
use chrono::Utc;
use serde_json::{json, Value};
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions};
use sqlx::SqlitePool;
use std::collections::HashMap;
use std::path::Path;
use std::str::FromStr;

pub type Db = SqlitePool;

pub async fn connect(url: &str) -> Result<Db> {
    create_parent_dir(url)?;

    let options = SqliteConnectOptions::from_str(url)?
        .create_if_missing(true)
        .foreign_keys(true)
        .journal_mode(SqliteJournalMode::Wal);
    let pool = SqlitePoolOptions::new().max_connections(8).connect_with(options).await?;

    sqlx::migrate!("./migrations").run(&pool).await?;
    mark_interrupted_runs(&pool).await?;
    Ok(pool)
}

/// Liczniki do dashboardu.
pub async fn counts(db: &Db) -> Result<Value> {
    let targets: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM targets").fetch_one(db).await?;
    let hosts: Vec<(String, i64)> = sqlx::query_as("SELECT status, COUNT(*) FROM host_state GROUP BY status")
        .fetch_all(db)
        .await?;
    let hosts: HashMap<String, i64> = hosts.into_iter().collect();
    Ok(json!({ "targets": targets, "hosts": hosts }))
}

fn create_parent_dir(url: &str) -> Result<()> {
    let Some(path) = url.strip_prefix("sqlite://").or_else(|| url.strip_prefix("sqlite:")) else {
        return Ok(());
    };
    if let Some(parent) = Path::new(path).parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    Ok(())
}

/// Skany, które trwały w chwili restartu aplikacji, oznaczamy jako przerwane.
async fn mark_interrupted_runs(db: &Db) -> Result<()> {
    sqlx::query("UPDATE scan_runs SET status = 'aborted' WHERE status = 'running'")
        .execute(db)
        .await?;
    Ok(())
}

fn now() -> String {
    Utc::now().to_rfc3339()
}

fn new_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

fn join_tags(tags: &[String]) -> String {
    tags.iter()
        .map(|t| t.trim())
        .filter(|t| !t.is_empty())
        .collect::<Vec<_>>()
        .join(",")
}
