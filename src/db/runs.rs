use super::crypto::FieldCrypto;
use super::{new_id, now, Db};
use anyhow::Result;
use serde::Serialize;
use serde_json::Value;

/// Statusy przebiegu: running, completed, partial (przerwany na końcu okna), aborted, failed.
#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct RunRow {
    pub id: String,
    pub source: String,
    pub status: String,
    pub started_at: String,
    pub finished_at: Option<String>,
    pub duration_secs: Option<f64>,
    pub stats_json: Option<String>,
    #[serde(skip_serializing)]
    pub pending_json: Option<String>,
    #[serde(skip_serializing)]
    pub note_enc: Option<String>,
    /// Odszyfrowana notatka analityka (wypełniana w `list_runs`).
    #[sqlx(skip)]
    pub note: Option<String>,
}

pub async fn create_run(db: &Db, source: &str) -> Result<String> {
    let id = new_id();
    sqlx::query("INSERT INTO scan_runs (id, source, status, started_at) VALUES (?, ?, 'running', ?)")
        .bind(&id)
        .bind(source)
        .bind(now())
        .execute(db)
        .await?;
    Ok(id)
}

pub async fn finish_run(
    db: &Db,
    id: &str,
    status: &str,
    duration_secs: f64,
    stats: &Value,
    pending: &[String],
) -> Result<()> {
    sqlx::query(
        "UPDATE scan_runs
         SET status = ?, finished_at = ?, duration_secs = ?, stats_json = ?, pending_json = ?
         WHERE id = ?",
    )
    .bind(status)
    .bind(now())
    .bind(duration_secs)
    .bind(stats.to_string())
    .bind(serde_json::to_string(pending)?)
    .bind(id)
    .execute(db)
    .await?;
    Ok(())
}

pub async fn list_runs(db: &Db, crypto: &FieldCrypto, limit: i64) -> Result<Vec<RunRow>> {
    let mut runs = sqlx::query_as::<_, RunRow>("SELECT * FROM scan_runs ORDER BY started_at DESC LIMIT ?")
        .bind(limit)
        .fetch_all(db)
        .await?;
    for run in &mut runs {
        run.note = crypto.decrypt_opt(run.note_enc.as_deref())?;
    }
    Ok(runs)
}

/// Notatkę można zmieniać niezależnie od stanu skanu.
pub async fn update_run_note(db: &Db, crypto: &FieldCrypto, id: &str, note: Option<&str>) -> Result<bool> {
    let res = sqlx::query("UPDATE scan_runs SET note_enc = ? WHERE id = ?")
        .bind(crypto.encrypt_opt(note)?)
        .bind(id)
        .execute(db)
        .await?;
    Ok(res.rows_affected() > 0)
}

pub async fn latest_finished_run(db: &Db) -> Result<Option<RunRow>> {
    let run = sqlx::query_as::<_, RunRow>(
        "SELECT * FROM scan_runs
         WHERE status IN ('completed', 'partial')
         ORDER BY started_at DESC
         LIMIT 1",
    )
    .fetch_optional(db)
    .await?;
    Ok(run)
}

/// Adresy, których nie zdążono zeskanować w ostatnim przebiegu (status `partial`).
pub async fn latest_pending(db: &Db) -> Result<Vec<String>> {
    let row: Option<(String, Option<String>)> = sqlx::query_as(
        "SELECT status, pending_json FROM scan_runs
         WHERE status != 'running'
         ORDER BY started_at DESC
         LIMIT 1",
    )
    .fetch_optional(db)
    .await?;

    let pending = match row {
        Some((status, Some(json))) if status == "partial" => serde_json::from_str(&json).unwrap_or_default(),
        _ => Vec::new(),
    };
    Ok(pending)
}
