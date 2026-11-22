//! Odczyt wyników: strony obserwacji i zmian z pełną liczbą oraz dashboard liczony w SQL.

use anyhow::Result;
use asi_core::model::Observation;
use asi_crypto::{aad, FieldCrypto};
use serde::Serialize;
use serde_json::{json, Value};
use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

pub fn decrypt_observation(crypto: &FieldCrypto, id: Uuid, data: &[u8]) -> Result<Observation> {
    let plain = crypto.decrypt(&aad("observations", "data_enc", id), data)?;
    Ok(serde_json::from_slice(&plain)?)
}

/// Strona obserwacji przebiegu (deszyfrowane tylko elementy strony) i liczba wszystkich.
pub async fn observations_page(
    db: &PgPool,
    crypto: &FieldCrypto,
    run_id: Uuid,
    ip: Option<&str>,
    limit: i64,
    offset: i64,
) -> Result<(i64, Vec<(Uuid, Observation)>)> {
    let total: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM observations WHERE run_id = $1 AND ($2::inet IS NULL OR ip = $2::inet)",
    )
    .bind(run_id)
    .bind(ip)
    .fetch_one(db)
    .await?;
    let rows: Vec<(Uuid, Vec<u8>)> = sqlx::query_as(
        "SELECT id, data_enc FROM observations WHERE run_id = $1 AND ($2::inet IS NULL OR ip = $2::inet)
         ORDER BY ip, port, proto LIMIT $3 OFFSET $4",
    )
    .bind(run_id)
    .bind(ip)
    .bind(limit)
    .bind(offset)
    .fetch_all(db)
    .await?;
    let items = rows
        .into_iter()
        .map(|(id, data)| Ok((id, decrypt_observation(crypto, id, &data)?)))
        .collect::<Result<_>>()?;
    Ok((total, items))
}

/// Pełna (nieredagowana) obserwacja — tylko dla odsłonięcia z uprawnieniem `results.reveal`.
pub async fn observation(
    db: &PgPool,
    crypto: &FieldCrypto,
    id: Uuid,
) -> Result<Option<(Uuid, Observation)>> {
    let row: Option<(Uuid, Vec<u8>)> =
        sqlx::query_as("SELECT run_id, data_enc FROM observations WHERE id = $1")
            .bind(id)
            .fetch_optional(db)
            .await?;
    row.map(|(run, data)| Ok((run, decrypt_observation(crypto, id, &data)?)))
        .transpose()
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct ChangeRow {
    pub id: i64,
    pub kind: String,
    pub entity_key: String,
    pub ip: String,
    pub field: Option<String>,
    pub before: Option<String>,
    pub after: Option<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

pub async fn changes_page(
    db: &PgPool,
    run_id: Uuid,
    kind: Option<&str>,
    limit: i64,
    offset: i64,
) -> Result<(i64, Vec<ChangeRow>)> {
    let total: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM changes WHERE run_id = $1 AND ($2::text IS NULL OR kind = $2)",
    )
    .bind(run_id)
    .bind(kind)
    .fetch_one(db)
    .await?;
    let items = sqlx::query_as::<_, ChangeRow>(
        "SELECT id, kind, entity_key, host(ip) AS ip, field, before, after, created_at FROM changes
         WHERE run_id = $1 AND ($2::text IS NULL OR kind = $2) ORDER BY entity_key, kind LIMIT $3 OFFSET $4",
    )
    .bind(run_id)
    .bind(kind)
    .bind(limit)
    .bind(offset)
    .fetch_all(db)
    .await?;
    Ok((total, items))
}

/// Kategorie znalezisk pokazywanych na dashboardzie jako „ciekawe”.
pub const NOTABLE_CATEGORIES: &[&str] = &["admin_panel", "staging", "interesting"];

/// Dashboard bez deszyfrowania: wszystko z kolumn jawnych i `detections`.
pub async fn dashboard(db: &PgPool) -> Result<Value> {
    let targets: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM targets")
        .fetch_one(db)
        .await?;
    let assets: Vec<(String, i64)> =
        sqlx::query_as("SELECT state, COUNT(*) FROM assets GROUP BY state ORDER BY state")
            .fetch_all(db)
            .await?;
    let latest: Option<crate::runs::RunView> = sqlx::query_as(
        "SELECT id, kind, status, reason, coverage, started_at, finished_at, duration_ms, hosts_total, hosts_done,
                triggered_by, created_at
         FROM scan_runs WHERE status IN ('done', 'partial') ORDER BY finished_at DESC NULLS LAST LIMIT 1",
    )
    .fetch_optional(db)
    .await?;
    let running: bool =
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM scan_runs WHERE status = 'running')")
            .fetch_one(db)
            .await?;

    let Some(run) = latest else {
        return Ok(
            json!({ "targets": targets, "assets": assets_map(assets), "latest_run": null, "scan_running": running,
                          "services": 0, "changes_total": 0, "technologies": [], "notable": [], "recent_changes": [] }),
        );
    };
    let services: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM observations WHERE run_id = $1")
        .bind(run.id)
        .fetch_one(db)
        .await?;
    let technologies: Vec<(String, String, i64)> = sqlx::query_as(
        "SELECT d->>'name', d->>'category', COUNT(*) FROM observations o, jsonb_array_elements(o.detections) d
         WHERE o.run_id = $1 GROUP BY 1, 2 ORDER BY 3 DESC, 1 LIMIT 15",
    )
    .bind(run.id)
    .fetch_all(db)
    .await?;
    let notable: Vec<(String, i32, String, String, Option<String>, i64)> = sqlx::query_as(
        "SELECT host(o.ip), o.port, d->>'name', d->>'category', o.http_title, (d->>'confidence')::bigint
         FROM observations o, jsonb_array_elements(o.detections) d
         WHERE o.run_id = $1 AND d->>'category' = ANY($2) ORDER BY 6 DESC, 1, 2 LIMIT 50",
    )
    .bind(run.id)
    .bind(NOTABLE_CATEGORIES)
    .fetch_all(db)
    .await?;
    let (changes_total, recent) = changes_page(db, run.id, None, 20, 0).await?;
    Ok(json!({
        "targets": targets,
        "assets": assets_map(assets),
        "latest_run": run,
        "scan_running": running,
        "services": services,
        "changes_total": changes_total,
        "technologies": technologies.into_iter().map(|(n, c, k)| json!({ "name": n, "category": c, "services": k })).collect::<Vec<_>>(),
        "notable": notable.into_iter().map(|(ip, port, n, c, t, conf)| json!({
            "ip": ip, "port": port, "name": n, "category": c, "title": t, "confidence": conf })).collect::<Vec<_>>(),
        "recent_changes": recent,
    }))
}

fn assets_map(rows: Vec<(String, i64)>) -> Value {
    Value::Object(rows.into_iter().map(|(k, v)| (k, json!(v))).collect())
}
