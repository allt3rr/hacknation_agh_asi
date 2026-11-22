//! Podatności przebiegu: stan sprawdzania (atomowe przejścia), zapis i odczyt podatności, cache CVE.

use anyhow::Result;
use asi_core::vuln::Vulnerability;
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

/// Wynik próby zmiany stanu sprawdzania.
#[derive(Debug, PartialEq, Eq)]
pub enum Transition {
    Done,
    /// Sprawdzanie już trwa.
    Busy,
    /// Przebieg nie jest opublikowany (trwa albo się nie udał).
    NotPublished,
    NotFound,
}

/// Opublikowany przebieg = `done` albo `partial` (wynik zapisany).
const PUBLISHED: &str = "status IN ('done', 'partial')";

async fn classify(db: &PgPool, run_id: Uuid) -> Result<Transition> {
    let row: Option<(String, String)> =
        sqlx::query_as("SELECT status, vuln_state FROM scan_runs WHERE id = $1")
            .bind(run_id)
            .fetch_optional(db)
            .await?;
    Ok(match row {
        None => Transition::NotFound,
        Some((_, v)) if v == "running" => Transition::Busy,
        Some(_) => Transition::NotPublished,
    })
}

/// `running`, o ile przebieg jest opublikowany i sprawdzanie nie trwa (jedno naraz na przebieg).
pub async fn begin(db: &PgPool, run_id: Uuid) -> Result<Transition> {
    let updated = sqlx::query(&format!(
        "UPDATE scan_runs SET vuln_state = 'running', vuln_reason = NULL
         WHERE id = $1 AND {PUBLISHED} AND vuln_state <> 'running'"
    ))
    .bind(run_id)
    .execute(db)
    .await?;
    if updated.rows_affected() == 1 {
        return Ok(Transition::Done);
    }
    classify(db, run_id).await
}

/// `skipped` (odrzucenie decyzji), o ile przebieg jest opublikowany i sprawdzanie nie trwa.
pub async fn skip(db: &PgPool, run_id: Uuid) -> Result<Transition> {
    let updated = sqlx::query(&format!(
        "UPDATE scan_runs SET vuln_state = 'skipped', vuln_reason = NULL
         WHERE id = $1 AND {PUBLISHED} AND vuln_state <> 'running'"
    ))
    .bind(run_id)
    .execute(db)
    .await?;
    if updated.rows_affected() == 1 {
        return Ok(Transition::Done);
    }
    classify(db, run_id).await
}

/// Stan po publikacji (`pending_decision` albo `none`); nie nadpisuje trwającego sprawdzania.
pub async fn set_initial(db: &PgPool, run_id: Uuid, state: &str) -> Result<()> {
    sqlx::query("UPDATE scan_runs SET vuln_state = $2 WHERE id = $1 AND vuln_state <> 'running'")
        .bind(run_id)
        .bind(state)
        .execute(db)
        .await?;
    Ok(())
}

/// Koniec sprawdzania: `done` albo `failed` z powodem i podsumowaniem.
pub async fn finish(
    db: &PgPool,
    run_id: Uuid,
    state: &str,
    reason: Option<&str>,
    summary: &Value,
) -> Result<()> {
    sqlx::query(
        "UPDATE scan_runs SET vuln_state = $2, vuln_reason = $3, vuln_summary = $4 WHERE id = $1",
    )
    .bind(run_id)
    .bind(state)
    .bind(reason)
    .bind(summary)
    .execute(db)
    .await?;
    Ok(())
}

/// Po restarcie procesu żadne sprawdzanie nie trwa: `running` → `failed`.
pub async fn recover_orphans(db: &PgPool) -> Result<u64> {
    let res = sqlx::query(
        "UPDATE scan_runs SET vuln_state = 'failed', vuln_reason = 'przerwane (restart procesu)'
         WHERE vuln_state = 'running'",
    )
    .execute(db)
    .await?;
    Ok(res.rows_affected())
}

/// Zastępuje podatności przebiegu (ponowne sprawdzanie daje pełny nowy wynik).
pub async fn replace(db: &PgPool, run_id: Uuid, items: &[Vulnerability]) -> Result<()> {
    let mut tx = db.begin().await?;
    sqlx::query("DELETE FROM vulnerabilities WHERE run_id = $1")
        .bind(run_id)
        .execute(&mut *tx)
        .await?;
    for v in items {
        sqlx::query(
            "INSERT INTO vulnerabilities (run_id, ip, port, proto, cve_id, cvss_score, cvss_vector,
                 severity, evidence, component, version, description, published)
             VALUES ($1, $2::inet, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
             ON CONFLICT (run_id, ip, port, proto, cve_id) DO NOTHING",
        )
        .bind(run_id)
        .bind(&v.ip)
        .bind(i32::from(v.port))
        .bind(&v.proto)
        .bind(&v.cve_id)
        .bind(v.cvss_score)
        .bind(&v.cvss_vector)
        .bind(&v.severity)
        .bind(&v.evidence)
        .bind(&v.component)
        .bind(&v.version)
        .bind(&v.description)
        .bind(&v.published)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(())
}

/// Zapisuje podatności potwierdzone sondą (`evidence = confirmed`). Wynik NVD dla tej usługi
/// i CVE zostaje (ocena i opis NVD mają pierwszeństwo), podnoszony jest tylko dowód; CVE spoza
/// wyniku NVD jest dodawane z oceną z szablonu. Zwraca liczbę potwierdzonych.
pub async fn confirm(db: &PgPool, run_id: Uuid, hits: &[Vulnerability]) -> Result<u64> {
    let mut tx = db.begin().await?;
    let mut n = 0;
    for v in hits {
        n += sqlx::query(
            "INSERT INTO vulnerabilities (run_id, ip, port, proto, cve_id, cvss_score, cvss_vector,
                 severity, evidence, component, version, description, published)
             VALUES ($1, $2::inet, $3, $4, $5, $6, $7, $8, 'confirmed', $9, $10, $11, $12)
             ON CONFLICT (run_id, ip, port, proto, cve_id) DO UPDATE SET evidence = 'confirmed'",
        )
        .bind(run_id)
        .bind(&v.ip)
        .bind(i32::from(v.port))
        .bind(&v.proto)
        .bind(&v.cve_id)
        .bind(v.cvss_score)
        .bind(&v.cvss_vector)
        .bind(&v.severity)
        .bind(&v.component)
        .bind(&v.version)
        .bind(&v.description)
        .bind(&v.published)
        .execute(&mut *tx)
        .await?
        .rows_affected();
    }
    tx.commit().await?;
    Ok(n)
}

type Row = (
    String,
    i32,
    String,
    String,
    Option<f64>,
    Option<String>,
    String,
    String,
    String,
    String,
    String,
    Option<String>,
);

/// Podatności przebiegu: najpierw najpewniejsze (potwierdzone, dokładna wersja), w nich
/// najgroźniejsze. Filtry: severity, IP.
pub async fn list(
    db: &PgPool,
    run_id: Uuid,
    severity: Option<&str>,
    ip: Option<&str>,
) -> Result<Vec<Vulnerability>> {
    let rows: Vec<Row> = sqlx::query_as(
        "SELECT host(ip), port, proto, cve_id, cvss_score, cvss_vector, severity, evidence,
                component, version, description, published
         FROM vulnerabilities
         WHERE run_id = $1 AND ($2::text IS NULL OR severity = $2) AND ($3::inet IS NULL OR ip = $3::inet)
         ORDER BY CASE evidence WHEN 'confirmed' THEN 0 WHEN 'version_match' THEN 1
                                WHEN 'version_backport' THEN 2 ELSE 3 END,
                  cvss_score DESC NULLS LAST, ip, port, cve_id",
    )
    .bind(run_id)
    .bind(severity)
    .bind(ip)
    .fetch_all(db)
    .await?;
    Ok(rows
        .into_iter()
        .map(|r| Vulnerability {
            ip: r.0,
            port: u16::try_from(r.1).unwrap_or_default(),
            proto: r.2,
            cve_id: r.3,
            cvss_score: r.4,
            cvss_vector: r.5,
            severity: r.6,
            evidence: r.7,
            component: r.8,
            version: r.9,
            description: r.10,
            published: r.11,
        })
        .collect())
}

/// Wpis cache CVE dla CPE, jeśli młodszy niż `max_age_hours`.
pub async fn cache_get(db: &PgPool, cpe: &str, max_age_hours: i64) -> Result<Option<Value>> {
    Ok(sqlx::query_scalar(
        "SELECT payload FROM cve_cache
         WHERE cpe = $1 AND fetched_at > now() - make_interval(hours => $2::int)",
    )
    .bind(cpe)
    .bind(max_age_hours as i32)
    .fetch_optional(db)
    .await?)
}

pub async fn cache_put(db: &PgPool, cpe: &str, payload: &Value) -> Result<()> {
    sqlx::query(
        "INSERT INTO cve_cache (cpe, payload) VALUES ($1, $2)
         ON CONFLICT (cpe) DO UPDATE SET payload = EXCLUDED.payload, fetched_at = now()",
    )
    .bind(cpe)
    .bind(payload)
    .execute(db)
    .await?;
    Ok(())
}
