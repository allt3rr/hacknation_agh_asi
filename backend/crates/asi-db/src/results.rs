//! Publikacja wyniku przebiegu w jednej transakcji: obserwacje, porównanie z poprzednim stanem,
//! assety, usługi, dane HTTP, stan hostów, zmiany, zaległe podgrupy i status końcowy.
//! Transakcja jest warunkowana posiadaniem dzierżawy — utracona dzierżawa nic nie zapisuje.

use anyhow::Result;
use asi_core::diff::{self, Change, ChangeKind};
use asi_core::model::Observation;
use asi_crypto::{aad, FieldCrypto};
use serde_json::{json, Value};
use sqlx::{PgConnection, PgPool};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use uuid::Uuid;

pub struct PublishInput<'a> {
    pub observations: &'a [Observation],
    pub live: &'a HashSet<String>,
    /// Wejścia nmap z udanych podgrup (adresy i domeny).
    pub scanned: &'a HashSet<String>,
    /// Domeny rozwiązane przez nmap: (domena, adres).
    pub resolved: &'a [(String, String)],
    pub failed: &'a [(Vec<String>, String)],
    pub pending: &'a [String],
    /// Dotychczasowa liczba nieudanych prób celów wznowionych z poprzedniego przebiegu.
    pub attempts: &'a HashMap<String, i32>,
    pub max_attempts: i32,
    pub inactive_after: i32,
    pub planned: usize,
    pub status: &'a str,
    pub reason: Option<&'a str>,
    pub coverage: Value,
}

#[derive(Debug, PartialEq, Eq)]
pub enum PublishOutcome {
    Published { changes: usize },
    LeaseLost,
}

/// Nazwy i atrybuty ciasteczek bez wartości (wartości trafiają tylko do `cookies_enc`).
pub fn cookie_meta(set_cookie: &str) -> Value {
    serde_json::to_value(asi_core::export::cookie_meta(set_cookie)).unwrap_or(Value::Null)
}

/// Detekcje bez dowodów (dowody mogą cytować treść strony) — do liczników dashboardu.
pub fn detections_json(o: &Observation) -> Value {
    Value::Array(
        o.detections
            .iter()
            .map(|d| json!({ "name": d.name, "category": d.category, "version": d.version, "confidence": d.confidence }))
            .collect(),
    )
}

pub async fn publish(
    db: &PgPool,
    crypto: &FieldCrypto,
    run_id: Uuid,
    owner: &str,
    input: &PublishInput<'_>,
) -> Result<PublishOutcome> {
    let mut tx = db.begin().await?;
    let held: Option<Uuid> = sqlx::query_scalar(
        "SELECT id FROM scan_runs WHERE id = $1 AND lease_owner = $2 AND status = 'running' FOR UPDATE",
    )
    .bind(run_id)
    .bind(owner)
    .fetch_optional(&mut *tx)
    .await?;
    if held.is_none() {
        return Ok(PublishOutcome::LeaseLost);
    }

    let scanned_ips = scanned_addresses(&mut tx, input).await?;
    let baseline = load_baseline(&mut tx, crypto, &scanned_ips).await?;
    let mut changes = diff::diff(&baseline, input.observations, input.live);

    let obs_ids = insert_observations(&mut tx, crypto, run_id, input.observations).await?;
    changes.extend(update_assets(&mut tx, input, &scanned_ips).await?);
    upsert_services(&mut tx, crypto, run_id, input.observations, &obs_ids).await?;
    mark_gone(&mut tx, &changes).await?;
    insert_changes(&mut tx, run_id, &changes).await?;
    insert_chunks(&mut tx, run_id, input).await?;

    sqlx::query(
        "UPDATE scan_runs SET status = $2, reason = $3, coverage = $4, finished_at = now(),
                duration_ms = (EXTRACT(EPOCH FROM now() - started_at) * 1000)::bigint,
                hosts_total = $5, hosts_done = $6, lease_owner = NULL
         WHERE id = $1",
    )
    .bind(run_id)
    .bind(input.status)
    .bind(input.reason)
    .bind(&input.coverage)
    .bind(input.planned as i32)
    .bind(input.scanned.len() as i32)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(PublishOutcome::Published {
        changes: changes.len(),
    })
}

/// Adresy zmierzone w tym przebiegu: IP z udanych podgrup, adresy rozwiązanych domen oraz adresy
/// assetów, które w poprzednich przebiegach należały do zeskanowanych domen.
async fn scanned_addresses(tx: &mut PgConnection, input: &PublishInput<'_>) -> Result<Vec<String>> {
    let mut ips: HashSet<String> = input
        .scanned
        .iter()
        .filter(|t| t.parse::<IpAddr>().is_ok())
        .cloned()
        .collect();
    let domains: Vec<String> = input
        .scanned
        .iter()
        .filter(|t| t.parse::<IpAddr>().is_err())
        .cloned()
        .collect();
    ips.extend(
        input
            .resolved
            .iter()
            .filter(|(d, _)| input.scanned.contains(d))
            .map(|(_, ip)| ip.clone()),
    );
    if !domains.is_empty() {
        let known: Vec<String> =
            sqlx::query_scalar("SELECT host(ip) FROM assets WHERE hostnames && $1")
                .bind(&domains)
                .fetch_all(&mut *tx)
                .await?;
        ips.extend(known);
    }
    Ok(ips.into_iter().collect())
}

async fn load_baseline(
    tx: &mut PgConnection,
    crypto: &FieldCrypto,
    ips: &[String],
) -> Result<Vec<Observation>> {
    let rows: Vec<(Uuid, Vec<u8>)> = sqlx::query_as(
        "SELECT o.id, o.data_enc FROM services s
         JOIN assets a ON a.id = s.asset_id
         JOIN observations o ON o.id = s.last_observation_id
         WHERE host(a.ip) = ANY($1) AND s.state <> 'gone'",
    )
    .bind(ips)
    .fetch_all(&mut *tx)
    .await?;
    rows.into_iter()
        .map(|(id, data)| {
            let plain = crypto.decrypt(&aad("observations", "data_enc", id), &data)?;
            Ok(serde_json::from_slice(&plain)?)
        })
        .collect()
}

async fn insert_observations(
    tx: &mut PgConnection,
    crypto: &FieldCrypto,
    run_id: Uuid,
    obs: &[Observation],
) -> Result<Vec<Uuid>> {
    let ids: Vec<Uuid> = obs.iter().map(|_| Uuid::new_v4()).collect();
    for (o, id) in obs.iter().zip(&ids) {
        let data = crypto.encrypt(
            &aad("observations", "data_enc", id),
            &serde_json::to_vec(o)?,
        )?;
        let technologies: Vec<String> = o.detections.iter().map(|d| d.name.clone()).collect();
        let cookie_names: Vec<String> = o
            .http
            .as_ref()
            .map(|h| h.cookie_names().map(str::to_string).collect())
            .unwrap_or_default();
        sqlx::query(
            "INSERT INTO observations (id, run_id, ip, port, proto, state, service, product, version, hostname,
                                       http_status, http_title, technologies, cookie_names, data_enc, observed_at, detections)
             VALUES ($1, $2, $3::inet, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)",
        )
        .bind(id)
        .bind(run_id)
        .bind(&o.ip)
        .bind(i32::from(o.port))
        .bind(&o.proto)
        .bind(&o.state)
        .bind(&o.service)
        .bind(&o.product)
        .bind(&o.version)
        .bind(&o.hostname)
        .bind(o.http.as_ref().map(|h| i32::from(h.status)))
        .bind(o.http.as_ref().and_then(|h| h.title.clone()))
        .bind(&technologies)
        .bind(&cookie_names)
        .bind(&data)
        .bind(o.seen_at)
        .bind(detections_json(o))
        .execute(&mut *tx)
        .await?;
    }
    Ok(ids)
}

/// Assety odpowiadające → `active`; zmierzone bez odpowiedzi → `unstable`, po N przebiegach `inactive`.
async fn update_assets(
    tx: &mut PgConnection,
    input: &PublishInput<'_>,
    scanned_ips: &[String],
) -> Result<Vec<Change>> {
    let mut changes = Vec::new();
    let mut hostnames: HashMap<&str, HashSet<String>> = HashMap::new();
    for (domain, ip) in input.resolved {
        hostnames
            .entry(ip.as_str())
            .or_default()
            .insert(domain.clone());
    }
    for o in input.observations {
        if let Some(h) = &o.hostname {
            hostnames
                .entry(o.ip.as_str())
                .or_default()
                .insert(h.to_ascii_lowercase());
        }
    }
    for ip in input.live {
        let names: Vec<String> = hostnames
            .get(ip.as_str())
            .map(|s| s.iter().cloned().collect())
            .unwrap_or_default();
        let previous: Option<String> = sqlx::query_scalar(
            "WITH prev AS (SELECT state FROM assets WHERE ip = $1::inet)
             INSERT INTO assets (ip, hostnames) VALUES ($1::inet, $2)
             ON CONFLICT (ip) DO UPDATE SET last_seen = now(), state = 'active', miss_streak = 0,
                 hostnames = ARRAY(SELECT DISTINCT unnest(assets.hostnames || EXCLUDED.hostnames))
             RETURNING (SELECT state FROM prev)",
        )
        .bind(ip)
        .bind(&names)
        .fetch_one(&mut *tx)
        .await?;
        if previous.as_deref() == Some("inactive") {
            changes.push(Change::host(
                ChangeKind::HostReturned,
                ip,
                Some("inactive".into()),
                Some("active".into()),
            ));
        }
    }

    let missing: Vec<&String> = scanned_ips
        .iter()
        .filter(|ip| !input.live.contains(*ip))
        .collect();
    let rows: Vec<(String, String, i32)> = sqlx::query_as(
        "UPDATE assets SET miss_streak = miss_streak + 1,
                state = CASE WHEN miss_streak + 1 >= $2 THEN 'inactive' ELSE 'unstable' END
         WHERE host(ip) = ANY($1) AND state <> 'inactive'
         RETURNING host(ip), state, miss_streak",
    )
    .bind(&missing)
    .bind(input.inactive_after)
    .fetch_all(&mut *tx)
    .await?;
    for (ip, state, misses) in rows {
        if state == "inactive" {
            let after = format!("brak odpowiedzi w {misses} kolejnych przebiegach");
            changes.push(Change::host(
                ChangeKind::HostInactive,
                &ip,
                Some("active".into()),
                Some(after),
            ));
        }
    }
    Ok(changes)
}

async fn upsert_services(
    tx: &mut PgConnection,
    crypto: &FieldCrypto,
    run_id: Uuid,
    obs: &[Observation],
    ids: &[Uuid],
) -> Result<()> {
    for (o, obs_id) in obs.iter().zip(ids) {
        let service_id: Uuid = sqlx::query_scalar(
            "INSERT INTO services (asset_id, run_id, proto, port, state, service, product, version, last_observation_id)
             SELECT id, $2, $3, $4, $5, $6, $7, $8, $9 FROM assets WHERE ip = $1::inet
             ON CONFLICT (asset_id, proto, port) DO UPDATE SET run_id = EXCLUDED.run_id, state = EXCLUDED.state,
                 service = EXCLUDED.service, product = EXCLUDED.product, version = EXCLUDED.version,
                 last_seen = now(), miss_streak = 0, last_observation_id = EXCLUDED.last_observation_id
             RETURNING id",
        )
        .bind(&o.ip)
        .bind(run_id)
        .bind(&o.proto)
        .bind(i32::from(o.port))
        .bind(&o.state)
        .bind(&o.service)
        .bind(&o.product)
        .bind(&o.version)
        .bind(obs_id)
        .fetch_one(&mut *tx)
        .await?;

        let Some(http) = &o.http else { continue };
        let http_id = Uuid::new_v4();
        let headers = crypto.encrypt(
            &aad("http_info", "headers_enc", http_id),
            &serde_json::to_vec(&http.headers)?,
        )?;
        let cookies = (!http.cookies.is_empty())
            .then(|| {
                crypto
                    .encrypt(
                        &aad("http_info", "cookies_enc", http_id),
                        &serde_json::to_vec(&http.cookies).ok()?,
                    )
                    .ok()
            })
            .flatten();
        let meta: Vec<Value> = http.cookies.iter().map(|c| cookie_meta(c)).collect();
        let scheme = if http.url.starts_with("https") {
            "https"
        } else {
            "http"
        };
        sqlx::query(
            "INSERT INTO http_info (id, service_id, run_id, vhost, scheme, status, title, redirects, headers_enc,
                                    cookies_meta, cookies_enc, tls, body_sha256)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, decode($13, 'hex'))",
        )
        .bind(http_id)
        .bind(service_id)
        .bind(run_id)
        .bind(&o.hostname)
        .bind(scheme)
        .bind(i32::from(http.status))
        .bind(&http.title)
        .bind(json!({ "followed": http.redirects, "blocked": http.blocked_redirects }))
        .bind(&headers)
        .bind(Value::Array(meta))
        .bind(&cookies)
        .bind(serde_json::to_value(&http.tls)?)
        .bind(&http.body_sha256)
        .execute(&mut *tx)
        .await?;
    }
    Ok(())
}

async fn mark_gone(tx: &mut PgConnection, changes: &[Change]) -> Result<()> {
    for c in changes.iter().filter(|c| c.kind == ChangeKind::Gone) {
        let Some((port, proto)) = c
            .key
            .rsplit_once(':')
            .and_then(|(_, pp)| pp.split_once('/'))
        else {
            continue;
        };
        sqlx::query(
            "UPDATE services SET state = 'gone' FROM assets a
             WHERE services.asset_id = a.id AND a.ip = $1::inet AND services.port = $2 AND services.proto = $3",
        )
        .bind(&c.ip)
        .bind(port.parse::<i32>().unwrap_or(-1))
        .bind(proto)
        .execute(&mut *tx)
        .await?;
    }
    Ok(())
}

async fn insert_changes(tx: &mut PgConnection, run_id: Uuid, changes: &[Change]) -> Result<()> {
    for c in changes {
        sqlx::query(
            "INSERT INTO changes (run_id, kind, entity_key, ip, field, before, after) VALUES ($1, $2, $3, $4::inet, $5, $6, $7)",
        )
        .bind(run_id)
        .bind(c.kind.as_str())
        .bind(&c.key)
        .bind(&c.ip)
        .bind(&c.field)
        .bind(&c.before)
        .bind(&c.after)
        .execute(&mut *tx)
        .await?;
    }
    Ok(())
}

/// Zaległe podgrupy (`pending`) i nieudane (`failed`, `attempt + 1`); po limicie prób `abandoned`.
async fn insert_chunks(
    tx: &mut PgConnection,
    run_id: Uuid,
    input: &PublishInput<'_>,
) -> Result<()> {
    let prior = |targets: &[String]| {
        targets
            .iter()
            .filter_map(|t| input.attempts.get(t))
            .copied()
            .max()
            .unwrap_or(0)
    };
    if !input.pending.is_empty() {
        sqlx::query("INSERT INTO scan_chunks (run_id, stage, targets, status, attempt) VALUES ($1, 'ports', $2, 'pending', $3)")
            .bind(run_id)
            .bind(input.pending)
            .bind(prior(input.pending))
            .execute(&mut *tx)
            .await?;
    }
    for (targets, error) in input.failed {
        let attempt = prior(targets) + 1;
        let status = if attempt >= input.max_attempts {
            "abandoned"
        } else {
            "failed"
        };
        sqlx::query("INSERT INTO scan_chunks (run_id, stage, targets, status, attempt, error) VALUES ($1, 'ports', $2, $3, $4, $5)")
            .bind(run_id)
            .bind(targets)
            .bind(status)
            .bind(attempt)
            .bind(error)
            .execute(&mut *tx)
            .await?;
    }
    Ok(())
}
