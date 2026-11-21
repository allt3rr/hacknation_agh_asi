//! Stan hostów w czasie: `active`, `unstable` (nie odpowiedział, ale jeszcze poniżej progu)
//! oraz `inactive` (brak odpowiedzi w `threshold` kolejnych skanach).

use super::{now, Db};
use crate::diff::{Change, ChangeKind};
use anyhow::Result;
use std::collections::{HashMap, HashSet};

struct KnownHost {
    status: String,
    misses: i64,
}

pub async fn hosts_expected_alive(db: &Db) -> Result<Vec<String>> {
    let ips = sqlx::query_scalar("SELECT ip FROM host_state WHERE status IN ('active', 'unstable')")
        .fetch_all(db)
        .await?;
    Ok(ips)
}

/// Aktualizuje stan hostów po przebiegu i zwraca zmiany na poziomie hostów.
///
/// - `live`: hosty, które odpowiedziały,
/// - `scanned`: cele, które zostały faktycznie zeskanowane (brak odpowiedzi liczy się tylko dla nich).
pub async fn update_host_states(
    db: &Db,
    run_id: &str,
    live: &HashSet<String>,
    scanned: &HashSet<String>,
    threshold: i64,
) -> Result<Vec<Change>> {
    let known = load_known_hosts(db).await?;
    let timestamp = now();
    let mut changes = Vec::new();
    let mut tx = db.begin().await?;

    for ip in live {
        match known.get(ip) {
            None => {
                sqlx::query(
                    "INSERT INTO host_state (ip, status, first_seen_at, last_seen_at, last_seen_run, miss_count)
                     VALUES (?, 'active', ?, ?, ?, 0)",
                )
                .bind(ip.as_str())
                .bind(&timestamp)
                .bind(&timestamp)
                .bind(run_id)
                .execute(&mut *tx)
                .await?;
            }
            Some(host) => {
                if host.status == "inactive" {
                    changes.push(Change::host(
                        ChangeKind::HostReturned,
                        ip,
                        Some("inactive".into()),
                        Some("active".into()),
                    ));
                }
                sqlx::query(
                    "UPDATE host_state
                     SET status = 'active', last_seen_at = ?, last_seen_run = ?, miss_count = 0
                     WHERE ip = ?",
                )
                .bind(&timestamp)
                .bind(run_id)
                .bind(ip.as_str())
                .execute(&mut *tx)
                .await?;
            }
        }
    }

    for (ip, host) in &known {
        let missed_this_run = host.status != "inactive" && scanned.contains(ip) && !live.contains(ip);
        if !missed_this_run {
            continue;
        }

        let misses = host.misses + 1;
        let new_status = if misses >= threshold { "inactive" } else { "unstable" };
        if new_status == "inactive" {
            changes.push(Change::host(
                ChangeKind::HostInactive,
                ip,
                Some(host.status.clone()),
                Some(format!("brak odpowiedzi w {misses} kolejnych skanach")),
            ));
        }

        sqlx::query("UPDATE host_state SET status = ?, miss_count = ? WHERE ip = ?")
            .bind(new_status)
            .bind(misses)
            .bind(ip.as_str())
            .execute(&mut *tx)
            .await?;
    }

    tx.commit().await?;
    Ok(changes)
}

async fn load_known_hosts(db: &Db) -> Result<HashMap<String, KnownHost>> {
    let rows: Vec<(String, String, i64)> = sqlx::query_as("SELECT ip, status, miss_count FROM host_state")
        .fetch_all(db)
        .await?;
    let hosts = rows
        .into_iter()
        .map(|(ip, status, misses)| (ip, KnownHost { status, misses }))
        .collect();
    Ok(hosts)
}
