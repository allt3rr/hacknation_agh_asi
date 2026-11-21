//! Pełny przebieg skanu:
//!
//! 1. rozwinięcie celów (adresy zaległe z przerwanego skanu idą na początek),
//! 2. skan nmap i sondy HTTP,
//! 3. ponowny pomiar hostów, które nie odpowiedziały (hosty niestabilne),
//! 4. zapis, porównanie z poprzednim stanem, aktualizacja stanu hostów.
//!
//! Import wyników z pliku korzysta z tych samych kroków zapisu i porównania (`ingest`).

use crate::db;
use crate::defectdojo;
use crate::diff::{self, Change};
use crate::input;
use crate::model::Observation;
use crate::scanner::{ScanReport, Scanner};
use crate::state::AppState;
use anyhow::{anyhow, Result};
use serde_json::{json, Value};
use std::collections::HashSet;
use tokio::time::Instant;

struct ScanOutcome {
    stats: Value,
    pending: Vec<String>,
    observations: Vec<Observation>,
    changes: Vec<Change>,
}

pub async fn execute_scan(st: &AppState, deadline: Option<Instant>, source: &str) -> Result<String> {
    let _guard = st.scan_lock.try_lock().map_err(|_| anyhow!("Skan już trwa"))?;

    let targets = build_target_list(st).await?;
    let run_id = db::create_run(&st.db, source).await?;
    let started = std::time::Instant::now();

    let outcome = scan_and_ingest(st, &run_id, targets, deadline).await;
    let duration = started.elapsed().as_secs_f64();

    match outcome {
        Ok(ScanOutcome { mut stats, pending, observations, changes }) => {
            let status = if pending.is_empty() { "completed" } else { "partial" };
            stats["duration_secs"] = json!(duration);
            db::finish_run(&st.db, &run_id, status, duration, &stats, &pending).await?;
            tracing::info!(%run_id, status, duration_secs = duration, "skan zakończony");
            if let Some(dd) = &st.cfg.defectdojo {
                // błąd wysyłki nie psuje skanu; można ponowić przyciskiem na stronie Skany
                match defectdojo::push(dd, &run_id, &observations, &changes).await {
                    Ok(_) => tracing::info!(%run_id, "wysłano do DefectDojo"),
                    Err(error) => tracing::warn!(%run_id, %error, "wysyłka do DefectDojo nieudana"),
                }
            }
            Ok(run_id)
        }
        Err(error) => {
            let stats = json!({ "error": error.to_string() });
            db::finish_run(&st.db, &run_id, "failed", duration, &stats, &[]).await?;
            Err(error)
        }
    }
}

/// Import wyników skanu (JSON/CSV). Dane są przetwarzane tak samo jak wynik skanera.
pub async fn import_results(st: &AppState, mut observations: Vec<Observation>, source: &str) -> Result<String> {
    let _guard = st
        .scan_lock
        .try_lock()
        .map_err(|_| anyhow!("Trwa skan. Spróbuj ponownie po jego zakończeniu."))?;

    apply_signatures(st, &mut observations).await;
    let live: HashSet<String> = observations.iter().map(|obs| obs.ip.clone()).collect();

    let run_id = db::create_run(&st.db, source).await?;
    let started = std::time::Instant::now();
    let changes = ingest(st, &run_id, &observations, &live, &live).await?;
    let duration = started.elapsed().as_secs_f64();

    let stats = json!({
        "imported": observations.len(),
        "live_hosts": live.len(),
        "services": observations.len(),
        "changes": changes.len(),
    });
    db::finish_run(&st.db, &run_id, "completed", duration, &stats, &[]).await?;
    Ok(run_id)
}

/// Zapis obserwacji, porównanie z ostatnim znanym stanem i aktualizacja stanu hostów.
pub async fn ingest(
    st: &AppState,
    run_id: &str,
    observations: &[Observation],
    live: &HashSet<String>,
    scanned: &HashSet<String>,
) -> Result<Vec<Change>> {
    // Punkt odniesienia trzeba wczytać przed aktualizacją host_state.
    let baseline = db::load_baseline(&st.db, &st.crypto).await?;
    let mut changes = diff::diff(&baseline, observations, live);

    db::insert_observations(&st.db, &st.crypto, run_id, observations).await?;

    let threshold = st.cfg.scan.inactive_after_misses;
    let host_changes = db::update_host_states(&st.db, run_id, live, scanned, threshold).await?;
    changes.extend(host_changes);

    db::insert_changes(&st.db, &st.crypto, run_id, &changes).await?;
    Ok(changes)
}

async fn build_target_list(st: &AppState) -> Result<Vec<String>> {
    let targets = db::enabled_targets(&st.db).await?;
    let mut list = input::expand(&targets, st.cfg.scan.max_targets)?;

    let pending: HashSet<String> = db::latest_pending(&st.db).await?.into_iter().collect();
    if !pending.is_empty() {
        tracing::info!(count = pending.len(), "wznawiam przerwany skan");
        // sort stabilny: najpierw zaległe adresy, potem reszta w dotychczasowej kolejności
        list.sort_by_key(|target| !pending.contains(target));
    }
    Ok(list)
}

async fn scan_and_ingest(
    st: &AppState,
    run_id: &str,
    targets: Vec<String>,
    deadline: Option<Instant>,
) -> Result<ScanOutcome> {
    let total = targets.len();
    let signatures = st.signatures.read().await.clone();
    let scanner = Scanner::new(&st.cfg.scan, signatures)?;

    let mut report = scanner.run(targets, deadline).await?;
    if st.cfg.scan.recheck_missing {
        recheck_missing_hosts(st, &scanner, &mut report, deadline).await?;
    }

    let changes = ingest(st, run_id, &report.observations, &report.live_hosts, &report.scanned).await?;

    let stats = json!({
        "targets": total,
        "scanned": report.scanned.len(),
        "live_hosts": report.live_hosts.len(),
        "services": report.observations.len(),
        "pending": report.pending.len(),
        "failed": report.failed.len(),
        "changes": changes.len(),
        "chunks": report.chunks,
    });
    Ok(ScanOutcome { stats, pending: report.pending, observations: report.observations, changes })
}

/// Hosty, które powinny żyć, a nie odpowiedziały, skanujemy drugi raz.
async fn recheck_missing_hosts(
    st: &AppState,
    scanner: &Scanner,
    report: &mut ScanReport,
    deadline: Option<Instant>,
) -> Result<()> {
    let time_left = deadline.map_or(true, |d| Instant::now() < d);
    if !time_left {
        return Ok(());
    }

    let missing: Vec<String> = db::hosts_expected_alive(&st.db)
        .await?
        .into_iter()
        .filter(|ip| report.scanned.contains(ip) && !report.live_hosts.contains(ip))
        .collect();
    if missing.is_empty() {
        return Ok(());
    }

    tracing::info!(count = missing.len(), "ponowny pomiar hostów, które nie odpowiedziały");
    let second = scanner.run(missing, deadline).await?;
    report.merge(second);
    Ok(())
}

async fn apply_signatures(st: &AppState, observations: &mut [Observation]) {
    let signatures = st.signatures.read().await;
    for obs in observations.iter_mut().filter(|obs| obs.detections.is_empty()) {
        obs.detections = signatures.evaluate(obs);
    }
}
