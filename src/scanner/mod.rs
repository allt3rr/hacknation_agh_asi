//! Orkiestracja skanu.
//!
//! - Cele trafiają do wspólnej kolejki, z której kilka workerów pobiera podgrupy
//!   i dla każdej uruchamia osobny proces nmap.
//! - Rozmiar podgrupy dopasowuje się do zmierzonej szybkości skanu (`target_chunk_secs`).
//! - Po upływie terminu (koniec okna czasowego) trwające procesy są zabijane,
//!   a niezeskanowane cele trafiają do `ScanReport::pending`.
//! - Na końcu wykryte usługi HTTP są sondowane i dopasowywane do sygnatur.

pub mod http;
pub mod nmap;

use crate::config::ScanConfig;
use crate::fingerprint::SignatureSet;
use crate::model::Observation;
use anyhow::Result;
use serde::Serialize;
use std::collections::{HashSet, VecDeque};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio::time::Instant;

/// Statystyka jednej podgrupy, zapisywana w wynikach przebiegu.
#[derive(Debug, Clone, Serialize)]
pub struct ChunkStat {
    pub size: usize,
    pub secs: f64,
    pub live: usize,
    pub ok: bool,
}

#[derive(Debug, Default)]
pub struct ScanReport {
    pub live_hosts: HashSet<String>,
    /// Cele, dla których nmap zakończył pracę (niezależnie od tego, czy odpowiedziały).
    pub scanned: HashSet<String>,
    pub observations: Vec<Observation>,
    /// Cele niezeskanowane przed upływem terminu. Zostaną wznowione w kolejnym oknie.
    pub pending: Vec<String>,
    /// Cele z podgrup, w których nmap zakończył się błędem.
    pub failed: Vec<String>,
    pub chunks: Vec<ChunkStat>,
}

impl ScanReport {
    pub fn merge(&mut self, other: ScanReport) {
        self.live_hosts.extend(other.live_hosts);
        self.scanned.extend(other.scanned);
        self.observations.extend(other.observations);
        self.failed.extend(other.failed);
        self.chunks.extend(other.chunks);
    }
}

pub struct Scanner {
    config: ScanConfig,
    nmap: Arc<nmap::NmapOptions>,
    http: Arc<http::HttpProber>,
    signatures: Arc<SignatureSet>,
}

/// Stan współdzielony przez workery jednego skanu.
struct SharedScan {
    queue: Mutex<VecDeque<String>>,
    chunk_size: AtomicUsize,
    report: Mutex<ScanReport>,
}

impl Scanner {
    pub fn new(config: &ScanConfig, signatures: SignatureSet) -> Result<Self> {
        let workers = config.concurrency.max(1) as u32;
        let nmap = nmap::NmapOptions {
            binary: config.nmap_binary.clone(),
            ports: config.ports.clone(),
            top_ports: config.top_ports,
            // Globalny limit pakietów/s dzielimy równo między procesy nmap.
            max_rate: (config.global_max_rate / workers).max(1),
            host_timeout: config.host_timeout.clone(),
            extra_args: config.extra_nmap_args.clone(),
        };
        let http_timeout = Duration::from_secs(config.http_timeout_secs);
        let http = http::HttpProber::new(http_timeout, &config.user_agent)?;

        Ok(Self {
            config: config.clone(),
            nmap: Arc::new(nmap),
            http: Arc::new(http),
            signatures: Arc::new(signatures),
        })
    }

    pub async fn run(&self, targets: Vec<String>, deadline: Option<Instant>) -> Result<ScanReport> {
        tracing::info!(targets = targets.len(), workers = self.config.concurrency, "start skanu nmap");

        let initial_chunk = self.config.chunk_size.clamp(self.config.min_chunk, self.config.max_chunk);
        let shared = Arc::new(SharedScan {
            queue: Mutex::new(targets.into()),
            chunk_size: AtomicUsize::new(initial_chunk),
            report: Mutex::new(ScanReport::default()),
        });

        let mut workers = JoinSet::new();
        for _ in 0..self.config.concurrency.max(1) {
            let shared = shared.clone();
            let nmap = self.nmap.clone();
            let config = self.config.clone();
            workers.spawn(async move { nmap_worker(shared, nmap, config, deadline).await });
        }
        while let Some(result) = workers.join_next().await {
            if let Err(error) = result {
                tracing::error!(error = %error, "worker nmap zakończył się błędem");
            }
        }

        let not_started: Vec<String> = shared.queue.lock().unwrap().drain(..).collect();
        let mut report = std::mem::take(&mut *shared.report.lock().unwrap());
        report.pending.extend(not_started);
        if !report.pending.is_empty() {
            tracing::warn!(pending = report.pending.len(), "skan przerwany po upływie terminu, reszta zostanie wznowiona");
        }

        self.probe_http_services(&mut report.observations, deadline).await;
        for obs in &mut report.observations {
            obs.detections = self.signatures.evaluate(obs);
        }
        Ok(report)
    }

    async fn probe_http_services(&self, observations: &mut [Observation], deadline: Option<Instant>) {
        let extra_paths = if self.config.probe_paths {
            self.signatures.required_paths()
        } else {
            Vec::new()
        };
        let extra_paths = Arc::new(extra_paths);
        let limit = Arc::new(Semaphore::new(self.config.http_concurrency.max(1)));
        let mut probes = JoinSet::new();

        for (index, obs) in observations.iter().enumerate() {
            let Some(url) = http::http_url_for(obs) else {
                continue;
            };
            let prober = self.http.clone();
            let extra_paths = extra_paths.clone();
            let limit = limit.clone();

            probes.spawn(async move {
                let _permit = limit.acquire_owned().await.ok()?;
                if deadline.is_some_and(|d| Instant::now() >= d) {
                    return None;
                }
                match prober.probe(&url, &extra_paths).await {
                    Ok(info) => Some((index, info)),
                    Err(error) => {
                        tracing::debug!(%url, error = %error, "sonda HTTP nieudana");
                        None
                    }
                }
            });
        }

        while let Some(result) = probes.join_next().await {
            if let Ok(Some((index, info))) = result {
                observations[index].http = Some(info);
            }
        }
    }
}

async fn nmap_worker(shared: Arc<SharedScan>, nmap: Arc<nmap::NmapOptions>, config: ScanConfig, deadline: Option<Instant>) {
    loop {
        if deadline.is_some_and(|d| Instant::now() >= d) {
            break;
        }
        let Some(chunk) = take_chunk(&shared) else {
            break;
        };

        let started = Instant::now();
        let result = match deadline {
            Some(d) => tokio::time::timeout_at(d, nmap::run_chunk(&nmap, &chunk)).await.ok(),
            None => Some(nmap::run_chunk(&nmap, &chunk).await),
        };
        let Some(result) = result else {
            // Termin minął w trakcie skanu: nmap został zabity, podgrupa wraca do zaległych.
            shared.report.lock().unwrap().pending.extend(chunk);
            break;
        };
        let secs = started.elapsed().as_secs_f64();

        record_chunk_result(&shared, &chunk, result, secs);
        adjust_chunk_size(&shared, &config, chunk.len(), secs);
        tracing::info!(size = chunk.len(), secs = %format!("{secs:.1}"), "podgrupa zakończona");
    }
}

fn take_chunk(shared: &SharedScan) -> Option<Vec<String>> {
    let mut queue = shared.queue.lock().unwrap();
    let size = shared.chunk_size.load(Ordering::Relaxed).min(queue.len());
    if size == 0 {
        return None;
    }
    Some(queue.drain(..size).collect())
}

fn record_chunk_result(shared: &SharedScan, chunk: &[String], result: Result<nmap::ChunkResult>, secs: f64) {
    let mut report = shared.report.lock().unwrap();
    match result {
        Ok(found) => {
            report.chunks.push(ChunkStat { size: chunk.len(), secs, live: found.live_hosts.len(), ok: true });
            report.scanned.extend(chunk.iter().cloned());
            report.live_hosts.extend(found.live_hosts);
            report.observations.extend(found.observations);
        }
        Err(error) => {
            tracing::error!(error = %error, size = chunk.len(), "podgrupa zakończona błędem");
            report.chunks.push(ChunkStat { size: chunk.len(), secs, live: 0, ok: false });
            report.failed.extend(chunk.iter().cloned());
        }
    }
}

/// Podgrupa szybsza od docelowego czasu rośnie, wolniejsza maleje (najwyżej 2x na krok).
fn adjust_chunk_size(shared: &SharedScan, config: &ScanConfig, last_size: usize, secs: f64) {
    if secs < 1.0 {
        return;
    }
    let factor = (config.target_chunk_secs as f64 / secs).clamp(0.5, 2.0);
    let next = (last_size.max(1) as f64 * factor) as usize;
    shared
        .chunk_size
        .store(next.clamp(config.min_chunk, config.max_chunk), Ordering::Relaxed);
}
