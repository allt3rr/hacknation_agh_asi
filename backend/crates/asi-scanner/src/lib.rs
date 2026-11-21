//! Orkiestracja skanu:
//! 1. kolejka celów → workery uruchamiają nmap na podgrupach (rozmiar dopasowuje się do czasu),
//! 2. ponowny pomiar hostów, które powinny żyć, a nie odpowiedziały,
//! 3. sondy HTTP pod semaforem, w zakresie (`Scope`) i z limitem odczytu,
//! 4. dopasowanie sygnatur i usunięcie treści stron z pamięci.
//!
//! Wszystkie etapy dzielą jeden termin i token anulowania (`http::Limits`). Praca niewykonana
//! przed terminem trafia do `ScanReport::pending`, nieudane podgrupy do `ScanReport::failed`.

pub mod config;
pub mod http;
pub mod nmap;
pub mod scope;

use anyhow::Result;
use asi_core::model::Observation;
use asi_core::targets::Target;
use asi_fingerprint::SignatureSet;
use config::ScanConfig;
use http::{HttpProber, Limits};
use nmap::{ChunkResult, ChunkRunner};
use scope::{PortSet, Scope};
use serde::Serialize;
use std::collections::{HashSet, VecDeque};
use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio::time::Instant;

pub use tokio_util::sync::CancellationToken;

/// Co skanować: cele (zakres) i kolejka wejść nmap (zaległe najpierw).
#[derive(Debug, Clone, Default)]
pub struct Plan {
    pub targets: Vec<Target>,
    pub queue: Vec<String>,
    /// Adresy, które powinny odpowiadać (stan `active`/`unstable`) — do ponownego pomiaru.
    pub expected_alive: HashSet<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ChunkStat {
    pub size: usize,
    pub secs: f64,
    pub live: usize,
    pub ok: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct FailedChunk {
    pub targets: Vec<String>,
    pub error: String,
}

#[derive(Debug, Default)]
pub struct ScanReport {
    pub planned: usize,
    pub live_hosts: HashSet<String>,
    /// Wejścia nmap z udanych podgrup (adresy lub domeny), niezależnie od odpowiedzi.
    pub scanned: HashSet<String>,
    pub observations: Vec<Observation>,
    /// Niewykonane przed terminem/anulowaniem (podgrupy nmap i adresy z niewykonanymi sondami HTTP).
    pub pending: Vec<String>,
    pub failed: Vec<FailedChunk>,
    pub chunks: Vec<ChunkStat>,
    /// Domeny-cele rozwiązane przez nmap: (domena, adres).
    pub resolved: Vec<(String, String)>,
    pub http_probed: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum RunStatus {
    Done,
    Partial,
    Failed,
    Cancelled,
}

impl RunStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            RunStatus::Done => "done",
            RunStatus::Partial => "partial",
            RunStatus::Failed => "failed",
            RunStatus::Cancelled => "cancelled",
        }
    }
}

impl ScanReport {
    /// `done` = cała zaplanowana praca (także bez odpowiedzi hostów); `failed` = żadna podgrupa
    /// się nie udała mimo prób; `partial` = część zaległa lub nieudana.
    pub fn status(&self, cancelled: bool, deadline_hit: bool) -> (RunStatus, Option<String>) {
        if cancelled {
            return (RunStatus::Cancelled, Some("anulowano".into()));
        }
        let any_ok = self.chunks.iter().any(|c| c.ok);
        if !self.failed.is_empty() && !any_ok {
            return (
                RunStatus::Failed,
                Some(format!(
                    "wszystkie podgrupy nieudane: {}",
                    self.failed[0].error
                )),
            );
        }
        if !self.pending.is_empty() || !self.failed.is_empty() {
            let reason = if deadline_hit && !self.pending.is_empty() {
                "koniec okna czasowego".to_string()
            } else {
                format!("{} podgrup nieudanych", self.failed.len())
            };
            return (RunStatus::Partial, Some(reason));
        }
        (RunStatus::Done, None)
    }

    fn merge(&mut self, other: ScanReport) {
        self.live_hosts.extend(other.live_hosts);
        self.scanned.extend(other.scanned);
        self.observations.extend(other.observations);
        self.pending.extend(other.pending);
        self.failed.extend(other.failed);
        self.chunks.extend(other.chunks);
        self.resolved.extend(other.resolved);
    }
}

pub struct Scanner<R: ChunkRunner> {
    cfg: ScanConfig,
    runner: Arc<R>,
    http: Arc<HttpProber>,
    signatures: Arc<SignatureSet>,
}

struct Shared {
    queue: Mutex<VecDeque<String>>,
    chunk_size: AtomicUsize,
    report: Mutex<ScanReport>,
}

impl<R: ChunkRunner> Scanner<R> {
    pub fn new(cfg: ScanConfig, runner: Arc<R>, signatures: SignatureSet) -> Result<Self> {
        let http = HttpProber::new(Duration::from_secs(cfg.http_timeout_secs), &cfg.user_agent)?;
        Ok(Self {
            cfg,
            runner,
            http: Arc::new(http),
            signatures: Arc::new(signatures),
        })
    }

    pub async fn run(&self, plan: Plan, limits: Limits) -> ScanReport {
        let mut report = self.nmap_phase(plan.queue.clone(), &limits).await;
        report.planned = plan.queue.len();

        if self.cfg.recheck_missing && !limits.expired() {
            let missing: Vec<String> = plan
                .expected_alive
                .iter()
                .filter(|ip| report.scanned.contains(*ip) && !report.live_hosts.contains(*ip))
                .cloned()
                .collect();
            if !missing.is_empty() {
                tracing::info!(
                    count = missing.len(),
                    "ponowny pomiar hostów bez odpowiedzi"
                );
                let mut second = self.nmap_phase(missing, &limits).await;
                // ponowny pomiar nie dodaje zaległości: cel został już zeskanowany raz
                second.pending.clear();
                second.failed.clear();
                report.merge(second);
            }
        }

        let allowed = self
            .cfg
            .ports
            .as_deref()
            .and_then(|p| PortSet::parse(p).ok());
        let mut scope = Scope::new(&plan.targets, allowed);
        for (_, ip) in &report.resolved {
            if let Ok(ip) = ip.parse::<IpAddr>() {
                scope.add_resolved(ip);
            }
        }
        for o in &report.observations {
            if let Ok(ip) = o.ip.parse::<IpAddr>() {
                if o.state == "open" && scope.ip_in_scope(ip) {
                    scope.add_open_port(ip, o.port);
                }
            }
        }
        // obserwacje spoza zakresu (np. błędny wynik nmap) odrzucamy
        report
            .observations
            .retain(|o| o.ip.parse::<IpAddr>().is_ok_and(|ip| scope.ip_in_scope(ip)));

        self.http_phase(&mut report, &scope, &limits).await;
        for o in report.observations.iter_mut().filter(|o| o.http.is_none()) {
            o.detections = self.signatures.evaluate(o);
        }
        report
    }

    async fn nmap_phase(&self, queue: Vec<String>, limits: &Limits) -> ScanReport {
        let initial = self
            .cfg
            .chunk_size
            .clamp(self.cfg.min_chunk, self.cfg.max_chunk);
        let shared = Arc::new(Shared {
            queue: Mutex::new(queue.into()),
            chunk_size: AtomicUsize::new(initial),
            report: Mutex::new(ScanReport::default()),
        });
        let mut workers = JoinSet::new();
        for _ in 0..self.cfg.concurrency.max(1) {
            let (shared, runner, cfg, limits) = (
                shared.clone(),
                self.runner.clone(),
                self.cfg.clone(),
                limits.clone(),
            );
            workers.spawn(async move { nmap_worker(shared, runner, cfg, limits).await });
        }
        while let Some(res) = workers.join_next().await {
            if let Err(e) = res {
                tracing::error!(error = %e, "worker nmap zakończył się błędem");
            }
        }
        let not_started: Vec<String> = shared.queue.lock().unwrap().drain(..).collect();
        let mut report = std::mem::take(&mut *shared.report.lock().unwrap());
        report.pending.extend(not_started);
        report
    }

    async fn http_phase(&self, report: &mut ScanReport, scope: &Scope, limits: &Limits) {
        let paths = Arc::new(if self.cfg.probe_paths {
            self.signatures.required_paths()
        } else {
            Vec::new()
        });
        let permits = Arc::new(Semaphore::new(self.cfg.http_concurrency.max(1)));
        let scope = Arc::new(scope.clone());
        let mut probes = JoinSet::new();

        for (index, obs) in report.observations.iter().enumerate() {
            let Some(url) = http::http_url_for(obs) else {
                continue;
            };
            // usługa z domeny-celu: nagłówek Host = domena
            // shortcut: SNI to nadal adres IP; vhosty HTTPS z SNI w kolejnym etapie
            let host = obs.hostname.clone().filter(|h| scope.is_domain_target(h));
            let (prober, paths, permits, scope, limits) = (
                self.http.clone(),
                paths.clone(),
                permits.clone(),
                scope.clone(),
                limits.clone(),
            );
            probes.spawn(async move {
                let Ok(_permit) = permits.acquire_owned().await else {
                    return (index, Err(anyhow::anyhow!(http::Interrupted)));
                };
                let res = prober
                    .probe(&url, host.as_deref(), &paths, &scope, &limits)
                    .await;
                (index, res)
            });
        }

        let mut pending = HashSet::new();
        while let Some(res) = probes.join_next().await {
            let Ok((index, res)) = res else { continue };
            let obs = &mut report.observations[index];
            match res {
                Ok(info) => {
                    report.http_probed += 1;
                    obs.http = Some(info);
                    obs.detections = self.signatures.evaluate(obs);
                    // treść stron tylko do dopasowania sygnatur — nie trafia do bazy ani dalej
                    if let Some(h) = obs.http.as_mut() {
                        h.body = String::new();
                        h.extra_paths
                            .values_mut()
                            .for_each(|p| p.body = String::new());
                    }
                }
                Err(e) if http::is_interrupted(&e) => {
                    pending.insert(obs.ip.clone());
                }
                Err(e) => {
                    tracing::debug!(ip = %obs.ip, port = obs.port, error = %e, "sonda HTTP nieudana")
                }
            }
        }
        report.pending.extend(pending);
    }
}

async fn nmap_worker<R: ChunkRunner>(
    shared: Arc<Shared>,
    runner: Arc<R>,
    cfg: ScanConfig,
    limits: Limits,
) {
    loop {
        if limits.expired() {
            break;
        }
        let Some(chunk) = take_chunk(&shared) else {
            break;
        };
        let started = Instant::now();
        let run = runner.run(chunk.clone());
        let result = tokio::select! {
            r = async {
                match limits.deadline {
                    Some(d) => tokio::time::timeout_at(d, run).await.ok(),
                    None => Some(run.await),
                }
            } => r,
            _ = limits.cancel.cancelled() => None,
        };
        let Some(result) = result else {
            // termin lub anulowanie w trakcie: proces nmap zabity, podgrupa wraca do zaległych
            shared.report.lock().unwrap().pending.extend(chunk);
            break;
        };
        let secs = started.elapsed().as_secs_f64();
        record(&shared, &chunk, result, secs);
        adjust_chunk_size(&shared, &cfg, chunk.len(), secs);
    }
}

fn take_chunk(shared: &Shared) -> Option<Vec<String>> {
    let mut queue = shared.queue.lock().unwrap();
    let size = shared.chunk_size.load(Ordering::Relaxed).min(queue.len());
    (size > 0).then(|| queue.drain(..size).collect())
}

fn record(shared: &Shared, chunk: &[String], result: Result<ChunkResult>, secs: f64) {
    let mut report = shared.report.lock().unwrap();
    match result {
        Ok(found) => {
            report.chunks.push(ChunkStat {
                size: chunk.len(),
                secs,
                live: found.live_hosts.len(),
                ok: true,
            });
            report.scanned.extend(chunk.iter().cloned());
            report.live_hosts.extend(found.live_hosts);
            report.observations.extend(found.observations);
            report.resolved.extend(found.resolved);
        }
        Err(e) => {
            tracing::error!(error = %e, size = chunk.len(), "podgrupa zakończona błędem");
            report.chunks.push(ChunkStat {
                size: chunk.len(),
                secs,
                live: 0,
                ok: false,
            });
            report.failed.push(FailedChunk {
                targets: chunk.to_vec(),
                error: e.to_string(),
            });
        }
    }
}

/// Podgrupa szybsza od docelowego czasu rośnie, wolniejsza maleje (najwyżej 2× na krok).
fn adjust_chunk_size(shared: &Shared, cfg: &ScanConfig, last: usize, secs: f64) {
    if secs < 1.0 {
        return;
    }
    let factor = (cfg.target_chunk_secs as f64 / secs).clamp(0.5, 2.0);
    let next = (last.max(1) as f64 * factor) as usize;
    shared
        .chunk_size
        .store(next.clamp(cfg.min_chunk, cfg.max_chunk), Ordering::Relaxed);
}

#[cfg(test)]
mod tests {
    use super::*;
    use asi_core::targets::classify;
    use std::future::Future;

    /// Atrapa nmap: każdy adres z kolejki „odpowiada” portem 22, chyba że ma być błąd lub wolno.
    struct Fake {
        fail: bool,
        delay: Duration,
        calls: Arc<AtomicUsize>,
    }

    impl ChunkRunner for Fake {
        fn run(&self, targets: Vec<String>) -> impl Future<Output = Result<ChunkResult>> + Send {
            let (fail, delay, calls) = (self.fail, self.delay, self.calls.clone());
            async move {
                calls.fetch_add(1, Ordering::SeqCst);
                tokio::time::sleep(delay).await;
                if fail {
                    anyhow::bail!("nmap: błąd testowy");
                }
                let mut r = ChunkResult::default();
                for t in targets {
                    r.live_hosts.push(t.clone());
                    r.observations.push(Observation::new(t, 22, "tcp".into()));
                }
                Ok(r)
            }
        }
    }

    fn cfg() -> ScanConfig {
        ScanConfig {
            chunk_size: 2,
            min_chunk: 1,
            concurrency: 2,
            recheck_missing: false,
            ..Default::default()
        }
    }

    fn plan(n: usize) -> Plan {
        let queue: Vec<String> = (1..=n).map(|i| format!("10.0.0.{i}")).collect();
        Plan {
            targets: vec![classify("10.0.0.0/24").unwrap()],
            queue,
            ..Default::default()
        }
    }

    fn scanner(fail: bool, delay: Duration) -> Scanner<Fake> {
        let fake = Fake {
            fail,
            delay,
            calls: Arc::new(AtomicUsize::new(0)),
        };
        Scanner::new(cfg(), Arc::new(fake), SignatureSet::default()).unwrap()
    }

    fn no_limits() -> Limits {
        Limits {
            deadline: None,
            cancel: CancellationToken::new(),
        }
    }

    #[tokio::test]
    async fn all_chunks_failing_is_failed() {
        let r = scanner(true, Duration::ZERO)
            .run(plan(6), no_limits())
            .await;
        assert!(r.scanned.is_empty());
        assert_eq!(r.failed.iter().map(|f| f.targets.len()).sum::<usize>(), 6);
        assert_eq!(r.status(false, false).0, RunStatus::Failed);
    }

    #[tokio::test]
    async fn complete_run_is_done_even_without_answers() {
        let r = scanner(false, Duration::ZERO)
            .run(plan(6), no_limits())
            .await;
        assert_eq!(r.scanned.len(), 6);
        assert_eq!(r.observations.len(), 6);
        assert_eq!(r.status(false, false), (RunStatus::Done, None));

        let empty = ScanReport {
            planned: 4,
            chunks: vec![ChunkStat {
                size: 4,
                secs: 1.0,
                live: 0,
                ok: true,
            }],
            ..Default::default()
        };
        assert_eq!(empty.status(false, false).0, RunStatus::Done);
    }

    #[tokio::test]
    async fn deadline_leaves_pending_work() {
        let s = scanner(false, Duration::from_millis(200));
        let deadline = Instant::now() + Duration::from_millis(300);
        let r = s
            .run(
                plan(12),
                Limits {
                    deadline: Some(deadline),
                    cancel: CancellationToken::new(),
                },
            )
            .await;
        assert!(!r.scanned.is_empty() && !r.pending.is_empty());
        assert_eq!(r.scanned.len() + r.pending.len(), 12);
        assert_eq!(
            r.status(false, true),
            (RunStatus::Partial, Some("koniec okna czasowego".into()))
        );
    }

    #[tokio::test]
    async fn cancel_stops_workers() {
        let s = scanner(false, Duration::from_millis(200));
        let limits = no_limits();
        limits.cancel.cancel();
        let r = s.run(plan(6), limits).await;
        assert!(r.scanned.is_empty());
        assert_eq!(r.pending.len(), 6);
        assert_eq!(r.status(true, false).0, RunStatus::Cancelled);
    }

    #[tokio::test]
    async fn out_of_scope_observations_are_dropped() {
        let mut p = plan(2);
        p.queue.push("192.168.5.5".into());
        let r = scanner(false, Duration::ZERO).run(p, no_limits()).await;
        assert!(r.observations.iter().all(|o| o.ip.starts_with("10.0.0.")));
    }
}
