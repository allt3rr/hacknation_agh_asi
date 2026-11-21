//! Konfiguracja skanu (TOML, `ASI_SCAN_CONFIG`). Wartości domyślne są celowo ostrożne.

use anyhow::{anyhow, bail, Context, Result};
use chrono::{Datelike, Duration as ChronoDuration, NaiveDate, NaiveDateTime, NaiveTime, Weekday};
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ScanConfig {
    pub nmap_binary: String,
    /// Lista portów (`nmap -p`), np. z listy dozwolonych portów organizatora. Gdy ustawiona,
    /// sondy HTTP mogą łączyć się tylko z tymi portami. Bez niej: `--top-ports`.
    pub ports: Option<String>,
    pub top_ports: u32,
    /// Łączny limit pakietów/s, dzielony równo między procesy nmap.
    pub global_max_rate: u32,
    /// Liczba równoległych procesów nmap.
    pub concurrency: usize,
    pub chunk_size: usize,
    pub min_chunk: usize,
    pub max_chunk: usize,
    /// Docelowy czas jednej podgrupy (s); rozmiar podgrupy dopasowuje się do zmierzonej szybkości.
    pub target_chunk_secs: u64,
    pub host_timeout: String,
    pub http_timeout_secs: u64,
    pub http_concurrency: usize,
    pub user_agent: String,
    /// Pobieranie dodatkowych ścieżek wymaganych przez sygnatury (GET, bez logowania).
    pub probe_paths: bool,
    pub max_targets: usize,
    /// Po ilu kolejnych przebiegach bez odpowiedzi host jest `inactive`.
    pub inactive_after_misses: i32,
    /// Ponowny pomiar hostów, które powinny żyć, a nie odpowiedziały.
    pub recheck_missing: bool,
    /// Ile razy podgrupa może być wznawiana, zanim zostanie porzucona.
    pub max_chunk_attempts: i32,
    pub schedule: ScheduleConfig,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            nmap_binary: "nmap".into(),
            ports: None,
            top_ports: 100,
            global_max_rate: 500,
            concurrency: 4,
            chunk_size: 64,
            min_chunk: 8,
            max_chunk: 512,
            target_chunk_secs: 300,
            host_timeout: "5m".into(),
            http_timeout_secs: 8,
            http_concurrency: 16,
            user_agent: "ASI-Scanner/0.1 (+security team discovery scan)".into(),
            probe_paths: true,
            max_targets: 70_000,
            inactive_after_misses: 3,
            recheck_missing: true,
            max_chunk_attempts: 3,
            schedule: ScheduleConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ScheduleConfig {
    pub enabled: bool,
    /// Minimalny odstęp między pełnymi skanami (godziny).
    pub every_hours: i64,
    pub windows: Vec<WindowConfig>,
}

impl Default for ScheduleConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            every_hours: 24,
            windows: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowConfig {
    /// Czas lokalny HH:MM.
    pub start: String,
    pub end: String,
    /// Dni tygodnia (mon..sun); pusta lista = codziennie.
    #[serde(default)]
    pub days: Vec<String>,
}

impl ScanConfig {
    pub fn from_toml(text: &str) -> Result<Self> {
        let cfg: Self = toml::from_str(text).context("Błąd w konfiguracji skanu")?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("Nie można odczytać {}", path.display()))?;
        Self::from_toml(&text).with_context(|| path.display().to_string())
    }

    pub fn validate(&self) -> Result<()> {
        if self.concurrency == 0 || self.http_concurrency == 0 || self.global_max_rate == 0 {
            bail!("concurrency, http_concurrency i global_max_rate muszą być > 0");
        }
        if self.min_chunk == 0 || self.min_chunk > self.max_chunk {
            bail!("wymagane 0 < min_chunk <= max_chunk");
        }
        if let Some(ports) = &self.ports {
            crate::scope::PortSet::parse(ports)?;
        }
        self.schedule.windows()?;
        Ok(())
    }

    /// Limit pakietów/s jednego procesu nmap.
    pub fn per_process_rate(&self) -> u32 {
        (self.global_max_rate / self.concurrency.max(1) as u32).max(1)
    }
}

impl ScheduleConfig {
    /// Wszystkie okna albo błąd przy pierwszym niepoprawnym — błędne okno nie jest pomijane.
    pub fn windows(&self) -> Result<Vec<Window>> {
        self.windows
            .iter()
            .enumerate()
            .map(|(i, w)| Window::parse(w).with_context(|| format!("okno czasowe nr {}", i + 1)))
            .collect()
    }
}

/// Decyzja polityki okien dla chwili `now` (czas lokalny).
#[derive(Debug, PartialEq, Eq)]
pub enum WindowDecision {
    /// Brak okien: dowolna pora, bez terminu.
    Unrestricted,
    /// W oknie: termin = koniec okna.
    Until(NaiveDateTime),
    /// Poza wszystkimi oknami.
    Closed,
}

pub fn window_decision(windows: &[Window], now: NaiveDateTime) -> WindowDecision {
    if windows.is_empty() {
        return WindowDecision::Unrestricted;
    }
    match windows.iter().filter_map(|w| w.end_if_active(now)).max() {
        Some(end) => WindowDecision::Until(end),
        None => WindowDecision::Closed,
    }
}

#[derive(Debug, Clone)]
pub struct Window {
    start: NaiveTime,
    end: NaiveTime,
    days: Vec<Weekday>,
}

impl Window {
    pub fn parse(config: &WindowConfig) -> Result<Self> {
        let time = |s: &str| {
            NaiveTime::parse_from_str(s, "%H:%M")
                .map_err(|_| anyhow!("niepoprawna godzina {s:?} (HH:MM)"))
        };
        let start = time(&config.start)?;
        let end = time(&config.end)?;
        if start == end {
            bail!("okno ma zerową długość ({})", config.start);
        }
        let days = config
            .days
            .iter()
            .map(|d| {
                d.parse::<Weekday>()
                    .map_err(|_| anyhow!("nieznany dzień tygodnia {d:?}"))
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Self { start, end, days })
    }

    /// Koniec okna, jeśli `now` mieści się w oknie. Okno może przechodzić przez północ
    /// (np. 22:00–06:00); dzień tygodnia liczy się dla dnia, w którym okno się zaczęło.
    pub fn end_if_active(&self, now: NaiveDateTime) -> Option<NaiveDateTime> {
        let time = now.time();
        let today = now.date();
        let yesterday = today - ChronoDuration::days(1);
        let tomorrow = today + ChronoDuration::days(1);

        if self.start < self.end {
            let inside = time >= self.start && time < self.end;
            return (inside && self.allows_day(today)).then(|| today.and_time(self.end));
        }
        if time >= self.start {
            self.allows_day(today).then(|| tomorrow.and_time(self.end))
        } else if time < self.end {
            self.allows_day(yesterday).then(|| today.and_time(self.end))
        } else {
            None
        }
    }

    fn allows_day(&self, day: NaiveDate) -> bool {
        self.days.is_empty() || self.days.contains(&day.weekday())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(value: &str) -> NaiveDateTime {
        NaiveDateTime::parse_from_str(value, "%Y-%m-%d %H:%M").unwrap()
    }

    fn window(start: &str, end: &str, days: &[&str]) -> Window {
        Window::parse(&WindowConfig {
            start: start.into(),
            end: end.into(),
            days: days.iter().map(|d| d.to_string()).collect(),
        })
        .unwrap()
    }

    #[test]
    fn window_across_midnight() {
        let w = window("22:00", "06:00", &[]);
        assert_eq!(
            w.end_if_active(at("2026-11-21 23:00")),
            Some(at("2026-11-22 06:00"))
        );
        assert_eq!(
            w.end_if_active(at("2026-11-22 05:59")),
            Some(at("2026-11-22 06:00"))
        );
        assert_eq!(w.end_if_active(at("2026-11-22 12:00")), None);
    }

    #[test]
    fn window_limited_to_weekdays() {
        let w = window("08:00", "16:00", &["mon"]);
        assert!(w.end_if_active(at("2026-11-23 09:00")).is_some()); // poniedziałek
        assert!(w.end_if_active(at("2026-11-24 09:00")).is_none());
    }

    #[test]
    fn invalid_window_fails_whole_config() {
        let bad = "[schedule]\nenabled = true\n[[schedule.windows]]\nstart = \"25:00\"\nend = \"06:00\"\n";
        let err = ScanConfig::from_toml(bad).unwrap_err();
        assert!(format!("{err:#}").contains("okno czasowe nr 1"), "{err:#}");
        let bad_day =
            "[[schedule.windows]]\nstart = \"22:00\"\nend = \"06:00\"\ndays = [\"pon\"]\n";
        assert!(ScanConfig::from_toml(&format!("[schedule]\n{bad_day}")).is_err());
        assert!(ScanConfig::from_toml("nieznane_pole = 1").is_err());
    }

    #[test]
    fn window_policy() {
        let windows = vec![window("22:00", "06:00", &[])];
        assert_eq!(
            window_decision(&[], at("2026-11-21 12:00")),
            WindowDecision::Unrestricted
        );
        assert_eq!(
            window_decision(&windows, at("2026-11-21 12:00")),
            WindowDecision::Closed
        );
        assert_eq!(
            window_decision(&windows, at("2026-11-21 23:00")),
            WindowDecision::Until(at("2026-11-22 06:00"))
        );
    }

    #[test]
    fn example_config_loads() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../config/scan.toml");
        ScanConfig::load(Path::new(path)).unwrap();
    }
}
