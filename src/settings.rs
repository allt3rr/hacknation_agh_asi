//! Ustawienia skanu zmieniane w trakcie działania (z interfejsu): harmonogram i tempo skanowania.
//! Przy starcie pochodzą z `config/asi.toml`, a po pierwszym zapisie z tabeli `settings`.

use crate::config::{Config, ScanConfig, ScheduleConfig};
use crate::scheduler::Window;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeSettings {
    pub schedule: ScheduleConfig,
    /// Łączny limit pakietów/s dzielony między równoległe procesy nmap.
    pub global_max_rate: u32,
    /// Liczba równoległych procesów nmap.
    pub concurrency: usize,
    /// Liczba równoległych zapytań HTTP.
    pub http_concurrency: usize,
}

impl RuntimeSettings {
    pub fn from_config(cfg: &Config) -> Self {
        Self {
            schedule: cfg.schedule.clone(),
            global_max_rate: cfg.scan.global_max_rate,
            concurrency: cfg.scan.concurrency,
            http_concurrency: cfg.scan.http_concurrency,
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        if !(1..=24 * 30).contains(&self.schedule.every_hours) {
            return Err("Częstotliwość: od 1 h do 720 h".into());
        }
        for window in &self.schedule.windows {
            Window::parse(window).map_err(|e| format!("Błędne okno {}-{}: {e}", window.start, window.end))?;
        }
        if !(1..=100_000).contains(&self.global_max_rate) {
            return Err("Limit pakietów/s: od 1 do 100000".into());
        }
        if !(1..=64).contains(&self.concurrency) {
            return Err("Równoległe procesy nmap: od 1 do 64".into());
        }
        if !(1..=256).contains(&self.http_concurrency) {
            return Err("Równoległe zapytania HTTP: od 1 do 256".into());
        }
        Ok(())
    }

    /// Konfiguracja skanera z tempem z bieżących ustawień.
    pub fn apply(&self, scan: &ScanConfig) -> ScanConfig {
        let mut scan = scan.clone();
        scan.global_max_rate = self.global_max_rate;
        scan.concurrency = self.concurrency;
        scan.http_concurrency = self.http_concurrency;
        scan
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::WindowConfig;

    fn settings() -> RuntimeSettings {
        RuntimeSettings {
            schedule: ScheduleConfig { enabled: true, every_hours: 24, windows: vec![] },
            global_max_rate: 2000,
            concurrency: 8,
            http_concurrency: 32,
        }
    }

    #[test]
    fn validation() {
        assert!(settings().validate().is_ok());

        let mut bad_window = settings();
        bad_window.schedule.windows.push(WindowConfig { start: "25:00".into(), end: "06:00".into(), days: vec![] });
        assert!(bad_window.validate().is_err());

        let mut bad_day = settings();
        bad_day.schedule.windows.push(WindowConfig { start: "22:00".into(), end: "06:00".into(), days: vec!["xyz".into()] });
        assert!(bad_day.validate().is_err());

        let mut bad_rate = settings();
        bad_rate.global_max_rate = 0;
        assert!(bad_rate.validate().is_err());
    }
}
