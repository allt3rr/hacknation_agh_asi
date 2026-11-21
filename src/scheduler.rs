//! Harmonogram skanów: okna czasowe i częstotliwość.
//! Skan, który nie zmieści się w oknie, jest przerywany na jego końcu,
//! a niezeskanowane adresy są skanowane jako pierwsze w następnym oknie.

use crate::config::WindowConfig;
use crate::db;
use crate::pipeline;
use crate::state::AppState;
use anyhow::{anyhow, Result};
use chrono::{DateTime, Datelike, Duration as ChronoDuration, Local, NaiveDate, NaiveDateTime, NaiveTime, Utc, Weekday};
use std::time::Duration;
use tokio::time::Instant;

const CHECK_INTERVAL: Duration = Duration::from_secs(60);

#[derive(Debug, Clone)]
pub struct Window {
    start: NaiveTime,
    end: NaiveTime,
    /// Pusta lista oznacza każdy dzień.
    days: Vec<Weekday>,
}

impl Window {
    pub fn parse(config: &WindowConfig) -> Result<Self> {
        let start = NaiveTime::parse_from_str(&config.start, "%H:%M")?;
        let end = NaiveTime::parse_from_str(&config.end, "%H:%M")?;
        let days = config
            .days
            .iter()
            .map(|day| day.parse::<Weekday>().map_err(|_| anyhow!("Nieznany dzień tygodnia: {day}")))
            .collect::<Result<Vec<_>>>()?;
        Ok(Self { start, end, days })
    }

    /// Zwraca moment końca okna, jeśli `now` mieści się w oknie.
    ///
    /// Okno może przechodzić przez północ, np. 22:00-06:00.
    /// Dzień tygodnia sprawdzamy dla dnia, w którym okno się zaczęło.
    pub fn end_if_active(&self, now: NaiveDateTime) -> Option<NaiveDateTime> {
        let time = now.time();
        let today = now.date();
        let yesterday = today - ChronoDuration::days(1);
        let tomorrow = today + ChronoDuration::days(1);

        let crosses_midnight = self.start > self.end;
        if !crosses_midnight {
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

pub async fn run(st: AppState) {
    let schedule = st.cfg.schedule.clone();
    if !schedule.enabled {
        tracing::info!("harmonogram wyłączony (schedule.enabled = false)");
        return;
    }

    let windows = parse_windows(&schedule.windows);
    tracing::info!(windows = windows.len(), every_hours = schedule.every_hours, "harmonogram aktywny");

    let mut ticker = tokio::time::interval(CHECK_INTERVAL);
    loop {
        ticker.tick().await;
        let now = Local::now().naive_local();

        // Bez zdefiniowanych okien skan może ruszyć o dowolnej porze.
        let window_end = if windows.is_empty() {
            None
        } else {
            match windows.iter().find_map(|window| window.end_if_active(now)) {
                Some(end) => Some(end),
                None => continue,
            }
        };

        if st.scan_running() || !is_scan_due(&st, schedule.every_hours).await {
            continue;
        }

        let deadline = window_end.map(|end| {
            let seconds_left = (end - now).num_seconds().max(0) as u64;
            Instant::now() + Duration::from_secs(seconds_left)
        });
        let st = st.clone();
        tokio::spawn(async move {
            if let Err(error) = pipeline::execute_scan(&st, deadline, "scheduler").await {
                tracing::error!(error = %error, "zaplanowany skan nie powiódł się");
            }
        });
    }
}

fn parse_windows(configs: &[WindowConfig]) -> Vec<Window> {
    configs
        .iter()
        .filter_map(|config| match Window::parse(config) {
            Ok(window) => Some(window),
            Err(error) => {
                tracing::error!(error = %error, "pomijam błędne okno czasowe");
                None
            }
        })
        .collect()
}

/// Skan jest potrzebny, gdy poprzedni został przerwany albo minęło `every_hours` godzin.
async fn is_scan_due(st: &AppState, every_hours: i64) -> bool {
    let last_run = match db::latest_finished_run(&st.db).await {
        Ok(Some(run)) => run,
        Ok(None) => return true,
        Err(error) => {
            tracing::error!(error = %error, "harmonogram: błąd odczytu bazy");
            return false;
        }
    };

    if last_run.status == "partial" {
        return true;
    }

    match DateTime::parse_from_rfc3339(&last_run.started_at) {
        Ok(started) => {
            let hours_since = Utc::now().signed_duration_since(started.with_timezone(&Utc)).num_hours();
            hours_since >= every_hours
        }
        Err(_) => true,
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
        assert_eq!(w.end_if_active(at("2026-11-21 23:00")), Some(at("2026-11-22 06:00")));
        assert_eq!(w.end_if_active(at("2026-11-22 03:00")), Some(at("2026-11-22 06:00")));
        assert_eq!(w.end_if_active(at("2026-11-22 12:00")), None);
    }

    #[test]
    fn window_limited_to_weekdays() {
        // 2026-11-21 to sobota, 2026-11-23 to poniedziałek
        let w = window("08:00", "16:00", &["mon"]);
        assert_eq!(w.end_if_active(at("2026-11-21 10:00")), None);
        assert_eq!(w.end_if_active(at("2026-11-23 10:00")), Some(at("2026-11-23 16:00")));
    }
}
