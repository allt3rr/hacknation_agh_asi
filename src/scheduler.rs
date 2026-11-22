//! Harmonogram skanów: okna czasowe i częstotliwość.
//! Skan, który nie zmieści się w oknie, jest przerywany na jego końcu,
//! a niezeskanowane adresy są skanowane jako pierwsze w następnym oknie.

use crate::config::WindowConfig;
use crate::db;
use crate::pipeline;
use crate::state::AppState;
use anyhow::{anyhow, Result};
use time::{Date, OffsetDateTime, PrimitiveDateTime, Time, Weekday};
use std::time::Duration;
use tokio::time::Instant;

const CHECK_INTERVAL: Duration = Duration::from_secs(60);

#[derive(Debug, Clone)]
pub struct Window {
    start: Time,
    end: Time,
    /// Pusta lista oznacza każdy dzień.
    days: Vec<Weekday>,
}

fn parse_weekday(value: &str) -> Option<Weekday> {
    use Weekday::*;
    [Monday, Tuesday, Wednesday, Thursday, Friday, Saturday, Sunday]
        .into_iter().find(|day| {
            let full = day.to_string();
            value.eq_ignore_ascii_case(&full) || value.eq_ignore_ascii_case(&full[..3])
        })
}

impl Window {
    pub fn parse(config: &WindowConfig) -> Result<Self> {
        let start = Time::parse(&config.start, time::macros::format_description!("[hour]:[minute]"))?;
        let end = Time::parse(&config.end, time::macros::format_description!("[hour]:[minute]"))?;
        let days = config
            .days
            .iter()
            .map(|day| parse_weekday(day).ok_or_else(|| anyhow!("Nieznany dzień tygodnia: {day}")))
            .collect::<Result<Vec<_>>>()?;
        Ok(Self { start, end, days })
    }

    /// Zwraca moment końca okna, jeśli `now` mieści się w oknie.
    ///
    /// Okno może przechodzić przez północ, np. 22:00-06:00.
    /// Dzień tygodnia sprawdzamy dla dnia, w którym okno się zaczęło.
    pub fn end_if_active(&self, now: PrimitiveDateTime) -> Option<PrimitiveDateTime> {
        let time = now.time();
        let today = now.date();
        let yesterday = today - time::Duration::days(1);
        let tomorrow = today + time::Duration::days(1);

        let crosses_midnight = self.start > self.end;
        if !crosses_midnight {
            let inside = time >= self.start && time < self.end;
            return (inside && self.allows_day(today)).then(|| today.with_time(self.end));
        }

        if time >= self.start {
            self.allows_day(today).then(|| tomorrow.with_time(self.end))
        } else if time < self.end {
            self.allows_day(yesterday).then(|| today.with_time(self.end))
        } else {
            None
        }
    }

    fn allows_day(&self, day: Date) -> bool {
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
        let Ok(local) = OffsetDateTime::now_local() else { tracing::error!("Nieznany czas lokalny"); continue; };
        let now = PrimitiveDateTime::new(local.date(), local.time());

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
            let seconds_left = (end - now).whole_seconds().max(0) as u64;
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

    match OffsetDateTime::parse(&last_run.started_at, &time::format_description::well_known::Rfc3339) {
        Ok(started) => {
            let hours_since = (OffsetDateTime::now_utc() - started).whole_hours();
            hours_since >= every_hours
        }
        Err(_) => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(value: &str) -> PrimitiveDateTime {
        PrimitiveDateTime::parse(value, time::macros::format_description!("[year]-[month]-[day] [hour]:[minute]")).unwrap()
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
