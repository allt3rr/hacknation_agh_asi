//! Konfiguracja z pliku TOML (domyślnie `config/asi.toml`).
//! Sekrety (klucz danych, tokeny) są czytane ze zmiennych środowiskowych, nie z tego pliku.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    pub database: DatabaseConfig,
    pub scan: ScanConfig,
    #[serde(default)]
    pub schedule: ScheduleConfig,
    #[serde(default)]
    pub defectdojo: Option<DefectDojoConfig>,
    #[serde(default = "default_signatures_dir")]
    pub signatures_dir: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    pub bind: String,
    #[serde(default = "default_session_hours")]
    pub session_hours: i64,
    /// Katalog ze zbudowanym frontendem (`npm run build` w `frontend/`).
    #[serde(default = "default_static_dir")]
    pub static_dir: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DatabaseConfig {
    pub url: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ScanConfig {
    pub nmap_binary: String,
    /// Lista portów dla `nmap -p`. Bez niej używane jest `--top-ports`.
    #[serde(default)]
    pub ports: Option<String>,
    #[serde(default = "default_top_ports")]
    pub top_ports: u32,
    #[serde(default)]
    pub extra_nmap_args: Vec<String>,

    /// Łączny limit pakietów/s, dzielony między równoległe procesy nmap.
    pub global_max_rate: u32,
    /// Liczba równoległych procesów nmap.
    pub concurrency: usize,
    pub chunk_size: usize,
    pub min_chunk: usize,
    pub max_chunk: usize,
    /// Docelowy czas skanu jednej podgrupy w sekundach.
    pub target_chunk_secs: u64,
    pub host_timeout: String,

    pub http_timeout_secs: u64,
    pub http_concurrency: usize,
    pub user_agent: String,
    /// Czy pobierać dodatkowe ścieżki wymagane przez sygnatury.
    #[serde(default = "default_true")]
    pub probe_paths: bool,

    pub max_targets: usize,
    /// Po ilu kolejnych skanach bez odpowiedzi host jest uznawany za nieaktywny.
    pub inactive_after_misses: i64,
    /// Czy skanować drugi raz hosty, które nie odpowiedziały.
    #[serde(default = "default_true")]
    pub recheck_missing: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ScheduleConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_every_hours")]
    pub every_hours: i64,
    #[serde(default)]
    pub windows: Vec<WindowConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WindowConfig {
    /// Czas lokalny w formacie HH:MM.
    pub start: String,
    pub end: String,
    /// Dni tygodnia (mon..sun). Pusta lista oznacza każdy dzień.
    #[serde(default)]
    pub days: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DefectDojoConfig {
    pub url: String,
    pub engagement_id: u64,
    /// Nazwa zmiennej środowiskowej z tokenem API.
    #[serde(default = "default_token_env")]
    pub token_env: String,
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("Nie można odczytać konfiguracji {}", path.display()))?;
        let mut config: Config = toml::from_str(&text).context("Błąd w pliku konfiguracji")?;

        if let Ok(bind) = std::env::var("ASI_BIND") {
            config.server.bind = bind;
        }
        Ok(config)
    }
}

fn default_signatures_dir() -> String {
    "signatures".into()
}

fn default_session_hours() -> i64 {
    12
}

fn default_static_dir() -> String {
    "frontend/dist".into()
}

fn default_top_ports() -> u32 {
    1000
}

fn default_true() -> bool {
    true
}

fn default_every_hours() -> i64 {
    24
}

fn default_token_env() -> String {
    "ASI_DD_TOKEN".into()
}
