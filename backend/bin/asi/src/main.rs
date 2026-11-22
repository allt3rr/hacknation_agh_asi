//! ASI: `asi serve` (migracje + API) i `asi migrate` (tylko migracje, seed ról i konto admina).

use anyhow::{Context, Result};
use asi_api::{ApiConfig, AppState};
use clap::{Parser, Subcommand};
use std::net::SocketAddr;
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(name = "asi", version, about = "Attack Surface Intelligence")]
struct Cli {
    /// Adres PostgreSQL, np. postgres://asi:haslo@localhost:5432/asi
    #[arg(long, env = "DATABASE_URL", global = true, hide_env_values = true)]
    database_url: Option<String>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Migracje, seed ról, konto admina i API HTTP
    Serve {
        #[arg(long, env = "ASI_BIND", default_value = "0.0.0.0:8080")]
        bind: SocketAddr,
        /// Atrybut Secure cookie sesji (włącz za HTTPS)
        #[arg(long, env = "ASI_COOKIE_SECURE", default_value_t = false)]
        cookie_secure: bool,
        #[arg(long, env = "ASI_SESSION_TTL_HOURS", default_value_t = 12)]
        session_ttl_hours: i64,
        /// Plik TOML z konfiguracją skanu (porty, limity, okna). Bez niego: ostrożne wartości domyślne.
        #[arg(long, env = "ASI_SCAN_CONFIG")]
        scan_config: Option<std::path::PathBuf>,
        /// Katalog wbudowanych sygnatur YAML.
        #[arg(long, env = "ASI_SIGNATURES_DIR", default_value = "signatures")]
        signatures_dir: std::path::PathBuf,
        /// Zbudowany frontend (`frontend/dist`), serwowany z tego samego originu co API.
        #[arg(long, env = "ASI_STATIC_DIR")]
        static_dir: Option<std::path::PathBuf>,
    },
    /// Tylko migracje, seed ról i konto admina
    Migrate,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info,sqlx=warn")),
        )
        .init();

    let cli = Cli::parse();
    let url = cli
        .database_url
        .context("Brak DATABASE_URL (adres PostgreSQL)")?;
    let db = asi_db::connect(&url).await?;
    asi_db::prepare(&db, std::env::var("ASI_ADMIN_PASSWORD").ok().as_deref()).await?;

    match cli.command {
        Command::Migrate => {
            tracing::info!("Migracje i seed wykonane");
            Ok(())
        }
        Command::Serve {
            bind,
            cookie_secure,
            session_ttl_hours,
            scan_config,
            signatures_dir,
            static_dir,
        } => {
            anyhow::ensure!(session_ttl_hours > 0, "ASI_SESSION_TTL_HOURS musi być > 0");
            let (crypto, source) = asi_crypto::FieldCrypto::from_env(|k| std::env::var(k).ok())?;
            if source == asi_crypto::KeySource::Demo {
                tracing::warn!("Tryb demo: klucz szyfrowania wygenerowany w pamięci, zaszyfrowane dane nie przetrwają restartu");
            }
            let state = AppState::new(
                db,
                ApiConfig {
                    session_ttl_hours,
                    cookie_secure,
                },
                crypto,
            )?;
            // błędna konfiguracja nie zatrzymuje API, ale blokuje skany (409 z opisem) i harmonogram
            let scan_cfg = match &scan_config {
                Some(path) => {
                    asi_scanner::config::ScanConfig::load(path).map_err(|e| format!("{e:#}"))
                }
                None => Ok(asi_scanner::config::ScanConfig::default()),
            };
            if let Err(e) = &scan_cfg {
                tracing::error!(error = %e, "błędna konfiguracja skanu: skany zablokowane");
            }
            let runner = asi_api::scans::ScanService::nmap_runner(
                scan_cfg.as_ref().unwrap_or(&Default::default()),
            );
            let state = state.with_scans(asi_api::scans::ScanService::new(
                scan_cfg,
                runner,
                signatures_dir,
            ));
            tokio::spawn(asi_api::scans::scheduler(state.clone()));
            let listener = tokio::net::TcpListener::bind(bind)
                .await
                .with_context(|| format!("Nie można nasłuchiwać na {bind}"))?;
            tracing::info!("ASI API na http://{bind}");
            axum::serve(
                listener,
                match &static_dir {
                    Some(dir) => asi_api::with_static(asi_api::router(state), dir),
                    None => asi_api::router(state),
                }
                .into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await?;
            Ok(())
        }
    }
}
