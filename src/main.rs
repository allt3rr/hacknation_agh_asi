//! ASI (Attack Surface Intelligence): cykliczny discovery scan dużych sieci
//! z wykrywaniem zmian w czasie.

mod api;
mod auth;
mod config;
mod db;
mod defectdojo;
mod diff;
mod export;
mod fingerprint;
mod input;
mod model;
mod pipeline;
mod scanner;
mod scheduler;
mod settings;
mod state;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use db::crypto::FieldCrypto;
use state::AppState;
use std::path::{Path, PathBuf};
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(name = "asi", version, about = "Attack Surface Intelligence: discovery scan dużej infrastruktury")]
struct Cli {
    /// Ścieżka do pliku konfiguracji
    #[arg(short, long, default_value = "config/asi.toml")]
    config: PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Uruchamia API, dashboard i harmonogram skanów
    Serve,
    /// Jednorazowy skan wszystkich aktywnych celów (bez okna czasowego)
    Scan,
    /// Importuje cele z pliku .txt, .csv lub .json
    ImportTargets { file: PathBuf },
    /// Generuje klucz szyfrowania danych (ASI_DATA_KEY)
    GenKey,
}

#[tokio::main]
async fn main() -> Result<()> {
    dotenvy::dotenv().ok();
    init_logging();

    let cli = Cli::parse();
    if let Command::GenKey = cli.command {
        println!("{}", FieldCrypto::generate_key());
        return Ok(());
    }

    let config = config::Config::load(&cli.config)?;
    let st = AppState::init(config).await?;

    match cli.command {
        Command::Serve => serve(st).await,
        Command::Scan => scan_once(st).await,
        Command::ImportTargets { file } => import_targets(st, &file).await,
        Command::GenKey => unreachable!("obsłużone wcześniej"),
    }
}

fn init_logging() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info,sqlx=warn"));
    tracing_subscriber::fmt().with_env_filter(filter).init();
}

async fn serve(st: AppState) -> Result<()> {
    auth::bootstrap_admin(&st).await?;
    tokio::spawn(scheduler::run(st.clone()));

    let address = st.cfg.server.bind.clone();
    let listener = tokio::net::TcpListener::bind(&address)
        .await
        .with_context(|| format!("Nie można nasłuchiwać na {address}"))?;
    tracing::info!("dashboard: http://{address}");

    axum::serve(listener, api::router(st)).await?;
    Ok(())
}

async fn scan_once(st: AppState) -> Result<()> {
    let run_id = pipeline::execute_scan(&st, None, "cli").await?;
    println!("Skan zakończony, run_id = {run_id}");
    Ok(())
}

async fn import_targets(st: AppState, file: &Path) -> Result<()> {
    let content = std::fs::read_to_string(file).with_context(|| format!("Nie można odczytać {}", file.display()))?;
    let format = file.extension().and_then(|ext| ext.to_str()).unwrap_or("txt");

    let (targets, invalid) = input::parse_by_format(format, &content)?;
    let inserted = db::insert_targets(&st.db, &st.crypto, &targets, "cli").await?;

    println!("Wczytano {}, dodano {inserted} nowych, odrzucono {}", targets.len(), invalid.len());
    for entry in invalid {
        println!("  nieprawidłowy wpis: {entry}");
    }
    Ok(())
}
