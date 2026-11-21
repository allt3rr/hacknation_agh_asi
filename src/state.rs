use crate::auth::Session;
use crate::config::Config;
use crate::db::{self, crypto::FieldCrypto, Db};
use crate::fingerprint::SignatureSet;
use crate::settings::RuntimeSettings;
use anyhow::{Context, Result};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};

#[derive(Clone)]
pub struct AppState {
    pub cfg: Arc<Config>,
    pub db: Db,
    pub crypto: Arc<FieldCrypto>,
    pub sessions: Arc<RwLock<HashMap<String, Session>>>,
    pub signatures: Arc<RwLock<SignatureSet>>,
    /// Harmonogram i tempo skanu zmieniane z interfejsu.
    pub settings: Arc<RwLock<RuntimeSettings>>,
    /// tylko jeden skan/import naraz
    pub scan_lock: Arc<Mutex<()>>,
}

impl AppState {
    pub async fn init(cfg: Config) -> Result<Self> {
        let key = std::env::var("ASI_DATA_KEY").context("Brak ASI_DATA_KEY w środowisku/.env (wygeneruj: asi gen-key)")?;
        let crypto = FieldCrypto::from_base64_key(&key)?;
        let db = db::connect(&cfg.database.url).await?;
        let settings = load_settings(&db, &cfg).await?;
        let st = Self {
            cfg: Arc::new(cfg),
            db,
            crypto: Arc::new(crypto),
            sessions: Arc::default(),
            signatures: Arc::new(RwLock::new(SignatureSet::default())),
            settings: Arc::new(RwLock::new(settings)),
            scan_lock: Arc::new(Mutex::new(())),
        };
        let n = st.reload_signatures().await?;
        tracing::info!("Załadowano {n} sygnatur");
        Ok(st)
    }

    /// Wbudowane sygnatury z katalogu + własne z bazy (własne nadpisują wbudowane o tym samym id).
    pub async fn reload_signatures(&self) -> Result<usize> {
        let mut sigs = SignatureSet::load_dir(Path::new(&self.cfg.signatures_dir))?;
        for row in db::list_signatures(&self.db).await? {
            if row.enabled == 0 {
                continue;
            }
            match SignatureSet::parse_yaml(&row.yaml) {
                Ok(s) => sigs.extend(s),
                Err(e) => tracing::warn!(name = %row.name, error = %e, "pominięto uszkodzoną sygnaturę"),
            }
        }
        let set = SignatureSet::new(sigs)?;
        let n = set.len();
        *self.signatures.write().await = set;
        Ok(n)
    }

    pub fn scan_running(&self) -> bool {
        self.scan_lock.try_lock().is_err()
    }
}

pub const SETTINGS_KEY: &str = "runtime";

/// Ustawienia zapisane z interfejsu mają pierwszeństwo przed plikiem konfiguracji.
async fn load_settings(db: &Db, cfg: &Config) -> Result<RuntimeSettings> {
    if let Some(json) = db::load_setting(db, SETTINGS_KEY).await? {
        match serde_json::from_str::<RuntimeSettings>(&json) {
            Ok(settings) => return Ok(settings),
            Err(error) => tracing::warn!(%error, "uszkodzone ustawienia w bazie, używam config/asi.toml"),
        }
    }
    Ok(RuntimeSettings::from_config(cfg))
}
