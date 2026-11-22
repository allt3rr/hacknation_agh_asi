//! Wspólne typy danych: cele, obserwacje usług, wyniki HTTP i detekcje.

use time::OffsetDateTime;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TargetKind {
    Ip,
    Cidr,
    Domain,
}

impl TargetKind {
    pub fn as_str(self) -> &'static str {
        match self {
            TargetKind::Ip => "ip",
            TargetKind::Cidr => "cidr",
            TargetKind::Domain => "domain",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "ip" => Some(TargetKind::Ip),
            "cidr" => Some(TargetKind::Cidr),
            "domain" => Some(TargetKind::Domain),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Target {
    pub value: String,
    pub kind: TargetKind,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub note: Option<String>,
}

/// Jedna usługa (ip:port/proto) zaobserwowana w danym przebiegu skanu.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Observation {
    pub ip: String,
    #[serde(default)]
    pub hostname: Option<String>,
    pub port: u16,
    #[serde(default = "default_proto")]
    pub proto: String,
    #[serde(default = "default_state")]
    pub state: String,
    #[serde(default)]
    pub service: Option<String>,
    #[serde(default)]
    pub product: Option<String>,
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub extra_info: Option<String>,
    /// "ssl", gdy nmap wykrył tunel TLS.
    #[serde(default)]
    pub tunnel: Option<String>,
    #[serde(default)]
    pub http: Option<HttpInfo>,
    #[serde(default)]
    pub detections: Vec<Detection>,
    #[serde(default = "OffsetDateTime::now_utc")]
    #[serde(with = "time::serde::rfc3339")]
    pub seen_at: OffsetDateTime,
}

fn default_proto() -> String {
    "tcp".into()
}

fn default_state() -> String {
    "open".into()
}

impl Observation {
    pub fn new(ip: String, port: u16, proto: String) -> Self {
        Self {
            ip,
            hostname: None,
            port,
            proto,
            state: default_state(),
            service: None,
            product: None,
            version: None,
            extra_info: None,
            tunnel: None,
            http: None,
            detections: Vec::new(),
            seen_at: OffsetDateTime::now_utc(),
        }
    }

    /// Klucz usługi używany w porównaniach między skanami i w adnotacjach.
    pub fn key(&self) -> String {
        format!("{}:{}/{}", self.ip, self.port, self.proto)
    }

    /// Krótki opis do raportu zmian, np. `http nginx 1.24.0 (title: "Panel")`.
    pub fn summary(&self) -> String {
        let parts: Vec<&str> = [&self.service, &self.product, &self.version]
            .into_iter()
            .flatten()
            .map(String::as_str)
            .filter(|part| !part.is_empty())
            .collect();
        let mut summary = parts.join(" ");

        if let Some(title) = self.http.as_ref().and_then(|http| http.title.as_deref()) {
            summary.push_str(&format!(" (title: \"{title}\")"));
        }
        summary
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HttpInfo {
    pub url: String,
    #[serde(default)]
    pub final_url: String,
    pub status: u16,
    #[serde(default)]
    pub title: Option<String>,
    /// Nazwy nagłówków zapisane małymi literami.
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    /// Surowe wartości nagłówków Set-Cookie.
    #[serde(default)]
    pub cookies: Vec<String>,
    #[serde(default)]
    pub redirects: Vec<String>,
    #[serde(default)]
    pub tls: Option<TlsCert>,
    #[serde(default)]
    pub body_sha256: Option<String>,
    /// Dodatkowe ścieżki pobrane na potrzeby sygnatur, np. /admin, /favicon.ico.
    #[serde(default)]
    pub extra_paths: BTreeMap<String, PathProbe>,
    /// Treść strony. Trzymana tylko w pamięci do dopasowania sygnatur, nie trafia do bazy.
    #[serde(skip)]
    pub body: String,
}

impl HttpInfo {
    pub fn cookie_names(&self) -> impl Iterator<Item = &str> + '_ {
        self.cookies
            .iter()
            .filter_map(|cookie| cookie.split('=').next())
            .map(str::trim)
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PathProbe {
    pub status: u16,
    #[serde(default)]
    pub sha256: Option<String>,
    #[serde(skip)]
    pub body: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TlsCert {
    pub subject: String,
    pub issuer: String,
    pub not_before: String,
    pub not_after: String,
    pub sha256: String,
}

/// Wynik dopasowania sygnatury.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Detection {
    pub signature_id: String,
    pub name: String,
    /// cms, framework, server, application, iot, admin_panel, staging, interesting
    pub category: String,
    #[serde(default)]
    pub version: Option<String>,
    /// Pewność w procentach (0-100).
    pub confidence: u8,
    #[serde(default)]
    pub evidence: Vec<String>,
}
