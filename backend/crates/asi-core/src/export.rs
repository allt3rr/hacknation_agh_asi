//! Widok wyniku dla API i eksportu: redakcja sekretów, nałożenie korekt analityka, CSV/JSON i import.

use crate::model::{Detection, HttpInfo, Observation, TlsCert};
use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, HashMap};

/// Nagłówki, których wartości nie pokazujemy (poza nimi: nazwy zawierające token/secret/session).
const SENSITIVE_HEADERS: &[&str] = &[
    "authorization",
    "cookie",
    "set-cookie",
    "proxy-authorization",
    "x-api-key",
    "x-auth-token",
];
pub const REDACTED: &str = "[redacted]";

pub fn is_sensitive_header(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    SENSITIVE_HEADERS.contains(&n.as_str())
        || ["token", "secret", "session"].iter().any(|w| n.contains(w))
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CookieMeta {
    pub name: String,
    pub attributes: Vec<String>,
}

/// Nazwa i atrybuty ciasteczka z nagłówka `Set-Cookie`, bez wartości.
pub fn cookie_meta(set_cookie: &str) -> CookieMeta {
    let mut parts = set_cookie.split(';').map(str::trim);
    let name = parts
        .next()
        .and_then(|nv| nv.split('=').next())
        .unwrap_or("")
        .trim()
        .to_string();
    let attributes = parts
        .filter(|p| !p.is_empty())
        .map(|p| match p.split_once('=') {
            Some((k, v)) => format!("{}={}", k.trim(), v.trim()),
            None => p.to_string(),
        })
        .collect();
    CookieMeta { name, attributes }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct HttpView {
    pub status: u16,
    pub title: Option<String>,
    pub final_url: String,
    pub redirects: Vec<String>,
    pub blocked_redirects: Vec<String>,
    pub headers: BTreeMap<String, String>,
    pub cookies: Vec<CookieMeta>,
    pub tls: Option<TlsCert>,
}

impl HttpView {
    fn redacted(h: &HttpInfo) -> Self {
        let headers = h
            .headers
            .iter()
            .map(|(k, v)| {
                (
                    k.clone(),
                    if is_sensitive_header(k) {
                        REDACTED.to_string()
                    } else {
                        v.clone()
                    },
                )
            })
            .collect();
        Self {
            status: h.status,
            title: h.title.clone(),
            final_url: h.final_url.clone(),
            redirects: h.redirects.clone(),
            blocked_redirects: h.blocked_redirects.clone(),
            headers,
            cookies: h.cookies.iter().map(|c| cookie_meta(c)).collect(),
            tls: h.tls.clone(),
        }
    }
}

/// Wynik dla API i eksportu: wartości po korektach, surowy pomiar w `raw_*`, bez wartości ciasteczek.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ResultRow {
    pub id: String,
    pub run_id: String,
    pub key: String,
    pub ip: String,
    pub hostname: Option<String>,
    pub port: u16,
    pub proto: String,
    pub state: String,
    pub service: Option<String>,
    pub product: Option<String>,
    pub version: Option<String>,
    pub http: Option<HttpView>,
    pub technologies: Vec<Detection>,
    pub status: Option<String>,
    pub severity: Option<String>,
    pub owner: Option<String>,
    pub note: Option<String>,
    pub raw_service: Option<String>,
    pub raw_product: Option<String>,
    pub raw_version: Option<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub seen_at: time::OffsetDateTime,
}

impl Default for ResultRow {
    fn default() -> Self {
        Self {
            id: Default::default(),
            run_id: Default::default(),
            key: Default::default(),
            ip: Default::default(),
            hostname: Default::default(),
            port: Default::default(),
            proto: Default::default(),
            state: Default::default(),
            service: Default::default(),
            product: Default::default(),
            version: Default::default(),
            http: Default::default(),
            technologies: Default::default(),
            status: Default::default(),
            severity: Default::default(),
            owner: Default::default(),
            note: Default::default(),
            raw_service: Default::default(),
            raw_product: Default::default(),
            raw_version: Default::default(),
            seen_at: time::OffsetDateTime::UNIX_EPOCH,
        }
    }
}

impl ResultRow {
    /// `overrides`: aktywne korekty usługi (pole → wartość).
    pub fn new(
        id: String,
        run_id: String,
        o: &Observation,
        overrides: &HashMap<String, String>,
    ) -> Self {
        let pick = |field: &str, raw: &Option<String>| {
            overrides.get(field).cloned().or_else(|| raw.clone())
        };
        Self {
            id,
            run_id,
            key: o.key(),
            ip: o.ip.clone(),
            hostname: o.hostname.clone(),
            port: o.port,
            proto: o.proto.clone(),
            state: o.state.clone(),
            service: pick("service", &o.service),
            product: pick("product", &o.product),
            version: pick("version", &o.version),
            http: o.http.as_ref().map(HttpView::redacted),
            technologies: o.detections.clone(),
            status: overrides.get("status").cloned(),
            severity: overrides.get("severity").cloned(),
            owner: overrides.get("owner").cloned(),
            note: overrides.get("note").cloned(),
            raw_service: o.service.clone(),
            raw_product: o.product.clone(),
            raw_version: o.version.clone(),
            seen_at: o.seen_at,
        }
    }
}

pub const CSV_HEADER: [&str; 17] = [
    "ip",
    "hostname",
    "port",
    "proto",
    "state",
    "service",
    "product",
    "version",
    "http_status",
    "http_title",
    "technologies",
    "status",
    "severity",
    "owner",
    "raw_service",
    "raw_product",
    "raw_version",
];

/// Komórka bezpieczna dla arkusza: tekst zaczynający się od znaku formuły dostaje apostrof.
fn spreadsheet_safe(v: String) -> String {
    if v.starts_with(['=', '+', '-', '@', '\t', '\r']) {
        format!("'{v}")
    } else {
        v
    }
}

fn technologies_cell(d: &[Detection]) -> String {
    d.iter()
        .map(|d| match &d.version {
            Some(v) => format!("{} {v}", d.name),
            None => d.name.clone(),
        })
        .collect::<Vec<_>>()
        .join("; ")
}

pub fn to_csv(rows: &[ResultRow], safe: bool) -> Result<String> {
    let mut w = csv::Writer::from_writer(Vec::new());
    w.write_record(CSV_HEADER)?;
    let s = |v: Option<String>| v.unwrap_or_default();
    for r in rows {
        let record = [
            r.ip.clone(),
            s(r.hostname.clone()),
            r.port.to_string(),
            r.proto.clone(),
            r.state.clone(),
            s(r.service.clone()),
            s(r.product.clone()),
            s(r.version.clone()),
            r.http
                .as_ref()
                .map(|h| h.status.to_string())
                .unwrap_or_default(),
            s(r.http.as_ref().and_then(|h| h.title.clone())),
            technologies_cell(&r.technologies),
            s(r.status.clone()),
            s(r.severity.clone()),
            s(r.owner.clone()),
            s(r.raw_service.clone()),
            s(r.raw_product.clone()),
            s(r.raw_version.clone()),
        ];
        let record: Vec<String> = if safe {
            record.into_iter().map(spreadsheet_safe).collect()
        } else {
            record.to_vec()
        };
        w.write_record(record)?;
    }
    let bytes = w.into_inner().map_err(|e| anyhow!("CSV: {e}"))?;
    Ok(String::from_utf8(bytes)?)
}

pub fn to_json(rows: &[ResultRow]) -> Result<String> {
    Ok(serde_json::to_string_pretty(rows)?)
}

#[derive(Deserialize)]
struct CsvResult {
    ip: String,
    #[serde(default)]
    hostname: Option<String>,
    port: u16,
    #[serde(default)]
    proto: Option<String>,
    #[serde(default)]
    state: Option<String>,
    #[serde(default)]
    service: Option<String>,
    #[serde(default)]
    product: Option<String>,
    #[serde(default)]
    version: Option<String>,
    #[serde(default)]
    http_status: Option<String>,
    #[serde(default)]
    http_title: Option<String>,
    #[serde(default)]
    technologies: Option<String>,
    #[serde(default)]
    raw_service: Option<String>,
    #[serde(default)]
    raw_product: Option<String>,
    #[serde(default)]
    raw_version: Option<String>,
}

fn non_empty(v: Option<String>) -> Option<String> {
    v.filter(|s| !s.is_empty())
}

/// Import wyników: JSON (tablica `ResultRow` z eksportu albo obserwacji) lub CSV w formacie eksportu.
/// Z eksportu bierzemy surowy pomiar (`raw_*`), żeby korekty nie stały się „pomiarem”.
pub fn parse_results(format: &str, data: &str) -> Result<Vec<Observation>> {
    match format.to_ascii_lowercase().as_str() {
        "json" => {
            let items: Vec<Value> =
                serde_json::from_str(data).context("JSON: oczekiwano tablicy wyników")?;
            items
                .into_iter()
                .enumerate()
                .map(|(i, v)| json_item(v).with_context(|| format!("JSON: element {}", i + 1)))
                .collect()
        }
        "csv" => {
            let mut rdr = csv::ReaderBuilder::new()
                .flexible(true)
                .trim(csv::Trim::All)
                .from_reader(data.as_bytes());
            let mut out = Vec::new();
            for (i, row) in rdr.deserialize::<CsvResult>().enumerate() {
                let r = row.with_context(|| format!("CSV: błąd w wierszu {}", i + 2))?;
                let mut o = Observation::new(
                    r.ip,
                    r.port,
                    non_empty(r.proto).unwrap_or_else(|| "tcp".into()),
                );
                o.hostname = non_empty(r.hostname);
                if let Some(s) = non_empty(r.state) {
                    o.state = s;
                }
                o.service = non_empty(r.raw_service).or(non_empty(r.service));
                o.product = non_empty(r.raw_product).or(non_empty(r.product));
                o.version = non_empty(r.raw_version).or(non_empty(r.version));
                if let Some(status) = non_empty(r.http_status) {
                    o.http = Some(HttpInfo {
                        status: status
                            .parse()
                            .with_context(|| format!("CSV: http_status w wierszu {}", i + 2))?,
                        title: non_empty(r.http_title),
                        ..Default::default()
                    });
                }
                o.detections = non_empty(r.technologies)
                    .map(|t| {
                        t.split(';')
                            .map(str::trim)
                            .filter(|x| !x.is_empty())
                            .map(imported_detection)
                            .collect()
                    })
                    .unwrap_or_default();
                out.push(o);
            }
            Ok(out)
        }
        other => bail!("Nieobsługiwany format: {other} (json|csv)"),
    }
}

/// „WordPress 6.4.2” → detekcja z wersją (ostatni wyraz z cyfrą to wersja).
fn imported_detection(text: &str) -> Detection {
    let (name, version) = match text.rsplit_once(' ') {
        Some((n, v)) if v.chars().any(|c| c.is_ascii_digit()) => {
            (n.to_string(), Some(v.to_string()))
        }
        _ => (text.to_string(), None),
    };
    Detection {
        signature_id: format!("import:{}", name.to_ascii_lowercase()),
        name,
        category: "imported".into(),
        version,
        confidence: 50,
        evidence: vec!["import".into()],
    }
}

fn json_item(v: Value) -> Result<Observation> {
    // `ResultRow` z eksportu: surowe pola i `technologies`; inaczej zwykła `Observation`
    if v.get("raw_product").is_some() || v.get("technologies").is_some() {
        let r: ResultRow = serde_json::from_value(v)?;
        let mut o = Observation::new(r.ip, r.port, r.proto);
        o.hostname = r.hostname;
        o.state = r.state;
        o.service = r.raw_service;
        o.product = r.raw_product;
        o.version = r.raw_version;
        o.detections = r.technologies;
        o.http = r.http.map(|h| HttpInfo {
            status: h.status,
            title: h.title,
            final_url: h.final_url,
            redirects: h.redirects,
            headers: h
                .headers
                .into_iter()
                .filter(|(_, v)| v != REDACTED)
                .collect(),
            tls: h.tls,
            ..Default::default()
        });
        return Ok(o);
    }
    Ok(serde_json::from_value(v)?)
}

/// Zastępuje sekret w zserializowanym JSON (np. raport) — używane w testach szczelności.
pub fn contains_secret(value: &Value, secret: &str) -> bool {
    value.to_string().contains(secret)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Observation {
        let mut o = Observation::new("10.0.0.1".into(), 443, "tcp".into());
        o.service = Some("https".into());
        o.product = Some("nginx".into());
        o.version = Some("1.24".into());
        let mut headers = BTreeMap::new();
        headers.insert("server".into(), "nginx".into());
        headers.insert("x-session-id".into(), "abc".into());
        headers.insert("authorization".into(), "Bearer x".into());
        o.http = Some(HttpInfo {
            status: 200,
            title: Some("=HYPERLINK(\"http://x\")".into()),
            headers,
            cookies: vec!["PHPSESSID=tajny-123; Path=/; HttpOnly".into()],
            ..Default::default()
        });
        o.detections = vec![Detection {
            signature_id: "wordpress".into(),
            name: "WordPress".into(),
            category: "cms".into(),
            version: Some("6.4.2".into()),
            confidence: 72,
            evidence: vec![],
        }];
        o
    }

    #[test]
    fn redaction_hides_cookie_values_and_sensitive_headers() {
        let row = ResultRow::new("1".into(), "r".into(), &sample(), &HashMap::new());
        let json = serde_json::to_value(&row).unwrap();
        assert!(!contains_secret(&json, "tajny-123"));
        let http = row.http.unwrap();
        assert_eq!(
            http.cookies,
            vec![CookieMeta {
                name: "PHPSESSID".into(),
                attributes: vec!["Path=/".into(), "HttpOnly".into()]
            }]
        );
        assert_eq!(http.headers["server"], "nginx");
        assert_eq!(http.headers["x-session-id"], REDACTED);
        assert_eq!(http.headers["authorization"], REDACTED);
    }

    #[test]
    fn overrides_are_applied_with_raw_values_kept() {
        let ov: HashMap<String, String> = [
            ("product".to_string(), "nginx-custom".to_string()),
            ("status".to_string(), "false_positive".to_string()),
        ]
        .into();
        let row = ResultRow::new("1".into(), "r".into(), &sample(), &ov);
        assert_eq!(row.product.as_deref(), Some("nginx-custom"));
        assert_eq!(row.raw_product.as_deref(), Some("nginx"));
        assert_eq!(row.status.as_deref(), Some("false_positive"));
    }

    #[test]
    fn csv_safe_and_raw_round_trip() {
        let row = ResultRow::new("1".into(), "r".into(), &sample(), &HashMap::new());
        let safe = to_csv(std::slice::from_ref(&row), true).unwrap();
        assert!(safe.contains("\"'=HYPERLINK(\"\"http://x\"\")\""), "{safe}");

        let raw = to_csv(&[row], false).unwrap();
        let back = parse_results("csv", &raw).unwrap();
        assert_eq!(back.len(), 1);
        let o = &back[0];
        assert_eq!((o.port, o.product.as_deref()), (443, Some("nginx")));
        let http = o.http.as_ref().unwrap();
        assert_eq!(
            (http.status, http.title.as_deref()),
            (200, Some("=HYPERLINK(\"http://x\")"))
        );
        assert_eq!(o.detections[0].name, "WordPress");
        assert_eq!(o.detections[0].version.as_deref(), Some("6.4.2"));
    }

    #[test]
    fn json_export_round_trip_uses_raw_measurement() {
        let ov: HashMap<String, String> =
            [("product".to_string(), "poprawione".to_string())].into();
        let row = ResultRow::new("1".into(), "r".into(), &sample(), &ov);
        let back = parse_results("json", &to_json(&[row]).unwrap()).unwrap();
        assert_eq!(back[0].product.as_deref(), Some("nginx"));
        assert_eq!(
            back[0].http.as_ref().unwrap().headers.get("authorization"),
            None
        );
        assert!(parse_results("xml", "").is_err());
    }
}
