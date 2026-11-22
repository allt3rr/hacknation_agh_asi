//! Korelacja usług z CVE: klient NVD CVE API 2.0 (zapytanie po CPE, stronicowanie, limit tempa,
//! ponowienia z backoffem) i budowa podatności z wynikiem i wektorem CVSS v3.x.

use anyhow::{bail, Context, Result};
use asi_core::model::Observation;
use asi_core::vuln::{
    severity_from_cvss, CveInfo, ServiceId, Vulnerability, EVIDENCE_VERSION_MATCH,
};
use serde_json::Value;
use std::time::Duration;
use tokio::sync::Mutex;
use tokio::time::Instant;

/// Maksymalny rozmiar strony NVD.
const PAGE: u64 = 2000;
const ATTEMPTS: u32 = 4;

pub struct NvdClient {
    base: String,
    api_key: Option<String>,
    http: reqwest::Client,
    /// Odstęp między żądaniami: NVD bez klucza pozwala na 5 żądań / 30 s, z kluczem 50 / 30 s.
    min_interval: Duration,
    retry_delay: Duration,
    last: Mutex<Option<Instant>>,
}

impl NvdClient {
    pub fn new(base: &str, api_key: Option<String>) -> Result<Self> {
        let api_key = api_key.filter(|k| !k.is_empty());
        let min_interval = if api_key.is_some() {
            Duration::from_millis(700)
        } else {
            Duration::from_secs(6)
        };
        Ok(Self {
            base: base.to_string(),
            api_key,
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(60))
                .user_agent("ASI-Scanner/0.1")
                .build()?,
            min_interval,
            retry_delay: Duration::from_secs(6),
            last: Mutex::new(None),
        })
    }

    /// Krótsze odstępy (testy z atrapą serwera).
    pub fn with_timing(mut self, min_interval: Duration, retry_delay: Duration) -> Self {
        self.min_interval = min_interval;
        self.retry_delay = retry_delay;
        self
    }

    async fn throttle(&self) {
        let mut last = self.last.lock().await;
        if let Some(t) = *last {
            tokio::time::sleep_until(t + self.min_interval).await;
        }
        *last = Some(Instant::now());
    }

    async fn page(&self, cpe: &str, start: u64) -> Result<Value> {
        let url = format!(
            "{}?cpeName={}&isVulnerable&resultsPerPage={PAGE}&startIndex={start}",
            self.base,
            encode(cpe)
        );
        let mut last_err = String::new();
        for attempt in 0..ATTEMPTS {
            if attempt > 0 {
                tokio::time::sleep(self.retry_delay * 2u32.pow(attempt - 1)).await;
            }
            self.throttle().await;
            let mut req = self.http.get(&url);
            if let Some(k) = &self.api_key {
                req = req.header("apiKey", k);
            }
            match req.send().await {
                Ok(res) if res.status().is_success() => {
                    let body = res.bytes().await.context("NVD: przerwana odpowiedź")?;
                    return serde_json::from_slice(&body).context("NVD: niepoprawny JSON");
                }
                // 403/429 = limit tempa NVD, 5xx = chwilowa awaria: ponawiamy
                Ok(res)
                    if res.status().as_u16() == 403
                        || res.status().as_u16() == 429
                        || res.status().is_server_error() =>
                {
                    last_err = format!("NVD zwróciło {}", res.status());
                }
                Ok(res) => bail!("NVD zwróciło {}", res.status()),
                Err(e) => last_err = format!("NVD niedostępne: {e}"),
            }
            tracing::debug!(%cpe, attempt, error = %last_err, "NVD: ponowienie");
        }
        bail!("{last_err} (po {ATTEMPTS} próbach)")
    }

    /// Wszystkie CVE, w których konfiguracji ten CPE jest podatny.
    pub async fn cves_for(&self, cpe: &str) -> Result<Vec<CveInfo>> {
        let mut out = Vec::new();
        let mut start = 0;
        loop {
            let page = self.page(cpe, start).await?;
            let items = parse_response(&page);
            let total = page["totalResults"].as_u64().unwrap_or(0);
            let got = page["vulnerabilities"].as_array().map_or(0, Vec::len) as u64;
            out.extend(items);
            start += got;
            if got == 0 || start >= total {
                return Ok(out);
            }
        }
    }
}

/// Kodowanie wartości parametru zapytania (CPE zawiera `:` i `*`, które NVD przyjmuje wprost).
fn encode(s: &str) -> String {
    s.bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b":*._-~".contains(&b) {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}

fn cvss_v3(metrics: &Value) -> (Option<f64>, Option<String>) {
    for key in ["cvssMetricV31", "cvssMetricV30"] {
        let Some(list) = metrics[key].as_array() else {
            continue;
        };
        // ocena NVD („Primary”) ma pierwszeństwo przed oceną zgłaszającego
        let m = list
            .iter()
            .find(|m| m["type"] == "Primary")
            .or(list.first());
        if let Some(m) = m {
            let data = &m["cvssData"];
            return (
                data["baseScore"].as_f64(),
                data["vectorString"].as_str().map(String::from),
            );
        }
    }
    (None, None)
}

/// Odpowiedź NVD CVE API 2.0 → lista CVE z CVSS v3.x (brak oceny = `None`).
pub fn parse_response(v: &Value) -> Vec<CveInfo> {
    v["vulnerabilities"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|item| {
            let cve = &item["cve"];
            let id = cve["id"].as_str()?.to_string();
            let descriptions = cve["descriptions"].as_array();
            let description = descriptions
                .and_then(|d| d.iter().find(|d| d["lang"] == "en").or(d.first()))
                .and_then(|d| d["value"].as_str())
                .unwrap_or("")
                .to_string();
            let (cvss_score, cvss_vector) = cvss_v3(&cve["metrics"]);
            Some(CveInfo {
                id,
                cvss_score,
                cvss_vector,
                description,
                published: cve["published"]
                    .as_str()
                    .map(|p| p.chars().take(10).collect()),
            })
        })
        .collect()
}

/// Podatności usługi z dopasowanych CVE (dowód: korelacja wersji).
pub fn correlate(o: &Observation, id: &ServiceId, cves: &[CveInfo]) -> Vec<Vulnerability> {
    cves.iter()
        .map(|c| Vulnerability {
            ip: o.ip.clone(),
            port: o.port,
            proto: o.proto.clone(),
            cve_id: c.id.clone(),
            cvss_score: c.cvss_score,
            cvss_vector: c.cvss_vector.clone(),
            severity: severity_from_cvss(c.cvss_score).into(),
            evidence: EVIDENCE_VERSION_MATCH.into(),
            component: id.product.clone(),
            version: id.version.clone(),
            description: c.description.clone(),
            published: c.published.clone(),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::extract::RawQuery;
    use axum::http::StatusCode;
    use axum::response::IntoResponse;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    const FIXTURE: &str = include_str!("../tests/fixtures/nvd_apache_2.4.49.json");

    #[test]
    fn parses_nvd_fixture() {
        let cves = parse_response(&serde_json::from_str(FIXTURE).unwrap());
        assert_eq!(cves.len(), 3);
        assert_eq!(cves[0].id, "CVE-2021-41773");
        assert_eq!(
            cves[0].cvss_score,
            Some(7.5),
            "ocena Primary przed Secondary"
        );
        assert_eq!(
            cves[0].cvss_vector.as_deref(),
            Some("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N")
        );
        assert_eq!(cves[0].published.as_deref(), Some("2021-10-05"));
        assert!(cves[0].description.starts_with("A flaw"));
        assert_eq!(cves[1].cvss_score, Some(9.8), "CVSS 3.0, gdy brak 3.1");
        assert_eq!(cves[2].cvss_score, None, "bez oceny");

        let o = Observation::new("10.0.0.1".into(), 80, "tcp".into());
        let id = ServiceId {
            cpe: "x".into(),
            product: "http_server".into(),
            version: "2.4.49".into(),
        };
        let v = correlate(&o, &id, &cves);
        assert_eq!(v[1].severity, "Critical");
        assert_eq!(v[2].severity, "Info");
        assert!(v.iter().all(|v| v.evidence == "version_match"));
    }

    async fn mock(
        statuses: Vec<StatusCode>,
    ) -> (String, Arc<AtomicUsize>, Arc<std::sync::Mutex<Vec<String>>>) {
        let calls = Arc::new(AtomicUsize::new(0));
        let queries = Arc::new(std::sync::Mutex::new(Vec::new()));
        let (c, q) = (calls.clone(), queries.clone());
        let app = axum::Router::new().route(
            "/cves",
            axum::routing::get(move |RawQuery(query): RawQuery| {
                let n = c.fetch_add(1, Ordering::SeqCst);
                q.lock().unwrap().push(query.unwrap_or_default());
                let status = statuses.get(n).copied().unwrap_or(StatusCode::OK);
                async move {
                    if status == StatusCode::OK {
                        (status, FIXTURE).into_response()
                    } else {
                        status.into_response()
                    }
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (format!("http://127.0.0.1:{port}/cves"), calls, queries)
    }

    fn client(url: &str) -> NvdClient {
        NvdClient::new(url, Some("klucz".into()))
            .unwrap()
            .with_timing(Duration::ZERO, Duration::from_millis(5))
    }

    #[tokio::test]
    async fn retries_rate_limit_then_succeeds() {
        let (url, calls, queries) =
            mock(vec![StatusCode::TOO_MANY_REQUESTS, StatusCode::FORBIDDEN]).await;
        let cpe = "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*";
        let cves = client(&url).cves_for(cpe).await.unwrap();
        assert_eq!(cves.len(), 3);
        assert_eq!(calls.load(Ordering::SeqCst), 3);
        let q = queries.lock().unwrap()[0].clone();
        assert!(q.contains(&format!("cpeName={cpe}")), "{q}");
        assert!(q.contains("isVulnerable"), "{q}");
    }

    #[tokio::test]
    async fn persistent_failure_is_an_error() {
        let (url, calls, _) = mock(vec![StatusCode::SERVICE_UNAVAILABLE; 10]).await;
        let err = client(&url).cves_for("cpe:2.3:a:x:y:1:*:*:*:*:*:*:*").await;
        assert!(err.is_err());
        assert_eq!(calls.load(Ordering::SeqCst), ATTEMPTS as usize);
        let (url, _, _) = mock(vec![StatusCode::NOT_FOUND]).await;
        assert!(
            client(&url).cves_for("cpe").await.is_err(),
            "4xx bez ponowień"
        );
        assert!(client("http://127.0.0.1:1/cves")
            .cves_for("cpe")
            .await
            .is_err());
    }
}
