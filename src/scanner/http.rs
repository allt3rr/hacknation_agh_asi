//! Moduł HTTP/HTTPS: tytuł, kod odpowiedzi, nagłówki, ciasteczka, certyfikat TLS,
//! przekierowania oraz dodatkowe ścieżki z sygnatur. Wyłącznie żądania GET, bez logowania.

use crate::model::{HttpInfo, Observation, PathProbe, TlsCert};
use anyhow::Result;
use regex::Regex;
use reqwest::{header::LOCATION, Client, Url};
use sha2::{Digest, Sha256};
use std::collections::btree_map::Entry;
use std::sync::OnceLock;
use std::time::Duration;

pub struct HttpProber {
    client: Client,
    body_limit: usize,
    max_redirects: usize,
}

impl HttpProber {
    pub fn new(timeout: Duration, user_agent: &str) -> Result<Self> {
        let client = Client::builder()
            .timeout(timeout)
            .connect_timeout(timeout)
            // przekierowania obsługujemy ręcznie, żeby je zapisać
            .redirect(reqwest::redirect::Policy::none())
            // akceptujemy certyfikaty self-signed, sam certyfikat zapisujemy do analizy
            .danger_accept_invalid_certs(true)
            .tls_info(true)
            .user_agent(user_agent)
            .build()?;
        Ok(Self {
            client,
            body_limit: 256 * 1024,
            max_redirects: 5,
        })
    }

    pub async fn probe(&self, base: &str, extra_paths: &[String]) -> Result<HttpInfo> {
        let base_url = Url::parse(base)?;
        let mut info = HttpInfo {
            url: base.to_string(),
            ..Default::default()
        };

        let mut url = base_url.clone();
        let mut resp = self.client.get(url.clone()).send().await?;
        info.tls = extract_tls(&resp);

        for _ in 0..self.max_redirects {
            if !resp.status().is_redirection() {
                break;
            }
            let Some(loc) = resp.headers().get(LOCATION).and_then(|v| v.to_str().ok()) else {
                break;
            };
            let next = url.join(loc)?;
            info.redirects.push(next.to_string());
            // Ostrożność: nie podążamy za przekierowaniem na inny host.
            if next.origin() != base_url.origin() {
                break;
            }
            url = next;
            resp = self.client.get(url.clone()).send().await?;
        }

        info.final_url = url.to_string();
        info.status = resp.status().as_u16();
        for (k, v) in resp.headers() {
            let name = k.as_str().to_ascii_lowercase();
            let value = String::from_utf8_lossy(v.as_bytes()).to_string();
            if name == "set-cookie" {
                info.cookies.push(value);
                continue;
            }
            match info.headers.entry(name) {
                Entry::Occupied(mut e) => {
                    let cur = e.get_mut();
                    cur.push_str(", ");
                    cur.push_str(&value);
                }
                Entry::Vacant(e) => {
                    e.insert(value);
                }
            }
        }

        let bytes = self.read_limited(resp).await?;
        let slice = bytes.as_slice();
        info.body_sha256 = Some(sha256_hex(slice));
        info.body = String::from_utf8_lossy(slice).into_owned();
        info.title = extract_title(&info.body);

        for p in extra_paths {
            if let Ok(probe) = self.fetch_path(&base_url, p).await {
                info.extra_paths.insert(p.clone(), probe);
            }
        }
        Ok(info)
    }

    async fn read_limited(&self, mut response: reqwest::Response) -> Result<Vec<u8>> {
        let mut bytes = Vec::new();
        while bytes.len() < self.body_limit {
            let Some(chunk) = response.chunk().await? else { break };
            bytes.extend_from_slice(&chunk[..chunk.len().min(self.body_limit - bytes.len())]);
        }
        Ok(bytes)
    }

    async fn fetch_path(&self, base: &Url, path: &str) -> Result<PathProbe> {
        let url = base.join(path)?;
        anyhow::ensure!(url.origin() == base.origin(), "Ścieżka poza zakresem");
        let resp = self.client.get(url).send().await?;
        let status = resp.status().as_u16();
        let bytes = self.read_limited(resp).await?;
        let slice = bytes.as_slice();
        Ok(PathProbe {
            status,
            sha256: Some(sha256_hex(slice)),
            body: String::from_utf8_lossy(slice).into_owned(),
        })
    }
}

/// Czy usługa wygląda na HTTP(S)? Zwraca bazowy URL do sondowania.
pub fn http_url_for(o: &Observation) -> Option<String> {
    if o.proto != "tcp" {
        return None;
    }
    let svc = o.service.as_deref().unwrap_or("").to_ascii_lowercase();
    let common_http = matches!(o.port, 80 | 443 | 8000 | 8008 | 8080 | 8081 | 8443 | 8888 | 9443);
    if !(svc.contains("http") || common_http) {
        return None;
    }
    let tls = o.tunnel.as_deref() == Some("ssl")
        || svc.contains("https")
        || svc.starts_with("ssl")
        || matches!(o.port, 443 | 8443 | 9443);
    // TODO: dla celów-domen wysyłać nagłówek Host (vhosty), zamiast samego IP.
    let host = if o.ip.contains(':') { format!("[{}]", o.ip) } else { o.ip.clone() };
    Some(format!("{}://{}:{}/", if tls { "https" } else { "http" }, host, o.port))
}

fn extract_tls(resp: &reqwest::Response) -> Option<TlsCert> {
    let der = resp.extensions().get::<reqwest::tls::TlsInfo>()?.peer_certificate()?;
    let mut cert = TlsCert {
        sha256: sha256_hex(der),
        ..Default::default()
    };
    if let Ok((_, x)) = x509_parser::parse_x509_certificate(der) {
        cert.subject = x.subject().to_string();
        cert.issuer = x.issuer().to_string();
        cert.not_before = x.validity().not_before.to_string();
        cert.not_after = x.validity().not_after.to_string();
        // TODO: odczyt SAN (x.subject_alternative_name()) do odkrywania domen.
    }
    Some(cert)
}

fn extract_title(body: &str) -> Option<String> {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| Regex::new(r"(?is)<title[^>]*>(.*?)</title>").unwrap());
    re.captures(body)
        .and_then(|c| c.get(1))
        .map(|m| m.as_str().split_whitespace().collect::<Vec<_>>().join(" "))
        .filter(|t| !t.is_empty())
        .map(|t| t.chars().take(300).collect())
}

pub fn sha256_hex(data: &[u8]) -> String {
    format!("{:x}", Sha256::digest(data))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn title_extraction() {
        assert_eq!(
            extract_title("<html><TITLE>\n  Panel   logowania </title>").as_deref(),
            Some("Panel logowania")
        );
        assert!(extract_title("<html></html>").is_none());
    }

    #[test]
    fn detects_http_services() {
        let mut o = Observation::new("10.0.0.1".into(), 8443, "tcp".into());
        o.service = Some("https-alt".into());
        assert_eq!(http_url_for(&o).as_deref(), Some("https://10.0.0.1:8443/"));
        let ssh = Observation::new("10.0.0.1".into(), 22, "tcp".into());
        assert!(http_url_for(&ssh).is_none());
    }
}
