//! Sondy HTTP/HTTPS: tytuł, kod, nagłówki, ciasteczka, certyfikat TLS, przekierowania i dodatkowe
//! ścieżki z sygnatur. Wyłącznie GET bez logowania. Każde połączenie przechodzi przez `Scope::check`,
//! odpowiedź jest czytana strumieniowo do `BODY_LIMIT`, a każde żądanie ogranicza wspólny termin.

use crate::scope::Scope;
use anyhow::{anyhow, Result};
use asi_core::model::{HttpInfo, Observation, PathProbe, TlsCert};
use regex::Regex;
use reqwest::header::{HOST, LOCATION};
use reqwest::{Client, Response, Url};
use sha2::{Digest, Sha256};
use std::collections::btree_map::Entry;
use std::sync::OnceLock;
use std::time::Duration;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

pub const BODY_LIMIT: usize = 256 * 1024;
const MAX_REDIRECTS: usize = 5;

/// Sonda przerwana terminem lub anulowaniem — praca wraca do zaległości.
#[derive(Debug)]
pub struct Interrupted;

impl std::fmt::Display for Interrupted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("przerwano (termin lub anulowanie)")
    }
}

impl std::error::Error for Interrupted {}

pub fn is_interrupted(e: &anyhow::Error) -> bool {
    e.downcast_ref::<Interrupted>().is_some()
}

/// Wspólne ograniczenia przebiegu dla każdego żądania.
#[derive(Clone)]
pub struct Limits {
    pub deadline: Option<Instant>,
    pub cancel: CancellationToken,
}

impl Limits {
    pub fn expired(&self) -> bool {
        self.cancel.is_cancelled() || self.deadline.is_some_and(|d| Instant::now() >= d)
    }
}

pub struct HttpProber {
    client: Client,
}

impl HttpProber {
    pub fn new(timeout: Duration, user_agent: &str) -> Result<Self> {
        let client = Client::builder()
            .timeout(timeout)
            .connect_timeout(timeout)
            // przekierowania obsługujemy ręcznie: każde sprawdzamy względem zakresu
            .redirect(reqwest::redirect::Policy::none())
            // certyfikaty self-signed akceptujemy, sam certyfikat zapisujemy do analizy
            .danger_accept_invalid_certs(true)
            .tls_info(true)
            .no_proxy()
            .user_agent(user_agent)
            .build()?;
        Ok(Self { client })
    }

    async fn get(
        &self,
        url: &Url,
        host: Option<&str>,
        scope: &Scope,
        limits: &Limits,
    ) -> Result<Response> {
        scope.check(url)?;
        if limits.expired() {
            return Err(Interrupted.into());
        }
        let mut req = self.client.get(url.clone());
        if let Some(host) = host {
            req = req.header(HOST, host);
        }
        let send = req.send();
        let res = match limits.deadline {
            Some(d) => tokio::select! {
                r = tokio::time::timeout_at(d, send) => r.map_err(|_| anyhow!(Interrupted))?,
                _ = limits.cancel.cancelled() => return Err(Interrupted.into()),
            },
            None => tokio::select! {
                r = send => r,
                _ = limits.cancel.cancelled() => return Err(Interrupted.into()),
            },
        };
        Ok(res?)
    }

    /// Czyta treść strumieniowo i przerywa po `BODY_LIMIT` bajtach (bez względu na Content-Length).
    async fn read_limited(&self, mut resp: Response, limits: &Limits) -> Result<Vec<u8>> {
        let mut body = Vec::new();
        while body.len() < BODY_LIMIT {
            let next = resp.chunk();
            let chunk = match limits.deadline {
                Some(d) => tokio::select! {
                    r = tokio::time::timeout_at(d, next) => r.map_err(|_| anyhow!(Interrupted))??,
                    _ = limits.cancel.cancelled() => return Err(Interrupted.into()),
                },
                None => next.await?,
            };
            match chunk {
                Some(bytes) => body.extend_from_slice(&bytes),
                None => break,
            }
        }
        body.truncate(BODY_LIMIT);
        Ok(body) // porzucenie `resp` zamyka połączenie bez czytania reszty
    }

    pub async fn probe(
        &self,
        base: &Url,
        host: Option<&str>,
        extra_paths: &[String],
        scope: &Scope,
        limits: &Limits,
    ) -> Result<HttpInfo> {
        let mut info = HttpInfo {
            url: base.to_string(),
            ..Default::default()
        };
        let mut url = base.clone();
        let mut resp = self.get(&url, host, scope, limits).await?;
        info.tls = extract_tls(&resp);

        for _ in 0..MAX_REDIRECTS {
            if !resp.status().is_redirection() {
                break;
            }
            let Some(loc) = resp.headers().get(LOCATION).and_then(|v| v.to_str().ok()) else {
                break;
            };
            let Ok(mut next) = url.join(loc) else {
                break;
            };
            // Domena pierwotnego celu pozostaje przypięta do sprawdzonego IP.
            // Pozostałe nazwy nie mają tu wiarygodnego przypisania do adresu.
            if host.is_some() && next.host_str() == host {
                next.set_host(base.host_str())?;
            }
            if scope.check(&next).is_err() {
                info.blocked_redirects.push(next.to_string());
                break;
            }
            info.redirects.push(next.to_string());
            let same_host = next.host_str() == url.host_str();
            url = next;
            resp = self
                .get(&url, host.filter(|_| same_host), scope, limits)
                .await?;
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
                    e.get_mut().push_str(", ");
                    e.get_mut().push_str(&value);
                }
                Entry::Vacant(e) => {
                    e.insert(value);
                }
            }
        }
        let body = self.read_limited(resp, limits).await?;
        info.body_sha256 = Some(sha256_hex(&body));
        info.body = String::from_utf8_lossy(&body).into_owned();
        info.title = extract_title(&info.body);

        for path in extra_paths {
            match self.fetch_path(base, host, path, scope, limits).await {
                Ok(probe) => {
                    info.extra_paths.insert(path.clone(), probe);
                }
                Err(e) if is_interrupted(&e) => return Err(e),
                Err(e) => tracing::debug!(%path, error = %e, "ścieżka pominięta"),
            }
        }
        Ok(info)
    }

    async fn fetch_path(
        &self,
        base: &Url,
        host: Option<&str>,
        path: &str,
        scope: &Scope,
        limits: &Limits,
    ) -> Result<PathProbe> {
        asi_fingerprint::validate_path(path)?;
        let url = base.join(path)?;
        if url.origin() != base.origin() {
            return Err(anyhow!("ścieżka {path:?} zmienia origin"));
        }
        let resp = self.get(&url, host, scope, limits).await?;
        let status = resp.status().as_u16();
        let body = self.read_limited(resp, limits).await?;
        Ok(PathProbe {
            status,
            sha256: Some(sha256_hex(&body)),
            body: String::from_utf8_lossy(&body).into_owned(),
        })
    }
}

/// Czy usługa wygląda na HTTP(S)? Zwraca bazowy URL do sondowania (po adresie IP).
pub fn http_url_for(o: &Observation) -> Option<Url> {
    if o.proto != "tcp" || o.state != "open" {
        return None;
    }
    let svc = o.service.as_deref().unwrap_or("").to_ascii_lowercase();
    let common_http = matches!(
        o.port,
        80 | 443 | 8000 | 8008 | 8080 | 8081 | 8443 | 8888 | 9443
    );
    if !(svc.contains("http") || common_http) {
        return None;
    }
    let tls = o.tunnel.as_deref() == Some("ssl")
        || svc.contains("https")
        || svc.starts_with("ssl")
        || matches!(o.port, 443 | 8443 | 9443);
    let host = if o.ip.contains(':') {
        format!("[{}]", o.ip)
    } else {
        o.ip.clone()
    };
    Url::parse(&format!(
        "{}://{}:{}/",
        if tls { "https" } else { "http" },
        host,
        o.port
    ))
    .ok()
}

fn extract_tls(resp: &Response) -> Option<TlsCert> {
    let der = resp
        .extensions()
        .get::<reqwest::tls::TlsInfo>()?
        .peer_certificate()?;
    let mut cert = TlsCert {
        sha256: sha256_hex(der),
        ..Default::default()
    };
    if let Ok((_, x)) = x509_parser::parse_x509_certificate(der) {
        cert.subject = x.subject().to_string();
        cert.issuer = x.issuer().to_string();
        cert.not_before = x.validity().not_before.to_string();
        cert.not_after = x.validity().not_after.to_string();
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
    use crate::scope::PortSet;
    use asi_core::targets::classify;
    use axum::body::Body;
    use axum::response::IntoResponse;
    use axum::routing::get;
    use axum::Router;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    /// Serwer testowy na 127.0.0.1 z licznikiem żądań (rejestr połączeń).
    async fn server(router: Router) -> (u16, Arc<AtomicUsize>) {
        let hits = Arc::new(AtomicUsize::new(0));
        let counter = hits.clone();
        let app = router.layer(axum::middleware::from_fn(
            move |req, next: axum::middleware::Next| {
                counter.fetch_add(1, Ordering::SeqCst);
                async move { next.run(req).await }
            },
        ));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (port, hits)
    }

    fn scope_with(ports: &[u16]) -> Scope {
        let mut s = Scope::new(&[classify("127.0.0.1").unwrap()], None);
        for p in ports {
            s.add_open_port("127.0.0.1".parse().unwrap(), *p);
        }
        s
    }

    fn limits(deadline: Option<Instant>) -> Limits {
        Limits {
            deadline,
            cancel: CancellationToken::new(),
        }
    }

    fn prober() -> HttpProber {
        HttpProber::new(Duration::from_secs(5), "test").unwrap()
    }

    /// 10 MiB w fragmentach 64 KiB, bez Content-Length.
    fn huge() -> impl IntoResponse {
        let chunk = bytes::Bytes::from(vec![b'a'; 64 * 1024]);
        let stream = futures_util::stream::iter(
            (0..160).map(move |_| Ok::<_, std::io::Error>(chunk.clone())),
        );
        Body::from_stream(stream)
    }

    #[tokio::test]
    async fn redirect_to_out_of_scope_port_is_not_followed() {
        let (other, other_hits) = server(Router::new().route("/", get(|| async { "inny" }))).await;
        let target = format!("http://127.0.0.1:{other}/");
        let (port, _) = server(Router::new().route(
            "/",
            get(move || {
                let t = target.clone();
                async move { (axum::http::StatusCode::FOUND, [("location", t)]) }
            }),
        ))
        .await;

        let base = Url::parse(&format!("http://127.0.0.1:{port}/")).unwrap();
        let info = prober()
            .probe(&base, None, &[], &scope_with(&[port]), &limits(None))
            .await
            .unwrap();
        assert_eq!(info.status, 302);
        assert_eq!(
            info.blocked_redirects,
            vec![format!("http://127.0.0.1:{other}/")]
        );
        assert_eq!(
            other_hits.load(Ordering::SeqCst),
            0,
            "połączenie poza zakresem"
        );

        // ten sam port w zakresie: przekierowanie wykonane
        let both = scope_with(&[port, other]);
        let info = prober()
            .probe(&base, None, &[], &both, &limits(None))
            .await
            .unwrap();
        assert_eq!(info.status, 200);
        assert_eq!(other_hits.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn foreign_host_redirect_and_path_outside_origin_are_blocked() {
        let (port, hits) = server(Router::new().route(
            "/",
            get(|| async {
                (
                    axum::http::StatusCode::FOUND,
                    [("location", "http://example.com/")],
                )
            }),
        ))
        .await;
        let base = Url::parse(&format!("http://127.0.0.1:{port}/")).unwrap();
        let paths = vec!["//example.com/x".to_string(), "/ok".to_string()];
        let info = prober()
            .probe(&base, None, &paths, &scope_with(&[port]), &limits(None))
            .await
            .unwrap();
        assert_eq!(info.blocked_redirects, vec!["http://example.com/"]);
        assert!(!info.extra_paths.contains_key("//example.com/x"));
        assert!(info.extra_paths.contains_key("/ok"));
        assert_eq!(hits.load(Ordering::SeqCst), 2, "strona główna + /ok");
    }

    #[tokio::test]
    async fn large_bodies_are_cut_while_reading() {
        let (port, _) = server(
            Router::new()
                .route("/", get(|| async { huge() }))
                .route("/big", get(|| async { huge() })),
        )
        .await;
        let base = Url::parse(&format!("http://127.0.0.1:{port}/")).unwrap();
        let info = prober()
            .probe(
                &base,
                None,
                &["/big".into()],
                &scope_with(&[port]),
                &limits(None),
            )
            .await
            .unwrap();
        assert_eq!(info.body.len(), BODY_LIMIT);
        assert_eq!(
            info.body_sha256.as_deref(),
            Some(sha256_hex(&vec![b'a'; BODY_LIMIT]).as_str())
        );
        assert_eq!(info.extra_paths["/big"].body.len(), BODY_LIMIT);
    }

    #[tokio::test]
    async fn deadline_interrupts_slow_response_and_blocks_next() {
        let (port, hits) = server(Router::new().route(
            "/",
            get(|| async {
                tokio::time::sleep(Duration::from_secs(10)).await;
                "wolno"
            }),
        ))
        .await;
        let base = Url::parse(&format!("http://127.0.0.1:{port}/")).unwrap();
        let started = std::time::Instant::now();
        let deadline = Instant::now() + Duration::from_millis(300);
        let err = prober()
            .probe(
                &base,
                None,
                &[],
                &scope_with(&[port]),
                &limits(Some(deadline)),
            )
            .await
            .unwrap_err();
        assert!(is_interrupted(&err));
        assert!(started.elapsed() < Duration::from_secs(3));

        let before = hits.load(Ordering::SeqCst);
        let err = prober()
            .probe(
                &base,
                None,
                &[],
                &scope_with(&[port]),
                &limits(Some(deadline)),
            )
            .await
            .unwrap_err();
        assert!(is_interrupted(&err));
        assert_eq!(
            hits.load(Ordering::SeqCst),
            before,
            "po terminie nowe żądanie nie startuje"
        );
    }

    #[test]
    fn title_and_http_detection() {
        assert_eq!(
            extract_title("<TITLE>\n Panel   logowania </title>").as_deref(),
            Some("Panel logowania")
        );
        let mut o = Observation::new("10.0.0.1".into(), 8443, "tcp".into());
        o.service = Some("https-alt".into());
        assert_eq!(http_url_for(&o).unwrap().as_str(), "https://10.0.0.1:8443/");
        assert!(http_url_for(&Observation::new("10.0.0.1".into(), 22, "tcp".into())).is_none());
        let _ = PortSet::parse("80").unwrap();
    }
}
