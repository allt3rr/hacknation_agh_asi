//! Uruchamianie nmap dla jednej podgrupy i parsowanie wyniku XML.
//! Argumenty jako lista (bez powłoki), cele przez stdin (`-iL -`).

use anyhow::{bail, Context, Result};
use asi_core::model::Observation;
use serde::Deserialize;
use std::future::Future;
use std::process::Stdio;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

#[derive(Debug, Clone)]
pub struct NmapOptions {
    pub binary: String,
    pub ports: Option<String>,
    pub top_ports: u32,
    /// Limit pakietów/s jednego procesu (`global_max_rate / concurrency`).
    pub max_rate: u32,
    pub host_timeout: String,
}

#[derive(Debug, Default, Clone)]
pub struct ChunkResult {
    pub live_hosts: Vec<String>,
    pub observations: Vec<Observation>,
    /// Domeny-cele rozwiązane przez nmap: (domena, adres).
    pub resolved: Vec<(String, String)>,
}

/// Wykonawca jednej podgrupy. W produkcji `NmapRunner`, w testach atrapa.
pub trait ChunkRunner: Send + Sync + 'static {
    fn run(&self, targets: Vec<String>) -> impl Future<Output = Result<ChunkResult>> + Send;
}

pub struct NmapRunner(pub NmapOptions);

impl ChunkRunner for NmapRunner {
    fn run(&self, targets: Vec<String>) -> impl Future<Output = Result<ChunkResult>> + Send {
        let opts = self.0.clone();
        async move { run_chunk(&opts, &targets).await }
    }
}

impl NmapOptions {
    pub fn build_args(&self) -> Vec<String> {
        let mut a: Vec<String> = ["-oX", "-", "-iL", "-", "-sV", "--version-light", "--open"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        a.extend(["--max-rate".into(), self.max_rate.to_string()]);
        a.extend(["--host-timeout".into(), self.host_timeout.clone()]);
        match &self.ports {
            Some(p) => a.extend(["-p".into(), p.clone()]),
            None => a.extend(["--top-ports".into(), self.top_ports.to_string()]),
        }
        a
    }
}

/// `kill_on_drop(true)`: porzucenie future (termin, anulowanie) zabija proces nmap.
pub async fn run_chunk(opts: &NmapOptions, targets: &[String]) -> Result<ChunkResult> {
    let mut child = Command::new(&opts.binary)
        .args(opts.build_args())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .with_context(|| {
            format!(
                "Nie można uruchomić '{}' (czy nmap jest zainstalowany?)",
                opts.binary
            )
        })?;

    let mut stdin = child.stdin.take().context("brak stdin procesu nmap")?;
    let payload = targets.join("\n");
    let writer = tokio::spawn(async move {
        let r = stdin.write_all(payload.as_bytes()).await;
        drop(stdin);
        r
    });
    let out = child.wait_with_output().await?;
    let _ = writer.await;
    if !out.status.success() {
        bail!(
            "nmap zakończył się błędem: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    parse_xml(&String::from_utf8_lossy(&out.stdout))
}

#[derive(Deserialize)]
struct XRun {
    #[serde(rename = "host", default)]
    hosts: Vec<XHost>,
}

#[derive(Deserialize)]
struct XHost {
    status: XState,
    #[serde(rename = "address", default)]
    addresses: Vec<XAddr>,
    #[serde(default)]
    hostnames: Option<XHostnames>,
    #[serde(default)]
    ports: Option<XPorts>,
}

#[derive(Deserialize)]
struct XState {
    #[serde(rename = "@state")]
    state: String,
}

#[derive(Deserialize)]
struct XAddr {
    #[serde(rename = "@addr")]
    addr: String,
    #[serde(rename = "@addrtype")]
    addrtype: String,
}

#[derive(Deserialize)]
struct XHostnames {
    #[serde(rename = "hostname", default)]
    names: Vec<XHostname>,
}

#[derive(Deserialize)]
struct XHostname {
    #[serde(rename = "@name")]
    name: String,
    #[serde(rename = "@type", default)]
    kind: Option<String>,
}

#[derive(Deserialize)]
struct XPorts {
    #[serde(rename = "port", default)]
    ports: Vec<XPort>,
}

#[derive(Deserialize)]
struct XPort {
    #[serde(rename = "@protocol")]
    protocol: String,
    #[serde(rename = "@portid")]
    portid: u16,
    state: XState,
    #[serde(default)]
    service: Option<XService>,
}

#[derive(Deserialize)]
struct XService {
    #[serde(rename = "@name", default)]
    name: Option<String>,
    #[serde(rename = "@product", default)]
    product: Option<String>,
    #[serde(rename = "@version", default)]
    version: Option<String>,
    #[serde(rename = "@extrainfo", default)]
    extrainfo: Option<String>,
    #[serde(rename = "@tunnel", default)]
    tunnel: Option<String>,
    #[serde(rename = "cpe", default)]
    cpe: Vec<String>,
}

pub fn parse_xml(xml: &str) -> Result<ChunkResult> {
    let run: XRun = quick_xml::de::from_str(xml).context("Nie można sparsować XML z nmap")?;
    let mut res = ChunkResult::default();
    for h in run.hosts {
        if h.status.state != "up" {
            continue;
        }
        let Some(ip) = h
            .addresses
            .iter()
            .find(|a| a.addrtype == "ipv4" || a.addrtype == "ipv6")
            .map(|a| a.addr.clone())
        else {
            continue;
        };
        let names = h.hostnames.map(|hn| hn.names).unwrap_or_default();
        // `type="user"` = nazwa podana jako cel (domena), `PTR` = odwrotny DNS
        let user = names.iter().find(|n| n.kind.as_deref() == Some("user"));
        if let Some(n) = user {
            res.resolved.push((n.name.to_ascii_lowercase(), ip.clone()));
        }
        let hostname = user.or(names.first()).map(|n| n.name.clone());
        res.live_hosts.push(ip.clone());
        for p in h.ports.map(|p| p.ports).unwrap_or_default() {
            let mut o = Observation::new(ip.clone(), p.portid, p.protocol);
            o.hostname = hostname.clone();
            o.state = p.state.state;
            if let Some(s) = p.service {
                o.service = s.name;
                o.product = s.product;
                o.version = s.version;
                o.extra_info = s.extrainfo;
                o.tunnel = s.tunnel;
                o.cpe = s.cpe;
            }
            res.observations.push(o);
        }
    }
    Ok(res)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_sample_xml() {
        let xml = r#"<?xml version="1.0"?>
<nmaprun scanner="nmap">
  <host><status state="up" reason="syn-ack"/>
    <address addr="10.0.0.5" addrtype="ipv4"/>
    <hostnames><hostname name="web.lab" type="user"/><hostname name="ptr.lab" type="PTR"/></hostnames>
    <ports>
      <extraports state="closed" count="998"/>
      <port protocol="tcp" portid="80"><state state="open"/><service name="http" product="nginx" version="1.24.0"><cpe>cpe:/a:f5:nginx:1.24.0</cpe></service></port>
      <port protocol="tcp" portid="443"><state state="open"/><service name="http" tunnel="ssl"/></port>
    </ports>
  </host>
  <hosthint><status state="up"/></hosthint>
  <host><status state="down"/><address addr="10.0.0.6" addrtype="ipv4"/></host>
  <runstats><finished time="1"/></runstats>
</nmaprun>"#;
        let r = parse_xml(xml).unwrap();
        assert_eq!(r.live_hosts, vec!["10.0.0.5"]);
        assert_eq!(r.observations.len(), 2);
        assert_eq!(r.observations[0].product.as_deref(), Some("nginx"));
        assert_eq!(r.observations[0].cpe, vec!["cpe:/a:f5:nginx:1.24.0"]);
        assert!(r.observations[1].cpe.is_empty());
        assert_eq!(r.observations[1].tunnel.as_deref(), Some("ssl"));
        assert_eq!(r.observations[0].hostname.as_deref(), Some("web.lab"));
        assert_eq!(
            r.resolved,
            vec![("web.lab".to_string(), "10.0.0.5".to_string())]
        );
    }

    #[test]
    fn arguments_are_a_list_with_limits() {
        let opts = NmapOptions {
            binary: "nmap".into(),
            ports: Some("80,443".into()),
            top_ports: 100,
            max_rate: 125,
            host_timeout: "5m".into(),
        };
        let args = opts.build_args();
        assert!(args.windows(2).any(|w| w == ["--max-rate", "125"]));
        assert!(args.windows(2).any(|w| w == ["-p", "80,443"]));
        assert!(args.windows(2).any(|w| w == ["-iL", "-"]));
    }

    #[tokio::test]
    async fn missing_binary_is_an_error() {
        let opts = NmapOptions {
            binary: "nmap-nie-istnieje".into(),
            ports: None,
            top_ports: 10,
            max_rate: 10,
            host_timeout: "1m".into(),
        };
        assert!(run_chunk(&opts, &["127.0.0.1".into()]).await.is_err());
    }
}

/// Atrapa nmap do testów i trybu demonstracyjnego bez sieci: każdy cel odpowiada otwartym
/// portem `open_port` (albo podgrupa kończy się błędem).
#[derive(Debug, Clone, Default)]
pub struct FakeRunner {
    pub fail: bool,
    pub open_port: u16,
    pub delay: std::time::Duration,
}

impl ChunkRunner for FakeRunner {
    fn run(&self, targets: Vec<String>) -> impl Future<Output = Result<ChunkResult>> + Send {
        let me = self.clone();
        async move {
            tokio::time::sleep(me.delay).await;
            if me.fail {
                bail!("nmap: błąd testowy");
            }
            let mut r = ChunkResult::default();
            for t in targets {
                r.live_hosts.push(t.clone());
                let mut o = Observation::new(t, me.open_port, "tcp".into());
                o.service = Some("ssh".into());
                r.observations.push(o);
            }
            Ok(r)
        }
    }
}

/// Wykonawca wybierany w czasie działania (prawdziwy nmap albo atrapa w testach).
pub enum AnyRunner {
    Nmap(NmapRunner),
    Fake(FakeRunner),
}

impl ChunkRunner for AnyRunner {
    fn run(&self, targets: Vec<String>) -> impl Future<Output = Result<ChunkResult>> + Send {
        let fut: std::pin::Pin<Box<dyn Future<Output = Result<ChunkResult>> + Send>> = match self {
            AnyRunner::Nmap(r) => Box::pin(r.run(targets)),
            AnyRunner::Fake(r) => Box::pin(r.run(targets)),
        };
        fut
    }
}
