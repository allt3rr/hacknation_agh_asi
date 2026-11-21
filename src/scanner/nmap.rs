//! Uruchamianie nmap dla jednej podgrupy adresów i parsowanie wyniku XML.
//! Ten sam XML można też wysłać do DefectDojo jako "Nmap Scan".

use crate::model::Observation;
use anyhow::{bail, Context, Result};
use serde::Deserialize;
use std::process::Stdio;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

#[derive(Debug, Clone)]
pub struct NmapOptions {
    pub binary: String,
    pub ports: Option<String>,
    pub top_ports: u32,
    /// limit pakietów/s dla JEDNEGO procesu (global_max_rate / concurrency)
    pub max_rate: u32,
    pub host_timeout: String,
    pub extra_args: Vec<String>,
}

#[derive(Debug, Default)]
pub struct ChunkResult {
    pub live_hosts: Vec<String>,
    pub observations: Vec<Observation>,
}

impl NmapOptions {
    pub fn build_args(&self) -> Vec<String> {
        let mut a: Vec<String> = [
            "-oX", "-", // XML na stdout
            "-iL", "-", // cele ze stdin (bez limitu długości linii poleceń)
            "-sV", "--version-light", "--open",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        a.push("--max-rate".into());
        a.push(self.max_rate.to_string());
        a.push("--host-timeout".into());
        a.push(self.host_timeout.clone());
        match &self.ports {
            Some(p) => {
                a.push("-p".into());
                a.push(p.clone());
            }
            None => {
                a.push("--top-ports".into());
                a.push(self.top_ports.to_string());
            }
        }
        a.extend(self.extra_args.iter().cloned());
        a
    }
}

/// Skanuje podgrupę. Dzięki `kill_on_drop(true)` proces nmap jest zabijany,
/// gdy future zostanie porzucony, np. po przekroczeniu okna czasowego.
pub async fn run_chunk(opts: &NmapOptions, targets: &[String]) -> Result<ChunkResult> {
    let mut child = Command::new(&opts.binary)
        .args(opts.build_args())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .with_context(|| format!("Nie można uruchomić '{}' (czy nmap jest zainstalowany?)", opts.binary))?;

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
        bail!("nmap zakończył się błędem: {}", String::from_utf8_lossy(&out.stderr).trim());
    }
    parse_xml(&String::from_utf8_lossy(&out.stdout))
}

// --- Struktury XML nmap (tylko potrzebne pola) ---

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
        let hostname = h.hostnames.and_then(|hn| hn.names.into_iter().next()).map(|n| n.name);
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
    <hostnames><hostname name="web.lab" type="PTR"/></hostnames>
    <ports>
      <extraports state="closed" count="998"/>
      <port protocol="tcp" portid="80"><state state="open"/><service name="http" product="nginx" version="1.24.0"/></port>
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
        assert_eq!(r.observations[1].tunnel.as_deref(), Some("ssl"));
        assert_eq!(r.observations[0].hostname.as_deref(), Some("web.lab"));
    }
}
