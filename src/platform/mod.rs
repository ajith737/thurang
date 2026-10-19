//! OS integration: routes, DNS, IP forwarding and NAT.
//!
//! Every change is recorded in a [`Journal`] together with the command that
//! reverts it, persisted to disk, and undone on shutdown — or on the next
//! start if the process crashed.

use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{bail, Context, Result};
use ipnet::{IpNet, Ipv4Net};
use serde::{Deserialize, Serialize};

use crate::proto::{NetConfig, UpOptions};

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::*;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
pub use macos::*;
#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use windows::*;

/// The tunnel interface as the OS sees it.
#[derive(Debug, Clone)]
pub struct TunIf {
    pub name: String,
    #[allow(dead_code)]
    pub index: u32,
    #[allow(dead_code)]
    pub ip: Ipv4Addr,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Undo {
    Cmd(Vec<String>),
    RestoreFile { backup: PathBuf, target: PathBuf },
    RestoreSymlink { link: PathBuf, target: PathBuf },
}

pub struct Journal {
    path: PathBuf,
    entries: Vec<Undo>,
}

impl Journal {
    /// Opens the journal, first reverting anything left by a previous crash.
    pub fn open(path: &Path) -> Result<Self> {
        let entries: Vec<Undo> = crate::config::load_json(path)?;
        let mut j = Journal { path: path.to_path_buf(), entries };
        if !j.entries.is_empty() {
            tracing::warn!("reverting {} system changes left by a previous run", j.entries.len());
            j.rollback();
        }
        Ok(j)
    }

    fn save(&self) {
        if let Err(e) = crate::config::save_json(&self.path, &self.entries) {
            tracing::error!("saving journal: {e:#}");
        }
    }

    pub fn push(&mut self, undo: Undo) {
        self.entries.push(undo);
        self.save();
    }

    /// Runs `cmd`; on success records `undo` to be run at rollback.
    pub fn exec(&mut self, cmd: &[&str], undo: Option<&[&str]>) -> Result<String> {
        let out = run(cmd)?;
        if let Some(u) = undo {
            self.push(Undo::Cmd(u.iter().map(|s| s.to_string()).collect()));
        }
        Ok(out)
    }

    pub fn rollback(&mut self) {
        while let Some(u) = self.entries.pop() {
            match &u {
                Undo::Cmd(c) => {
                    let args: Vec<&str> = c.iter().map(String::as_str).collect();
                    if let Err(e) = run(&args) {
                        tracing::debug!("undo {:?}: {e:#}", c);
                    }
                }
                Undo::RestoreFile { backup, target } => {
                    if let Err(e) = std::fs::copy(backup, target) {
                        tracing::warn!("restoring {}: {e}", target.display());
                    }
                    let _ = std::fs::remove_file(backup);
                }
                Undo::RestoreSymlink { link, target } => {
                    let _ = std::fs::remove_file(target);
                    #[cfg(unix)]
                    if let Err(e) = std::os::unix::fs::symlink(link, target) {
                        tracing::warn!("restoring {}: {e}", target.display());
                    }
                    #[cfg(not(unix))]
                    let _ = link;
                }
            }
            self.save();
        }
        let _ = std::fs::remove_file(&self.path);
    }
}

pub fn run(cmd: &[&str]) -> Result<String> {
    tracing::debug!("exec: {}", cmd.join(" "));
    let out = Command::new(cmd[0])
        .args(&cmd[1..])
        .output()
        .with_context(|| format!("running {}", cmd[0]))?;
    if !out.status.success() {
        bail!(
            "`{}` failed: {}{}",
            cmd.join(" "),
            String::from_utf8_lossy(&out.stderr).trim(),
            String::from_utf8_lossy(&out.stdout).trim()
        );
    }
    let mut s = String::from_utf8_lossy(&out.stdout).to_string();
    s.push_str(&String::from_utf8_lossy(&out.stderr));
    Ok(s)
}

#[cfg(windows)]
pub fn powershell(script: &str) -> Vec<String> {
    ["powershell", "-NoProfile", "-NonInteractive", "-Command", script].iter().map(|s| s.to_string()).collect()
}

/// Physical interface carrying the default route.
pub fn default_interface() -> Result<netdev::Interface> {
    netdev::get_default_interface().map_err(|e| anyhow::anyhow!("no default interface: {e}"))
}

pub fn find_interface(name: &str) -> Result<netdev::Interface> {
    netdev::get_interfaces()
        .into_iter()
        .find(|i| i.name == name || i.friendly_name.as_deref() == Some(name))
        .with_context(|| format!("interface {name} not found"))
}

/// IPv4 subnets directly attached to this host (excluding the tunnel).
pub fn local_subnets(exclude_if: &str) -> Vec<Ipv4Net> {
    netdev::get_interfaces()
        .into_iter()
        .filter(|i| i.is_up() && !i.is_loopback() && i.name != exclude_if)
        .flat_map(|i| i.ipv4.into_iter())
        .filter(|n| n.prefix_len() < 32)
        .map(|n| n.trunc())
        .collect()
}

pub fn default_gateway(iface: &netdev::Interface) -> Option<IpAddr> {
    iface.gateway.as_ref()?.ipv4.first().map(|ip| IpAddr::V4(*ip))
}

/// Routes a client installs for a given server config and options.
#[derive(Debug, Default, PartialEq)]
pub struct RoutePlan {
    pub routes: Vec<IpNet>,
    /// Server endpoint needs a host route outside the tunnel.
    pub bypass_endpoint: bool,
    /// Advertised routes skipped because the client is already on that network.
    pub skipped: Vec<Ipv4Net>,
}

pub fn plan_routes(net: &NetConfig, opts: &UpOptions, endpoint: Ipv4Addr, local: &[Ipv4Net]) -> RoutePlan {
    let mut plan = RoutePlan::default();
    let mut tunneled: Vec<Ipv4Net> = Vec::new();
    if opts.accept_routes {
        for r in &net.advertised_routes {
            if local.iter().any(|l| l.contains(r)) {
                plan.skipped.push(*r);
            } else {
                tunneled.push(*r);
            }
        }
    }
    if opts.exit_node {
        // Two /1 halves override the default route without replacing it.
        tunneled.push("0.0.0.0/1".parse().unwrap());
        tunneled.push("128.0.0.0/1".parse().unwrap());
    }
    let on_link = local.iter().any(|l| l.contains(&endpoint));
    plan.bypass_endpoint = !on_link && tunneled.iter().any(|r| r.contains(&endpoint));
    plan.routes = tunneled.into_iter().map(IpNet::V4).collect();
    if opts.exit_node {
        // Blackhole IPv6 into the tunnel (the engine drops it) so it can't leak.
        plan.routes.push("::/1".parse().unwrap());
        plan.routes.push("8000::/1".parse().unwrap());
    }
    plan
}

#[cfg(test)]
mod tests {
    use super::*;

    fn net() -> NetConfig {
        NetConfig {
            subnet: "100.64.0.0/24".parse().unwrap(),
            server_ip: "100.64.0.1".parse().unwrap(),
            advertised_routes: vec!["192.168.1.0/24".parse().unwrap(), "10.20.0.0/16".parse().unwrap()],
            exit_node_available: true,
            dns: None,
            magic_domain: "thurang".into(),
        }
    }

    #[test]
    fn routes_only() {
        let local = vec!["192.168.1.0/24".parse().unwrap()];
        let opts = UpOptions { accept_routes: true, ..Default::default() };
        let p = plan_routes(&net(), &opts, "192.168.1.5".parse().unwrap(), &local);
        assert_eq!(p.routes, vec!["10.20.0.0/16".parse::<IpNet>().unwrap()]);
        assert_eq!(p.skipped, vec!["192.168.1.0/24".parse::<Ipv4Net>().unwrap()]);
        assert!(!p.bypass_endpoint);
    }

    #[test]
    fn exit_node_on_link_server() {
        let local = vec!["192.168.1.0/24".parse().unwrap()];
        let opts = UpOptions { exit_node: true, ..Default::default() };
        let p = plan_routes(&net(), &opts, "192.168.1.5".parse().unwrap(), &local);
        assert_eq!(p.routes.len(), 4);
        assert!(!p.bypass_endpoint);
    }

    #[test]
    fn exit_node_routed_server_needs_bypass() {
        let local = vec!["192.168.2.0/24".parse().unwrap()];
        let opts = UpOptions { exit_node: true, ..Default::default() };
        let p = plan_routes(&net(), &opts, "192.168.1.5".parse().unwrap(), &local);
        assert!(p.bypass_endpoint);
    }

    #[test]
    fn advertised_route_covering_endpoint_needs_bypass() {
        let local = vec!["192.168.2.0/24".parse().unwrap()];
        let mut n = net();
        n.advertised_routes = vec!["10.0.0.0/8".parse().unwrap()];
        let opts = UpOptions { accept_routes: true, ..Default::default() };
        let p = plan_routes(&n, &opts, "10.1.1.1".parse().unwrap(), &local);
        assert!(p.bypass_endpoint);
    }
}
