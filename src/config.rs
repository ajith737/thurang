//! Persistent configuration: server settings, enrolled peers, client pairing, keys.

use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;

use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use boringtun::x25519::{PublicKey, StaticSecret};
use ipnet::Ipv4Net;
use rand::RngCore;
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::proto::{self, NetConfig};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// UDP address for WireGuard.
    pub listen: SocketAddr,
    /// TCP port for OTP enrollment.
    pub enroll_port: u16,
    /// Tunnel address pool; the first host is the server.
    pub subnet: Ipv4Net,
    /// Upstream resolvers for the server's DNS forwarder. Empty disables DNS.
    #[serde(default)]
    pub dns_upstreams: Vec<IpAddr>,
    /// Peers resolve as `<name>.<magic_domain>` through the server's DNS.
    #[serde(default = "default_magic_domain")]
    pub magic_domain: String,
    /// LAN subnets reachable through the server.
    #[serde(default)]
    pub advertise_routes: Vec<Ipv4Net>,
    /// Allow clients to send all traffic through this node.
    #[serde(default)]
    pub exit_node: bool,
    /// Interface used for NAT. Autodetected from the default route when unset.
    #[serde(default)]
    pub egress_interface: Option<String>,
    /// Advertise the server on the LAN via mDNS.
    #[serde(default = "default_true")]
    pub mdns: bool,
}

fn default_magic_domain() -> String {
    "thurang".into()
}

fn default_true() -> bool {
    true
}

impl ServerConfig {
    pub fn server_ip(&self) -> Ipv4Addr {
        self.subnet.hosts().next().expect("subnet has no hosts")
    }

    pub fn net_config(&self) -> NetConfig {
        NetConfig {
            subnet: self.subnet,
            server_ip: self.server_ip(),
            advertised_routes: self.advertise_routes.clone(),
            exit_node_available: self.exit_node,
            dns: (!self.dns_upstreams.is_empty()).then(|| self.server_ip()),
            magic_domain: self.magic_domain.clone(),
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.subnet.prefix_len() > 30 {
            bail!("subnet {} is too small", self.subnet);
        }
        if self.listen.port() == self.enroll_port {
            bail!("WireGuard and enrollment ports must differ");
        }
        if !valid_label(&self.magic_domain) {
            bail!("magic_domain must be a single DNS label, e.g. \"thurang\"");
        }
        Ok(())
    }
}

impl Default for ServerConfig {
    fn default() -> Self {
        ServerConfig {
            listen: SocketAddr::from(([0, 0, 0, 0], proto::DEFAULT_WG_PORT)),
            enroll_port: proto::DEFAULT_ENROLL_PORT,
            subnet: "100.64.0.0/24".parse().unwrap(),
            dns_upstreams: vec![],
            magic_domain: default_magic_domain(),
            advertise_routes: vec![],
            exit_node: false,
            egress_interface: None,
            mdns: true,
        }
    }
}

/// DNS name of the server itself; peers can't use it.
pub const RESERVED_NAME: &str = "server";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PeerRecord {
    pub name: String,
    pub public_key: String,
    pub ip: Ipv4Addr,
}

/// Enrolled clients, stored on the server.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PeerList {
    pub peers: Vec<PeerRecord>,
}

impl PeerList {
    /// Adds a peer. A device re-pairing with the same key keeps its address;
    /// a name already used by a different key gets a numeric suffix, so one
    /// device can never take over another's address or DNS name.
    pub fn enroll(&mut self, subnet: Ipv4Net, server_ip: Ipv4Addr, name: &str, public_key: &str) -> Result<PeerRecord> {
        let name = self.unique_name(name, public_key);
        if let Some(p) = self.peers.iter_mut().find(|p| p.public_key == public_key) {
            p.name = name;
            return Ok(p.clone());
        }
        let ip = subnet
            .hosts()
            .find(|ip| *ip != server_ip && !self.peers.iter().any(|p| p.ip == *ip))
            .context("tunnel subnet is full")?;
        let rec = PeerRecord { name, public_key: public_key.to_string(), ip };
        self.peers.push(rec.clone());
        Ok(rec)
    }

    fn unique_name(&self, base: &str, public_key: &str) -> String {
        let taken = |n: &str| n == RESERVED_NAME || self.peers.iter().any(|p| p.name == n && p.public_key != public_key);
        if !taken(base) {
            return base.to_string();
        }
        let base = &base[..base.len().min(56)];
        (2..).map(|i| format!("{base}-{i}")).find(|n| !taken(n)).expect("unbounded")
    }

    pub fn remove(&mut self, name: &str) -> Option<PeerRecord> {
        let idx = self.peers.iter().position(|p| p.name == name)?;
        Some(self.peers.remove(idx))
    }
}

/// What a client learned when pairing with a server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientConfig {
    pub name: String,
    pub server_public_key: String,
    /// Server's WireGuard UDP endpoint.
    pub server_endpoint: SocketAddr,
    pub ip: Ipv4Addr,
    /// Last network config received from the server (refreshed on every `up`).
    pub net: NetConfig,
}

/// Turns a free-form name into a DNS label.
pub fn sanitize_name(name: &str) -> String {
    let s: String = name
        .to_ascii_lowercase()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect();
    let s = s.trim_matches('-');
    let s = if s.len() > 63 { &s[..63] } else { s };
    if s.is_empty() {
        "client".into()
    } else {
        s.to_string()
    }
}

fn valid_label(s: &str) -> bool {
    !s.is_empty() && s.len() <= 63 && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
}

pub fn load_toml<T: DeserializeOwned>(path: &Path) -> Result<T> {
    let text = fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))
}

pub fn save_toml<T: Serialize>(path: &Path, v: &T) -> Result<()> {
    write_atomic(path, toml::to_string_pretty(v)?.as_bytes(), false)
}

pub fn load_json<T: DeserializeOwned + Default>(path: &Path) -> Result<T> {
    match fs::read(path) {
        Ok(data) => serde_json::from_slice(&data).with_context(|| format!("parsing {}", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(T::default()),
        Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
    }
}

pub fn save_json<T: Serialize>(path: &Path, v: &T) -> Result<()> {
    write_atomic(path, &serde_json::to_vec_pretty(v)?, false)
}

/// Writes via a temp file + rename. `secret` restricts the file to its owner.
pub fn write_atomic(path: &Path, data: &[u8], secret: bool) -> Result<()> {
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    }
    let tmp = path.with_extension("tmp");
    {
        let mut opts = fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        if secret {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        use std::io::Write;
        let mut f = opts.open(&tmp).with_context(|| format!("writing {}", tmp.display()))?;
        f.write_all(data)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path).with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

/// Creates the state directory and makes sure only root/Administrators can
/// touch it. The journal in it holds commands that are replayed with full
/// privileges, so a directory other users can write to is a privilege
/// escalation. Refuses to run if someone else already planted files there.
pub fn secure_home() -> Result<()> {
    let home = crate::paths::home();
    fs::create_dir_all(&home).with_context(|| format!("creating {}", home.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        // SAFETY: geteuid has no preconditions.
        let me = unsafe { libc::geteuid() };
        let check = |p: &Path| -> Result<()> {
            let m = fs::symlink_metadata(p)?;
            if m.uid() != me {
                bail!("refusing to use {}: owned by uid {}, not {}", p.display(), m.uid(), me);
            }
            if !m.is_dir() && m.mode() & 0o022 != 0 {
                bail!("refusing to use {}: writable by other users", p.display());
            }
            Ok(())
        };
        check(&home)?;
        fs::set_permissions(&home, fs::Permissions::from_mode(0o700))?;
        for entry in fs::read_dir(&home)? {
            check(&entry?.path())?;
        }
    }
    #[cfg(windows)]
    {
        // Users may create files under %ProgramData% by default. Allow only
        // SYSTEM, Administrators and the current (elevated) user as owners,
        // then replace the ACL with SYSTEM + Administrators full control.
        let h = home.to_string_lossy().replace('\'', "''");
        let script = format!(
            "$ErrorActionPreference='Stop'; $ok=@('S-1-5-18','S-1-5-32-544',[Security.Principal.WindowsIdentity]::GetCurrent().User.Value); \
             $items=@(Get-Item -LiteralPath '{h}' -Force) + @(Get-ChildItem -LiteralPath '{h}' -Force -Recurse); \
             foreach($i in $items){{ $o=(Get-Acl -LiteralPath $i.FullName).GetOwner([Security.Principal.SecurityIdentifier]).Value; \
             if($ok -notcontains $o){{ Write-Output ('untrusted owner ' + $o + ' on ' + $i.FullName); exit 3 }} }}"
        );
        let out = std::process::Command::new("powershell")
            .args(["-NoProfile", "-NonInteractive", "-Command", &script])
            .output()
            .context("running powershell")?;
        if !out.status.success() {
            bail!(
                "refusing to use {}: {}",
                home.display(),
                String::from_utf8_lossy(&out.stdout).trim().to_string() + String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        let h = home.to_string_lossy().to_string();
        let out = std::process::Command::new("icacls")
            .args([h.as_str(), "/inheritance:r", "/grant:r", "*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F", "/T", "/C", "/Q"])
            .output()
            .context("running icacls")?;
        if !out.status.success() {
            bail!("restricting {}: {}", home.display(), String::from_utf8_lossy(&out.stdout).trim());
        }
    }
    Ok(())
}

pub fn encode_key(bytes: &[u8; 32]) -> String {
    B64.encode(bytes)
}

pub fn decode_key(s: &str) -> Result<[u8; 32]> {
    let v = B64.decode(s.trim()).context("invalid base64 key")?;
    v.try_into().map_err(|_| anyhow::anyhow!("key must be 32 bytes"))
}

pub fn public_key_of(secret: &StaticSecret) -> PublicKey {
    PublicKey::from(secret)
}

/// Loads a WireGuard private key, generating one on first use.
pub fn load_or_create_key(path: &Path) -> Result<StaticSecret> {
    match fs::read_to_string(path) {
        Ok(s) => Ok(StaticSecret::from(decode_key(&s)?)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let mut bytes = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut bytes);
            write_atomic(path, encode_key(&bytes).as_bytes(), true)?;
            Ok(StaticSecret::from(bytes))
        }
        Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enroll_allocates_and_reuses() {
        let subnet: Ipv4Net = "100.64.0.0/29".parse().unwrap();
        let server = Ipv4Addr::new(100, 64, 0, 1);
        let mut list = PeerList::default();
        let a = list.enroll(subnet, server, "a", "ka").unwrap();
        let b = list.enroll(subnet, server, "b", "kb").unwrap();
        assert_eq!(a.ip, Ipv4Addr::new(100, 64, 0, 2));
        assert_eq!(b.ip, Ipv4Addr::new(100, 64, 0, 3));
        // Same device re-pairing keeps its address, even under a new name.
        let a2 = list.enroll(subnet, server, "a-renamed", "ka").unwrap();
        assert_eq!(a2.ip, a.ip);
        assert_eq!(list.peers.len(), 2);
        list.remove("a-renamed");
        let c = list.enroll(subnet, server, "c", "kc").unwrap();
        assert_eq!(c.ip, a.ip);
    }

    #[test]
    fn names_cannot_be_taken_over() {
        let subnet: Ipv4Net = "100.64.0.0/24".parse().unwrap();
        let server = Ipv4Addr::new(100, 64, 0, 1);
        let mut list = PeerList::default();
        let a = list.enroll(subnet, server, "laptop", "k1").unwrap();
        let b = list.enroll(subnet, server, "laptop", "k2").unwrap();
        assert_eq!(b.name, "laptop-2");
        assert_ne!(b.ip, a.ip);
        assert_eq!(list.enroll(subnet, server, "server", "k3").unwrap().name, "server-2");
    }

    #[test]
    fn subnet_exhaustion() {
        let subnet: Ipv4Net = "100.64.0.0/30".parse().unwrap();
        let server = Ipv4Addr::new(100, 64, 0, 1);
        let mut list = PeerList::default();
        list.enroll(subnet, server, "a", "ka").unwrap();
        assert!(list.enroll(subnet, server, "b", "kb").is_err());
    }

    #[test]
    fn names_are_sanitized() {
        assert_eq!(sanitize_name("Kira's MacBook"), "kira-s-macbook");
        assert_eq!(sanitize_name("---"), "client");
    }

    #[test]
    fn config_roundtrip() {
        let c = ServerConfig {
            dns_upstreams: vec!["1.1.1.1".parse().unwrap()],
            advertise_routes: vec!["192.168.1.0/24".parse().unwrap()],
            ..Default::default()
        };
        let s = toml::to_string_pretty(&c).unwrap();
        let back: ServerConfig = toml::from_str(&s).unwrap();
        assert_eq!(back.net_config(), c.net_config());
        assert_eq!(back.net_config().dns, Some(Ipv4Addr::new(100, 64, 0, 1)));
    }
}
