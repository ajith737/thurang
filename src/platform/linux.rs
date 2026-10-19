use std::net::Ipv4Addr;
use std::path::Path;

use anyhow::Result;
use ipnet::{IpNet, Ipv4Net};

use super::{default_gateway, run, Journal, TunIf, Undo};

pub fn add_route(j: &mut Journal, tun: &TunIf, net: IpNet) -> Result<()> {
    let fam = if net.addr().is_ipv6() { "-6" } else { "-4" };
    let n = net.to_string();
    j.exec(&["ip", fam, "route", "replace", &n, "dev", &tun.name], Some(&["ip", fam, "route", "del", &n, "dev", &tun.name]))?;
    Ok(())
}

pub fn add_bypass_route(j: &mut Journal, host: Ipv4Addr, iface: &netdev::Interface) -> Result<()> {
    let h = format!("{host}/32");
    let mut cmd = vec!["ip", "-4", "route", "replace", &h];
    let gw = default_gateway(iface).map(|g| g.to_string());
    if let Some(gw) = &gw {
        cmd.extend(["via", gw.as_str()]);
    }
    cmd.extend(["dev", iface.name.as_str()]);
    j.exec(&cmd, Some(&["ip", "-4", "route", "del", &h]))?;
    Ok(())
}

pub fn set_dns(j: &mut Journal, tun: &TunIf, dns: Ipv4Addr) -> Result<()> {
    let d = dns.to_string();
    let resolved = run(&["resolvectl", "status"]).is_ok();
    if resolved {
        j.exec(&["resolvectl", "dns", &tun.name, &d], Some(&["resolvectl", "revert", &tun.name]))?;
        // "~." makes this link the default route for all DNS queries.
        j.exec(&["resolvectl", "domain", &tun.name, "~."], None)?;
        let _ = run(&["resolvectl", "default-route", &tun.name, "yes"]);
        let _ = run(&["resolvectl", "flush-caches"]);
        return Ok(());
    }
    let target = Path::new("/etc/resolv.conf");
    // resolv.conf is often a symlink (systemd, NetworkManager); put the link back, not a copy.
    if std::fs::symlink_metadata(target)?.file_type().is_symlink() {
        let link = std::fs::read_link(target)?;
        j.push(Undo::RestoreSymlink { link, target: target.to_path_buf() });
    } else {
        let backup = crate::paths::home().join("resolv.conf.backup");
        std::fs::copy(target, &backup)?;
        j.push(Undo::RestoreFile { backup, target: target.to_path_buf() });
    }
    let _ = std::fs::remove_file(target);
    std::fs::write(target, format!("# managed by thurang\nnameserver {d}\n"))?;
    Ok(())
}

fn sysctl_set(j: &mut Journal, key: &str, value: &str) -> Result<()> {
    let old = run(&["sysctl", "-n", key])?.trim().to_string();
    if old != value {
        let restore = format!("{key}={old}");
        j.exec(&["sysctl", "-w", &format!("{key}={value}")], Some(&["sysctl", "-w", &restore]))?;
    }
    Ok(())
}

pub fn enable_forwarding(j: &mut Journal, _tun: &TunIf, _egress: &netdev::Interface) -> Result<()> {
    sysctl_set(j, "net.ipv4.ip_forward", "1")
}

/// Adds an iptables rule (`-A`/`-I`) and records its deletion.
fn iptables(j: &mut Journal, table: &str, op: &str, rule: &[&str]) -> Result<()> {
    let mut add = vec!["iptables", "-t", table, op];
    add.extend_from_slice(rule);
    add.extend(["-m", "comment", "--comment", "thurang"]);
    let mut del = add.clone();
    del[3] = "-D";
    j.exec(&add, Some(&del))?;
    Ok(())
}

/// Masquerades tunnel traffic leaving through any other interface, so
/// advertised subnets on secondary NICs work too.
pub fn enable_nat(j: &mut Journal, tun: &TunIf, subnet: Ipv4Net, _egress: &netdev::Interface) -> Result<()> {
    let s = subnet.to_string();
    let t = tun.name.as_str();
    iptables(j, "nat", "-A", &["POSTROUTING", "-s", &s, "!", "-o", t, "-j", "MASQUERADE"])?;
    iptables(j, "filter", "-I", &["FORWARD", "-i", t, "-j", "ACCEPT"])?;
    iptables(j, "filter", "-I", &["FORWARD", "-o", t, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"])?;
    iptables(j, "mangle", "-A", &["FORWARD", "-o", t, "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--clamp-mss-to-pmtu"])?;
    Ok(())
}
