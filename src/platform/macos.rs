use std::net::Ipv4Addr;

use anyhow::Result;
use ipnet::{IpNet, Ipv4Net};

use super::{default_gateway, run, Journal, TunIf};

pub fn add_route(j: &mut Journal, tun: &TunIf, net: IpNet) -> Result<()> {
    let fam = if net.addr().is_ipv6() { "-inet6" } else { "-inet" };
    let n = net.to_string();
    // Remove a stale route from an unclean exit before adding.
    let _ = run(&["route", "-q", "-n", "delete", fam, &n, "-interface", &tun.name]);
    j.exec(
        &["route", "-q", "-n", "add", fam, &n, "-interface", &tun.name],
        Some(&["route", "-q", "-n", "delete", fam, &n, "-interface", &tun.name]),
    )?;
    Ok(())
}

pub fn add_bypass_route(j: &mut Journal, host: Ipv4Addr, iface: &netdev::Interface) -> Result<()> {
    let h = host.to_string();
    let _ = run(&["route", "-q", "-n", "delete", "-inet", "-host", &h]);
    match default_gateway(iface) {
        Some(gw) => j.exec(
            &["route", "-q", "-n", "add", "-inet", "-host", &h, &gw.to_string()],
            Some(&["route", "-q", "-n", "delete", "-inet", "-host", &h]),
        )?,
        None => j.exec(
            &["route", "-q", "-n", "add", "-inet", "-host", &h, "-interface", &iface.name],
            Some(&["route", "-q", "-n", "delete", "-inet", "-host", &h]),
        )?,
    };
    Ok(())
}

fn network_services() -> Result<Vec<String>> {
    let out = run(&["networksetup", "-listallnetworkservices"])?;
    Ok(out
        .lines()
        .skip(1) // "An asterisk (*) denotes that a network service is disabled."
        .filter(|l| !l.is_empty() && !l.starts_with('*'))
        .map(str::to_string)
        .collect())
}

/// Points every network service at the tunnel resolver, restoring the old
/// servers (or DHCP-provided ones, via "Empty") on rollback.
pub fn set_dns(j: &mut Journal, _tun: &TunIf, dns: Ipv4Addr) -> Result<()> {
    let d = dns.to_string();
    for svc in network_services()? {
        let current = run(&["networksetup", "-getdnsservers", &svc]).unwrap_or_default();
        let mut old: Vec<String> = current
            .lines()
            .map(str::trim)
            .filter(|l| l.parse::<std::net::IpAddr>().is_ok())
            .map(str::to_string)
            .collect();
        if old.is_empty() {
            old.push("Empty".into());
        }
        let mut undo = vec!["networksetup", "-setdnsservers", svc.as_str()];
        undo.extend(old.iter().map(String::as_str));
        j.exec(&["networksetup", "-setdnsservers", &svc, &d], Some(&undo))?;
    }
    let _ = run(&["dscacheutil", "-flushcache"]);
    let _ = run(&["killall", "-HUP", "mDNSResponder"]);
    Ok(())
}

pub fn enable_forwarding(j: &mut Journal, _tun: &TunIf, _egress: &netdev::Interface) -> Result<()> {
    let old = run(&["sysctl", "-n", "net.inet.ip.forwarding"])?.trim().to_string();
    if old != "1" {
        let restore = format!("net.inet.ip.forwarding={old}");
        j.exec(&["sysctl", "-w", "net.inet.ip.forwarding=1"], Some(&["sysctl", "-w", &restore]))?;
    }
    Ok(())
}

/// NAT via a pf anchor under com.apple/, which the stock pf.conf already evaluates.
pub fn enable_nat(j: &mut Journal, _tun: &TunIf, subnet: Ipv4Net, egress: &netdev::Interface) -> Result<()> {
    let rules = format!("nat on {e} inet from {subnet} to any -> ({e})\n", e = egress.name);
    let file = crate::paths::home().join("pf-nat.conf");
    std::fs::write(&file, rules)?;
    let f = file.to_string_lossy().to_string();
    j.exec(&["pfctl", "-a", "com.apple/thurang", "-f", &f], Some(&["pfctl", "-a", "com.apple/thurang", "-F", "all"]))?;
    // -E takes a reference on pf being enabled; -X releases only ours.
    let out = run(&["pfctl", "-E"])?;
    if let Some(token) = out.lines().find_map(|l| l.trim().strip_prefix("Token : ")) {
        j.push(super::Undo::Cmd(vec!["pfctl".into(), "-X".into(), token.trim().into()]));
    }
    Ok(())
}
