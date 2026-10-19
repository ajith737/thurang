use std::net::Ipv4Addr;

use anyhow::Result;
use ipnet::{IpNet, Ipv4Net};

use super::{default_gateway, powershell, run, Journal, TunIf, Undo};

fn as_refs(v: &[String]) -> Vec<&str> {
    v.iter().map(String::as_str).collect()
}

pub fn add_route(j: &mut Journal, tun: &TunIf, net: IpNet) -> Result<()> {
    let fam = if net.addr().is_ipv6() { "ipv6" } else { "ipv4" };
    let hop = if net.addr().is_ipv6() { "nexthop=::" } else { "nexthop=0.0.0.0" };
    let n = net.to_string();
    let idx = format!("interface={}", tun.index);
    j.exec(
        &["netsh", "interface", fam, "add", "route", &n, &idx, hop, "metric=1", "store=active"],
        Some(&["netsh", "interface", fam, "delete", "route", &n, &idx, hop, "store=active"]),
    )?;
    Ok(())
}

pub fn add_bypass_route(j: &mut Journal, host: Ipv4Addr, iface: &netdev::Interface) -> Result<()> {
    let h = format!("{host}/32");
    let idx = format!("interface={}", iface.index);
    let hop = format!("nexthop={}", default_gateway(iface).map(|g| g.to_string()).unwrap_or_else(|| "0.0.0.0".into()));
    j.exec(
        &["netsh", "interface", "ipv4", "add", "route", &h, &idx, &hop, "store=active"],
        Some(&["netsh", "interface", "ipv4", "delete", "route", &h, &idx, &hop, "store=active"]),
    )?;
    Ok(())
}

pub fn set_dns(j: &mut Journal, tun: &TunIf, dns: Ipv4Addr) -> Result<()> {
    let d = dns.to_string();
    let name = format!("name={}", tun.index);
    run(&["netsh", "interface", "ipv4", "set", "dnsservers", &name, "source=static", &format!("address={d}"), "register=none", "validate=no"])?;
    run(&["netsh", "interface", "ipv4", "set", "interface", &tun.index.to_string(), "metric=1"])?;
    // Windows queries all adapters in parallel; an NRPT rule for "." forces the tunnel resolver.
    let add = powershell(&format!("Add-DnsClientNrptRule -Namespace '.' -NameServers '{d}' -Comment 'thurang'"));
    let del = powershell("Get-DnsClientNrptRule | Where-Object Comment -eq 'thurang' | Remove-DnsClientNrptRule -Force");
    let _ = run(&as_refs(&del));
    j.exec(&as_refs(&add), Some(&as_refs(&del)))?;
    let _ = run(&["ipconfig", "/flushdns"]);
    Ok(())
}

pub fn enable_forwarding(j: &mut Journal, tun: &TunIf, egress: &netdev::Interface) -> Result<()> {
    for idx in [tun.index, egress.index] {
        let i = idx.to_string();
        // Leave interfaces that already forward alone, so rollback doesn't disable them.
        let state = run(&["netsh", "interface", "ipv4", "show", "interface", &i]).unwrap_or_default();
        if state.lines().any(|l| l.trim_start().starts_with("Forwarding") && l.trim_end().ends_with("enabled")) {
            continue;
        }
        j.exec(
            &["netsh", "interface", "ipv4", "set", "interface", &i, "forwarding=enabled"],
            Some(&["netsh", "interface", "ipv4", "set", "interface", &i, "forwarding=disabled"]),
        )?;
    }
    Ok(())
}

/// WinNAT (Windows 10 / Server 2016+).
pub fn enable_nat(j: &mut Journal, _tun: &TunIf, subnet: Ipv4Net, _egress: &netdev::Interface) -> Result<()> {
    let del = powershell("Remove-NetNat -Name thurang -Confirm:$false -ErrorAction SilentlyContinue");
    let _ = run(&as_refs(&del));
    let add = powershell(&format!("New-NetNat -Name thurang -InternalIPInterfaceAddressPrefix {subnet}"));
    run(&as_refs(&add))?;
    j.push(Undo::Cmd(del));
    Ok(())
}
