//! LAN discovery of servers via mDNS.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use anyhow::{bail, Result};
use mdns_sd::{ServiceDaemon, ServiceEvent, ServiceInfo};

use crate::proto::MDNS_SERVICE;

pub fn hostname() -> String {
    #[cfg(unix)]
    {
        let mut buf = [0u8; 256];
        // SAFETY: buf is valid for writes of its length.
        if unsafe { libc::gethostname(buf.as_mut_ptr() as *mut libc::c_char, buf.len()) } == 0 {
            let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
            let name = String::from_utf8_lossy(&buf[..end]).to_string();
            return name.split('.').next().unwrap_or("thurang").to_string();
        }
        "thurang".into()
    }
    #[cfg(windows)]
    {
        std::env::var("COMPUTERNAME").unwrap_or_else(|_| "thurang".into())
    }
}

/// Advertises the enrollment port. Keep the returned daemon alive.
pub fn advertise(enroll_port: u16, ips: Vec<IpAddr>) -> Result<ServiceDaemon> {
    let mdns = ServiceDaemon::new()?;
    let host = hostname();
    let mut props = HashMap::new();
    props.insert("v".to_string(), crate::proto::PROTOCOL_VERSION.to_string());
    let info = ServiceInfo::new(MDNS_SERVICE, &host, &format!("{host}.local."), &ips[..], enroll_port, props)?;
    let info = if ips.is_empty() { info.enable_addr_auto() } else { info };
    mdns.register(info)?;
    tracing::info!("advertising {host} via mDNS");
    Ok(mdns)
}

/// Finds the first server on the LAN (blocking).
pub fn discover(timeout: Duration) -> Result<(String, SocketAddr)> {
    let mdns = ServiceDaemon::new()?;
    let rx = mdns.browse(MDNS_SERVICE)?;
    let deadline = Instant::now() + timeout;
    while let Some(left) = deadline.checked_duration_since(Instant::now()) {
        match rx.recv_timeout(left) {
            Ok(ServiceEvent::ServiceResolved(info)) => {
                if let Some(ip) = info.get_addresses_v4().into_iter().next() {
                    let _ = mdns.shutdown();
                    return Ok((info.get_hostname().trim_end_matches('.').to_string(), SocketAddr::new(IpAddr::V4(*ip), info.get_port())));
                }
            }
            Ok(_) => {}
            Err(_) => break,
        }
    }
    let _ = mdns.shutdown();
    bail!("no thurang server found on the LAN; pass its address, e.g. `thurang join 192.168.1.10 --otp ...`")
}
