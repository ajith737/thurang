//! Client node: tunnel to the server, routes, DNS; managed by the daemon.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use ipnet::Ipv4Net;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::task::JoinSet;

use crate::config::{self, ClientConfig};
use crate::platform::{self, Journal, RoutePlan, TunIf};
use crate::proto::{IpcRequest, IpcResponse, NetConfig, UpOptions};
use crate::wg::{self, Engine, Policy};
use crate::{control, ipc, paths, util};

pub struct Session {
    cfg: ClientConfig,
    opts: UpOptions,
    engine: Arc<Engine>,
    tasks: JoinSet<()>,
    journal: Journal,
    tun: TunIf,
    plan: RoutePlan,
    dns: Option<Ipv4Addr>,
    _dev: Arc<tun_rs::AsyncDevice>,
}

/// ULA used only so IPv6 can be routed into (and dropped by) the tunnel.
fn blackhole_v6(ip: Ipv4Addr) -> Ipv6Addr {
    let o = ip.octets();
    Ipv6Addr::new(0xfd7a, 0x7e57, 0x7e57, 0, 0, 0, u16::from_be_bytes([o[0], o[1]]), u16::from_be_bytes([o[2], o[3]]))
}

/// Checks config pushed by the server before it touches routes or DNS.
fn validate_net(paired: &NetConfig, mut net: NetConfig) -> Result<NetConfig> {
    if net.subnet != paired.subnet || net.server_ip != paired.server_ip {
        bail!("server changed its tunnel subnet; pair again with `thurang join`");
    }
    if let Some(dns) = net.dns {
        if !net.subnet.contains(&dns) {
            bail!("server pushed DNS {dns} outside the tunnel; refusing (it would leak queries)");
        }
    }
    net.advertised_routes.retain(|r| {
        // A default route is the exit node's job, not an advertised subnet.
        let ok = r.prefix_len() > 0 && !r.contains(&net.server_ip);
        if !ok {
            tracing::warn!("ignoring advertised route {r}");
        }
        ok
    });
    Ok(net)
}

impl Session {
    pub async fn start(opts: UpOptions) -> Result<Session> {
        let mut cfg: ClientConfig =
            config::load_toml(&paths::client_config()).context("not paired yet; run `thurang join` first")?;
        if opts.exit_node && !cfg.net.exit_node_available {
            bail!("server does not offer an exit node (enable it with `thurang server init --exit-node`)");
        }
        let secret = config::load_or_create_key(&paths::client_key())?;
        let server_key = config::decode_key(&cfg.server_public_key)?;
        let journal = Journal::open(&paths::journal("client"))?;

        let v6 = opts.exit_node.then(|| (blackhole_v6(cfg.ip), 64));
        let dev = wg::create_tun(cfg.ip, cfg.net.subnet.prefix_len(), v6)?;
        let tun = TunIf { name: wg::tun_name(&dev), index: wg::tun_index(&dev), ip: cfg.ip };
        let udp = Arc::new(UdpSocket::bind(("0.0.0.0", 0)).await?);
        let engine = Engine::new(dev.clone(), udp, secret, Policy::Client { local_ip: cfg.ip, allow_any: false, allowed: vec![cfg.net.subnet] });
        engine.add_peer("server", server_key, cfg.net.server_ip, Some(cfg.server_endpoint), Some(25));
        let tasks = engine.start();
        engine.initiate().await;

        let mut session = Session {
            plan: RoutePlan::default(),
            dns: None,
            cfg: cfg.clone(),
            opts,
            engine,
            tasks,
            journal,
            tun,
            _dev: dev,
        };
        // Refresh routes/DNS from the server; also proves the tunnel works.
        match control::fetch(cfg.net.server_ip, Duration::from_secs(10)).await.and_then(|n| validate_net(&cfg.net, n)) {
            Ok(net) => {
                if net != cfg.net {
                    cfg.net = net;
                    config::save_toml(&paths::client_config(), &cfg)?;
                }
                session.cfg = cfg;
            }
            Err(e) => {
                session.stop();
                bail!("no response from server {} through the tunnel: {e:#}", cfg.server_endpoint);
            }
        }
        if let Err(e) = session.apply() {
            session.stop();
            return Err(e);
        }
        Ok(session)
    }

    fn apply(&mut self) -> Result<()> {
        let net = self.cfg.net.clone();
        if self.opts.exit_node && !net.exit_node_available {
            bail!("server no longer offers an exit node");
        }
        let endpoint = match self.cfg.server_endpoint.ip() {
            IpAddr::V4(v) => v,
            IpAddr::V6(_) => bail!("IPv6 server endpoints are not supported yet"),
        };
        let local = platform::local_subnets(&self.tun.name);
        let plan = platform::plan_routes(&net, &self.opts, endpoint, &local);
        for r in &plan.skipped {
            tracing::info!("not routing {r}: already directly connected");
        }
        if plan.bypass_endpoint {
            let iface = platform::default_interface()?;
            platform::add_bypass_route(&mut self.journal, endpoint, &iface).context("adding server bypass route")?;
        }
        for r in &plan.routes {
            platform::add_route(&mut self.journal, &self.tun, *r).with_context(|| format!("adding route {r}"))?;
        }
        let mut allowed: Vec<Ipv4Net> = vec![net.subnet];
        if self.opts.accept_routes {
            allowed.extend(net.advertised_routes.iter().copied());
        }
        self.engine.set_policy(Policy::Client { local_ip: self.cfg.ip, allow_any: self.opts.exit_node, allowed });
        if self.opts.accept_dns {
            match net.dns {
                Some(d) => {
                    platform::set_dns(&mut self.journal, &self.tun, d).context("configuring DNS")?;
                    self.dns = Some(d);
                }
                None => tracing::warn!("server has no DNS forwarder configured; leaving system DNS alone"),
            }
        }
        self.plan = plan;
        Ok(())
    }

    pub fn stop(mut self) {
        self.journal.rollback();
        self.tasks.abort_all();
    }

    pub async fn status(&self) -> String {
        let peer = self.engine.stats().await.into_iter().next();
        let c = &self.cfg;
        let mode = match (self.opts.exit_node, self.opts.accept_routes) {
            (true, _) => "exit node (all traffic)",
            (false, true) => "advertised routes",
            (false, false) => "tunnel subnet only",
        };
        let routes: Vec<String> = self.plan.routes.iter().map(|r| r.to_string()).collect();
        format!(
            "role:        client ({})\nstate:       {}\nserver:      {} ({})\ntunnel ip:   {}/{} on {}\nmode:        {}\nroutes:      {}\ndns:         {}\nhandshake:   {}\ntraffic:     rx {} / tx {}",
            c.name,
            match peer.as_ref().and_then(|p| p.last_handshake) {
                Some(d) if d < Duration::from_secs(180) => "connected",
                _ => "connecting",
            },
            c.server_endpoint,
            c.net.server_ip,
            c.ip,
            c.net.subnet.prefix_len(),
            self.tun.name,
            mode,
            util::list(&routes),
            self.dns.map(|d| format!("{d} (via server)")).unwrap_or_else(|| "system".into()),
            util::ago(peer.as_ref().and_then(|p| p.last_handshake)),
            util::bytes(peer.as_ref().map_or(0, |p| p.rx_bytes)),
            util::bytes(peer.as_ref().map_or(0, |p| p.tx_bytes)),
        )
    }
}

/// Runs a session in the foreground until Ctrl-C.
pub async fn run_foreground(opts: UpOptions) -> Result<()> {
    let session = Session::start(opts).await?;
    println!("{}", session.status().await);
    println!("\nPress Ctrl-C to disconnect.");
    util::shutdown_signal().await;
    session.stop();
    Ok(())
}

/// Client daemon: waits for `up`/`down`/`status` from the CLI.
pub async fn run_daemon() -> Result<()> {
    let (tx, mut rx) = mpsc::channel(16);
    ipc::listen(tx).await?;
    // Clean up after a crashed previous run before accepting commands.
    drop(Journal::open(&paths::journal("client"))?);
    tracing::info!("client daemon ready");
    let mut session: Option<Session> = None;
    loop {
        let (req, reply) = tokio::select! {
            _ = util::shutdown_signal() => break,
            Some(call) = rx.recv() => call,
        };
        let stop = matches!(req, IpcRequest::Shutdown);
        let res = match req {
            IpcRequest::Up(opts) => {
                if let Some(s) = session.take() {
                    s.stop();
                }
                match Session::start(opts).await {
                    Ok(s) => {
                        let text = s.status().await;
                        session = Some(s);
                        Ok(text)
                    }
                    Err(e) => Err(e),
                }
            }
            IpcRequest::Down => match session.take() {
                Some(s) => {
                    s.stop();
                    Ok("disconnected".into())
                }
                None => Ok("not connected".into()),
            },
            IpcRequest::Status => match &session {
                Some(s) => Ok(s.status().await),
                None => Ok(match config::load_toml::<ClientConfig>(&paths::client_config()) {
                    Ok(c) => format!("role:        client ({})\nstate:       down\nserver:      {}", c.name, c.server_endpoint),
                    Err(_) => "state: not paired (run `thurang join`)".into(),
                }),
            },
            IpcRequest::Shutdown => Ok("shutting down".into()),
            IpcRequest::Otp { .. } | IpcRequest::Peers | IpcRequest::Revoke { .. } => {
                Err(anyhow::anyhow!("this is a client daemon; run that command on the server"))
            }
        };
        let _ = reply.send(IpcResponse::from_result(res));
        if stop {
            break;
        }
    }
    if let Some(s) = session.take() {
        s.stop();
    }
    ipc::cleanup();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn net() -> NetConfig {
        NetConfig {
            subnet: "100.64.0.0/24".parse().unwrap(),
            server_ip: "100.64.0.1".parse().unwrap(),
            advertised_routes: vec!["192.168.1.0/24".parse().unwrap()],
            exit_node_available: false,
            dns: Some("100.64.0.1".parse().unwrap()),
            magic_domain: "thurang".into(),
        }
    }

    #[test]
    fn accepts_normal_config() {
        assert_eq!(validate_net(&net(), net()).unwrap(), net());
    }

    #[test]
    fn rejects_dns_outside_tunnel() {
        let mut n = net();
        n.dns = Some("8.8.8.8".parse().unwrap());
        assert!(validate_net(&net(), n).is_err());
    }

    #[test]
    fn rejects_subnet_change() {
        let mut n = net();
        n.subnet = "100.65.0.0/24".parse().unwrap();
        assert!(validate_net(&net(), n).is_err());
    }

    #[test]
    fn drops_default_route_from_advertised() {
        let mut n = net();
        n.advertised_routes.push("0.0.0.0/0".parse().unwrap());
        assert_eq!(validate_net(&net(), n).unwrap().advertised_routes, net().advertised_routes);
    }
}
