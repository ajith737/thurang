//! Server node: WireGuard endpoint, enrollment, DNS, config service, NAT.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use anyhow::{Context, Result};
use boringtun::x25519::StaticSecret;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Mutex};

use crate::auth::OtpManager;
use crate::config::{self, PeerList, PeerRecord, ServerConfig};
use crate::dns::NameTable;
use crate::platform::{self, Journal, TunIf};
use crate::proto::{IpcRequest, IpcResponse};
use crate::wg::{self, Engine, Policy};
use crate::{control, discovery, dns, enroll, ipc, paths, util};

pub struct ServerState {
    pub cfg: ServerConfig,
    pub otp: OtpManager,
    secret: StaticSecret,
    peers: Mutex<PeerList>,
    engine: Arc<Engine>,
    names: NameTable,
}

impl ServerState {
    pub fn public_key(&self) -> [u8; 32] {
        *config::public_key_of(&self.secret).as_bytes()
    }

    pub async fn enroll_peer(&self, name: &str, key: [u8; 32]) -> Result<PeerRecord> {
        let mut peers = self.peers.lock().await;
        let mut updated = peers.clone();
        let rec = updated.enroll(self.cfg.subnet, self.cfg.server_ip(), name, &config::encode_key(&key))?;
        config::save_json(&paths::peers(), &updated)?;
        *peers = updated;
        // add_peer replaces any session for this key or address.
        self.engine.add_peer(&rec.name, key, rec.ip, None, None);
        self.sync_names(&peers);
        Ok(rec)
    }

    fn sync_names(&self, peers: &PeerList) {
        let mut names = self.names.write().unwrap();
        names.clear();
        names.insert(config::RESERVED_NAME.to_string(), self.cfg.server_ip());
        names.extend(peers.peers.iter().map(|p| (p.name.clone(), p.ip)));
    }

    async fn revoke(&self, name: &str) -> Result<String> {
        let mut peers = self.peers.lock().await;
        let rec = peers.remove(name).with_context(|| format!("no peer named {name}"))?;
        config::save_json(&paths::peers(), &*peers)?;
        self.engine.remove_peer(&config::decode_key(&rec.public_key)?);
        self.sync_names(&peers);
        Ok(format!("revoked {} ({})", rec.name, rec.ip))
    }

    async fn peers_text(&self) -> String {
        let stats = self.engine.stats().await;
        if stats.is_empty() {
            return "no peers enrolled (pair one with `thurang otp` + `thurang join`)".into();
        }
        let mut s = format!("{:<20} {:<15} {:<22} {:<16} {:>10} {:>10}\n", "NAME", "IP", "ENDPOINT", "HANDSHAKE", "RX", "TX");
        for p in stats {
            s += &format!(
                "{:<20} {:<15} {:<22} {:<16} {:>10} {:>10}\n",
                p.name,
                p.ip,
                p.endpoint.map(|e| e.to_string()).unwrap_or_else(|| "-".into()),
                util::ago(p.last_handshake),
                util::bytes(p.rx_bytes),
                util::bytes(p.tx_bytes),
            );
        }
        s.trim_end().to_string()
    }

    async fn status_text(&self) -> String {
        let c = &self.cfg;
        let mut s = format!(
            "role:        server\nlisten:      {} (enroll tcp/{})\ntunnel ip:   {}/{}\nexit node:   {}\nroutes:      {}\ndns:         {}\npublic key:  {}\n\n",
            c.listen,
            c.enroll_port,
            c.server_ip(),
            c.subnet.prefix_len(),
            if c.exit_node { "offered" } else { "off" },
            util::list(&c.advertise_routes),
            if c.dns_upstreams.is_empty() { "off".into() } else { format!("{} -> {}", c.server_ip(), util::list(&c.dns_upstreams)) },
            config::encode_key(&self.public_key()),
        );
        s += &self.peers_text().await;
        s
    }

    async fn handle(&self, req: IpcRequest) -> Result<String> {
        match req {
            IpcRequest::Status => Ok(self.status_text().await),
            IpcRequest::Peers => Ok(self.peers_text().await),
            IpcRequest::Otp { ttl_secs } => {
                let ttl = Duration::from_secs(ttl_secs).min(crate::auth::MAX_TTL);
                let code = self.otp.issue(ttl);
                Ok(format!(
                    "{}-{}\n(valid {} for one device: `thurang join {} --otp {}`)",
                    &code[..4],
                    &code[4..],
                    util::duration(ttl),
                    util::lan_hint(self.cfg.enroll_port),
                    code
                ))
            }
            IpcRequest::Revoke { name } => self.revoke(&name).await,
            IpcRequest::Up(_) | IpcRequest::Down => anyhow::bail!("this is a server node; `up`/`down` are for clients"),
            IpcRequest::Shutdown => Ok("shutting down".into()),
        }
    }
}

pub async fn run() -> Result<()> {
    let cfg: ServerConfig =
        config::load_toml(&paths::server_config()).context("server not initialised; run `thurang server init` first")?;
    cfg.validate()?;
    let (ipc_tx, mut ipc_rx) = mpsc::channel(16);
    ipc::listen(ipc_tx).await?;
    let mut journal = Journal::open(&paths::journal("server"))?;
    let res = run_inner(cfg, &mut journal, &mut ipc_rx).await;
    journal.rollback();
    ipc::cleanup();
    res
}

async fn run_inner(cfg: ServerConfig, journal: &mut Journal, ipc_rx: &mut mpsc::Receiver<ipc::Call>) -> Result<()> {
    let secret = config::load_or_create_key(&paths::server_key())?;
    let peers: PeerList = config::load_json(&paths::peers())?;
    let server_ip = cfg.server_ip();

    let tun = wg::create_tun(server_ip, cfg.subnet.prefix_len(), None)?;
    let tun_if = TunIf { name: wg::tun_name(&tun), index: wg::tun_index(&tun), ip: server_ip };
    let udp = Arc::new(UdpSocket::bind(cfg.listen).await.with_context(|| format!("binding {}", cfg.listen))?);
    let engine = Engine::new(
        tun,
        udp,
        secret.clone(),
        Policy::Server { subnet: cfg.subnet, routes: cfg.advertise_routes.clone(), exit_node: cfg.exit_node },
    );
    for p in &peers.peers {
        match config::decode_key(&p.public_key) {
            Ok(k) => engine.add_peer(&p.name, k, p.ip, None, None),
            Err(e) => tracing::warn!("skipping peer {}: {e}", p.name),
        }
    }
    let mut tasks = engine.start();

    if cfg.exit_node || !cfg.advertise_routes.is_empty() {
        let egress = match &cfg.egress_interface {
            Some(n) => platform::find_interface(n)?,
            None => platform::default_interface()?,
        };
        platform::enable_forwarding(journal, &tun_if, &egress).context("enabling IP forwarding")?;
        platform::enable_nat(journal, &tun_if, cfg.subnet, &egress).context("enabling NAT")?;
        tracing::info!("forwarding {} via {}", cfg.subnet, egress.name);
    }

    let state = Arc::new(ServerState {
        cfg: cfg.clone(),
        otp: OtpManager::default(),
        secret,
        peers: Mutex::new(peers.clone()),
        engine,
        names: Arc::new(RwLock::new(HashMap::new())),
    });
    state.sync_names(&peers);

    let enroll_addr = std::net::SocketAddr::new(cfg.listen.ip(), cfg.enroll_port);
    tasks.spawn(log_exit("enrollment", enroll::serve(state.clone(), enroll_addr)));
    tasks.spawn(log_exit("control", control::serve(state.clone(), server_ip)));
    if !cfg.dns_upstreams.is_empty() {
        tasks.spawn(log_exit(
            "dns",
            dns::serve(server_ip, cfg.subnet, cfg.dns_upstreams.clone(), cfg.magic_domain.clone(), state.names.clone()),
        ));
    }
    let _mdns = if cfg.mdns {
        let ips = platform::default_interface().map(|i| i.ip_addrs()).unwrap_or_default();
        let ips = ips.into_iter().filter(|ip| ip.is_ipv4()).collect();
        discovery::advertise(cfg.enroll_port, ips).map_err(|e| tracing::warn!("mDNS: {e:#}")).ok()
    } else {
        None
    };

    tracing::info!(
        "server up on {} as {}/{} — pair clients with `thurang otp`",
        cfg.listen,
        server_ip,
        cfg.subnet.prefix_len()
    );
    loop {
        tokio::select! {
            _ = util::shutdown_signal() => break,
            Some((req, reply)) = ipc_rx.recv() => {
                let stop = matches!(req, IpcRequest::Shutdown);
                let _ = reply.send(IpcResponse::from_result(state.handle(req).await));
                if stop { break; }
            }
        }
    }
    tracing::info!("shutting down");
    tasks.abort_all();
    Ok(())
}

async fn log_exit(what: &'static str, fut: impl std::future::Future<Output = Result<()>>) {
    if let Err(e) = fut.await {
        tracing::error!("{what}: {e:#}");
    }
}
