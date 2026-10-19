//! Userspace WireGuard: boringtun sessions between a TUN device and a UDP socket.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use boringtun::noise::errors::WireGuardError;
use boringtun::noise::handshake::parse_handshake_anon;
use boringtun::noise::rate_limiter::RateLimiter;
use boringtun::noise::{Packet, Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use ipnet::Ipv4Net;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tokio::task::JoinSet;
use tun_rs::AsyncDevice;

pub const MTU: u16 = 1420;
const BUF: usize = 65536;
/// Handshakes per second before senders must answer a cookie challenge.
const HANDSHAKE_RATE_LIMIT: u64 = 20;
const COOKIE_REPLY: u8 = 3;

/// What decrypted traffic a node accepts from its peers.
#[derive(Debug, Clone)]
pub enum Policy {
    /// Peers may only use their own tunnel IP as source, and only reach the
    /// tunnel subnet, advertised routes, or anything when acting as exit node.
    Server { subnet: Ipv4Net, routes: Vec<Ipv4Net>, exit_node: bool },
    /// Accept packets addressed to us from these sources (or any, when using an exit node).
    Client { local_ip: Ipv4Addr, allow_any: bool, allowed: Vec<Ipv4Net> },
}

impl Policy {
    pub fn allows(&self, peer_ip: Ipv4Addr, src: Ipv4Addr, dst: Ipv4Addr) -> bool {
        match self {
            Policy::Server { subnet, routes, exit_node } => {
                src == peer_ip && (*exit_node || subnet.contains(&dst) || routes.iter().any(|r| r.contains(&dst)))
            }
            Policy::Client { local_ip, allow_any, allowed } => {
                dst == *local_ip && (*allow_any || allowed.iter().any(|r| r.contains(&src)))
            }
        }
    }
}

pub struct Peer {
    pub name: String,
    pub public_key: [u8; 32],
    /// Server: the client's tunnel IP. Client: the server's tunnel IP.
    pub ip: Ipv4Addr,
    index: u32,
    keepalive: bool,
    tunn: Mutex<Tunn>,
    endpoint: RwLock<Option<SocketAddr>>,
}

impl Peer {
    pub fn endpoint(&self) -> Option<SocketAddr> {
        *self.endpoint.read().unwrap()
    }
}

#[derive(Debug, Clone)]
pub struct PeerStats {
    pub name: String,
    pub ip: Ipv4Addr,
    pub endpoint: Option<SocketAddr>,
    pub last_handshake: Option<Duration>,
    pub tx_bytes: usize,
    pub rx_bytes: usize,
}

#[derive(Default)]
struct PeerTable {
    by_index: HashMap<u32, Arc<Peer>>,
    by_key: HashMap<[u8; 32], Arc<Peer>>,
    by_ip: HashMap<Ipv4Addr, Arc<Peer>>,
}

pub struct Engine {
    tun: Arc<AsyncDevice>,
    udp: Arc<UdpSocket>,
    secret: StaticSecret,
    public: PublicKey,
    is_server: bool,
    policy: RwLock<Policy>,
    peers: RwLock<PeerTable>,
    next_index: AtomicU32,
    rate_limiter: Arc<RateLimiter>,
}

fn ipv4_addrs(pkt: &[u8]) -> Option<(Ipv4Addr, Ipv4Addr)> {
    if pkt.len() < 20 || pkt[0] >> 4 != 4 {
        return None;
    }
    let src = Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]);
    let dst = Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]);
    Some((src, dst))
}

impl Engine {
    pub fn new(tun: Arc<AsyncDevice>, udp: Arc<UdpSocket>, secret: StaticSecret, policy: Policy) -> Arc<Self> {
        let public = PublicKey::from(&secret);
        let is_server = matches!(policy, Policy::Server { .. });
        Arc::new(Engine {
            tun,
            udp,
            secret,
            public,
            is_server,
            policy: RwLock::new(policy),
            peers: RwLock::new(PeerTable::default()),
            next_index: AtomicU32::new(rand::random::<u32>() & 0x00ff_ffff),
            rate_limiter: Arc::new(RateLimiter::new(&public, HANDSHAKE_RATE_LIMIT)),
        })
    }

    pub fn set_policy(&self, policy: Policy) {
        *self.policy.write().unwrap() = policy;
    }

    /// Adds a peer, replacing any existing peer with the same key or IP.
    pub fn add_peer(&self, name: &str, public_key: [u8; 32], ip: Ipv4Addr, endpoint: Option<SocketAddr>, keepalive: Option<u16>) {
        let index = self.next_index.fetch_add(1, Ordering::Relaxed) & 0x00ff_ffff;
        let tunn = Tunn::new(
            self.secret.clone(),
            PublicKey::from(public_key),
            None,
            keepalive,
            index,
            Some(self.rate_limiter.clone()),
        );
        let peer = Arc::new(Peer {
            name: name.to_string(),
            public_key,
            ip,
            index,
            keepalive: keepalive.is_some(),
            tunn: Mutex::new(tunn),
            endpoint: RwLock::new(endpoint),
        });
        self.remove_peer(&public_key);
        if let Some(old) = self.peers.read().unwrap().by_ip.get(&ip).cloned() {
            self.remove_peer(&old.public_key);
        }
        let mut t = self.peers.write().unwrap();
        t.by_index.insert(index, peer.clone());
        t.by_key.insert(public_key, peer.clone());
        t.by_ip.insert(ip, peer);
    }

    pub fn remove_peer(&self, public_key: &[u8; 32]) {
        let mut t = self.peers.write().unwrap();
        if let Some(p) = t.by_key.remove(public_key) {
            t.by_index.remove(&p.index);
            t.by_ip.remove(&p.ip);
        }
    }

    fn all_peers(&self) -> Vec<Arc<Peer>> {
        self.peers.read().unwrap().by_key.values().cloned().collect()
    }

    pub async fn stats(&self) -> Vec<PeerStats> {
        let mut out = Vec::new();
        for p in self.all_peers() {
            let (last_handshake, tx_bytes, rx_bytes, _, _) = p.tunn.lock().await.stats();
            out.push(PeerStats { name: p.name.clone(), ip: p.ip, endpoint: p.endpoint(), last_handshake, tx_bytes, rx_bytes });
        }
        out.sort_by_key(|s| s.ip);
        out
    }

    /// Sends a handshake initiation to every peer with a known endpoint.
    pub async fn initiate(&self) {
        let mut out = vec![0u8; 256];
        for p in self.all_peers() {
            let Some(ep) = p.endpoint() else { continue };
            let mut tunn = p.tunn.lock().await;
            if let TunnResult::WriteToNetwork(pkt) = tunn.format_handshake_initiation(&mut out, false) {
                let _ = self.udp.send_to(pkt, ep).await;
            }
        }
    }

    /// Starts the packet loops. Dropping/aborting the returned set stops the engine.
    pub fn start(self: &Arc<Self>) -> JoinSet<()> {
        let mut set = JoinSet::new();
        set.spawn(self.clone().tun_loop());
        set.spawn(self.clone().udp_loop());
        set.spawn(self.clone().timer_loop());
        set
    }

    fn route_outbound(&self, pkt: &[u8]) -> Option<Arc<Peer>> {
        let t = self.peers.read().unwrap();
        if self.is_server {
            let (_, dst) = ipv4_addrs(pkt)?;
            t.by_ip.get(&dst).cloned()
        } else {
            // IPv6 is not tunneled; packets routed here are dropped so they can't leak.
            ipv4_addrs(pkt)?;
            t.by_key.values().next().cloned()
        }
    }

    fn peer_for_packet(&self, packet: Packet) -> Option<Arc<Peer>> {
        let t = self.peers.read().unwrap();
        match packet {
            Packet::HandshakeInit(h) => {
                // Costs a DH; only reached after the rate limiter checked mac1/cookies.
                let half = parse_handshake_anon(&self.secret, &self.public, &h).ok()?;
                t.by_key.get(&half.peer_static_public).cloned()
            }
            Packet::HandshakeResponse(p) => t.by_index.get(&(p.receiver_idx >> 8)).cloned(),
            Packet::PacketCookieReply(p) => t.by_index.get(&(p.receiver_idx >> 8)).cloned(),
            Packet::PacketData(p) => t.by_index.get(&(p.receiver_idx >> 8)).cloned(),
        }
    }

    fn relay_target(&self, dst: Ipv4Addr, from: &Peer) -> Option<Arc<Peer>> {
        if !self.is_server {
            return None;
        }
        self.peers.read().unwrap().by_ip.get(&dst).filter(|p| p.ip != from.ip).cloned()
    }

    async fn send_to_peer(&self, peer: &Peer, pkt: &[u8], out: &mut [u8]) {
        let Some(ep) = peer.endpoint() else { return };
        let mut tunn = peer.tunn.lock().await;
        match tunn.encapsulate(pkt, out) {
            TunnResult::WriteToNetwork(p) => {
                let _ = self.udp.send_to(p, ep).await;
            }
            TunnResult::Err(e) => tracing::debug!("encapsulate for {}: {e:?}", peer.name),
            _ => {}
        }
    }

    async fn tun_loop(self: Arc<Self>) {
        let mut buf = vec![0u8; BUF];
        let mut out = vec![0u8; BUF + 32];
        loop {
            let n = match self.tun.recv(&mut buf).await {
                Ok(n) => n,
                Err(e) => {
                    tracing::warn!("tun read: {e}");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            };
            let pkt = &buf[..n];
            let Some(peer) = self.route_outbound(pkt) else { continue };
            self.send_to_peer(&peer, pkt, &mut out).await;
        }
    }

    async fn udp_loop(self: Arc<Self>) {
        let mut buf = vec![0u8; BUF];
        let mut out = vec![0u8; BUF];
        loop {
            let (n, src) = match self.udp.recv_from(&mut buf).await {
                Ok(v) => v,
                Err(e) => {
                    // Windows reports ICMP port-unreachable as a recv error; keep going.
                    tracing::debug!("udp recv: {e}");
                    continue;
                }
            };
            // Cheap MAC check (and cookie challenge under load) before any DH work.
            let packet = match self.rate_limiter.verify_packet(Some(src.ip()), &buf[..n], &mut out) {
                Ok(p) => p,
                Err(TunnResult::WriteToNetwork(cookie)) => {
                    let _ = self.udp.send_to(cookie, src).await;
                    continue;
                }
                Err(_) => continue,
            };
            let Some(peer) = self.peer_for_packet(packet) else { continue };
            let mut tunn = peer.tunn.lock().await;
            let mut authenticated = false;
            let mut flush = false;
            let mut relay = None;
            match tunn.decapsulate(Some(src.ip()), &buf[..n], &mut out) {
                TunnResult::WriteToNetwork(p) => {
                    // A cookie reply goes to unauthenticated senders; don't roam on it.
                    authenticated = p.first() != Some(&COOKIE_REPLY);
                    flush = authenticated;
                    let _ = self.udp.send_to(p, src).await;
                }
                TunnResult::WriteToTunnelV4(p, from) => {
                    authenticated = true;
                    let dst = ipv4_addrs(p).map(|(_, d)| d);
                    let ok = dst.is_some_and(|dst| self.policy.read().unwrap().allows(peer.ip, from, dst));
                    if ok {
                        // Client-to-client traffic is relayed here, without the OS.
                        match dst.and_then(|d| self.relay_target(d, &peer)) {
                            Some(target) => relay = Some((target, p.to_vec())),
                            None => {
                                let _ = self.tun.send(p).await;
                            }
                        }
                    } else {
                        tracing::debug!("policy drop from {} ({from} -> {dst:?})", peer.name);
                    }
                }
                TunnResult::WriteToTunnelV6(..) => authenticated = true,
                TunnResult::Done => {}
                TunnResult::Err(e) => tracing::debug!("decapsulate from {src}: {e:?}"),
            }
            // Drain packets queued while the handshake was in progress.
            while flush {
                match tunn.decapsulate(None, &[], &mut out) {
                    TunnResult::WriteToNetwork(p) => {
                        let _ = self.udp.send_to(p, src).await;
                    }
                    _ => flush = false,
                }
            }
            drop(tunn);
            if let Some((target, pkt)) = relay {
                self.send_to_peer(&target, &pkt, &mut out).await;
            }
            if authenticated && peer.endpoint() != Some(src) {
                tracing::info!("peer {} at {src}", peer.name);
                *peer.endpoint.write().unwrap() = Some(src);
            }
        }
    }

    async fn timer_loop(self: Arc<Self>) {
        let mut out = vec![0u8; BUF];
        let mut tick = tokio::time::interval(Duration::from_millis(250));
        let mut n: u64 = 0;
        loop {
            tick.tick().await;
            n += 1;
            if n.is_multiple_of(4) {
                self.rate_limiter.reset_count();
            }
            for p in self.all_peers() {
                let Some(ep) = p.endpoint() else { continue };
                let mut tunn = p.tunn.lock().await;
                match tunn.update_timers(&mut out) {
                    TunnResult::WriteToNetwork(pkt) => {
                        let _ = self.udp.send_to(pkt, ep).await;
                    }
                    TunnResult::Err(WireGuardError::ConnectionExpired) if p.keepalive => {
                        // Keep trying to reach the server (e.g. after it restarts).
                        if let TunnResult::WriteToNetwork(pkt) = tunn.format_handshake_initiation(&mut out, false) {
                            let _ = self.udp.send_to(pkt, ep).await;
                        }
                    }
                    _ => {}
                }
            }
        }
    }
}

/// Creates the TUN device with the node's tunnel address.
pub fn create_tun(ip: Ipv4Addr, prefix: u8, ipv6: Option<(std::net::Ipv6Addr, u8)>) -> anyhow::Result<Arc<AsyncDevice>> {
    let mut b = tun_rs::DeviceBuilder::new().ipv4(ip, prefix, None).mtu(MTU);
    if let Some((v6, p)) = ipv6 {
        b = b.ipv6(v6, p);
    }
    #[cfg(target_os = "linux")]
    {
        b = b.name("thurang0");
    }
    #[cfg(windows)]
    {
        b = b.name("thurang").description("thurang WireGuard");
    }
    let dev = b.build_async().map_err(|e| {
        #[cfg(windows)]
        return anyhow::anyhow!("creating TUN device: {e} (is wintun.dll next to thurang.exe, and running as Administrator?)");
        #[cfg(not(windows))]
        anyhow::anyhow!("creating TUN device: {e} (are you root?)")
    })?;
    Ok(Arc::new(dev))
}

pub fn tun_name(dev: &AsyncDevice) -> String {
    dev.name().unwrap_or_else(|_| "thurang".into())
}

/// Interface index (used by Windows netsh commands).
pub fn tun_index(_dev: &AsyncDevice) -> u32 {
    #[cfg(windows)]
    return _dev.if_index().unwrap_or(0);
    #[cfg(not(windows))]
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_policy() {
        let p = Policy::Server {
            subnet: "100.64.0.0/24".parse().unwrap(),
            routes: vec!["192.168.1.0/24".parse().unwrap()],
            exit_node: false,
        };
        let me = Ipv4Addr::new(100, 64, 0, 2);
        assert!(p.allows(me, me, Ipv4Addr::new(100, 64, 0, 1)));
        assert!(p.allows(me, me, Ipv4Addr::new(192, 168, 1, 10)));
        assert!(!p.allows(me, me, Ipv4Addr::new(8, 8, 8, 8)));
        // Spoofed source
        assert!(!p.allows(me, Ipv4Addr::new(100, 64, 0, 3), Ipv4Addr::new(100, 64, 0, 1)));
        let exit = Policy::Server { subnet: "100.64.0.0/24".parse().unwrap(), routes: vec![], exit_node: true };
        assert!(exit.allows(me, me, Ipv4Addr::new(8, 8, 8, 8)));
    }

    #[test]
    fn client_policy() {
        let me = Ipv4Addr::new(100, 64, 0, 2);
        let p = Policy::Client { local_ip: me, allow_any: false, allowed: vec!["100.64.0.0/24".parse().unwrap()] };
        let any = Ipv4Addr::UNSPECIFIED;
        assert!(p.allows(any, Ipv4Addr::new(100, 64, 0, 1), me));
        assert!(!p.allows(any, Ipv4Addr::new(8, 8, 8, 8), me));
        // The server must not inject packets for other hosts on the client's network.
        assert!(!p.allows(any, Ipv4Addr::new(100, 64, 0, 1), Ipv4Addr::new(192, 168, 1, 5)));
        let exit = Policy::Client { local_ip: me, allow_any: true, allowed: vec![] };
        assert!(exit.allows(any, Ipv4Addr::new(8, 8, 8, 8), me));
    }
}
