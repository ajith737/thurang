//! DNS forwarder on the server's tunnel IP: answers `<peer>.<domain>` for
//! enrolled peers and relays everything else to the configured upstreams.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use anyhow::Result;
use ipnet::Ipv4Net;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

const TYPE_A: u16 = 1;
const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(3);
const TCP_IDLE: Duration = Duration::from_secs(10);
/// Queries being resolved at once; more are dropped (clients retry).
const MAX_IN_FLIGHT: usize = 256;
const RCODE_NXDOMAIN: u8 = 3;
const RCODE_SERVFAIL: u8 = 2;

pub type NameTable = Arc<RwLock<HashMap<String, Ipv4Addr>>>;

struct Question {
    /// Lowercased name without trailing dot.
    name: String,
    qtype: u16,
    /// Offset just past the question section.
    end: usize,
}

fn parse_question(msg: &[u8]) -> Option<Question> {
    if msg.len() < 12 || u16::from_be_bytes([msg[4], msg[5]]) != 1 {
        return None;
    }
    let mut pos = 12;
    let mut labels = Vec::new();
    loop {
        let len = *msg.get(pos)? as usize;
        pos += 1;
        if len == 0 {
            break;
        }
        if len & 0xc0 != 0 {
            return None; // no compression in queries
        }
        labels.push(std::str::from_utf8(msg.get(pos..pos + len)?).ok()?.to_ascii_lowercase());
        pos += len;
    }
    let qtype = u16::from_be_bytes([*msg.get(pos)?, *msg.get(pos + 1)?]);
    Some(Question { name: labels.join("."), qtype, end: pos + 4 })
}

/// Builds a response to `query` with an optional single A record.
fn respond(query: &[u8], q: &Question, rcode: u8, answer: Option<Ipv4Addr>) -> Vec<u8> {
    let mut r = Vec::with_capacity(q.end + 16);
    r.extend_from_slice(&query[0..2]); // id
    let rd = query[2] & 0x01;
    r.push(0x84 | rd); // QR, AA, RD copied
    r.push(0x80 | rcode); // RA
    r.extend_from_slice(&[0, 1, 0, answer.is_some() as u8, 0, 0, 0, 0]);
    r.extend_from_slice(&query[12..q.end]);
    if let Some(ip) = answer {
        r.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4]);
        r.extend_from_slice(&ip.octets());
    }
    r
}

/// Answers names under `domain` locally. `None` means forward upstream.
fn local_answer(query: &[u8], domain: &str, names: &NameTable) -> Option<Vec<u8>> {
    let q = parse_question(query)?;
    let host = if q.name == domain {
        "server"
    } else {
        q.name.strip_suffix(domain)?.strip_suffix('.')?
    };
    let ip = names.read().unwrap().get(host).copied();
    Some(match (ip, q.qtype) {
        (Some(ip), TYPE_A) => respond(query, &q, 0, Some(ip)),
        (Some(_), _) => respond(query, &q, 0, None), // name exists, no record of this type
        (None, _) => respond(query, &q, RCODE_NXDOMAIN, None),
    })
}

async fn forward_udp(query: &[u8], upstreams: &[SocketAddr]) -> Option<Vec<u8>> {
    for up in upstreams {
        let bind: SocketAddr = if up.is_ipv4() { "0.0.0.0:0".parse().unwrap() } else { "[::]:0".parse().unwrap() };
        let Ok(sock) = UdpSocket::bind(bind).await else { continue };
        // Connecting makes the kernel drop replies from anyone but the upstream.
        if sock.connect(up).await.is_err() || sock.send(query).await.is_err() {
            continue;
        }
        let mut buf = vec![0u8; 4096];
        if let Ok(Ok(n)) = tokio::time::timeout(UPSTREAM_TIMEOUT, sock.recv(&mut buf)).await {
            if n >= 12 && buf[..2] == query[..2] {
                buf.truncate(n);
                return Some(buf);
            }
        }
    }
    None
}

async fn forward_tcp(query: &[u8], upstreams: &[SocketAddr]) -> Option<Vec<u8>> {
    for up in upstreams {
        let res = tokio::time::timeout(UPSTREAM_TIMEOUT, async {
            let mut s = TcpStream::connect(up).await?;
            write_tcp_msg(&mut s, query).await?;
            read_tcp_msg(&mut s).await
        })
        .await;
        if let Ok(Ok(resp)) = res {
            return Some(resp);
        }
    }
    None
}

async fn read_tcp_msg<R: AsyncRead + Unpin>(r: &mut R) -> std::io::Result<Vec<u8>> {
    let len = r.read_u16().await? as usize;
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf).await?;
    Ok(buf)
}

async fn write_tcp_msg<W: AsyncWrite + Unpin>(w: &mut W, msg: &[u8]) -> std::io::Result<()> {
    let len = u16::try_from(msg.len()).map_err(|_| std::io::Error::other("message too long"))?;
    w.write_u16(len).await?;
    w.write_all(msg).await
}

struct Ctx {
    upstreams: Vec<SocketAddr>,
    domain: String,
    names: NameTable,
    /// Only tunnel peers may use the resolver.
    clients: Ipv4Net,
    slots: Arc<Semaphore>,
}

impl Ctx {
    fn admit(&self, src: SocketAddr) -> Option<OwnedSemaphorePermit> {
        match src.ip() {
            IpAddr::V4(ip) if self.clients.contains(&ip) => self.slots.clone().try_acquire_owned().ok(),
            _ => None,
        }
    }

    /// Local name, upstream reply, or SERVFAIL.
    async fn resolve(&self, query: &[u8], tcp: bool) -> Option<Vec<u8>> {
        if let Some(resp) = local_answer(query, &self.domain, &self.names) {
            return Some(resp);
        }
        let resp = if tcp { forward_tcp(query, &self.upstreams).await } else { forward_udp(query, &self.upstreams).await };
        resp.or_else(|| parse_question(query).map(|q| respond(query, &q, RCODE_SERVFAIL, None)))
    }
}

/// Retries binding while the tunnel address comes up (it can lag the TUN device).
async fn bind_retry<T, F, Fut>(what: &str, mut f: F) -> Result<T>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = std::io::Result<T>>,
{
    let mut tries = 0;
    loop {
        match f().await {
            Ok(s) => return Ok(s),
            Err(e) if tries < 20 => {
                tries += 1;
                tracing::debug!("{what} bind: {e}");
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
            Err(e) => return Err(anyhow::anyhow!("binding {what}: {e}")),
        }
    }
}

pub async fn serve(listen: Ipv4Addr, clients: Ipv4Net, upstreams: Vec<IpAddr>, domain: String, names: NameTable) -> Result<()> {
    let ctx = Arc::new(Ctx {
        upstreams: upstreams.into_iter().map(|ip| SocketAddr::new(ip, 53)).collect(),
        domain,
        names,
        clients,
        slots: Arc::new(Semaphore::new(MAX_IN_FLIGHT)),
    });
    let udp = Arc::new(bind_retry("DNS udp", || UdpSocket::bind((listen, 53))).await?);
    let tcp = bind_retry("DNS tcp", || TcpListener::bind((listen, 53))).await?;
    tracing::info!("DNS forwarder on {listen}:53 -> {:?}", ctx.upstreams);

    let tcp_ctx = ctx.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, src)) = tcp.accept().await else { continue };
            let Some(permit) = tcp_ctx.admit(src) else { continue };
            let ctx = tcp_ctx.clone();
            tokio::spawn(async move {
                let _permit = permit;
                let _ = tokio::time::timeout(TCP_IDLE, async {
                    // Clients may send several queries on one connection.
                    while let Ok(query) = read_tcp_msg(&mut stream).await {
                        let Some(resp) = ctx.resolve(&query, true).await else { break };
                        if write_tcp_msg(&mut stream, &resp).await.is_err() {
                            break;
                        }
                    }
                })
                .await;
            });
        }
    });

    let mut buf = vec![0u8; 4096];
    loop {
        let (n, src) = match udp.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(_) => continue,
        };
        let Some(permit) = ctx.admit(src) else { continue };
        let query = buf[..n].to_vec();
        let (udp, ctx) = (udp.clone(), ctx.clone());
        tokio::spawn(async move {
            let _permit = permit;
            if let Some(resp) = ctx.resolve(&query, false).await {
                let _ = udp.send_to(&resp, src).await;
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query(name: &str, qtype: u16) -> Vec<u8> {
        let mut q = vec![0xab, 0xcd, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        for l in name.split('.') {
            q.push(l.len() as u8);
            q.extend_from_slice(l.as_bytes());
        }
        q.push(0);
        q.extend_from_slice(&qtype.to_be_bytes());
        q.extend_from_slice(&[0, 1]);
        q
    }

    fn names() -> NameTable {
        let mut m = HashMap::new();
        m.insert("laptop".to_string(), Ipv4Addr::new(100, 64, 0, 2));
        m.insert("server".to_string(), Ipv4Addr::new(100, 64, 0, 1));
        Arc::new(RwLock::new(m))
    }

    #[test]
    fn answers_peer_names() {
        let q = query("Laptop.thurang", TYPE_A);
        let r = local_answer(&q, "thurang", &names()).unwrap();
        assert_eq!(&r[..2], &[0xab, 0xcd]);
        assert_eq!(r[3] & 0x0f, 0);
        assert_eq!(&r[r.len() - 4..], &[100, 64, 0, 2]);
    }

    #[test]
    fn unknown_peer_is_nxdomain() {
        let r = local_answer(&query("nope.thurang", TYPE_A), "thurang", &names()).unwrap();
        assert_eq!(r[3] & 0x0f, RCODE_NXDOMAIN);
    }

    #[test]
    fn other_names_are_forwarded() {
        assert!(local_answer(&query("example.com", TYPE_A), "thurang", &names()).is_none());
        assert!(local_answer(&query("mythurang", TYPE_A), "thurang", &names()).is_none());
    }
}
