//! OTP pairing over TCP: SPAKE2 handshake, then key/config exchange.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;

use crate::auth;
use crate::config::{self, ClientConfig};
use crate::proto::{JoinRequest, JoinResponse, PROTOCOL_VERSION};
use crate::server::ServerState;

const TIMEOUT: Duration = Duration::from_secs(15);
/// Concurrent pairing connections; extra ones are dropped.
const MAX_CONCURRENT: usize = 4;

pub async fn serve(state: Arc<ServerState>, addr: SocketAddr) -> Result<()> {
    let listener = TcpListener::bind(addr).await.with_context(|| format!("binding enrollment port {addr}"))?;
    tracing::info!("enrollment listening on {addr}");
    let slots = Arc::new(Semaphore::new(MAX_CONCURRENT));
    loop {
        let (stream, peer) = listener.accept().await?;
        let Ok(permit) = slots.clone().try_acquire_owned() else {
            tracing::warn!("dropping pairing connection from {peer}: too many in progress");
            continue;
        };
        let state = state.clone();
        tokio::spawn(async move {
            let _permit = permit;
            match tokio::time::timeout(TIMEOUT, handle(state, stream)).await {
                Ok(Ok(Some(name))) => tracing::info!("enrolled {name} from {peer}"),
                Ok(Ok(None)) => {}
                Ok(Err(e)) => tracing::warn!("enrollment from {peer} failed: {e:#}"),
                Err(_) => tracing::warn!("enrollment from {peer} timed out"),
            }
        });
    }
}

async fn handle(state: Arc<ServerState>, mut stream: TcpStream) -> Result<Option<String>> {
    let (mut ch, code) = auth::handshake_server(&mut stream, || state.otp.begin_attempt()).await?;
    let req: JoinRequest = match ch.recv_json(&mut stream).await {
        Ok(r) => r,
        Err(e) => {
            // Slow down online guessing.
            tokio::time::sleep(Duration::from_secs(1)).await;
            return Err(e);
        }
    };
    let reject = |reason: &str| JoinResponse::Rejected { reason: reason.to_string() };
    if req.version != PROTOCOL_VERSION {
        ch.send_json(&mut stream, &reject("protocol version mismatch")).await?;
        return Ok(None);
    }
    let Ok(key) = config::decode_key(&req.public_key) else {
        ch.send_json(&mut stream, &reject("invalid public key")).await?;
        return Ok(None);
    };
    if !state.otp.consume(&code) {
        ch.send_json(&mut stream, &reject("pairing code already used or expired")).await?;
        return Ok(None);
    }
    let name = config::sanitize_name(&req.name);
    let rec = match state.enroll_peer(&name, key).await {
        Ok(r) => r,
        Err(e) => {
            ch.send_json(&mut stream, &reject(&format!("{e:#}"))).await?;
            return Err(e);
        }
    };
    let resp = JoinResponse::Accepted {
        server_public_key: config::encode_key(&state.public_key()),
        wg_port: state.cfg.listen.port(),
        client_ip: rec.ip,
        name: rec.name.clone(),
        net: state.cfg.net_config(),
    };
    ch.send_json(&mut stream, &resp).await?;
    Ok(Some(rec.name))
}

/// Client side: pairs with the server at `addr` and returns the resulting config.
pub async fn join(addr: SocketAddr, otp: &str, name: &str, public_key: [u8; 32]) -> Result<ClientConfig> {
    let otp = auth::normalize_otp(otp);
    if otp.len() != auth::OTP_DIGITS {
        bail!("pairing code must have {} digits", auth::OTP_DIGITS);
    }
    let fut = async {
        let mut stream = TcpStream::connect(addr).await.with_context(|| format!("connecting to {addr}"))?;
        let mut ch = auth::handshake_client(&mut stream, &otp).await?;
        let req = JoinRequest { version: PROTOCOL_VERSION, name: name.to_string(), public_key: config::encode_key(&public_key) };
        ch.send_json(&mut stream, &req).await?;
        ch.recv_json::<_, JoinResponse>(&mut stream)
            .await
            .context("server rejected the pairing code (wrong, expired or already used)")
    };
    match tokio::time::timeout(TIMEOUT, fut).await.context("pairing timed out")?? {
        JoinResponse::Accepted { server_public_key, wg_port, client_ip, name, net } => Ok(ClientConfig {
            name,
            server_public_key,
            server_endpoint: SocketAddr::new(addr.ip(), wg_port),
            ip: client_ip,
            net,
        }),
        JoinResponse::Rejected { reason } => bail!("server rejected pairing: {reason}"),
    }
}
