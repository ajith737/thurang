//! Wire types shared between server, client, daemon and CLI.

use std::net::Ipv4Addr;

use anyhow::{bail, Context, Result};
use ipnet::Ipv4Net;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const PROTOCOL_VERSION: u32 = 1;
pub const DEFAULT_WG_PORT: u16 = 51820;
pub const DEFAULT_ENROLL_PORT: u16 = 51821;
/// TCP port of the config service, reachable only inside the tunnel.
pub const CONTROL_PORT: u16 = 7001;
pub const MDNS_SERVICE: &str = "_thurang._tcp.local.";
const MAX_FRAME: usize = 64 * 1024;

/// Network settings the server pushes to clients.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetConfig {
    pub subnet: Ipv4Net,
    pub server_ip: Ipv4Addr,
    pub advertised_routes: Vec<Ipv4Net>,
    pub exit_node_available: bool,
    /// DNS forwarder on the server's tunnel IP, if upstreams are configured.
    pub dns: Option<Ipv4Addr>,
    pub magic_domain: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct JoinRequest {
    pub version: u32,
    pub name: String,
    /// Base64 WireGuard public key.
    pub public_key: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum JoinResponse {
    Accepted {
        server_public_key: String,
        wg_port: u16,
        client_ip: Ipv4Addr,
        name: String,
        net: NetConfig,
    },
    Rejected {
        reason: String,
    },
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UpOptions {
    pub exit_node: bool,
    pub accept_routes: bool,
    pub accept_dns: bool,
}

/// CLI -> daemon requests.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum IpcRequest {
    Status,
    Otp { ttl_secs: u64 },
    Peers,
    Revoke { name: String },
    Up(UpOptions),
    Down,
    Shutdown,
}

/// Daemon -> CLI reply: human-readable text, or an error.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum IpcResponse {
    Ok { text: String },
    Error { error: String },
}

impl IpcResponse {
    pub fn from_result(r: Result<String>) -> Self {
        match r {
            Ok(text) => IpcResponse::Ok { text },
            Err(e) => IpcResponse::Error { error: format!("{e:#}") },
        }
    }
}

pub async fn write_frame<W: AsyncWrite + Unpin>(w: &mut W, data: &[u8]) -> Result<()> {
    if data.len() > MAX_FRAME {
        bail!("frame too large");
    }
    w.write_all(&(data.len() as u32).to_be_bytes()).await?;
    w.write_all(data).await?;
    w.flush().await?;
    Ok(())
}

pub async fn read_frame<R: AsyncRead + Unpin>(r: &mut R) -> Result<Vec<u8>> {
    let mut len = [0u8; 4];
    r.read_exact(&mut len).await.context("connection closed")?;
    let len = u32::from_be_bytes(len) as usize;
    if len > MAX_FRAME {
        bail!("frame too large ({len} bytes)");
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf).await?;
    Ok(buf)
}

pub async fn write_json<W: AsyncWrite + Unpin, T: Serialize>(w: &mut W, v: &T) -> Result<()> {
    write_frame(w, &serde_json::to_vec(v)?).await
}

pub async fn read_json<R: AsyncRead + Unpin, T: DeserializeOwned>(r: &mut R) -> Result<T> {
    let buf = read_frame(r).await?;
    Ok(serde_json::from_slice(&buf)?)
}
