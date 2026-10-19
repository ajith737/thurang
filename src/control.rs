//! Config service on the server's tunnel IP. Only reachable through the
//! tunnel, so WireGuard authenticates the caller.

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tokio::net::{TcpListener, TcpStream};

use crate::proto::{self, NetConfig, CONTROL_PORT};
use crate::server::ServerState;

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum ControlRequest {
    Config,
}

pub async fn serve(state: Arc<ServerState>, ip: Ipv4Addr) -> Result<()> {
    let mut tries = 0;
    let listener = loop {
        match TcpListener::bind((ip, CONTROL_PORT)).await {
            Ok(l) => break l,
            Err(_) if tries < 20 => {
                tries += 1;
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
            Err(e) => return Err(e).context("binding control port"),
        }
    };
    loop {
        let (mut stream, _) = listener.accept().await?;
        let state = state.clone();
        tokio::spawn(async move {
            let res = tokio::time::timeout(Duration::from_secs(5), async {
                let ControlRequest::Config = proto::read_json(&mut stream).await?;
                proto::write_json(&mut stream, &state.cfg.net_config()).await
            })
            .await
            .unwrap_or_else(|_| Err(anyhow::anyhow!("timed out")));
            if let Err(e) = res {
                tracing::debug!("control: {e:#}");
            }
        });
    }
}

async fn fetch_once(server_ip: Ipv4Addr) -> Result<NetConfig> {
    let mut stream = TcpStream::connect((server_ip, CONTROL_PORT)).await?;
    proto::write_json(&mut stream, &ControlRequest::Config).await?;
    proto::read_json(&mut stream).await
}

/// Fetches the current network config through the tunnel, retrying while the
/// WireGuard handshake completes.
pub async fn fetch(server_ip: Ipv4Addr, deadline: Duration) -> Result<NetConfig> {
    let end = tokio::time::Instant::now() + deadline;
    let mut last_err = anyhow::anyhow!("timed out");
    while let Some(left) = end.checked_duration_since(tokio::time::Instant::now()) {
        match tokio::time::timeout(left.min(Duration::from_secs(3)), fetch_once(server_ip)).await {
            Ok(Ok(c)) => return Ok(c),
            Ok(Err(e)) => last_err = e,
            Err(_) => {}
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    Err(last_err)
}
