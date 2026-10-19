//! Local CLI <-> daemon channel: Unix socket, or a named pipe on Windows.

use anyhow::{Context, Result};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{mpsc, oneshot};

use crate::proto::{self, IpcRequest, IpcResponse};

pub type Call = (IpcRequest, oneshot::Sender<IpcResponse>);

async fn handle<S: AsyncRead + AsyncWrite + Unpin>(mut conn: S, tx: mpsc::Sender<Call>) -> Result<()> {
    let req: IpcRequest = tokio::time::timeout(std::time::Duration::from_secs(5), proto::read_json(&mut conn))
        .await
        .context("timed out reading request")??;
    let (rtx, rrx) = oneshot::channel();
    tx.send((req, rtx)).await.ok().context("daemon shutting down")?;
    let resp = rrx.await.unwrap_or(IpcResponse::Error { error: "daemon shutting down".into() });
    proto::write_json(&mut conn, &resp).await
}

/// Starts accepting CLI connections; requests are delivered on `tx`.
#[cfg(unix)]
pub async fn listen(tx: mpsc::Sender<Call>) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let path = crate::paths::ipc_socket();
    if tokio::net::UnixStream::connect(&path).await.is_ok() {
        anyhow::bail!("another thurang daemon is already running");
    }
    let _ = std::fs::remove_file(&path);
    std::fs::create_dir_all(crate::paths::home())?;
    let listener = tokio::net::UnixListener::bind(&path).with_context(|| format!("binding {}", path.display()))?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    tokio::spawn(async move {
        loop {
            let Ok((conn, _)) = listener.accept().await else { continue };
            let tx = tx.clone();
            tokio::spawn(async move {
                if let Err(e) = handle(conn, tx).await {
                    tracing::debug!("ipc: {e:#}");
                }
            });
        }
    });
    Ok(())
}

#[cfg(windows)]
pub async fn listen(tx: mpsc::Sender<Call>) -> Result<()> {
    use tokio::net::windows::named_pipe::ServerOptions;
    let name = crate::paths::ipc_pipe();
    let mut server = ServerOptions::new()
        .first_pipe_instance(true)
        .create(&name)
        .context("another thurang daemon is already running (or pipe unavailable)")?;
    tokio::spawn(async move {
        loop {
            if server.connect().await.is_err() {
                continue;
            }
            let conn = server;
            server = match ServerOptions::new().create(&name) {
                Ok(s) => s,
                Err(e) => {
                    tracing::error!("named pipe: {e}");
                    return;
                }
            };
            let tx = tx.clone();
            tokio::spawn(async move {
                if let Err(e) = handle(conn, tx).await {
                    tracing::debug!("ipc: {e:#}");
                }
            });
        }
    });
    Ok(())
}

/// True if a server or client daemon is accepting commands.
pub async fn is_running() -> bool {
    #[cfg(unix)]
    return tokio::net::UnixStream::connect(crate::paths::ipc_socket()).await.is_ok();
    #[cfg(windows)]
    return tokio::net::windows::named_pipe::ClientOptions::new().open(crate::paths::ipc_pipe()).is_ok();
}

/// Removes the socket file on shutdown.
pub fn cleanup() {
    #[cfg(unix)]
    let _ = std::fs::remove_file(crate::paths::ipc_socket());
}

/// What to start so that `req` has a daemon to talk to.
fn start_hint(req: &IpcRequest) -> &'static str {
    match req {
        IpcRequest::Up(_) => {
            "start the client daemon first (`sudo thurang daemon` in another terminal), \
             or connect without it: `sudo thurang up --foreground ...`"
        }
        IpcRequest::Down => "nothing is connected through the daemon (a `--foreground` session stops with Ctrl-C)",
        IpcRequest::Otp { .. } | IpcRequest::Peers | IpcRequest::Revoke { .. } => {
            "start the server first: `sudo thurang server up`"
        }
        IpcRequest::Status | IpcRequest::Shutdown => {
            "neither `thurang server up` nor `thurang daemon` is running"
        }
    }
}

pub async fn request(req: &IpcRequest) -> Result<IpcResponse> {
    #[cfg(unix)]
    let mut conn = {
        let path = crate::paths::ipc_socket();
        match tokio::net::UnixStream::connect(&path).await {
            Ok(c) => c,
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                anyhow::bail!("permission denied on {}: run this command with sudo", path.display())
            }
            Err(e) if matches!(e.kind(), std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused) => {
                anyhow::bail!("no thurang daemon running: {}", start_hint(req))
            }
            Err(e) => return Err(e).with_context(|| format!("connecting to {}", path.display())),
        }
    };
    #[cfg(windows)]
    let mut conn = match tokio::net::windows::named_pipe::ClientOptions::new().open(crate::paths::ipc_pipe()) {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            anyhow::bail!("access denied: run this from an Administrator shell")
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            anyhow::bail!("no thurang daemon running: {}", start_hint(req))
        }
        Err(e) => return Err(e).context("connecting to the thurang daemon"),
    };
    proto::write_json(&mut conn, req).await?;
    proto::read_json(&mut conn).await
}
