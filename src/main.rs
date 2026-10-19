//! `thurang` — LAN-only WireGuard exit node / subnet router with OTP pairing.

mod auth;
mod clean;
mod client;
mod config;
mod control;
mod discovery;
mod dns;
mod enroll;
mod ipc;
mod paths;
mod platform;
mod proto;
mod server;
mod util;
mod wg;

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use clap::{Args, Parser, Subcommand};
use ipnet::Ipv4Net;

use crate::config::ServerConfig;
use crate::proto::{IpcRequest, IpcResponse, UpOptions};

#[derive(Parser)]
#[command(name = "thurang", version, about = "LAN-only WireGuard exit node and subnet router with OTP pairing")]
struct Cli {
    /// Verbose logging (same as RUST_LOG=debug).
    #[arg(short, long, global = true)]
    verbose: bool,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Server (exit node / subnet router) commands.
    #[command(subcommand)]
    Server(ServerCmd),
    /// Generate a one-time pairing code on the running server.
    Otp {
        /// How long the code stays valid (e.g. 90s, 5m, 1h).
        #[arg(long, default_value = "5m")]
        ttl: String,
    },
    /// List enrolled clients on the running server.
    Peers,
    /// Remove a client from the server.
    Revoke { name: String },
    /// Pair this machine with a server using its OTP.
    Join {
        /// Server address (ip or ip:port). Discovered via mDNS when omitted.
        server: Option<String>,
        /// Pairing code printed by `thurang otp` on the server.
        #[arg(long)]
        otp: String,
        /// Name for this device (defaults to the hostname).
        #[arg(long)]
        name: Option<String>,
    },
    /// Connect to the paired server.
    Up {
        #[command(flatten)]
        opts: UpArgs,
        /// Run in this terminal instead of handing off to `thurang daemon`.
        #[arg(long)]
        foreground: bool,
    },
    /// Disconnect from the server.
    Down,
    /// Show tunnel status.
    Status,
    /// Run the client daemon (as root/Administrator) that `up`/`down` control.
    Daemon,
    /// Forget all pairings on this machine and undo leftover network changes.
    Clean {
        /// Also delete WireGuard keys, so every device has to pair again.
        #[arg(long)]
        keys: bool,
        /// Delete everything, including the server configuration.
        #[arg(long, conflicts_with = "keys")]
        all: bool,
        /// Don't ask for confirmation.
        #[arg(short, long)]
        yes: bool,
    },
}

#[derive(Args)]
struct UpArgs {
    /// Send all traffic through the server.
    #[arg(long)]
    exit_node: bool,
    /// Route the LAN subnets the server advertises.
    #[arg(long)]
    accept_routes: bool,
    /// Use the server's DNS forwarder for all lookups.
    #[arg(long)]
    accept_dns: bool,
}

#[derive(Subcommand)]
enum ServerCmd {
    /// Create or replace the server configuration.
    Init(InitArgs),
    /// Run the server in the foreground.
    Up,
    /// Print the server configuration.
    Show,
    /// Stop a running server.
    Stop,
}

#[derive(Args)]
struct InitArgs {
    /// WireGuard UDP listen address.
    #[arg(long, default_value = "0.0.0.0:51820")]
    listen: SocketAddr,
    /// TCP port for OTP pairing.
    #[arg(long, default_value_t = proto::DEFAULT_ENROLL_PORT)]
    enroll_port: u16,
    /// Tunnel address pool; the server takes the first address.
    #[arg(long, default_value = "100.64.0.0/24")]
    subnet: Ipv4Net,
    /// Upstream DNS servers for clients using --accept-dns (comma-separated).
    #[arg(long, value_delimiter = ',')]
    dns: Vec<IpAddr>,
    /// LAN subnets to make reachable through this node (comma-separated).
    #[arg(long, value_delimiter = ',')]
    advertise_routes: Vec<Ipv4Net>,
    /// Allow clients to use this node for all their traffic.
    #[arg(long)]
    exit_node: bool,
    /// Interface to NAT out of (defaults to the one with the default route).
    #[arg(long)]
    egress_interface: Option<String>,
    /// Domain for peer names served by the DNS forwarder.
    #[arg(long, default_value = "thurang")]
    magic_domain: String,
    /// Don't advertise the server via mDNS.
    #[arg(long)]
    no_mdns: bool,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let filter = if cli.verbose { "debug".into() } else { std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into()) };
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new(filter))
        .with_target(false)
        .init();
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(run(cli.cmd))
}

async fn run(cmd: Cmd) -> Result<()> {
    // Privileged commands that read or write state.
    if matches!(
        cmd,
        Cmd::Server(ServerCmd::Init(_) | ServerCmd::Up) | Cmd::Join { .. } | Cmd::Up { foreground: true, .. } | Cmd::Daemon
    ) {
        config::secure_home()?;
    }
    match cmd {
        Cmd::Server(ServerCmd::Init(a)) => server_init(a),
        Cmd::Server(ServerCmd::Up) => server::run().await,
        Cmd::Server(ServerCmd::Show) => {
            let text = std::fs::read_to_string(paths::server_config()).context("server not initialised")?;
            println!("# {}\n{text}", paths::server_config().display());
            Ok(())
        }
        Cmd::Server(ServerCmd::Stop) => call(IpcRequest::Shutdown).await,
        Cmd::Otp { ttl } => call(IpcRequest::Otp { ttl_secs: util::parse_duration(&ttl)?.as_secs() }).await,
        Cmd::Peers => call(IpcRequest::Peers).await,
        Cmd::Revoke { name } => call(IpcRequest::Revoke { name }).await,
        Cmd::Join { server, otp, name } => join(server, otp, name).await,
        Cmd::Up { opts, foreground } => {
            let opts = UpOptions { exit_node: opts.exit_node, accept_routes: opts.accept_routes, accept_dns: opts.accept_dns };
            if foreground {
                client::run_foreground(opts).await
            } else {
                call(IpcRequest::Up(opts)).await
            }
        }
        Cmd::Down => call(IpcRequest::Down).await,
        Cmd::Status => call(IpcRequest::Status).await,
        Cmd::Daemon => client::run_daemon().await,
        Cmd::Clean { keys, all, yes } => clean::run(clean::CleanOptions { keys, all, yes }).await,
    }
}

async fn call(req: IpcRequest) -> Result<()> {
    match ipc::request(&req).await? {
        IpcResponse::Ok { text } => {
            println!("{text}");
            Ok(())
        }
        IpcResponse::Error { error } => bail!(error),
    }
}

fn server_init(a: InitArgs) -> Result<()> {
    let cfg = ServerConfig {
        listen: a.listen,
        enroll_port: a.enroll_port,
        subnet: a.subnet.trunc(),
        dns_upstreams: a.dns,
        magic_domain: a.magic_domain.to_ascii_lowercase(),
        advertise_routes: a.advertise_routes.into_iter().map(|r| r.trunc()).collect(),
        exit_node: a.exit_node,
        egress_interface: a.egress_interface,
        mdns: !a.no_mdns,
    };
    cfg.validate()?;
    config::save_toml(&paths::server_config(), &cfg)?;
    let key = config::load_or_create_key(&paths::server_key())?;
    println!("wrote {}", paths::server_config().display());
    println!("server public key: {}", config::encode_key(config::public_key_of(&key).as_bytes()));
    println!("start it with `thurang server up`, then pair clients with `thurang otp`");
    Ok(())
}

async fn join(server: Option<String>, otp: String, name: Option<String>) -> Result<()> {
    let addr = match server {
        Some(s) => parse_server_addr(&s)?,
        None => {
            println!("looking for a thurang server on the LAN...");
            let (host, addr) = tokio::task::spawn_blocking(|| discovery::discover(Duration::from_secs(5))).await??;
            println!("found {host} at {addr}");
            addr
        }
    };
    let name = name.unwrap_or_else(discovery::hostname);
    let secret = config::load_or_create_key(&paths::client_key())?;
    let cfg = enroll::join(addr, &otp, &name, *config::public_key_of(&secret).as_bytes()).await?;
    config::save_toml(&paths::client_config(), &cfg)?;
    println!("paired as {} ({}) with server {}", cfg.name, cfg.ip, cfg.server_endpoint);
    println!(
        "server offers: exit node {}, routes {}, dns {}",
        if cfg.net.exit_node_available { "yes" } else { "no" },
        util::list(&cfg.net.advertised_routes),
        if cfg.net.dns.is_some() { "yes" } else { "no" }
    );
    println!("connect with `thurang up` (add --exit-node / --accept-routes / --accept-dns)");
    Ok(())
}

fn parse_server_addr(s: &str) -> Result<SocketAddr> {
    if let Ok(a) = s.parse::<SocketAddr>() {
        return Ok(a);
    }
    if let Ok(ip) = s.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, proto::DEFAULT_ENROLL_PORT));
    }
    // Hostname, with or without port.
    let with_port = if s.contains(':') { s.to_string() } else { format!("{s}:{}", proto::DEFAULT_ENROLL_PORT) };
    std::net::ToSocketAddrs::to_socket_addrs(&with_port)
        .with_context(|| format!("resolving {s}"))?
        .find(|a| a.is_ipv4())
        .with_context(|| format!("no IPv4 address for {s}"))
}
