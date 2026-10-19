//! Locations of config, keys, state and the daemon IPC endpoint.

use std::path::PathBuf;

/// Root directory for all thurang state. Override with `THURANG_HOME`.
pub fn home() -> PathBuf {
    if let Some(dir) = std::env::var_os("THURANG_HOME") {
        return PathBuf::from(dir);
    }
    #[cfg(target_os = "linux")]
    {
        PathBuf::from("/etc/thurang")
    }
    #[cfg(target_os = "macos")]
    {
        PathBuf::from("/Library/Application Support/thurang")
    }
    #[cfg(windows)]
    {
        let base = std::env::var_os("ProgramData").unwrap_or_else(|| "C:\\ProgramData".into());
        PathBuf::from(base).join("thurang")
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    {
        PathBuf::from("/usr/local/etc/thurang")
    }
}

pub fn server_config() -> PathBuf {
    home().join("server.toml")
}

pub fn server_key() -> PathBuf {
    home().join("server.key")
}

pub fn peers() -> PathBuf {
    home().join("peers.json")
}

pub fn client_config() -> PathBuf {
    home().join("client.toml")
}

pub fn client_key() -> PathBuf {
    home().join("client.key")
}

/// Journal of system changes (routes, DNS, NAT) that must be undone on shutdown.
pub fn journal(role: &str) -> PathBuf {
    home().join(format!("journal-{role}.json"))
}

#[cfg(unix)]
pub fn ipc_socket() -> PathBuf {
    home().join("thurang.sock")
}

#[cfg(windows)]
pub fn ipc_pipe() -> String {
    r"\\.\pipe\thurang-daemon".to_string()
}
