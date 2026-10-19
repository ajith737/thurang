//! `thurang clean`: forget pairings (and optionally keys/config) on this machine.

use std::io::{BufRead, IsTerminal, Write};
use std::path::PathBuf;

use anyhow::{bail, Result};

use crate::platform::{Journal, Undo};
use crate::{config, ipc, paths};

pub struct CleanOptions {
    /// Also delete WireGuard keys, so every peer must pair again.
    pub keys: bool,
    /// Delete the whole state directory, including the server config.
    pub all: bool,
    /// Don't ask for confirmation.
    pub yes: bool,
}

pub async fn run(opts: CleanOptions) -> Result<()> {
    let home = paths::home();
    if !home.exists() {
        println!("nothing to clean: {} does not exist", home.display());
        return Ok(());
    }
    // The journal replays commands with full privileges; only trust a locked-down directory.
    config::secure_home()?;
    if ipc::is_running().await {
        bail!(
            "a thurang server or daemon is still running; stop it first \
             (Ctrl-C it, or `thurang server stop`, or `thurang down` and then stop `thurang daemon`)"
        );
    }

    let mut targets: Vec<(PathBuf, &str)> = Vec::new();
    if opts.all {
        targets.push((home.clone(), "the whole state directory (config, keys, pairings)"));
    } else {
        targets.push((paths::peers(), "clients paired with this server"));
        targets.push((paths::client_config(), "this device's pairing with its server"));
        if opts.keys {
            targets.push((paths::server_key(), "server key (all clients must pair again)"));
            targets.push((paths::client_key(), "this device's key (it pairs as a new device next time)"));
        }
    }
    targets.retain(|(p, _)| p.exists());
    let pending: usize = ["server", "client"]
        .iter()
        .map(|r| config::load_json::<Vec<Undo>>(&paths::journal(r)).map_or(0, |v| v.len()))
        .sum();

    if targets.is_empty() && pending == 0 {
        println!("nothing to clean: no pairings found in {}", home.display());
        return Ok(());
    }
    println!("This will:");
    if pending > 0 {
        println!("  - undo {pending} leftover network change(s) from a previous run (routes, DNS, NAT)");
    }
    for (p, what) in &targets {
        println!("  - delete {}  ({what})", p.display());
    }
    if !opts.yes && !confirm()? {
        println!("aborted");
        return Ok(());
    }

    // Opening a journal replays and clears whatever a crashed run left behind.
    for role in ["server", "client"] {
        drop(Journal::open(&paths::journal(role))?);
    }
    ipc::cleanup();
    for (p, _) in &targets {
        let res = if p.is_dir() { std::fs::remove_dir_all(p) } else { std::fs::remove_file(p) };
        match res {
            Ok(()) => println!("deleted {}", p.display()),
            Err(e) => eprintln!("could not delete {}: {e}", p.display()),
        }
    }
    println!(
        "\ndone. Devices paired with this machine must `thurang join` again; \
         if this device was a client, also `thurang revoke` it on its server."
    );
    Ok(())
}

fn confirm() -> Result<bool> {
    if !std::io::stdin().is_terminal() {
        bail!("not a terminal; pass --yes to confirm");
    }
    print!("Continue? [y/N] ");
    std::io::stdout().flush()?;
    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line)?;
    Ok(matches!(line.trim().to_ascii_lowercase().as_str(), "y" | "yes"))
}
