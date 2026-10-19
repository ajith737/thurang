//! Small formatting and process helpers.

use std::fmt::Display;
use std::time::Duration;

use anyhow::{bail, Result};

pub fn ago(d: Option<Duration>) -> String {
    match d {
        None => "never".into(),
        Some(d) => format!("{} ago", duration(d)),
    }
}

pub fn duration(d: Duration) -> String {
    let s = d.as_secs();
    match s {
        0..=59 => format!("{s}s"),
        60..=3599 => format!("{}m{:02}s", s / 60, s % 60),
        _ => format!("{}h{:02}m", s / 3600, (s % 3600) / 60),
    }
}

pub fn bytes(n: usize) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = n as f64;
    let mut u = 0;
    while v >= 1024.0 && u < UNITS.len() - 1 {
        v /= 1024.0;
        u += 1;
    }
    if u == 0 {
        format!("{n} B")
    } else {
        format!("{v:.1} {}", UNITS[u])
    }
}

pub fn list<T: Display>(items: &[T]) -> String {
    if items.is_empty() {
        return "none".into();
    }
    items.iter().map(|i| i.to_string()).collect::<Vec<_>>().join(", ")
}

/// Accepts "300", "90s", "5m", "1h".
pub fn parse_duration(s: &str) -> Result<Duration> {
    let s = s.trim();
    let (num, mult) = match s.chars().last() {
        Some('s') => (&s[..s.len() - 1], 1),
        Some('m') => (&s[..s.len() - 1], 60),
        Some('h') => (&s[..s.len() - 1], 3600),
        _ => (s, 1),
    };
    let Ok(n) = num.parse::<u64>() else { bail!("invalid duration {s:?} (try 5m, 90s, 1h)") };
    if n == 0 {
        bail!("duration must be positive");
    }
    match n.checked_mul(mult) {
        Some(secs) if secs <= 24 * 3600 => Ok(Duration::from_secs(secs)),
        _ => bail!("duration must be at most 24h"),
    }
}

/// "<lan-ip>" hint for the join command printed by `thurang otp`.
pub fn lan_hint(enroll_port: u16) -> String {
    let ip = crate::platform::default_interface()
        .ok()
        .and_then(|i| i.ipv4.first().map(|n| n.addr().to_string()))
        .unwrap_or_else(|| "<server-ip>".into());
    if enroll_port == crate::proto::DEFAULT_ENROLL_PORT {
        ip
    } else {
        format!("{ip}:{enroll_port}")
    }
}

/// Resolves on Ctrl-C, or SIGTERM on Unix.
pub async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut term = signal(SignalKind::terminate()).expect("SIGTERM handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations() {
        assert_eq!(parse_duration("5m").unwrap(), Duration::from_secs(300));
        assert_eq!(parse_duration("90").unwrap(), Duration::from_secs(90));
        assert!(parse_duration("0").is_err());
        assert!(parse_duration("abc").is_err());
        assert!(parse_duration("99999999999999999h").is_err());
        assert!(parse_duration("25h").is_err());
        assert_eq!(duration(Duration::from_secs(300)), "5m00s");
    }

    #[test]
    fn byte_units() {
        assert_eq!(bytes(512), "512 B");
        assert_eq!(bytes(1536), "1.5 KiB");
    }
}
