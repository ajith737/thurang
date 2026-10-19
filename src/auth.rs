//! OTP pairing codes and the SPAKE2-authenticated enrollment channel.
//!
//! The OTP is low-entropy, so it is never sent or used directly as a key.
//! Both sides run SPAKE2 with the OTP as the password; an eavesdropper learns
//! nothing, and an active attacker gets exactly one online guess per attempt.

use std::sync::Mutex;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hkdf::Hkdf;
use rand::Rng;
use sha2::Sha256;
use spake2::{Ed25519Group, Identity, Password, Spake2};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::proto;

pub const OTP_DIGITS: usize = 8;
/// Pairing attempts allowed per code. Counted when an attempt *starts*, so
/// concurrent connections can't get more guesses than this.
pub const MAX_ATTEMPTS: u32 = 5;
pub const MAX_TTL: Duration = Duration::from_secs(24 * 3600);
const SPAKE_ID: &[u8] = b"thurang-enroll-v1";

struct ActiveOtp {
    code: String,
    expires: Instant,
    attempts: u32,
    used: bool,
}

/// Holds the single active pairing code. Issuing a new one replaces the old.
#[derive(Default)]
pub struct OtpManager {
    active: Mutex<Option<ActiveOtp>>,
}

impl OtpManager {
    pub fn issue(&self, ttl: Duration) -> String {
        let ttl = ttl.min(MAX_TTL);
        let n: u32 = rand::rngs::OsRng.gen_range(0..10u32.pow(OTP_DIGITS as u32));
        let code = format!("{n:0width$}", width = OTP_DIGITS);
        *self.active.lock().unwrap() =
            Some(ActiveOtp { code: code.clone(), expires: Instant::now() + ttl, attempts: 0, used: false });
        code
    }

    /// Starts a pairing attempt: returns the code the peer must prove
    /// knowledge of, using up one of its [`MAX_ATTEMPTS`].
    pub fn begin_attempt(&self) -> Option<String> {
        let mut guard = self.active.lock().unwrap();
        let otp = guard.as_mut()?;
        if otp.used || otp.attempts >= MAX_ATTEMPTS || otp.expires <= Instant::now() {
            return None;
        }
        otp.attempts += 1;
        if otp.attempts == MAX_ATTEMPTS {
            tracing::warn!("last pairing attempt for the current code; issue a new one if it fails");
        }
        Some(otp.code.clone())
    }

    /// Marks `code` used after a successful pairing. Returns false if another
    /// device already used it, or it was replaced or expired.
    pub fn consume(&self, code: &str) -> bool {
        let mut guard = self.active.lock().unwrap();
        match guard.as_mut() {
            Some(otp) if otp.code == code && !otp.used && otp.expires > Instant::now() => {
                otp.used = true;
                true
            }
            _ => false,
        }
    }
}

pub fn normalize_otp(input: &str) -> String {
    input.chars().filter(|c| c.is_ascii_digit()).collect()
}

/// AEAD channel keyed from the SPAKE2 shared secret, one key per direction.
pub struct SecureChannel {
    send: ChaCha20Poly1305,
    recv: ChaCha20Poly1305,
    send_ctr: u64,
    recv_ctr: u64,
}

impl SecureChannel {
    fn new(shared: &[u8], is_server: bool) -> Self {
        let hk = Hkdf::<Sha256>::new(Some(SPAKE_ID), shared);
        let mut c2s = [0u8; 32];
        let mut s2c = [0u8; 32];
        hk.expand(b"client->server", &mut c2s).expect("hkdf length");
        hk.expand(b"server->client", &mut s2c).expect("hkdf length");
        let (send, recv) = if is_server { (s2c, c2s) } else { (c2s, s2c) };
        SecureChannel {
            send: ChaCha20Poly1305::new(Key::from_slice(&send)),
            recv: ChaCha20Poly1305::new(Key::from_slice(&recv)),
            send_ctr: 0,
            recv_ctr: 0,
        }
    }

    fn nonce(ctr: u64) -> Nonce {
        let mut n = [0u8; 12];
        n[..8].copy_from_slice(&ctr.to_le_bytes());
        *Nonce::from_slice(&n)
    }

    pub fn seal(&mut self, plaintext: &[u8]) -> Vec<u8> {
        let ct = self.send.encrypt(&Self::nonce(self.send_ctr), plaintext).expect("encryption cannot fail");
        self.send_ctr += 1;
        ct
    }

    /// Fails if the peer used a different OTP (keys differ) or tampered with data.
    pub fn open(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let pt = self
            .recv
            .decrypt(&Self::nonce(self.recv_ctr), ciphertext)
            .map_err(|_| anyhow!("pairing code mismatch"))?;
        self.recv_ctr += 1;
        Ok(pt)
    }

    pub async fn send_json<W: AsyncWrite + Unpin, T: serde::Serialize>(&mut self, w: &mut W, v: &T) -> Result<()> {
        let ct = self.seal(&serde_json::to_vec(v)?);
        proto::write_frame(w, &ct).await
    }

    pub async fn recv_json<R: AsyncRead + Unpin, T: serde::de::DeserializeOwned>(&mut self, r: &mut R) -> Result<T> {
        let ct = proto::read_frame(r).await?;
        let pt = self.open(&ct)?;
        Ok(serde_json::from_slice(&pt)?)
    }
}

fn spake_start(otp: &str) -> (Spake2<Ed25519Group>, Vec<u8>) {
    Spake2::<Ed25519Group>::start_symmetric(&Password::new(otp.as_bytes()), &Identity::new(SPAKE_ID))
}

/// Client side of the SPAKE2 exchange. The client sends first.
pub async fn handshake_client<S: AsyncRead + AsyncWrite + Unpin>(stream: &mut S, otp: &str) -> Result<SecureChannel> {
    let (state, outbound) = spake_start(otp);
    proto::write_frame(stream, &outbound).await?;
    let inbound = proto::read_frame(stream).await?;
    let shared = state.finish(&inbound).map_err(|e| anyhow!("SPAKE2 failed: {e:?}"))?;
    Ok(SecureChannel::new(&shared, false))
}

/// Server side. `code` is asked for only once the client's SPAKE2 message
/// has arrived, so bare connections don't use up pairing attempts.
pub async fn handshake_server<S, F>(stream: &mut S, code: F) -> Result<(SecureChannel, String)>
where
    S: AsyncRead + AsyncWrite + Unpin,
    F: FnOnce() -> Option<String>,
{
    let inbound = proto::read_frame(stream).await?;
    let otp = code().context("no active pairing code (run `thurang otp` on the server)")?;
    let (state, outbound) = spake_start(&otp);
    proto::write_frame(stream, &outbound).await?;
    let shared = state.finish(&inbound).map_err(|e| anyhow!("SPAKE2 failed: {e:?}"))?;
    Ok((SecureChannel::new(&shared, true), otp))
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn pair(client_otp: &str, server_otp: &str) -> Result<String> {
        let (mut a, mut b) = tokio::io::duplex(4096);
        let s = server_otp.to_string();
        let server = tokio::spawn(async move {
            let (mut ch, _) = handshake_server(&mut b, || Some(s)).await?;
            let msg: String = ch.recv_json(&mut b).await?;
            ch.send_json(&mut b, &format!("echo:{msg}")).await?;
            anyhow::Ok(())
        });
        let mut ch = handshake_client(&mut a, client_otp).await?;
        ch.send_json(&mut a, &"hi").await?;
        let reply: Result<String> = ch.recv_json(&mut a).await;
        let _ = server.await;
        reply
    }

    #[tokio::test]
    async fn matching_otp_pairs() {
        assert_eq!(pair("12345678", "12345678").await.unwrap(), "echo:hi");
    }

    #[tokio::test]
    async fn wrong_otp_fails() {
        assert!(pair("12345678", "87654321").await.is_err());
    }

    #[test]
    fn otp_single_use() {
        let m = OtpManager::default();
        let code = m.issue(Duration::from_secs(60));
        assert_eq!(code.len(), OTP_DIGITS);
        assert_eq!(m.begin_attempt().as_deref(), Some(code.as_str()));
        assert!(m.consume(&code));
        assert!(!m.consume(&code));
        assert!(m.begin_attempt().is_none());
    }

    #[test]
    fn otp_attempts_are_capped() {
        let m = OtpManager::default();
        let code = m.issue(Duration::from_secs(60));
        for _ in 0..MAX_ATTEMPTS {
            assert!(m.begin_attempt().is_some());
        }
        assert!(m.begin_attempt().is_none());
        // An attempt that started in time may still succeed.
        assert!(m.consume(&code));
    }

    #[test]
    fn otp_replaced_and_expired() {
        let m = OtpManager::default();
        let old = m.issue(Duration::from_secs(60));
        m.issue(Duration::from_secs(60));
        assert!(!m.consume(&old));
        let code = m.issue(Duration::from_millis(0));
        assert!(m.begin_attempt().is_none());
        assert!(!m.consume(&code));
    }

    #[test]
    fn otp_normalization() {
        assert_eq!(normalize_otp("1234-5678"), "12345678");
    }
}
