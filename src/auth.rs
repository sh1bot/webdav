//! Optional HTTP Basic authentication. This is the only auth tiny-webdav
//! enforces itself; client-certificate (mutual TLS) auth, if used, is handled
//! by stunnel in front of us.
//!
//! Credentials are read from a file (`user:password` per line) and/or a single
//! inline `--auth user:password` pair — the same `user:password` syntax either
//! way, via [`Auth::add_pair`]. If no credentials are configured, Basic auth is
//! disabled. When enabled, every request must carry valid `Authorization: Basic`
//! credentials.
//!
//! Basic auth sends the password in (base64 of) cleartext, so it is only as
//! private as the transport: it assumes a TLS-terminating front (stunnel,
//! cloudflared, a reverse proxy) encrypts the connection to the client and that
//! tiny-webdav is not reachable on the network directly.

use std::collections::HashMap;
use std::io::{self, Read};

use crate::http::{self, Request};

pub struct Auth {
    /// username -> password. Empty means authentication is disabled.
    creds: HashMap<String, String>,
}

impl Auth {
    pub fn new() -> Self {
        Auth {
            creds: HashMap::new(),
        }
    }

    pub fn is_enabled(&self) -> bool {
        !self.creds.is_empty()
    }

    /// Parse and add a single `username:password` credential (only the first
    /// colon separates them, so the password may itself contain `:`). The one
    /// splitting rule shared by an `--auth-file` line and the inline `--auth`
    /// flag.
    pub fn add_pair(&mut self, user_pass: &str) -> Result<(), &'static str> {
        match user_pass.split_once(':') {
            Some((user, pass)) if !user.is_empty() => {
                self.creds.insert(user.to_string(), pass.to_string());
                Ok(())
            }
            _ => Err("expected 'username:password'"),
        }
    }

    /// Load `username:password` lines from a file. Blank lines and lines
    /// starting with `#` are ignored. Reads from an already-open `reader` (so
    /// the file can be opened before a chroot/privilege drop and parsed
    /// afterwards); `source` only labels errors.
    pub fn load(&mut self, mut reader: impl Read, source: &str) -> io::Result<()> {
        let mut text = String::new();
        reader.read_to_string(&mut text)?;
        for (lineno, raw) in text.lines().enumerate() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            self.add_pair(line).map_err(|msg| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("{}:{}: {}", source, lineno + 1, msg),
                )
            })?;
        }
        Ok(())
    }

    /// Returns true if the request is permitted. When auth is disabled this is
    /// always true; otherwise the request must present a valid Basic credential.
    pub fn authorize(&self, req: &Request) -> bool {
        !self.is_enabled() || self.check_credential(req).unwrap_or(false)
    }

    /// Extract and verify a Basic credential from the request. `None` means the
    /// header was missing or malformed in some way (wrong scheme, bad base64,
    /// not UTF-8, no colon); the caller treats that the same as "wrong password".
    fn check_credential(&self, req: &Request) -> Option<bool> {
        let header = req.header("authorization")?;
        // The auth scheme is case-insensitive (RFC 7617).
        let (scheme, rest) = header.split_once(' ')?;
        if !scheme.eq_ignore_ascii_case("Basic") {
            return None;
        }
        let decoded = String::from_utf8(base64_decode(rest.trim())?).ok()?;
        // Only split on the *first* colon: passwords may contain colons.
        let (user, pass) = decoded.split_once(':')?;
        // Timing-uniform even for an unknown user; see password_matches.
        let stored = self.creds.get(user).map(String::as_bytes);
        Some(password_matches(stored, pass.as_bytes()))
    }

    /// Send a `401 Unauthorized` challenge prompting for Basic credentials.
    pub fn challenge<S: io::Write>(&self, stream: &mut S) -> io::Result<()> {
        let h = (
            "WWW-Authenticate",
            "Basic realm=\"webdav\", charset=\"UTF-8\"".to_string(),
        );
        http::write_status(stream, 401, &[h])
    }
}

/// Check `candidate` against the stored password (`None` for an unknown account)
/// without leaking, by timing, whether the account exists or how long its
/// password is. There is deliberately **no** early return on a length mismatch:
/// the work is governed solely by `candidate.len()` (which the caller already
/// controls), so an unknown user, a wrong-length password, and a wrong password
/// all take the same time. The length difference is folded into the accumulator
/// so unequal lengths can never compare equal, and a trailing existence check
/// rejects a candidate that happens to match an empty/absent reference.
///
/// (Each connection is its own fork+exec+chroot+setuid process, whose spawn cost
/// dwarfs any byte-compare timing, so this closes the obvious algorithmic signal
/// rather than promising perfect constant-time at the instruction level.)
fn password_matches(stored: Option<&[u8]>, candidate: &[u8]) -> bool {
    let reference = stored.unwrap_or(&[]);
    let mut diff = (reference.len() ^ candidate.len()) as u32;
    for (i, &c) in candidate.iter().enumerate() {
        let r = reference.get(i).copied().unwrap_or(0); // 0-pad past the reference
        diff |= u32::from(r ^ c);
    }
    diff == 0 && stored.is_some()
}

/// Minimal standard-alphabet base64 decoder. Tolerates missing `=` padding and
/// embedded whitespace. Returns `None` on any invalid character.
fn base64_decode(input: &str) -> Option<Vec<u8>> {
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let mut out = Vec::with_capacity(input.len() * 3 / 4);
    for &c in input.as_bytes() {
        if c == b'=' || c.is_ascii_whitespace() {
            continue;
        }
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        } as u32;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::password_matches as pm;

    #[test]
    fn correct_password_matches() {
        assert!(pm(Some(b"s3cret"), b"s3cret"));
    }

    #[test]
    fn wrong_password_rejected() {
        assert!(!pm(Some(b"s3cret"), b"s3crXt")); // same length, wrong byte
        assert!(!pm(Some(b"s3cret"), b"s3cre")); // shorter
        assert!(!pm(Some(b"s3cret"), b"s3cretX")); // longer
    }

    #[test]
    fn unknown_account_rejected_for_any_candidate() {
        assert!(!pm(None, b""));
        assert!(!pm(None, b"anything"));
        assert!(!pm(None, b"\0")); // can't sneak past via the 0-padding
    }

    #[test]
    fn empty_stored_password_only_matches_empty() {
        assert!(pm(Some(b""), b""));
        assert!(!pm(Some(b""), b"x"));
    }
}
