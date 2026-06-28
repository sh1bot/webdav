//! Optional HTTP Basic authentication. This is the only auth tiny-webdav
//! enforces itself; client-certificate (mutual TLS) auth, if used, is handled
//! by stunnel in front of us.
//!
//! Credentials are read from a file (`user:password` per line) and/or a single
//! inline `--user`/`--password` pair. If no credentials are configured, Basic
//! auth is disabled. When enabled, every request must carry valid
//! `Authorization: Basic` credentials.
//!
//! Basic auth sends the password in (base64 of) cleartext, which is fine here
//! because stunnel has already encrypted the entire connection with TLS.

use std::collections::HashMap;
use std::io::{self, Read};

use crate::http::{self, Request};

pub struct Auth {
    realm: String,
    /// username -> password. Empty means authentication is disabled.
    creds: HashMap<String, String>,
}

impl Auth {
    pub fn new(realm: String) -> Self {
        Auth {
            realm,
            creds: HashMap::new(),
        }
    }

    pub fn is_enabled(&self) -> bool {
        !self.creds.is_empty()
    }

    /// Add a single `username` / `password` credential.
    pub fn add(&mut self, username: String, password: String) {
        self.creds.insert(username, password);
    }

    /// Load `username:password` lines from a file. Blank lines and lines
    /// starting with `#` are ignored. The password may itself contain `:`.
    /// Reads from an already-open `reader` (so the file can be opened before a
    /// chroot/privilege drop and parsed afterwards); `source` only labels errors.
    pub fn load(&mut self, mut reader: impl Read, source: &str) -> io::Result<()> {
        let mut text = String::new();
        reader.read_to_string(&mut text)?;
        for (lineno, raw) in text.lines().enumerate() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            match line.split_once(':') {
                Some((user, pass)) if !user.is_empty() => {
                    self.creds.insert(user.to_string(), pass.to_string());
                }
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("{}:{}: expected 'username:password'", source, lineno + 1),
                    ));
                }
            }
        }
        Ok(())
    }

    /// Returns true if the request is permitted. When auth is disabled this is
    /// always true; otherwise the request must present a valid Basic credential.
    pub fn authorize(&self, req: &Request) -> bool {
        if !self.is_enabled() {
            return true;
        }
        let header = match req.header("authorization") {
            Some(h) => h,
            None => return false,
        };
        // The auth scheme is case-insensitive (RFC 7617).
        let encoded = match header.split_once(' ') {
            Some((scheme, rest)) if scheme.eq_ignore_ascii_case("Basic") => rest.trim(),
            _ => return false,
        };
        let decoded = match base64_decode(encoded) {
            Some(d) => d,
            None => return false,
        };
        let decoded = match String::from_utf8(decoded) {
            Ok(s) => s,
            Err(_) => return false,
        };
        // Only split on the *first* colon: passwords may contain colons.
        let (user, pass) = match decoded.split_once(':') {
            Some(p) => p,
            None => return false,
        };
        // `password_matches` does the same length-governed work whether or not
        // the account exists, so a wrong password, a length mismatch, and an
        // unknown user are not distinguishable by timing.
        let stored = self.creds.get(user).map(String::as_bytes);
        password_matches(stored, pass.as_bytes())
    }

    /// Send a `401 Unauthorized` challenge prompting for Basic credentials.
    pub fn challenge<S: io::Write>(&self, stream: &mut S) -> io::Result<()> {
        http::write_response(
            stream,
            401,
            "Unauthorized",
            "text/plain; charset=utf-8",
            &[(
                "WWW-Authenticate",
                format!("Basic realm=\"{}\", charset=\"UTF-8\"", self.realm),
            )],
            b"401 Unauthorized\n",
            true,
        )
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
