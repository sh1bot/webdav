//! Optional HTTP Basic authentication, layered on top of the mandatory mTLS.
//!
//! Credentials are read from a file (`user:password` per line) and/or a single
//! inline `--user`/`--password` pair. If no credentials are configured, Basic
//! auth is disabled and only the client certificate is required. When enabled,
//! every request must additionally carry valid `Authorization: Basic` creds.
//!
//! Basic auth sends the password in (base64 of) cleartext, which is fine here
//! because the entire connection is already encrypted by TLS.

use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::Path;

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
    pub fn load_file(&mut self, path: &Path) -> io::Result<()> {
        let text = fs::read_to_string(path)?;
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
                        format!(
                            "{}:{}: expected 'username:password'",
                            path.display(),
                            lineno + 1
                        ),
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
        let encoded = match header
            .strip_prefix("Basic ")
            .or_else(|| header.strip_prefix("basic "))
        {
            Some(e) => e.trim(),
            None => return false,
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
        match self.creds.get(user) {
            Some(expected) => constant_time_eq(expected.as_bytes(), pass.as_bytes()),
            // Still do a comparison against a dummy to keep timing uniform-ish.
            None => {
                let _ = constant_time_eq(b"x", pass.as_bytes());
                false
            }
        }
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

/// Length-independent-ish equality: compares all bytes when lengths match so a
/// match doesn't return faster than a near-match. (Length itself is not hidden.)
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
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
