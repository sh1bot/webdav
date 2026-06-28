//! A deliberately tiny HTTP/1.1 layer: just enough request parsing and
//! response writing to serve read-only WebDAV. Persistent connections are
//! supported — the serve loop sets [`set_keep_alive`] per request and
//! [`write_head`] emits the matching `Connection` header. Every response carries
//! a `Content-Length`, so each one is self-delimiting on a kept-alive connection.

use std::cell::Cell;
use std::collections::HashMap;
use std::fmt::Write as _;
use std::io::{self, BufRead, Write};
use std::time::SystemTime;

use crate::util;

const MAX_HEADER_BYTES: usize = 64 * 1024;
const MAX_BODY_BYTES: usize = 1024 * 1024; // PROPFIND bodies are tiny.

thread_local! {
    /// Whether the response now being written should keep the connection open.
    /// Set once per request by the serve loop and read by `write_head`. The
    /// process is single-threaded and handles one connection, so this is a
    /// per-connection flag without threading it through every response helper.
    static KEEP_ALIVE: Cell<bool> = const { Cell::new(false) };
}

/// Set the connection disposition for subsequent responses (see [`write_head`]).
pub fn set_keep_alive(v: bool) {
    KEEP_ALIVE.with(|k| k.set(v));
}

pub struct Request {
    pub method: String,
    pub path: String,
    pub version: String,
    /// Header names are stored lowercased for case-insensitive lookup.
    pub headers: HashMap<String, String>,
    /// False if we couldn't determine the body boundary (oversized/unparseable
    /// `Content-Length`, `Transfer-Encoding`, or a truncated body) — the stream
    /// position is then unknown, so the connection must not be reused.
    well_framed: bool,
}

impl Request {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).map(|s| s.as_str())
    }

    /// Whether this request permits a persistent connection: HTTP/1.1 unless it
    /// asks to `close`, or HTTP/1.0 only if it asks to `keep-alive`. Always false
    /// if the body framing was lost (see `well_framed`).
    pub fn keep_alive(&self) -> bool {
        if !self.well_framed {
            return false;
        }
        let conn = self.header("connection").unwrap_or("");
        let has = |tok: &str| conn.split(',').any(|t| t.trim().eq_ignore_ascii_case(tok));
        if self.version.eq_ignore_ascii_case("HTTP/1.1") {
            !has("close")
        } else {
            has("keep-alive")
        }
    }
}

/// Read and parse a single request line + headers, then drain any body
/// announced via `Content-Length` (we don't need the body content, but we
/// must consume it to keep the stream sane before replying).
pub fn read_request<S: BufRead>(stream: &mut S) -> io::Result<Request> {
    // Read the header block a line at a time until the blank line that ends it.
    // `read_until` pulls a whole line straight from the buffer, rather than one
    // trait call per byte.
    let mut buf = Vec::with_capacity(1024);
    loop {
        let start = buf.len();
        if stream.read_until(b'\n', &mut buf)? == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "connection closed before request was complete",
            ));
        }
        if buf.len() > MAX_HEADER_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "request headers too large",
            ));
        }
        if &buf[start..] == b"\r\n" {
            break; // a CRLF on its own line terminates the header block
        }
    }

    let text = String::from_utf8_lossy(&buf);
    let mut lines = text.split("\r\n");

    let request_line = lines.next().unwrap_or("");
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let raw_target = parts.next().unwrap_or("").to_string();
    let version = parts.next().unwrap_or("HTTP/1.0").to_string();

    if method.is_empty() || raw_target.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "malformed request line",
        ));
    }

    // Strip any query string; we only serve by path.
    let path = raw_target
        .split(['?', '#'])
        .next()
        .unwrap_or("/")
        .to_string();

    let mut headers = HashMap::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        if let Some((k, v)) = line.split_once(':') {
            headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
        }
    }

    // Drain the request body so the stream is positioned at the next request.
    // If we can't be sure where the body ends, leave `well_framed` false so the
    // caller closes the connection instead of risking a desync.
    let mut well_framed = true;
    if headers.contains_key("transfer-encoding") {
        // We don't decode chunked, so we can't find the next request boundary.
        well_framed = false;
    } else if let Some(cl) = headers.get("content-length") {
        match cl.parse::<usize>() {
            Ok(len) if len <= MAX_BODY_BYTES => {
                let mut remaining = len;
                let mut sink = [0u8; 4096];
                while remaining > 0 {
                    let want = remaining.min(sink.len());
                    let n = stream.read(&mut sink[..want])?;
                    if n == 0 {
                        well_framed = false; // truncated body
                        break;
                    }
                    remaining -= n;
                }
            }
            _ => well_framed = false, // oversized or unparseable
        }
    }

    Ok(Request {
        method,
        path,
        version,
        headers,
        well_framed,
    })
}

/// Write a complete response with the given status, extra headers and body.
/// `body` is the raw bytes; for HEAD requests pass `send_body = false` to omit
/// it while still advertising the correct `Content-Length`.
pub fn write_response<S: Write>(
    stream: &mut S,
    status: u16,
    reason: &str,
    content_type: &str,
    extra_headers: &[(&str, String)],
    body: &[u8],
    send_body: bool,
) -> io::Result<()> {
    write_head(
        stream,
        status,
        reason,
        content_type,
        extra_headers,
        body.len() as u64,
    )?;
    if send_body {
        stream.write_all(body)?;
    }
    stream.flush()
}

/// Write just the status line and headers, declaring `content_length` but
/// emitting no body. Callers stream the body themselves afterwards (see
/// [`send_file`]) — this lets us serve arbitrarily large files without ever
/// holding them in memory.
pub fn write_head<S: Write>(
    stream: &mut S,
    status: u16,
    reason: &str,
    content_type: &str,
    extra_headers: &[(&str, String)],
    content_length: u64,
) -> io::Result<()> {
    let mut head = String::new();
    let _ = write!(head, "HTTP/1.1 {} {}\r\n", status, reason);
    let _ = write!(head, "Content-Length: {}\r\n", content_length);
    if !content_type.is_empty() {
        let _ = write!(head, "Content-Type: {}\r\n", content_type);
    }
    for (k, v) in extra_headers {
        let _ = write!(head, "{}: {}\r\n", k, v);
    }
    let _ = write!(head, "Date: {}\r\n", util::http_date(SystemTime::now()));
    head.push_str("Server: tiny-webdav\r\n");
    let alive = KEEP_ALIVE.with(|k| k.get());
    head.push_str(if alive {
        "Connection: keep-alive\r\n"
    } else {
        "Connection: close\r\n"
    });
    head.push_str("\r\n");
    stream.write_all(head.as_bytes())
}

/// Stream `count` bytes of `file` starting at byte `offset` to the socket
/// `out_fd` using the kernel's `sendfile(2)`, so the bytes go straight from the
/// page cache to the socket without ever passing through userspace. Used to send
/// file bodies after [`write_head`].
///
/// The kernel advances its own copy of the offset (the `off` pointer), so the
/// file's cursor is untouched and ranges need no prior `seek`. A short transfer
/// (the file was truncated under us, so we can't deliver the `Content-Length` we
/// promised) is an error: the framing is broken, so the caller must close the
/// connection rather than keep it alive.
#[cfg(unix)]
pub fn send_file(
    out_fd: std::os::unix::io::RawFd,
    file: &std::fs::File,
    offset: u64,
    count: u64,
) -> io::Result<()> {
    use std::os::unix::io::AsRawFd;

    let in_fd = file.as_raw_fd();
    let mut off = offset as libc::off_t;
    let mut remaining = count;
    while remaining > 0 {
        // sendfile transfers at most ~2 GiB per call.
        let want = remaining.min(0x7fff_f000) as usize;
        let sent = unsafe { libc::sendfile(out_fd, in_fd, &mut off, want) };
        if sent < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e);
        }
        if sent == 0 {
            // File ended before its declared length: we've under-delivered the
            // body. Fail so the connection is closed (it can't be reused safely).
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "file truncated during send",
            ));
        }
        remaining -= sent as u64;
    }
    Ok(())
}

/// Convenience for short text/error responses.
pub fn write_status<S: Write>(stream: &mut S, status: u16, reason: &str) -> io::Result<()> {
    let body = format!("{} {}\n", status, reason);
    write_response(
        stream,
        status,
        reason,
        "text/plain; charset=utf-8",
        &[],
        body.as_bytes(),
        true,
    )
}
