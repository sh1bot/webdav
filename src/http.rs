//! A deliberately tiny HTTP/1.1 layer: just enough request parsing and
//! response writing to serve read-only WebDAV. Every response sets
//! `Connection: close`, so we handle exactly one request per connection and
//! never have to worry about keep-alive framing.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::io::{self, Read, Write};
use std::time::SystemTime;

use crate::util;

const MAX_HEADER_BYTES: usize = 64 * 1024;
const MAX_BODY_BYTES: usize = 1024 * 1024; // PROPFIND bodies are tiny.

pub struct Request {
    pub method: String,
    pub path: String,
    /// Header names are stored lowercased for case-insensitive lookup.
    pub headers: HashMap<String, String>,
}

impl Request {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).map(|s| s.as_str())
    }
}

/// Read and parse a single request line + headers, then drain any body
/// announced via `Content-Length` (we don't need the body content, but we
/// must consume it to keep the stream sane before replying).
pub fn read_request<S: Read>(stream: &mut S) -> io::Result<Request> {
    let mut buf = Vec::with_capacity(1024);
    let mut byte = [0u8; 1];

    // Read until the CRLFCRLF that terminates the header block.
    loop {
        let n = stream.read(&mut byte)?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "connection closed before request was complete",
            ));
        }
        buf.push(byte[0]);
        if buf.len() >= 4 && &buf[buf.len() - 4..] == b"\r\n\r\n" {
            break;
        }
        if buf.len() > MAX_HEADER_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "request headers too large",
            ));
        }
    }

    let text = String::from_utf8_lossy(&buf);
    let mut lines = text.split("\r\n");

    let request_line = lines.next().unwrap_or("");
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let raw_target = parts.next().unwrap_or("").to_string();

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

    // Drain request body if present so the socket is clean.
    if let Some(len) = headers
        .get("content-length")
        .and_then(|v| v.parse::<usize>().ok())
    {
        let to_read = len.min(MAX_BODY_BYTES);
        let mut remaining = to_read;
        let mut sink = [0u8; 4096];
        while remaining > 0 {
            let want = remaining.min(sink.len());
            let n = stream.read(&mut sink[..want])?;
            if n == 0 {
                break;
            }
            remaining -= n;
        }
    }

    Ok(Request {
        method,
        path,
        headers,
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
    head.push_str("Connection: close\r\n");
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
/// (fewer bytes than the declared length) means the file was truncated under us;
/// we stop, and `Connection: close` framing bounds the response.
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
            break; // file ended before its declared length
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
