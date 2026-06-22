//! A deliberately tiny HTTP/1.1 layer: just enough request parsing and
//! response writing to serve read-only WebDAV. Every response sets
//! `Connection: close`, so we handle exactly one request per connection and
//! never have to worry about keep-alive framing.

use std::collections::HashMap;
use std::io::{self, Read, Write};

const MAX_HEADER_BYTES: usize = 64 * 1024;
const MAX_BODY_BYTES: usize = 1 * 1024 * 1024; // PROPFIND bodies are tiny.

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
    if let Some(len) = headers.get("content-length").and_then(|v| v.parse::<usize>().ok()) {
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

    Ok(Request { method, path, headers })
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
    write_head(stream, status, reason, content_type, extra_headers, body.len() as u64)?;
    if send_body {
        stream.write_all(body)?;
    }
    stream.flush()
}

/// Write just the status line and headers, declaring `content_length` but
/// emitting no body. Callers stream the body themselves afterwards (see
/// [`stream_body`]) — this lets us serve arbitrarily large files without ever
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
    head.push_str(&format!("HTTP/1.1 {} {}\r\n", status, reason));
    head.push_str(&format!("Content-Length: {}\r\n", content_length));
    if !content_type.is_empty() {
        head.push_str(&format!("Content-Type: {}\r\n", content_type));
    }
    for (k, v) in extra_headers {
        head.push_str(&format!("{}: {}\r\n", k, v));
    }
    head.push_str("Server: tiny-webdav\r\n");
    head.push_str("Connection: close\r\n");
    head.push_str("\r\n");
    stream.write_all(head.as_bytes())
}

/// Copy exactly `len` bytes from `reader` to `writer` in fixed-size chunks,
/// then flush. Used to stream file bodies after [`write_head`].
pub fn stream_body<R: Read, W: Write>(reader: &mut R, writer: &mut W, len: u64) -> io::Result<()> {
    const CHUNK: usize = 64 * 1024;
    let mut buf = vec![0u8; CHUNK];
    let mut remaining = len;
    while remaining > 0 {
        let want = remaining.min(CHUNK as u64) as usize;
        let n = reader.read(&mut buf[..want])?;
        if n == 0 {
            // File ended sooner than its declared length (e.g. truncated
            // concurrently). Stop; the Connection: close framing bounds it.
            break;
        }
        writer.write_all(&buf[..n])?;
        remaining -= n as u64;
    }
    writer.flush()
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
