//! Read-only WebDAV request handling: OPTIONS, GET, HEAD and PROPFIND.
//! Anything that would modify the filesystem (PUT, DELETE, MKCOL, COPY,
//! MOVE, PROPPATCH, LOCK, …) is answered with 405 Method Not Allowed.

use std::fs;
use std::io::{self, Read, Write};
use std::path::Path;
use std::time::SystemTime;

use crate::auth::Auth;
use crate::http::{self, Request};
use crate::util;

const ALLOW: &str = "OPTIONS, GET, HEAD, PROPFIND";

pub fn handle<S: Read + Write>(
    stream: &mut S,
    root: &Path,
    auth: &Auth,
    req: &Request,
) -> io::Result<()> {
    // Require valid Basic credentials (if configured) before doing anything.
    if !auth.authorize(req) {
        return auth.challenge(stream);
    }

    // Percent-decode and sanitise the request path before touching disk.
    let decoded = util::percent_decode(&req.path);
    let fs_path = match util::resolve_within(root, &decoded) {
        Some(p) => p,
        None => return http::write_status(stream, 403, "Forbidden"),
    };

    match req.method.as_str() {
        "OPTIONS" => options(stream),
        "GET" => get_or_head(stream, &decoded, &fs_path, req, true),
        "HEAD" => get_or_head(stream, &decoded, &fs_path, req, false),
        "PROPFIND" => propfind(stream, root, &decoded, &fs_path, req),
        // Read-only: reject every mutating / unsupported method.
        _ => http::write_response(
            stream,
            405,
            "Method Not Allowed",
            "text/plain; charset=utf-8",
            &[("Allow", ALLOW.to_string())],
            b"405 Method Not Allowed\n",
            true,
        ),
    }
}

fn options<S: Write>(stream: &mut S) -> io::Result<()> {
    http::write_response(
        stream,
        200,
        "OK",
        "",
        &[
            // DAV: 1 is all a read-only browser/list server needs to advertise.
            ("DAV", "1".to_string()),
            ("Allow", ALLOW.to_string()),
        ],
        b"",
        true,
    )
}

fn get_or_head<S: Write>(
    stream: &mut S,
    decoded_path: &str,
    fs_path: &Path,
    req: &Request,
    send_body: bool,
) -> io::Result<()> {
    let meta = match fs::metadata(fs_path) {
        Ok(m) => m,
        Err(_) => return http::write_status(stream, 404, "Not Found"),
    };

    if meta.is_dir() {
        // GET on a collection returns a simple HTML index for browsers.
        let html = directory_index_html(decoded_path, fs_path);
        return http::write_response(
            stream,
            200,
            "OK",
            "text/html; charset=utf-8",
            &[],
            html.as_bytes(),
            send_body,
        );
    }

    let len = meta.len();
    let mut headers: Vec<(&str, String)> = Vec::new();
    if let Ok(modified) = meta.modified() {
        headers.push(("Last-Modified", util::http_date(modified)));
    }
    // We honour single byte ranges; advertise that to clients.
    headers.push(("Accept-Ranges", "bytes".to_string()));

    let content_type = util::mime_for(fs_path);

    match req.header("range").map(|r| parse_byte_range(r, len)) {
        // A range was requested and it is satisfiable: 206 Partial Content.
        Some(RangeSpec::Satisfiable { start, end }) => {
            let count = end - start + 1;
            headers.push(("Content-Range", format!("bytes {}-{}/{}", start, end, len)));
            stream_file(stream, fs_path, start, count, 206, "Partial Content", content_type, &headers, send_body)
        }
        // A range was requested but cannot be satisfied: 416.
        Some(RangeSpec::Unsatisfiable) => http::write_response(
            stream,
            416,
            "Range Not Satisfiable",
            "text/plain; charset=utf-8",
            &[("Content-Range", format!("bytes */{}", len))],
            b"416 Range Not Satisfiable\n",
            true,
        ),
        // No usable Range header: serve the whole file (200).
        _ => stream_file(stream, fs_path, 0, len, 200, "OK", content_type, &headers, send_body),
    }
}

/// Stream `count` bytes of a file starting at byte `offset` as the response
/// body, after writing the status line and headers. The file is read in
/// chunks (see [`http::stream_body`]) so large files never sit in memory.
#[allow(clippy::too_many_arguments)]
fn stream_file<S: Write>(
    stream: &mut S,
    fs_path: &Path,
    offset: u64,
    count: u64,
    status: u16,
    reason: &str,
    content_type: &str,
    headers: &[(&str, String)],
    send_body: bool,
) -> io::Result<()> {
    use std::io::{Seek as _, SeekFrom};

    // Open (and seek) before writing the header so a failure can still be
    // reported as an error response rather than a truncated body.
    let mut file = match fs::File::open(fs_path) {
        Ok(f) => f,
        Err(_) => return http::write_status(stream, 404, "Not Found"),
    };
    if offset != 0 && file.seek(SeekFrom::Start(offset)).is_err() {
        return http::write_status(stream, 500, "Internal Server Error");
    }

    http::write_head(stream, status, reason, content_type, headers, count)?;
    if send_body {
        http::stream_body(&mut file, stream, count)?;
    } else {
        stream.flush()?;
    }
    Ok(())
}

/// The outcome of interpreting a `Range` header against a known content length.
enum RangeSpec {
    /// A single satisfiable range, inclusive of both endpoints.
    Satisfiable { start: u64, end: u64 },
    /// The header was a well-formed byte range that cannot be satisfied.
    Unsatisfiable,
    /// The header is absent/unsupported (e.g. multiple ranges, non-`bytes`
    /// units, or unparseable); the caller should serve the full entity.
    Ignore,
}

/// Parse a single-range `Range: bytes=...` header against `len` bytes.
///
/// Supports the three standard single-range forms:
///   `bytes=START-END`, `bytes=START-`, and `bytes=-SUFFIXLEN`.
/// Multiple comma-separated ranges and non-`bytes` units are ignored (the
/// caller then serves the whole file, which the spec permits).
fn parse_byte_range(value: &str, len: u64) -> RangeSpec {
    let spec = match value.trim().strip_prefix("bytes=") {
        Some(s) => s.trim(),
        None => return RangeSpec::Ignore,
    };

    // We only implement single ranges; a comma means a multi-range request.
    if spec.contains(',') {
        return RangeSpec::Ignore;
    }

    let (start_s, end_s) = match spec.split_once('-') {
        Some(parts) => parts,
        None => return RangeSpec::Ignore,
    };
    let start_s = start_s.trim();
    let end_s = end_s.trim();

    // An empty file can satisfy no range.
    if len == 0 {
        return RangeSpec::Unsatisfiable;
    }

    if start_s.is_empty() {
        // Suffix form: `bytes=-N` => the final N bytes.
        let suffix: u64 = match end_s.parse() {
            Ok(n) => n,
            Err(_) => return RangeSpec::Ignore,
        };
        if suffix == 0 {
            return RangeSpec::Unsatisfiable;
        }
        let start = len.saturating_sub(suffix);
        return RangeSpec::Satisfiable { start, end: len - 1 };
    }

    let start: u64 = match start_s.parse() {
        Ok(n) => n,
        Err(_) => return RangeSpec::Ignore,
    };
    if start >= len {
        return RangeSpec::Unsatisfiable;
    }

    let end: u64 = if end_s.is_empty() {
        len - 1
    } else {
        match end_s.parse::<u64>() {
            Ok(n) => n.min(len - 1), // clamp to the last byte
            Err(_) => return RangeSpec::Ignore,
        }
    };

    if end < start {
        return RangeSpec::Unsatisfiable;
    }
    RangeSpec::Satisfiable { start, end }
}

struct IndexEntry {
    name: String,
    is_dir: bool,
    /// Last-modified time, if the filesystem reports one.
    modified: Option<SystemTime>,
    /// Size in bytes (meaningful for files only).
    len: u64,
}

fn directory_index_html(decoded_path: &str, fs_path: &Path) -> String {
    let mut entries: Vec<IndexEntry> = Vec::new();
    if let Ok(rd) = fs::read_dir(fs_path) {
        for e in rd.flatten() {
            // Follow symlinks so size/date match what GET would actually serve.
            // Fall back to the entry's own type if the target can't be stat'd.
            let md = fs::metadata(e.path()).ok();
            let is_dir = md
                .as_ref()
                .map(|m| m.is_dir())
                .or_else(|| e.file_type().map(|t| t.is_dir()).ok())
                .unwrap_or(false);
            entries.push(IndexEntry {
                name: e.file_name().to_string_lossy().into_owned(),
                is_dir,
                modified: md.as_ref().and_then(|m| m.modified().ok()),
                len: md.as_ref().map(|m| m.len()).unwrap_or(0),
            });
        }
    }
    // Directories first, then alphabetical.
    entries.sort_by(|a, b| b.is_dir.cmp(&a.is_dir).then(a.name.cmp(&b.name)));

    let base = if decoded_path.ends_with('/') {
        decoded_path.to_string()
    } else {
        format!("{}/", decoded_path)
    };
    let title = util::xml_escape(decoded_path);

    let mut html = String::new();
    html.push_str("<!DOCTYPE html>\n<html><head><meta charset=\"utf-8\">");
    html.push_str(&format!("<title>Index of {}</title>", title));
    html.push_str(
        "<style>body{font-family:sans-serif;margin:1.5rem}\
         h1{font-size:1.1rem}table{border-collapse:collapse}\
         th,td{text-align:left;padding:.2rem 1.2rem .2rem 0;white-space:nowrap}\
         th{border-bottom:1px solid #ccc}td.size{text-align:right;font-variant-numeric:tabular-nums}\
         td.date{font-variant-numeric:tabular-nums;color:#444}</style></head><body>",
    );
    html.push_str(&format!("<h1>Index of {}</h1>", title));
    html.push_str(
        "<table><thead><tr><th>Name</th><th>Last modified (UTC)</th><th>Size</th></tr></thead><tbody>",
    );

    if decoded_path != "/" {
        html.push_str("<tr><td><a href=\"../\">../</a></td><td></td><td></td></tr>");
    }
    for e in entries {
        let suffix = if e.is_dir { "/" } else { "" };
        let href = util::percent_encode_path(&format!("{}{}{}", base, e.name, suffix));
        let modified = e
            .modified
            .map(util::datetime_utc)
            .unwrap_or_else(|| "-".to_string());
        let size = if e.is_dir {
            "-".to_string()
        } else {
            util::human_size(e.len)
        };
        html.push_str(&format!(
            "<tr><td><a href=\"{}\">{}{}</a></td><td class=\"date\">{}</td><td class=\"size\">{}</td></tr>",
            href,
            util::xml_escape(&e.name),
            suffix,
            modified,
            size,
        ));
    }
    html.push_str("</tbody></table></body></html>");
    html
}

fn propfind<S: Write>(
    stream: &mut S,
    _root: &Path,
    decoded_path: &str,
    fs_path: &Path,
    req: &Request,
) -> io::Result<()> {
    let meta = match fs::metadata(fs_path) {
        Ok(m) => m,
        Err(_) => return http::write_status(stream, 404, "Not Found"),
    };

    // Depth: 0 => just this resource; 1 => this resource + immediate children.
    // "infinity" is treated as 1 to stay simple and bounded.
    let depth = req.header("depth").unwrap_or("1").trim();
    let include_children = depth != "0";

    let mut xml = String::new();
    xml.push_str("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n");
    xml.push_str("<D:multistatus xmlns:D=\"DAV:\">\n");

    // The resource itself.
    xml.push_str(&response_xml(decoded_path, &meta, fs_path));

    // Immediate children, if this is a collection and depth allows it.
    if meta.is_dir() && include_children {
        let base = if decoded_path.ends_with('/') {
            decoded_path.to_string()
        } else {
            format!("{}/", decoded_path)
        };
        if let Ok(rd) = fs::read_dir(fs_path) {
            for entry in rd.flatten() {
                if let Ok(child_meta) = entry.metadata() {
                    let name = entry.file_name().to_string_lossy().into_owned();
                    let child_path = format!("{}{}", base, name);
                    xml.push_str(&response_xml(&child_path, &child_meta, &entry.path()));
                }
            }
        }
    }

    xml.push_str("</D:multistatus>\n");

    http::write_response(
        stream,
        207,
        "Multi-Status",
        "application/xml; charset=utf-8",
        &[],
        xml.as_bytes(),
        true,
    )
}

/// Build one `<D:response>` block describing a single resource.
fn response_xml(href_path: &str, meta: &fs::Metadata, fs_path: &Path) -> String {
    let is_dir = meta.is_dir();

    // Collections must end with a trailing slash in their href.
    let mut href = href_path.to_string();
    if is_dir && !href.ends_with('/') {
        href.push('/');
    }
    let href = util::percent_encode_path(&href);

    let display = fs_path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "/".to_string());

    let modified = meta
        .modified()
        .map(util::http_date)
        .unwrap_or_else(|_| util::http_date(SystemTime::UNIX_EPOCH));

    let mut block = String::new();
    block.push_str("  <D:response>\n");
    block.push_str(&format!("    <D:href>{}</D:href>\n", href));
    block.push_str("    <D:propstat>\n");
    block.push_str("      <D:prop>\n");
    block.push_str(&format!(
        "        <D:displayname>{}</D:displayname>\n",
        util::xml_escape(&display)
    ));
    block.push_str(&format!(
        "        <D:getlastmodified>{}</D:getlastmodified>\n",
        modified
    ));
    if is_dir {
        block.push_str("        <D:resourcetype><D:collection/></D:resourcetype>\n");
    } else {
        block.push_str("        <D:resourcetype/>\n");
        block.push_str(&format!(
            "        <D:getcontentlength>{}</D:getcontentlength>\n",
            meta.len()
        ));
        block.push_str(&format!(
            "        <D:getcontenttype>{}</D:getcontenttype>\n",
            util::mime_for(fs_path)
        ));
    }
    block.push_str("      </D:prop>\n");
    block.push_str("      <D:status>HTTP/1.1 200 OK</D:status>\n");
    block.push_str("    </D:propstat>\n");
    block.push_str("  </D:response>\n");
    block
}
