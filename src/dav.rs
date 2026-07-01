//! Read-only WebDAV request handling: OPTIONS, GET, HEAD and PROPFIND.
//! Anything that would modify the filesystem (PUT, DELETE, MKCOL, COPY,
//! MOVE, PROPPATCH, LOCK, …) is answered with 405 Method Not Allowed.

use std::fs;
use std::io::{self, Write};
use std::os::unix::io::AsRawFd;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::auth::Auth;
use crate::http::{self, Request};
use crate::util;

const ALLOW: &str = "OPTIONS, GET, HEAD, PROPFIND";

pub fn handle<S: Write + AsRawFd>(
    stream: &mut S,
    root: &Path,
    auth: &Auth,
    req: &Request,
    exposes: &[String],
) -> io::Result<()> {
    // Require valid Basic credentials (if configured) before doing anything.
    if !auth.authorize(req) {
        return auth.challenge(stream);
    }

    // Percent-decode and sanitise the request path before touching disk. A `..`
    // escape is reported as 404 (not 403), like an out-of-root symlink, so the
    // response never reveals that the traversal filter (or a chroot) is in play.
    let decoded = util::percent_decode(&req.path);
    let fs_path = match util::resolve_within(root, &decoded) {
        Some(p) => p,
        None => return http::write_status(stream, 404, "Not Found"),
    };

    // Hidden system entries (.htpasswd, .git, @eaDir, …) are never served unless
    // re-exposed by an `--expose` glob: a request naming a still-hidden one is
    // refused with the same reveal-nothing 404, consistent with its omission from
    // the listings below.
    if util::path_has_hidden(&decoded, exposes) {
        return http::write_status(stream, 404, "Not Found");
    }

    match req.method.as_str() {
        "OPTIONS" => options(stream),
        "GET" => get_or_head(stream, root, &decoded, &fs_path, req, true, exposes),
        "HEAD" => get_or_head(stream, root, &decoded, &fs_path, req, false, exposes),
        "PROPFIND" => propfind(stream, root, &decoded, &fs_path, req, exposes),
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

fn get_or_head<S: Write + AsRawFd>(
    stream: &mut S,
    root: &Path,
    decoded_path: &str,
    fs_path: &Path,
    req: &Request,
    send_body: bool,
    exposes: &[String],
) -> io::Result<()> {
    let meta = match stat_within_root(stream, root, fs_path)? {
        Some(m) => m,
        None => return Ok(()),
    };

    if meta.is_dir() {
        // GET on a collection returns a simple HTML index for browsers.
        let html = directory_index_html(root, decoded_path, fs_path, exposes);
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
    let modified = meta.modified().ok();
    let etag = etag_for(&meta);

    // Conditional GET: If-None-Match / If-Modified-Since => 304 Not Modified.
    if not_modified(req, etag.as_deref(), modified) {
        let mut h: Vec<(&str, String)> = Vec::new();
        if let Some(e) = &etag {
            h.push(("ETag", e.clone()));
        }
        if let Some(m) = modified {
            h.push(("Last-Modified", util::http_date(m)));
        }
        return http::write_response(stream, 304, "Not Modified", "", &h, b"", false);
    }

    let mut headers: Vec<(&str, String)> = Vec::new();
    if let Some(m) = modified {
        headers.push(("Last-Modified", util::http_date(m)));
    }
    if let Some(e) = &etag {
        headers.push(("ETag", e.clone()));
    }
    // We honour single byte ranges; advertise that to clients.
    headers.push(("Accept-Ranges", "bytes".to_string()));

    let content_type = util::mime_for(fs_path);

    // Honour Range only when there's no If-Range or its validator still matches;
    // otherwise serve the full entity (so a resumed download can't splice bytes
    // from two different versions of a file).
    let range = req.header("range");
    let spec = match range {
        Some(r) if if_range_matches(req, etag.as_deref(), modified) => parse_byte_range(r, len),
        _ => RangeSpec::Ignore,
    };

    match spec {
        // A range was requested and it is satisfiable: 206 Partial Content.
        RangeSpec::Satisfiable { start, end } => {
            let count = end - start + 1;
            headers.push(("Content-Range", format!("bytes {}-{}/{}", start, end, len)));
            let resp = Resp {
                status: 206,
                reason: "Partial Content",
                content_type,
                headers: &headers,
            };
            stream_file(stream, fs_path, start, count, &resp, send_body)
        }
        // A range was requested but cannot be satisfied: 416.
        RangeSpec::Unsatisfiable => http::write_response(
            stream,
            416,
            "Range Not Satisfiable",
            "text/plain; charset=utf-8",
            &[("Content-Range", format!("bytes */{}", len))],
            b"416 Range Not Satisfiable\n",
            true,
        ),
        // No usable Range header: serve the whole file (200).
        RangeSpec::Ignore => {
            let resp = Resp {
                status: 200,
                reason: "OK",
                content_type,
                headers: &headers,
            };
            stream_file(stream, fs_path, 0, len, &resp, send_body)
        }
    }
}

/// The status line + headers for a streamed file response.
struct Resp<'a> {
    status: u16,
    reason: &'a str,
    content_type: &'a str,
    headers: &'a [(&'a str, String)],
}

/// Stream `count` bytes of a file starting at byte `offset` as the response
/// body, after writing the status line and headers. The body goes straight from
/// the page cache to the socket via the kernel (see [`http::send_file`]), so
/// large files never sit in memory.
fn stream_file<S: Write + AsRawFd>(
    stream: &mut S,
    fs_path: &Path,
    offset: u64,
    count: u64,
    resp: &Resp,
    send_body: bool,
) -> io::Result<()> {
    // Open before writing the header so a failure can still be reported as an
    // error response rather than a truncated body. sendfile takes the offset
    // directly, so there is no need to seek.
    let file = match fs::File::open(fs_path) {
        Ok(f) => f,
        Err(e) => return err_status(stream, &e),
    };

    http::write_head(
        stream,
        resp.status,
        resp.reason,
        resp.content_type,
        resp.headers,
        count,
    )?;
    if send_body {
        http::send_file(stream.as_raw_fd(), &file, offset, count)?;
    } else {
        stream.flush()?;
    }
    Ok(())
}

/// `stat` the target and confine it to `root` in one place, so every handler
/// applies the same gate. On success returns the metadata; on any failure writes
/// the response (404/403/500, with an out-of-root target mapped to 404 so the
/// chroot status isn't revealed) and returns `None`.
fn stat_within_root<S: Write>(
    stream: &mut S,
    root: &Path,
    fs_path: &Path,
) -> io::Result<Option<fs::Metadata>> {
    let meta = match fs::metadata(fs_path) {
        Ok(m) => m,
        Err(e) => return err_status(stream, &e).map(|()| None),
    };
    if !within_root(root, fs_path) {
        return http::write_status(stream, 404, "Not Found").map(|()| None);
    }
    Ok(Some(meta))
}

/// Map a filesystem error to the appropriate HTTP status response.
fn err_status<S: Write>(stream: &mut S, e: &io::Error) -> io::Result<()> {
    match e.kind() {
        io::ErrorKind::NotFound => http::write_status(stream, 404, "Not Found"),
        io::ErrorKind::PermissionDenied => http::write_status(stream, 403, "Forbidden"),
        _ => http::write_status(stream, 500, "Internal Server Error"),
    }
}

/// True if `fs_path`, fully resolved (following symlinks), is still inside
/// `root`. When the server has chrooted, `root` is `/` so nothing can be outside
/// it — short-circuit and skip the per-path `canonicalize`. Otherwise resolve and
/// check the prefix, which stops a symlink under the served tree from escaping.
fn within_root(root: &Path, fs_path: &Path) -> bool {
    if root == Path::new("/") {
        return true;
    }
    match fs_path.canonicalize() {
        Ok(real) => real.starts_with(root),
        Err(_) => false,
    }
}

/// A strong validator built from size and mtime, e.g. `"1f-65a3b2c0"`.
fn etag_for(meta: &fs::Metadata) -> Option<String> {
    let secs = meta
        .modified()
        .ok()?
        .duration_since(UNIX_EPOCH)
        .ok()?
        .as_secs();
    Some(format!("\"{:x}-{:x}\"", meta.len(), secs))
}

/// Does an `If-None-Match` entry list match our ETag (or is it `*`)?
fn etag_list_matches(header: &str, etag: &str) -> bool {
    let h = header.trim();
    h == "*"
        || h.split(',')
            .map(|t| t.trim().trim_start_matches("W/"))
            .any(|t| t == etag)
}

/// Evaluate conditional-GET preconditions. Returns true when the client's
/// cached copy is still current and we should answer `304 Not Modified`.
/// `If-None-Match` takes precedence over `If-Modified-Since` (RFC 7232).
fn not_modified(req: &Request, etag: Option<&str>, modified: Option<SystemTime>) -> bool {
    if let Some(inm) = req.header("if-none-match") {
        return etag.map(|e| etag_list_matches(inm, e)).unwrap_or(false);
    }
    if let (Some(ims), Some(m)) = (req.header("if-modified-since"), modified) {
        if let (Some(since), Ok(mtime)) = (
            util::parse_http_date(ims),
            m.duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64),
        ) {
            return mtime <= since;
        }
    }
    false
}

/// For a ranged request, decide whether the `If-Range` validator still matches
/// (so the range is safe to serve). No `If-Range` header => always matches.
fn if_range_matches(req: &Request, etag: Option<&str>, modified: Option<SystemTime>) -> bool {
    let ir = match req.header("if-range") {
        Some(v) => v.trim(),
        None => return true,
    };
    if ir.starts_with('"') {
        return etag == Some(ir);
    }
    if let (Some(since), Some(m)) = (util::parse_http_date(ir), modified) {
        if let Ok(mtime) = m.duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64) {
            return mtime <= since;
        }
    }
    false
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
        return RangeSpec::Satisfiable {
            start,
            end: len - 1,
        };
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

fn directory_index_html(
    root: &Path,
    decoded_path: &str,
    fs_path: &Path,
    exposes: &[String],
) -> String {
    let mut entries: Vec<IndexEntry> = Vec::new();
    if let Ok(rd) = fs::read_dir(fs_path) {
        for e in rd.flatten() {
            // Hidden system entries are omitted (they're also refused on access),
            // unless re-exposed by an --expose glob.
            if util::is_hidden(&e.file_name().to_string_lossy(), exposes) {
                continue;
            }
            // Don't list entries (e.g. symlinks) that resolve outside the root.
            if !within_root(root, &e.path()) {
                continue;
            }
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

    let base = util::with_trailing_slash(decoded_path);
    let title = util::xml_escape(decoded_path);

    let mut html = String::new();
    html.push_str("<!DOCTYPE html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">");
    html.push_str(&format!("<title>Index of {}</title>", title));
    html.push_str(
        "<style>body{font-family:sans-serif}td,th{text-align:left;padding:0 1.5rem 0 0}</style></head><body>",
    );
    html.push_str(&format!("<h1>Index of {}</h1>", title));
    html.push_str(
        "<table><thead><tr><th scope=\"col\">Name</th>\
         <th scope=\"col\">Last modified (UTC)</th>\
         <th scope=\"col\">Size</th></tr></thead><tbody>",
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
            "<tr><td><a href=\"{}\">{}{}</a></td><td>{}</td><td>{}</td></tr>",
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
    root: &Path,
    decoded_path: &str,
    fs_path: &Path,
    req: &Request,
    exposes: &[String],
) -> io::Result<()> {
    let meta = match stat_within_root(stream, root, fs_path)? {
        Some(m) => m,
        None => return Ok(()),
    };

    // Depth: 0 => just this resource; 1 => this resource + immediate children.
    let depth = req.header("depth").unwrap_or("1").trim();
    // We don't crawl recursively; tell an "infinity" client to walk per-level
    // instead of silently returning only one level as if it were the whole tree.
    if depth.eq_ignore_ascii_case("infinity") {
        let body = "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n\
                    <D:error xmlns:D=\"DAV:\"><D:propfind-finite-depth/></D:error>\n";
        return http::write_response(
            stream,
            403,
            "Forbidden",
            "application/xml; charset=utf-8",
            &[],
            body.as_bytes(),
            true,
        );
    }
    let include_children = depth != "0";

    let mut xml = String::new();
    xml.push_str("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n");
    xml.push_str("<D:multistatus xmlns:D=\"DAV:\">\n");

    // The resource itself.
    xml.push_str(&response_xml(decoded_path, &meta, fs_path));

    // Immediate children, if this is a collection and depth allows it.
    if meta.is_dir() && include_children {
        let base = util::with_trailing_slash(decoded_path);
        if let Ok(rd) = fs::read_dir(fs_path) {
            for entry in rd.flatten() {
                let path = entry.path();
                // Hidden system entries are omitted (and refused on direct
                // access), unless re-exposed by an --expose glob.
                if util::is_hidden(&entry.file_name().to_string_lossy(), exposes) {
                    continue;
                }
                // Skip children that resolve outside the root (escaping symlinks).
                if !within_root(root, &path) {
                    continue;
                }
                let name = entry.file_name().to_string_lossy().into_owned();
                let child_path = format!("{}{}", base, name);
                // Follow symlinks (matching GET); list un-stattable entries with
                // a 404 propstat rather than dropping them from the listing.
                match fs::metadata(&path) {
                    Ok(child_meta) => xml.push_str(&response_xml(&child_path, &child_meta, &path)),
                    Err(_) => xml.push_str(&response_failed_xml(&child_path)),
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
    let href = if is_dir {
        util::with_trailing_slash(href_path)
    } else {
        href_path.to_string()
    };
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
        // Same strong validator GET sends as ETag; the value has no XML specials.
        if let Some(etag) = etag_for(meta) {
            block.push_str(&format!("        <D:getetag>{}</D:getetag>\n", etag));
        }
    }
    block.push_str("      </D:prop>\n");
    block.push_str("      <D:status>HTTP/1.1 200 OK</D:status>\n");
    block.push_str("    </D:propstat>\n");
    block.push_str("  </D:response>\n");
    block
}

/// A `<D:response>` for an entry whose metadata couldn't be read: list the
/// href with a 404 status so the client sees a complete (if partial) listing.
fn response_failed_xml(href_path: &str) -> String {
    format!(
        "  <D:response>\n    <D:href>{}</D:href>\n    \
         <D:status>HTTP/1.1 404 Not Found</D:status>\n  </D:response>\n",
        util::percent_encode_path(href_path)
    )
}
