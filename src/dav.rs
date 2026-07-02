//! Read-only WebDAV request handling: OPTIONS, GET, HEAD and PROPFIND.
//! Anything that would modify the filesystem (PUT, DELETE, MKCOL, COPY,
//! MOVE, PROPPATCH, LOCK, …) is answered with 405 Method Not Allowed.

use std::fmt::Write as _;
use std::fs;
use std::io::{self, Write};
use std::os::unix::io::AsRawFd;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::auth::Auth;
use crate::http::{self, Request};
use crate::util;

const ALLOW: &str = "OPTIONS, GET, HEAD, PROPFIND";

/// The static, per-server configuration every handler needs: the served root
/// (for the symlink-escape check) and the `--expose` overrides (for the
/// hidden-file gate).
pub struct Served<'a> {
    pub root: &'a Path,
    pub exposes: &'a [String],
}

pub fn handle<S: Write + AsRawFd>(
    stream: &mut S,
    served: &Served,
    auth: &Auth,
    req: &Request,
) -> io::Result<()> {
    // Require valid Basic credentials (if configured) before doing anything.
    if !auth.authorize(req) {
        return auth.challenge(stream);
    }

    // Percent-decode and sanitise the request path before touching disk. A `..`
    // escape is reported as 404 (not 403), like an out-of-root symlink, so the
    // response never reveals that the traversal filter (or a chroot) is in play.
    let decoded = util::percent_decode(&req.path);
    let Some(fs_path) = util::resolve_within(served.root, &decoded) else {
        return http::write_status(stream, 404);
    };

    // Hidden system entries (.htpasswd, .git, @eaDir, …) are never served unless
    // re-exposed by an `--expose` glob: a request naming a still-hidden one is
    // refused with the same reveal-nothing 404, consistent with its omission from
    // the listings below.
    if util::path_has_hidden(&decoded, served.exposes) {
        return http::write_status(stream, 404);
    }

    match req.method.as_str() {
        "OPTIONS" => options(stream),
        "GET" => get_or_head(stream, served, &decoded, &fs_path, req, true),
        "HEAD" => get_or_head(stream, served, &decoded, &fs_path, req, false),
        "PROPFIND" => propfind(stream, served, &decoded, &fs_path, req),
        // Read-only: reject every mutating / unsupported method.
        _ => http::write_response(
            stream,
            405,
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
    served: &Served,
    decoded_path: &str,
    fs_path: &Path,
    req: &Request,
    send_body: bool,
) -> io::Result<()> {
    let Some(meta) = stat_within_root(stream, served.root, fs_path)? else {
        return Ok(());
    };

    if meta.is_dir() {
        // GET on a collection returns a simple HTML index for browsers.
        let html = directory_index_html(served, decoded_path, fs_path);
        return http::write_response(
            stream,
            200,
            "text/html; charset=utf-8",
            &[],
            html.as_bytes(),
            send_body,
        );
    }

    let len = meta.len();
    let modified = meta.modified().ok();
    let etag = etag_for(&meta);

    // Both the 304 and the 200/206 paths carry the same validators; build once.
    let mut headers = validator_headers(etag.as_deref(), modified);

    // Conditional GET: If-None-Match / If-Modified-Since => 304 Not Modified.
    if not_modified(req, etag.as_deref(), modified) {
        return http::write_response(stream, 304, "", &headers, b"", false);
    }

    // We honour single byte ranges; advertise that to clients.
    headers.push(("Accept-Ranges", "bytes".to_string()));

    let content_type = util::mime_for(fs_path);

    // Honour Range only when there's no If-Range or its validator still matches;
    // otherwise serve the full entity (so a resumed download can't splice bytes
    // from two different versions of a file).
    let spec = match req.header("range") {
        Some(r) if if_range_matches(req, etag.as_deref(), modified) => parse_byte_range(r, len),
        _ => RangeSpec::Ignore,
    };

    // Resolve the range to (status, offset, count); 416 is the one outcome that
    // sends its own tiny body rather than streaming the file.
    let (status, offset, count) = match spec {
        RangeSpec::Satisfiable { start, end } => {
            headers.push(("Content-Range", format!("bytes {}-{}/{}", start, end, len)));
            (206, start, end - start + 1)
        }
        RangeSpec::Ignore => (200, 0, len),
        RangeSpec::Unsatisfiable => {
            return http::write_response(
                stream,
                416,
                "text/plain; charset=utf-8",
                &[("Content-Range", format!("bytes */{}", len))],
                b"416 Range Not Satisfiable\n",
                true,
            );
        }
    };
    let resp = Resp {
        status,
        content_type,
        headers: &headers,
    };
    stream_file(stream, fs_path, offset, count, &resp, send_body)
}

/// Build the `Last-Modified`/`ETag` headers shared by the 304 and 200/206 paths.
fn validator_headers(
    etag: Option<&str>,
    modified: Option<SystemTime>,
) -> Vec<(&'static str, String)> {
    let mut h = Vec::new();
    if let Some(m) = modified {
        h.push(("Last-Modified", util::http_date(m)));
    }
    if let Some(e) = etag {
        h.push(("ETag", e.to_string()));
    }
    h
}

/// The status line + headers for a streamed file response.
struct Resp<'a> {
    status: u16,
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

    http::write_head(stream, resp.status, resp.content_type, resp.headers, count)?;
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
        return http::write_status(stream, 404).map(|()| None);
    }
    Ok(Some(meta))
}

/// Map a filesystem error to an HTTP status. Permission-denied is reported as
/// `404`, not `403`, so the response never reveals that an inaccessible path
/// exists — matching the reveal-nothing `404` used for traversal and out-of-root
/// paths.
fn err_status<S: Write>(stream: &mut S, e: &io::Error) -> io::Result<()> {
    let status = match e.kind() {
        // NotFound and PermissionDenied both 404 (reveal nothing). InvalidInput
        // is what a path with an interior NUL (`%00`) becomes at the CString
        // boundary — it can't name a real file, so 404 it too rather than 500.
        io::ErrorKind::NotFound | io::ErrorKind::PermissionDenied | io::ErrorKind::InvalidInput => {
            404
        }
        _ => 500,
    };
    http::write_status(stream, status)
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

/// True if an HTTP-date header value is at or after `modified` — i.e. the
/// client's cached copy is still current. Shared by `If-Modified-Since` and the
/// date form of `If-Range`; both compare at one-second resolution (`as_secs`),
/// matching what `Last-Modified` itself was rendered from.
fn date_covers(header_val: &str, modified: SystemTime) -> bool {
    util::parse_http_date(header_val).is_some_and(|since| {
        modified
            .duration_since(UNIX_EPOCH)
            .is_ok_and(|d| d.as_secs() as i64 <= since)
    })
}

/// Evaluate conditional-GET preconditions. Returns true when the client's
/// cached copy is still current and we should answer `304 Not Modified`.
/// `If-None-Match` takes precedence over `If-Modified-Since` (RFC 7232).
fn not_modified(req: &Request, etag: Option<&str>, modified: Option<SystemTime>) -> bool {
    if let Some(inm) = req.header("if-none-match") {
        return etag.is_some_and(|e| etag_list_matches(inm, e));
    }
    req.header("if-modified-since")
        .zip(modified)
        .is_some_and(|(ims, m)| date_covers(ims, m))
}

/// For a ranged request, decide whether the `If-Range` validator still matches
/// (so the range is safe to serve). No `If-Range` header => always matches.
fn if_range_matches(req: &Request, etag: Option<&str>, modified: Option<SystemTime>) -> bool {
    let Some(ir) = req.header("if-range").map(str::trim) else {
        return true;
    };
    if ir.starts_with('"') {
        return etag == Some(ir);
    }
    modified.is_some_and(|m| date_covers(ir, m))
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
    let Some(spec) = value.trim().strip_prefix("bytes=") else {
        return RangeSpec::Ignore;
    };
    let spec = spec.trim();

    // We only implement single ranges; a comma means a multi-range request.
    if spec.contains(',') {
        return RangeSpec::Ignore;
    }

    let Some((start_s, end_s)) = spec.split_once('-') else {
        return RangeSpec::Ignore;
    };
    let start_s = start_s.trim();
    let end_s = end_s.trim();

    // An empty file can satisfy no range.
    if len == 0 {
        return RangeSpec::Unsatisfiable;
    }

    if start_s.is_empty() {
        // Suffix form: `bytes=-N` => the final N bytes.
        let Ok(suffix) = end_s.parse::<u64>() else {
            return RangeSpec::Ignore;
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

    let Ok(start) = start_s.parse::<u64>() else {
        return RangeSpec::Ignore;
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

/// List `fs_path`'s children that aren't hidden (per `served.exposes`) and
/// don't resolve outside `served.root` (an escaping symlink). Shared by the
/// HTML index and PROPFIND.
fn visible_children(served: &Served, fs_path: &Path) -> Vec<fs::DirEntry> {
    let Ok(rd) = fs::read_dir(fs_path) else {
        return Vec::new();
    };
    rd.flatten()
        .filter(|e| !util::is_hidden(&e.file_name().to_string_lossy(), served.exposes))
        .filter(|e| within_root(served.root, &e.path()))
        .collect()
}

fn directory_index_html(served: &Served, decoded_path: &str, fs_path: &Path) -> String {
    let mut entries: Vec<IndexEntry> = Vec::new();
    for e in visible_children(served, fs_path) {
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
    // Directories first, then alphabetical.
    entries.sort_by(|a, b| b.is_dir.cmp(&a.is_dir).then(a.name.cmp(&b.name)));

    let base = util::with_trailing_slash(decoded_path);
    let title = util::xml_escape(decoded_path);

    let mut html = String::new();
    html.push_str("<!DOCTYPE html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">");
    let _ = write!(html, "<title>Index of {title}</title>");
    html.push_str(
        "<style>body{font-family:sans-serif}td,th{text-align:left;padding:0 1.5rem 0 0}</style></head><body>",
    );
    let _ = write!(html, "<h1>Index of {title}</h1>");
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
        let _ = write!(
            html,
            "<tr><td><a href=\"{href}\">{}{suffix}</a></td><td>{modified}</td><td>{size}</td></tr>",
            util::xml_escape(&e.name),
        );
    }
    html.push_str("</tbody></table></body></html>");
    html
}

fn propfind<S: Write>(
    stream: &mut S,
    served: &Served,
    decoded_path: &str,
    fs_path: &Path,
    req: &Request,
) -> io::Result<()> {
    let Some(meta) = stat_within_root(stream, served.root, fs_path)? else {
        return Ok(());
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
    response_xml(&mut xml, decoded_path, &meta, fs_path);

    // Immediate children, if this is a collection and depth allows it.
    if meta.is_dir() && include_children {
        let base = util::with_trailing_slash(decoded_path);
        for entry in visible_children(served, fs_path) {
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().into_owned();
            let child_path = format!("{}{}", base, name);
            // Follow symlinks (matching GET); list un-stattable entries with
            // a 404 propstat rather than dropping them from the listing.
            match fs::metadata(&path) {
                Ok(child_meta) => response_xml(&mut xml, &child_path, &child_meta, &path),
                Err(_) => response_failed_xml(&mut xml, &child_path),
            }
        }
    }

    xml.push_str("</D:multistatus>\n");

    http::write_response(
        stream,
        207,
        "application/xml; charset=utf-8",
        &[],
        xml.as_bytes(),
        true,
    )
}

/// Append one `<D:response>` block describing a single resource to `out`
/// (written in place, so a Depth: 1 listing doesn't allocate a String per child).
fn response_xml(out: &mut String, href_path: &str, meta: &fs::Metadata, fs_path: &Path) {
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

    let _ = write!(
        out,
        "  <D:response>\n    <D:href>{href}</D:href>\n    <D:propstat>\n      <D:prop>\n        \
         <D:displayname>{}</D:displayname>\n        <D:getlastmodified>{modified}</D:getlastmodified>\n",
        util::xml_escape(&display),
    );
    if is_dir {
        out.push_str("        <D:resourcetype><D:collection/></D:resourcetype>\n");
    } else {
        let _ = write!(
            out,
            "        <D:resourcetype/>\n        <D:getcontentlength>{}</D:getcontentlength>\n        \
             <D:getcontenttype>{}</D:getcontenttype>\n",
            meta.len(),
            util::mime_for(fs_path),
        );
        // Same strong validator GET sends as ETag; the value has no XML specials.
        if let Some(etag) = etag_for(meta) {
            let _ = writeln!(out, "        <D:getetag>{etag}</D:getetag>");
        }
    }
    out.push_str("      </D:prop>\n      <D:status>HTTP/1.1 200 OK</D:status>\n    </D:propstat>\n  </D:response>\n");
}

/// Append a `<D:response>` for an entry whose metadata couldn't be read: list
/// the href with a 404 status so the client sees a complete (if partial) listing.
fn response_failed_xml(out: &mut String, href_path: &str) {
    let _ = write!(
        out,
        "  <D:response>\n    <D:href>{}</D:href>\n    \
         <D:status>HTTP/1.1 404 Not Found</D:status>\n  </D:response>\n",
        util::percent_encode_path(href_path)
    );
}
