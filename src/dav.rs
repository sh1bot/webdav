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

/// A filesystem path that has passed the one universal acceptability test:
/// it resolves inside the served root (no `..` and no symlink escape), no
/// component is a hidden system name (unless `--expose`d), and its target is
/// readable by us. A `SafePath` can *only* be produced by [`Served::accept`] or
/// [`Served::children`], so a request string can never reach the filesystem
/// without passing the test, and holding one means the checks are already done —
/// nothing downstream re-validates. The `Metadata` stat'd during the check is
/// carried along so callers don't stat again.
pub struct SafePath {
    // Owned (both constructors mint a fresh path — nothing outlives them to
    // borrow), but boxed rather than a PathBuf: the path is fixed once the checks
    // pass, so we don't need PathBuf's growable spare capacity.
    path: Box<Path>,
    meta: fs::Metadata,
}

impl SafePath {
    fn path(&self) -> &Path {
        &self.path
    }
    fn meta(&self) -> &fs::Metadata {
        &self.meta
    }
    fn is_dir(&self) -> bool {
        self.meta.is_dir()
    }
    /// The leaf name, lossily decoded, for hrefs and display.
    fn name(&self) -> String {
        self.path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "/".to_string())
    }
}

impl Served<'_> {
    /// The universal acceptability test: turn a decoded request path into a
    /// [`SafePath`], or `None` (⇒ a reveal-nothing 404) if it escapes the root
    /// via `..`, names a hidden component, resolves through a symlink to outside
    /// the root, or isn't readable by us. This is the ONE place a request string
    /// becomes a filesystem path.
    fn accept(&self, request_path: &str) -> Option<SafePath> {
        // String-level checks first: reject `..`/absolute escapes, then any
        // hidden component anywhere in the request path.
        let path = util::resolve_within(self.root, request_path)?;
        if util::path_has_hidden(request_path, self.exposes) {
            return None;
        }
        // Filesystem-level checks: it must exist and stat, resolve (through any
        // symlinks) inside the root, and be readable.
        let meta = fs::metadata(&path).ok()?;
        if !within_root(self.root, &path) || !is_readable(&path) {
            return None;
        }
        Some(SafePath {
            path: path.into_boxed_path(),
            meta,
        })
    }

    /// Iterate the acceptable children of an already-trusted directory,
    /// streamwise — no `Vec` of entries is built. Because `dir` is a `SafePath`
    /// (its whole ancestry is validated by type), each entry is judged on its
    /// *leaf* alone, without re-parsing the parent chain: see [`accept_child`].
    fn children<'s>(&'s self, dir: &SafePath) -> impl Iterator<Item = SafePath> + 's {
        fs::read_dir(&dir.path)
            .ok()
            .into_iter()
            .flatten() // ReadDir → io::Result<DirEntry>
            .filter_map(Result::ok) // drop entries we couldn't read
            .filter_map(move |entry| self.accept_child(entry))
    }

    /// Accept one child of a trusted directory by its leaf only. The parent is
    /// already known to sit inside the root, so a *non-symlink* child is inside
    /// the root by construction (a single normal component can't climb out) —
    /// only a symlink can point elsewhere, so we pay for the escape check
    /// (`within_root`'s `canonicalize`) solely in that case. Hidden and
    /// readability are judged on this entry alone.
    fn accept_child(&self, entry: fs::DirEntry) -> Option<SafePath> {
        let name = entry.file_name();
        if util::is_hidden(&name.to_string_lossy(), self.exposes) {
            return None;
        }
        let path = entry.path();
        // A symlink (or an entry whose type we couldn't determine) is the only
        // way a child could resolve outside the root; check just those.
        let maybe_symlink = entry.file_type().map(|t| t.is_symlink()).unwrap_or(true);
        if maybe_symlink && !within_root(self.root, &path) {
            return None;
        }
        let meta = fs::metadata(&path).ok()?; // follows the symlink to its target
        if !is_readable(&path) {
            return None;
        }
        Some(SafePath {
            path: path.into_boxed_path(),
            meta,
        })
    }
}

/// True if we can read `path` (following symlinks) as the user we now run as —
/// the same permission `File::open` needs, so the listing never advertises a
/// file a GET would then 404. `access(2)` uses the real uid, which equals our
/// effective uid after the privilege drop.
fn is_readable(path: &Path) -> bool {
    use std::os::unix::ffi::OsStrExt;
    match std::ffi::CString::new(path.as_os_str().as_bytes()) {
        Ok(c) => (unsafe { libc::access(c.as_ptr(), libc::R_OK) }) == 0,
        Err(_) => false, // interior NUL: not a real path
    }
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

    // OPTIONS describes the server, not a resource, so it needs no path at all —
    // answer it without touching the filesystem. Reject unsupported methods here
    // too, before any path work.
    match req.method.as_str() {
        "OPTIONS" => return options(stream),
        "GET" | "HEAD" | "PROPFIND" => {}
        _ => {
            return http::write_response(
                stream,
                405,
                "text/plain; charset=utf-8",
                &[("Allow", ALLOW.to_string())],
                b"405 Method Not Allowed\n",
                true,
            );
        }
    }

    // The single gate: a request string becomes a filesystem path only by
    // passing the universal acceptability test. Any rejection is a 404 that
    // reveals nothing about why (missing, hidden, escaping, or unreadable).
    let decoded = util::percent_decode(&req.path);
    let Some(target) = served.accept(&decoded) else {
        return http::write_status(stream, 404);
    };

    match req.method.as_str() {
        "GET" => get_or_head(stream, served, &decoded, &target, req, true),
        "HEAD" => get_or_head(stream, served, &decoded, &target, req, false),
        "PROPFIND" => propfind(stream, served, &decoded, &target, req),
        _ => unreachable!("method gated above"),
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
    target: &SafePath,
    req: &Request,
    send_body: bool,
) -> io::Result<()> {
    if target.is_dir() {
        // GET on a collection returns a simple HTML index for browsers.
        let html = directory_index_html(served, decoded_path, target);
        return http::write_response(
            stream,
            200,
            "text/html; charset=utf-8",
            &[],
            html.as_bytes(),
            send_body,
        );
    }

    let meta = target.meta();
    let len = meta.len();
    let modified = meta.modified().ok();
    let etag = etag_for(meta);

    // Both the 304 and the 200/206 paths carry the same validators; build once.
    let mut headers = validator_headers(etag.as_deref(), modified);

    // Conditional GET: If-None-Match / If-Modified-Since => 304 Not Modified.
    if not_modified(req, etag.as_deref(), modified) {
        return http::write_response(stream, 304, "", &headers, b"", false);
    }

    // We honour single byte ranges; advertise that to clients.
    headers.push(("Accept-Ranges", "bytes".to_string()));

    let content_type = util::mime_for(target.path());

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
    stream_file(stream, target, offset, count, &resp, send_body)
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
    target: &SafePath,
    offset: u64,
    count: u64,
    resp: &Resp,
    send_body: bool,
) -> io::Result<()> {
    // Open before writing the header so a failure can still be reported as an
    // error response rather than a truncated body. sendfile takes the offset
    // directly, so there is no need to seek.
    let file = match fs::File::open(target.path()) {
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

/// A dependency-free client-side sorter, inlined into the index `<head>`. The
/// server streams rows in filesystem order (no server-side buffering to sort);
/// the browser reorders them to directories-first, then natural-alphabetical,
/// keeping `../` pinned at the top. No-JS clients still get a usable (unsorted)
/// listing, so this is pure progressive enhancement. Filenames reach the DOM
/// only as escaped text/href, so the static script can't be injected into.
const SORT_SCRIPT: &str = r#"<script>
document.addEventListener('DOMContentLoaded',function(){
  var tb=document.querySelector('tbody');if(!tb)return;
  var up=null,items=[];
  Array.prototype.forEach.call(tb.rows,function(r){
    var a=r.querySelector('a');
    if(a&&a.getAttribute('href')==='../')up=r;else items.push(r);
  });
  items.sort(function(x,y){
    var ax=x.querySelector('a'),ay=y.querySelector('a');
    var dx=ax.getAttribute('href').slice(-1)==='/'?0:1;
    var dy=ay.getAttribute('href').slice(-1)==='/'?0:1;
    return dx-dy||ax.textContent.localeCompare(ay.textContent,undefined,{sensitivity:'base',numeric:true});
  });
  tb.replaceChildren.apply(tb,(up?[up]:[]).concat(items));
});
</script>"#;

/// Render the HTML directory index, streaming entries straight from
/// [`Served::children`] into the output (filesystem order, no intermediate list
/// and no sort). Ordering for display is done client-side by [`SORT_SCRIPT`].
fn directory_index_html(served: &Served, decoded_path: &str, target: &SafePath) -> String {
    let base = util::with_trailing_slash(decoded_path);
    let title = util::xml_escape(decoded_path);

    let mut html = String::new();
    html.push_str(
        "<!DOCTYPE html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">",
    );
    // The path is user data, not English prose, so mark it translate="no". A
    // browser's built-in / Google page translation then converts the labels
    // around it ("Index of", the column headers) into the reader's language for
    // free, without touching the path, filenames, dates or sizes. lang="en"
    // above tells the translator the source language.
    let _ = write!(html, "<title translate=\"no\">Index of {title}</title>");
    html.push_str(
        "<style>body{font-family:sans-serif}td,th{text-align:left;padding:0 1.5rem 0 0}tbody th{font-weight:normal}</style>",
    );
    html.push_str(SORT_SCRIPT);
    html.push_str("</head><body>");
    let _ = write!(
        html,
        "<h1 id=\"t\">Index of <span translate=\"no\">{title}</span></h1>"
    );
    // aria-labelledby names the table from the <h1> (no duplicate caption).
    // scope=col on the headers plus scope=row on each name cell let a screen
    // reader announce every value with its column *and* its filename. The data
    // rows are translate="no": filenames/dates/sizes are data, not prose.
    html.push_str(
        "<table aria-labelledby=\"t\"><thead><tr><th scope=\"col\">Name</th>\
         <th scope=\"col\">Last modified (UTC)</th>\
         <th scope=\"col\">Size</th></tr></thead><tbody translate=\"no\">",
    );

    if decoded_path != "/" {
        html.push_str(
            "<tr><th scope=\"row\"><a href=\"../\" aria-label=\"Parent directory\">../</a></th>\
             <td></td><td></td></tr>",
        );
    }
    for child in served.children(target) {
        let name = child.name();
        let is_dir = child.is_dir();
        let suffix = if is_dir { "/" } else { "" };
        let href = util::percent_encode_path(&format!("{}{}{}", base, name, suffix));
        let modified = child
            .meta()
            .modified()
            .ok()
            .map(util::datetime_utc)
            .unwrap_or_else(|| "-".to_string());
        let size = if is_dir {
            "-".to_string()
        } else {
            util::human_size(child.meta().len())
        };
        let _ = write!(
            html,
            "<tr><th scope=\"row\"><a href=\"{href}\">{}{suffix}</a></th><td>{modified}</td><td>{size}</td></tr>",
            util::xml_escape(&name),
        );
    }
    html.push_str("</tbody></table></body></html>");
    html
}

fn propfind<S: Write>(
    stream: &mut S,
    served: &Served,
    decoded_path: &str,
    target: &SafePath,
    req: &Request,
) -> io::Result<()> {
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
    response_xml(&mut xml, decoded_path, target);

    // Immediate children, if this is a collection and depth allows it — streamed
    // straight from `children` (already filtered to the acceptable set, so an
    // unreadable or hidden entry is simply absent, never a 404 stub).
    if target.is_dir() && include_children {
        let base = util::with_trailing_slash(decoded_path);
        for child in served.children(target) {
            let child_path = format!("{}{}", base, child.name());
            response_xml(&mut xml, &child_path, &child);
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
fn response_xml(out: &mut String, href_path: &str, target: &SafePath) {
    let meta = target.meta();
    let is_dir = meta.is_dir();

    // Collections must end with a trailing slash in their href.
    let href = if is_dir {
        util::with_trailing_slash(href_path)
    } else {
        href_path.to_string()
    };
    let href = util::percent_encode_path(&href);
    let display = target.name();

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
            util::mime_for(target.path()),
        );
        // Same strong validator GET sends as ETag; the value has no XML specials.
        if let Some(etag) = etag_for(meta) {
            let _ = writeln!(out, "        <D:getetag>{etag}</D:getetag>");
        }
    }
    out.push_str("      </D:prop>\n      <D:status>HTTP/1.1 200 OK</D:status>\n    </D:propstat>\n  </D:response>\n");
}
