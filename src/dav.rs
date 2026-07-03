//! Read-only WebDAV request handling: OPTIONS, GET, HEAD and PROPFIND.
//! Anything that would modify the filesystem (PUT, DELETE, MKCOL, COPY,
//! MOVE, PROPPATCH, LOCK, …) is answered with 405 Method Not Allowed.

use std::fmt::Write as _;
use std::fs;
use std::io::{self, Write};
use std::os::unix::io::AsRawFd;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::auth::Auth;
use crate::http::{self, Request};
use crate::util;

use safe::SafePath;
pub use safe::Served;

const ALLOW: &str = "OPTIONS, GET, HEAD, PROPFIND";

/// Path acceptability, sealed. `SafePath`'s fields are private to this module
/// and it has no public literal form, so the *only* way to obtain one anywhere
/// in the crate is through the constructors below — each of which runs the full
/// acceptability test. Code elsewhere in `dav` can read a `SafePath` but can
/// never fabricate one that skipped the checks.
mod safe {
    use std::fs;
    use std::path::Path;

    use crate::util;

    /// The serving context — validated root (trust anchor) plus `--expose`
    /// overrides — bound together so the two are never passed as a mismatched
    /// pair. Private fields, so `dav` can pass one around but can't build a rogue
    /// one with an unchecked root; [`Served::new`] is the only constructor.
    pub struct Served<'a> {
        root: SafePath,
        exposes: &'a [String],
    }

    impl<'a> Served<'a> {
        /// Validate the served root and bundle it with the expose overrides.
        /// `None` if `root` isn't a directory we can read.
        pub fn new(root: &Path, exposes: &'a [String]) -> Option<Served<'a>> {
            Some(Served {
                root: SafePath::root(root)?,
                exposes,
            })
        }
    }

    /// A path we are permitted to serve: it exists, is readable by us, resolves
    /// inside the served root (no `..`, no symlink escape), and — for a path
    /// derived from a request — names no hidden component. The served root itself
    /// is the base case (there is no request part to check). Holding one means
    /// those checks have passed; the `Metadata` stat'd during the check is
    /// carried along so callers don't stat again.
    pub struct SafePath {
        path: Box<Path>, // owned but immutable once validated; no PathBuf capacity needed
        meta: fs::Metadata,
    }

    impl SafePath {
        pub fn path(&self) -> &Path {
            &self.path
        }
        pub fn meta(&self) -> &fs::Metadata {
            &self.meta
        }
        pub fn is_dir(&self) -> bool {
            self.meta.is_dir()
        }
        /// The leaf name, lossily decoded, for hrefs and display.
        pub fn name(&self) -> String {
            self.path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_else(|| "/".to_string())
        }

        /// The trust anchor: the served root skips the request-relative checks
        /// (there's no request part yet) — just confirm it's a readable directory.
        pub fn root(dir: &Path) -> Option<SafePath> {
            let meta = fs::metadata(dir).ok()?;
            let ok = meta.is_dir() && is_readable(dir);
            ok.then(|| SafePath {
                path: dir.into(),
                meta,
            })
        }

        /// The universal acceptability test: turn a decoded request path into a
        /// `SafePath` under `served`'s root, or `None` (⇒ a reveal-nothing 404) if
        /// it escapes the root via `..`, names a hidden component, resolves through
        /// a symlink to outside the root, or isn't readable by us. This is the ONE
        /// place a request string becomes a filesystem path.
        pub fn accept(served: &Served, request_path: &str) -> Option<SafePath> {
            // String-level checks first: reject `..`/absolute escapes, then any
            // hidden component anywhere in the request path.
            let path = util::resolve_within(served.root.path(), request_path)?;
            if util::path_has_hidden(request_path, served.exposes) {
                return None;
            }
            // Filesystem-level checks: it must exist and stat, resolve (through
            // any symlinks) inside the root, and be readable.
            let meta = fs::metadata(&path).ok()?;
            if !within_root(served.root.path(), &path) || !is_readable(&path) {
                return None;
            }
            Some(SafePath {
                path: path.into_boxed_path(),
                meta,
            })
        }

        /// Iterate the acceptable children of this (already-trusted) directory,
        /// streamwise — no `Vec` of entries is built. Because `self` is a
        /// `SafePath` (its whole ancestry is validated by type), each entry is
        /// judged on its *leaf* alone, without re-parsing the parent chain.
        pub fn children<'c>(&self, served: &'c Served) -> impl Iterator<Item = SafePath> + 'c {
            fs::read_dir(&self.path)
                .ok()
                .into_iter()
                .flatten()
                .filter_map(Result::ok)
                .filter_map(move |entry| SafePath::accept_child(served, entry))
        }

        /// Accept one child of a trusted directory by its leaf only. The parent is
        /// already known to sit inside the root, so a *non-symlink* child is inside
        /// the root by construction (a single normal component can't climb out) —
        /// only a symlink can point elsewhere, so we pay for the escape check
        /// (`within_root`'s `canonicalize`) solely in that case. Hidden and
        /// readability are judged on this entry alone.
        fn accept_child(served: &Served, entry: fs::DirEntry) -> Option<SafePath> {
            let name = entry.file_name();
            if util::is_hidden(&name.to_string_lossy(), served.exposes) {
                return None;
            }
            let path = entry.path();
            // Unknown type: treat as a possible symlink (the only way to escape).
            let maybe_symlink = entry.file_type().map(|t| t.is_symlink()).unwrap_or(true);
            if maybe_symlink && !within_root(served.root.path(), &path) {
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

    /// True if `fs_path`, fully resolved (following symlinks), is still inside
    /// `root`. When the server has chrooted, `root` is `/` so nothing can be
    /// outside it — short-circuit and skip the per-path `canonicalize`. Otherwise
    /// resolve and check the prefix, which stops a symlink under the served tree
    /// from escaping.
    fn within_root(root: &Path, fs_path: &Path) -> bool {
        root == Path::new("/")
            || fs_path
                .canonicalize()
                .is_ok_and(|real| real.starts_with(root))
    }

    /// True if we can read `path` (following symlinks) as the user we now run as —
    /// the same permission `File::open` needs, so a listing never advertises a
    /// file a GET would then 404. `access(2)` uses the real uid, which equals our
    /// effective uid after the privilege drop.
    fn is_readable(path: &Path) -> bool {
        use std::os::unix::ffi::OsStrExt;
        match std::ffi::CString::new(path.as_os_str().as_bytes()) {
            Ok(c) => (unsafe { libc::access(c.as_ptr(), libc::R_OK) }) == 0,
            Err(_) => false, // interior NUL: not a real path
        }
    }
}

pub fn handle<S: Write + AsRawFd>(
    stream: &mut S,
    served: &Served,
    auth: &Auth,
    req: &Request,
) -> io::Result<()> {
    if !auth.authorize(req) {
        return auth.challenge(stream);
    }

    // OPTIONS describes the server, not a resource, so it needs no path at all —
    // answer it without touching the filesystem. Reject unsupported methods here
    // too, before any path work.
    match req.method.as_str() {
        "OPTIONS" => return options(stream),
        "GET" | "HEAD" | "PROPFIND" => {}
        _ => return http::write_status(stream, 405, &[("Allow", ALLOW.to_string())]),
    }

    // The single gate: a request string becomes a filesystem path only by
    // passing the universal acceptability test. Any rejection is a 404 that
    // reveals nothing about why (missing, hidden, escaping, or unreadable).
    let decoded = util::percent_decode(&req.path);
    let Some(target) = SafePath::accept(served, &decoded) else {
        return http::write_status(stream, 404, &[]);
    };

    match req.method.as_str() {
        "PROPFIND" => propfind(stream, served, &decoded, &target, req),
        method => get_or_head(stream, served, &decoded, &target, req, method == "GET"),
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

    let mut headers = validator_headers(etag.as_deref(), modified);
    if not_modified(req, etag.as_deref(), modified) {
        return http::write_response(stream, 304, "", &headers, b"", false);
    }
    headers.push(("Accept-Ranges", "bytes".to_string()));

    let content_type = util::mime_for(target.path());

    // Ignore Range when If-Range is present and its validator no longer matches,
    // so a resumed download can't splice bytes from two versions of the file.
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
            let cr = ("Content-Range", format!("bytes */{}", len));
            return http::write_status(stream, 416, &[cr]);
        }
    };

    // Open before writing the header so a failure is an error response, not a
    // truncated body; sendfile takes the offset directly, so no seek is needed.
    let file = match fs::File::open(target.path()) {
        Ok(f) => f,
        Err(e) => return err_status(stream, &e),
    };
    http::write_head(stream, status, content_type, &headers, count)?;
    if send_body {
        http::send_file(stream.as_raw_fd(), &file, offset, count)?;
    } else {
        stream.flush()?;
    }
    Ok(())
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

/// Map a filesystem error to a status; anything access-shaped (missing, denied,
/// bad path) becomes a reveal-nothing `404` rather than exposing that it exists.
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
    http::write_status(stream, status, &[])
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

    if spec.contains(',') {
        return RangeSpec::Ignore; // multi-range: unsupported, serve whole file
    }

    let Some((start_s, end_s)) = spec.split_once('-') else {
        return RangeSpec::Ignore;
    };
    let start_s = start_s.trim();
    let end_s = end_s.trim();

    if len == 0 {
        return RangeSpec::Unsatisfiable; // an empty file satisfies no range
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
addEventListener('DOMContentLoaded', () => {
  const tb = document.querySelector('tbody');
  if (!tb) return;
  const a = r => r.querySelector('a');
  const rows = [...tb.rows];
  const up = rows.find(r => a(r).getAttribute('href') === '../');
  const dir = r => a(r).getAttribute('href').endsWith('/') ? 0 : 1;
  const items = rows.filter(r => r !== up).sort((x, y) =>
    dir(x) - dir(y) ||
    a(x).textContent.localeCompare(a(y).textContent, undefined, {sensitivity: 'base', numeric: true}));
  tb.replaceChildren(...(up ? [up] : []), ...items);
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
    // translate="no" on the path/data so page-translation (lang="en") localizes
    // only the fixed labels ("Index of", column headers), never filenames.
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
    // scope + aria-labelledby: screen readers announce each value with its column
    // and filename; tbody translate="no" keeps filenames/dates/sizes untranslated.
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
    for child in target.children(served) {
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
        for child in target.children(served) {
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
