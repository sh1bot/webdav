//! Small self-contained helpers: percent-coding, HTTP dates, MIME guessing,
//! XML escaping and safe path resolution. Kept dependency-free on purpose.

use std::borrow::Cow;
use std::fmt::Write as _;
use std::path::{Component, Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Decode `%XX` escapes in a URL path segment string into raw bytes, then
/// interpret as UTF-8 (lossily). Stops decoding at `?` (query) and `#`.
pub fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                let h = (bytes[i + 1] as char).to_digit(16);
                let l = (bytes[i + 2] as char).to_digit(16);
                if let (Some(h), Some(l)) = (h, l) {
                    out.push(((h << 4) | l) as u8);
                    i += 3;
                    continue;
                }
                out.push(b'%');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    // The overwhelmingly common case is valid UTF-8, where this is a move with
    // no copy; only a malformed sequence pays for the lossy-replacement path.
    String::from_utf8(out).unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned())
}

/// Percent-encode a path for use inside a WebDAV `<D:href>`. We keep the path
/// separators and the usual unreserved characters, escaping everything else.
pub fn percent_encode_path(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for &b in input.as_bytes() {
        let keep = matches!(b,
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' |
            b'-' | b'_' | b'.' | b'~' | b'/');
        if keep {
            out.push(b as char);
        } else {
            let _ = write!(out, "%{:02x}", b);
        }
    }
    out
}

/// Escape text for safe inclusion in XML element content / attributes.
pub fn xml_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            _ => out.push(c),
        }
    }
    out
}

/// Safely resolve a request path (already percent-decoded, starting with `/`)
/// against the served root directory. Rejects any attempt to escape the root
/// via `..` or absolute components. Returns the resolved filesystem path.
pub fn resolve_within(root: &Path, request_path: &str) -> Option<PathBuf> {
    let mut resolved = PathBuf::from(root);
    for comp in Path::new(request_path).components() {
        match comp {
            Component::Normal(seg) => resolved.push(seg),
            Component::RootDir | Component::Prefix(_) => { /* ignore leading slash */ }
            Component::CurDir => {}
            // Any `..` is rejected outright — no climbing above the root.
            Component::ParentDir => return None,
        }
    }
    Some(resolved)
}

/// True if `name` is a hidden system/metadata *name*: it begins with one of the
/// scratch prefixes — `.` (dotfiles), `@` (`@eaDir`), or `$` (`$RECYCLE.BIN`).
/// This is the base rule, before any `--expose` overrides are applied (see
/// [`is_hidden`]).
pub fn is_hidden_name(name: &str) -> bool {
    matches!(name.chars().next(), Some('.' | '@' | '$'))
}

/// Whether `name` should be hidden and never served: a hidden system name that
/// no `--expose` glob re-exposes. An override like `.mpdignore` un-hides that one
/// name; `.*` un-hides all dotfiles; `*` un-hides everything.
pub fn is_hidden(name: &str, exposes: &[String]) -> bool {
    is_hidden_name(name) && !exposes.iter().any(|p| glob_match(p, name))
}

/// True if any segment of `request_path` is hidden (see [`is_hidden`]) — so a
/// request for `/dir/.htpasswd` or `/.git/config` is refused, not just omitted
/// from listings. Only `Normal` components are checked (`.`/`..`/root are handled
/// by `resolve_within`).
pub fn path_has_hidden(request_path: &str, exposes: &[String]) -> bool {
    Path::new(request_path).components().any(|c| match c {
        Component::Normal(seg) => seg.to_str().is_some_and(|s| is_hidden(s, exposes)),
        _ => false,
    })
}

/// Match `name` against a shell-style glob supporting `*` (any run, including
/// empty) and `?` (exactly one character); case-sensitive, whole-string, no
/// character classes. Used for `--expose` overrides.
pub fn glob_match(pattern: &str, name: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let s: Vec<char> = name.chars().collect();
    let (mut pi, mut si) = (0, 0);
    // Backtracking wildcard match: `star` remembers the last '*' in the pattern
    // and `mark` how much of `name` it had consumed, so a later mismatch can make
    // that '*' swallow one more character and retry.
    let (mut star, mut mark): (Option<usize>, usize) = (None, 0);
    while si < s.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == s[si]) {
            pi += 1;
            si += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            mark = si;
            pi += 1;
        } else if let Some(sp) = star {
            pi = sp + 1;
            mark += 1;
            si = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

/// Append a trailing slash to `path` if it doesn't already have one.
pub fn with_trailing_slash(path: &str) -> String {
    if path.ends_with('/') {
        path.to_string()
    } else {
        format!("{}/", path)
    }
}

/// Very small extension -> MIME type table. Falls back to octet-stream.
pub fn mime_for(path: &Path) -> &'static str {
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
    // Extensions are already lowercase in the overwhelming common case; only
    // allocate a folded copy when one actually needs it.
    let ext: Cow<str> = if ext.bytes().any(|b| b.is_ascii_uppercase()) {
        Cow::Owned(ext.to_ascii_lowercase())
    } else {
        Cow::Borrowed(ext)
    };
    match ext.as_ref() {
        "html" | "htm" => "text/html; charset=utf-8",
        "txt" | "text" | "md" => "text/plain; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "js" | "mjs" => "text/javascript; charset=utf-8",
        "json" => "application/json",
        "xml" => "application/xml",
        "csv" => "text/csv; charset=utf-8",
        "pdf" => "application/pdf",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "svg" => "image/svg+xml",
        "webp" => "image/webp",
        "ico" => "image/x-icon",
        // Audio — common first, then progressively more esoteric.
        "mp3" | "mp2" | "mpga" => "audio/mpeg",
        "m4a" | "m4b" => "audio/mp4",
        "aac" => "audio/aac",
        "flac" => "audio/flac",
        "ogg" | "oga" => "audio/ogg",
        "opus" => "audio/opus",
        "spx" => "audio/ogg", // Speex, Ogg-encapsulated
        "wav" => "audio/wav",
        "weba" => "audio/webm",
        "aif" | "aiff" | "aifc" => "audio/aiff",
        "mid" | "midi" | "kar" => "audio/midi",
        "wma" => "audio/x-ms-wma",
        "wax" => "audio/x-ms-wax",
        "ra" | "ram" => "audio/x-pn-realaudio",
        "au" | "snd" => "audio/basic",
        "amr" => "audio/amr",
        "awb" => "audio/amr-wb",
        "3ga" => "audio/3gpp",
        "caf" => "audio/x-caf",
        "ape" => "audio/x-ape",
        "wv" => "audio/x-wavpack",
        "tta" => "audio/x-tta",
        "mpc" => "audio/x-musepack",
        "mka" => "audio/x-matroska",
        "dsf" => "audio/x-dsf",
        "dff" => "audio/x-dff",
        "dts" => "audio/vnd.dts",
        "dtshd" => "audio/vnd.dts.hd",
        "ac3" => "audio/ac3",
        "eac3" => "audio/eac3",
        "gsm" => "audio/x-gsm",
        "voc" => "audio/x-voc",
        "mod" => "audio/x-mod",
        "s3m" => "audio/x-s3m",
        "xm" => "audio/x-xm",
        "it" => "audio/x-it",
        "m3u" => "audio/x-mpegurl",
        "m3u8" => "application/vnd.apple.mpegurl",
        "pls" => "audio/x-scpls",
        "mp4" => "video/mp4",
        "zip" => "application/zip",
        "gz" | "tgz" => "application/gzip",
        "tar" => "application/x-tar",
        _ => "application/octet-stream",
    }
}

const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

/// Decompose a `SystemTime` into UTC `(year, month, mday, hour, min, sec, wday)`,
/// where `wday` is 0=Sunday. Shared by the date formatters.
fn ymd_hms(t: SystemTime) -> (i64, i64, i64, i64, i64, i64, usize) {
    let secs = t
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let days = secs.div_euclid(86400);
    let rem = secs.rem_euclid(86400);
    let (hour, min, sec) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    // 1970-01-01 was a Thursday (index 4 with Sunday = 0).
    let wday = ((days % 7) + 4).rem_euclid(7) as usize;
    let (year, month, mday) = civil_from_days(days);
    (year, month, mday, hour, min, sec, wday)
}

/// Format a `SystemTime` as an HTTP-date (RFC 7231 / IMF-fixdate), e.g.
/// `Tue, 15 Nov 1994 08:12:31 GMT`. Always in GMT.
pub fn http_date(t: SystemTime) -> String {
    let (year, month, mday, hour, min, sec, wday) = ymd_hms(t);
    const WDAYS: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
    format!(
        "{}, {:02} {} {:04} {:02}:{:02}:{:02} GMT",
        WDAYS[wday],
        mday,
        MONTHS[(month - 1) as usize],
        year,
        hour,
        min,
        sec
    )
}

/// Format a `SystemTime` as a compact UTC timestamp `YYYY-MM-DD HH:MM:SS`,
/// suitable for a human-readable directory listing.
pub fn datetime_utc(t: SystemTime) -> String {
    let (year, month, mday, hour, min, sec, _) = ymd_hms(t);
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        year, month, mday, hour, min, sec
    )
}

/// Parse an IMF-fixdate HTTP-date (e.g. `Sun, 06 Nov 1994 08:49:37 GMT`) into
/// seconds since the Unix epoch. Returns `None` if it isn't this exact form
/// (the obsolete RFC 850 / asctime forms are not supported — modern clients
/// send IMF-fixdate). Used for `If-Modified-Since` / `If-Range`.
pub fn parse_http_date(s: &str) -> Option<i64> {
    // "Sun, 06 Nov 1994 08:49:37 GMT" -> [wday] [day] [mon] [year] [hh:mm:ss] [GMT]
    let mut it = s.split_whitespace();
    let _wday = it.next()?;
    let day: i64 = it.next()?.parse().ok()?;
    let mon_name = it.next()?;
    let year: i64 = it.next()?.parse().ok()?;
    let time = it.next()?;

    let month = MONTHS.iter().position(|&m| m == mon_name)? as i64 + 1;
    let mut tp = time.split(':');
    let h: i64 = tp.next()?.parse().ok()?;
    let mi: i64 = tp.next()?.parse().ok()?;
    let se: i64 = tp.next()?.parse().ok()?;

    Some(days_from_civil(year, month, day) * 86400 + h * 3600 + mi * 60 + se)
}

/// Inverse of `civil_from_days`: days since the Unix epoch for a civil date.
/// Howard Hinnant's `days_from_civil` algorithm.
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = (if y >= 0 { y } else { y - 399 }) / 400;
    let yoe = y - era * 400;
    let mp = if m > 2 { m - 3 } else { m + 9 };
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

/// Render a byte count compactly: plain bytes below 1 KiB, otherwise a single
/// decimal with a binary unit suffix (e.g. `1.4K`, `3.2M`).
pub fn human_size(n: u64) -> String {
    const UNITS: [&str; 6] = ["B", "K", "M", "G", "T", "P"];
    if n < 1024 {
        return format!("{} B", n);
    }
    let mut size = n as f64;
    let mut unit = 0;
    while size >= 1024.0 && unit < UNITS.len() - 1 {
        size /= 1024.0;
        unit += 1;
    }
    format!("{:.1}{}", size, UNITS[unit])
}

/// Convert days since the Unix epoch to a (year, month, day) civil date.
/// Based on Howard Hinnant's `civil_from_days` algorithm.
fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hidden_prefixes_are_filtered() {
        for n in [
            ".htpasswd",
            ".git",
            ".env",
            ".DS_Store",
            "@eaDir",
            "$RECYCLE.BIN",
        ] {
            assert!(is_hidden_name(n), "{n} should be hidden");
        }
    }

    #[test]
    fn ordinary_and_named_turds_are_not_hidden() {
        // Only the .@#$ prefixes are filtered; plain names are served — including
        // Windows turds like Desktop.ini/Thumbs.db and old VCS dirs like CVS.
        for n in [
            "index.html",
            "photo.jpg",
            "notes",
            "git",
            "#recycle",
            "Thumbs.db",
            "Desktop.ini",
            "lost+found",
            "CVS",
        ] {
            assert!(!is_hidden_name(n), "{n} should not be hidden");
        }
    }

    #[test]
    fn path_hidden_matches_any_segment() {
        let none: &[String] = &[];
        assert!(path_has_hidden("/dir/.htpasswd", none));
        assert!(path_has_hidden("/.git/config", none)); // hidden ancestor
        assert!(path_has_hidden("/a/@eaDir/thumb.jpg", none));
        assert!(!path_has_hidden("/dir/sub/file.txt", none));
        assert!(!path_has_hidden("/", none));
    }

    #[test]
    fn glob_matches_star_and_question() {
        assert!(glob_match("*", ".anything"));
        assert!(glob_match(".*", ".mpdignore"));
        assert!(glob_match(".mpdignore", ".mpdignore"));
        assert!(!glob_match(".mpdignore", ".mpdignorex"));
        assert!(glob_match("*.log", "server.log"));
        assert!(glob_match("a?c", "abc"));
        assert!(!glob_match("a?c", "ac"));
        assert!(glob_match("", ""));
        assert!(!glob_match("", "x"));
    }

    #[test]
    fn expose_overrides_hiding() {
        let one = [".mpdignore".to_string()];
        assert!(!is_hidden(".mpdignore", &one)); // exposed by name
        assert!(is_hidden(".htpasswd", &one)); // still hidden
                                               // Whole-tree escape hatches:
        assert!(!is_hidden(".htpasswd", &["*".to_string()]));
        assert!(!is_hidden(".git", &[".*".to_string()]));
        // A non-hidden name is never hidden, with or without overrides.
        assert!(!is_hidden("file.txt", &[]));
        // Path gate honours the override too.
        assert!(!path_has_hidden("/music/.mpdignore", &one));
        assert!(path_has_hidden("/music/.git/x", &one));
    }

    #[test]
    fn exposing_a_directory_reaches_its_children() {
        let data = [".data".to_string()];
        // Exposed hidden dir: the dir and its (non-hidden) descendants are reachable.
        assert!(!path_has_hidden("/.data", &data));
        assert!(!path_has_hidden("/.data/file.txt", &data));
        assert!(!path_has_hidden("/.data/sub/deep.txt", &data));
        // Not exposed: the hidden ancestor blocks every child.
        assert!(path_has_hidden("/.data/file.txt", &[]));
        // A *nested* hidden segment is still blocked even when the parent is
        // exposed — each segment is judged on its own.
        assert!(path_has_hidden("/.data/.secret/x", &data));
    }
}
