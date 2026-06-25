//! Small self-contained helpers: percent-coding, HTTP dates, MIME guessing,
//! XML escaping and safe path resolution. Kept dependency-free on purpose.

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
                let h = hex_val(bytes[i + 1]);
                let l = hex_val(bytes[i + 2]);
                if let (Some(h), Some(l)) = (h, l) {
                    out.push((h << 4) | l);
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
    String::from_utf8_lossy(&out).into_owned()
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
            out.push('%');
            out.push(hex_digit(b >> 4));
            out.push(hex_digit(b & 0x0f));
        }
    }
    out
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn hex_digit(n: u8) -> char {
    match n {
        0..=9 => (b'0' + n) as char,
        _ => (b'a' + (n - 10)) as char,
    }
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
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    match ext.as_str() {
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
        "mp3" => "audio/mpeg",
        "mp4" => "video/mp4",
        "wav" => "audio/wav",
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
