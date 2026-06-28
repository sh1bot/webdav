//! tiny-webdav: a read-only WebDAV server run under inetd / xinetd, with TLS
//! terminated by **stunnel** in front of it.
//!
//! This program speaks *plaintext* HTTP. It does not do TLS itself: stunnel
//! terminates TLS (and verifies client certificates, if configured), then hands
//! us the decrypted connection on stdin (fd 0) — the classic inetd contract.
//! We serve the one request and exit, so stunnel/inetd gives per-connection
//! concurrency (one process per client) for free.
//!
//! Access control splits across the two layers: **client certificate (mutual
//! TLS)** is enforced by stunnel (`verify`/`CAfile`, which we never see), while
//! **HTTP Basic username/password** is enforced here, layered on top. If no
//! Basic credentials are configured, this program enforces no auth of its own
//! and relies entirely on stunnel / the network for access control.

mod auth;
mod dav;
mod http;
mod util;

use std::io::{self, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process;
use std::time::Duration;

use auth::Auth;

struct Args {
    root: PathBuf,
    auth_file: Option<PathBuf>,
    user: Option<String>,
    password: Option<String>,
    realm: String,
    log_file: Option<PathBuf>,
    timeout: u64,
}

fn usage() -> ! {
    eprintln!(
        "tiny-webdav — read-only WebDAV, run under inetd/xinetd behind stunnel\n\n\
         It speaks plaintext HTTP on a connection passed on stdin (fd 0) and\n\
         exits. Put stunnel in front to terminate TLS (and verify client certs);\n\
         launch it per-connection from stunnel's exec/execargs or from\n\
         inetd/xinetd in 'nowait' mode.\n\n\
         USAGE:\n  \
           tiny-webdav [--root <dir>] [options]\n\n\
         OPTIONS:\n  \
           --root <dir>            Directory to serve (default: current directory)\n  \
           --timeout <secs>        Per-read/write socket timeout (default: 30, 0 to\n                          \
                       disable; raise/disable for large transfers to slow links)\n  \
           --log-file <file>       Write diagnostics to this file. Default: stderr\n                          \
                       (captured by stunnel/systemd). Use this under xinetd,\n                          \
                       where stderr is the client socket.\n\n  \
           HTTP Basic auth (client certs are handled by stunnel, not here):\n  \
           --auth-file <file>      File of 'username:password' lines (# comments)\n  \
           --user <name>           A single username (use with --password)\n  \
           --password <pass>       Password for --user\n  \
           --realm <realm>         Basic-auth realm shown to clients (default: tiny-webdav)\n"
    );
    process::exit(2);
}

fn parse_args() -> Args {
    let mut root = PathBuf::from(".");
    let mut auth_file: Option<PathBuf> = None;
    let mut user: Option<String> = None;
    let mut password: Option<String> = None;
    let mut realm = "tiny-webdav".to_string();
    let mut log_file: Option<PathBuf> = None;
    let mut timeout: u64 = 30;

    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--root" => root = PathBuf::from(it.next().unwrap_or_else(|| usage())),
            "--auth-file" => auth_file = Some(PathBuf::from(it.next().unwrap_or_else(|| usage()))),
            "--user" => user = Some(it.next().unwrap_or_else(|| usage())),
            "--password" => password = Some(it.next().unwrap_or_else(|| usage())),
            "--realm" => realm = it.next().unwrap_or_else(|| usage()),
            "--log-file" => log_file = Some(PathBuf::from(it.next().unwrap_or_else(|| usage()))),
            "--timeout" => {
                timeout = it
                    .next()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or_else(|| usage())
            }
            "-h" | "--help" => usage(),
            other => {
                eprintln!("error: unexpected argument '{}'\n", other);
                usage();
            }
        }
    }

    if user.is_some() != password.is_some() {
        eprintln!("error: --user and --password must be given together\n");
        usage();
    }

    Args {
        root,
        auth_file,
        user,
        password,
        realm,
        log_file,
        timeout,
    }
}

fn build_auth(args: &Args) -> io::Result<Auth> {
    let mut auth = Auth::new(args.realm.clone());
    if let Some(path) = &args.auth_file {
        auth.load_file(path)?;
    }
    if let (Some(u), Some(p)) = (&args.user, &args.password) {
        auth.add(u.clone(), p.clone());
    }
    Ok(auth)
}

/// Serve the single plaintext connection on `tcp` (fd 0 from stunnel/inetd).
fn serve_connection(root: &Path, auth: &Auth, timeout: u64, mut tcp: TcpStream) -> io::Result<()> {
    // Bound how long a single blocking I/O can stall us. `--timeout 0` disables
    // it (needed for large transfers to slow links, since this is a
    // per-operation timeout, not an idle timeout). Best-effort: the inherited
    // fd may not support socket timeouts in every stunnel/inetd configuration.
    let to = (timeout != 0).then(|| Duration::from_secs(timeout));
    let _ = tcp.set_read_timeout(to);
    let _ = tcp.set_write_timeout(to);

    let req = http::read_request(&mut tcp)?;
    dav::handle(&mut tcp, root, auth, &req)?;
    tcp.flush()
}

/// Serve the single connection stunnel/inetd handed us on stdin (fd 0).
#[cfg(unix)]
fn serve_stdin(root: &Path, auth: &Auth, timeout: u64) {
    use std::os::unix::io::FromRawFd;

    // Safety: under inetd/stunnel, fd 0 is the connected, owned socket. We take
    // ownership of it; it is closed when the resulting TcpStream is dropped.
    let sock = unsafe { TcpStream::from_raw_fd(0) };
    let peer = sock
        .peer_addr()
        .map(|a| a.to_string())
        .unwrap_or_else(|_| "?".to_string());
    if let Err(e) = serve_connection(root, auth, timeout, sock) {
        eprintln!("[{}] connection error: {}", peer, e);
    }
}

#[cfg(not(unix))]
fn serve_stdin(_root: &Path, _auth: &Auth, _timeout: u64) {
    eprintln!("error: tiny-webdav is only supported on Unix platforms");
    process::exit(1);
}

/// stunnel hands us the connection on fd 0 and dups it onto fd 1, so point fd 1
/// at /dev/null before we emit anything — a stray write to stdout would
/// otherwise corrupt the stream stunnel re-encrypts to the client. fd 0 (the
/// connection we serve) is left untouched.
///
/// fd 2 carries our diagnostics. By default we leave it alone so it flows to
/// stunnel's own stderr — the systemd journal / terminal when stunnel runs as a
/// daemon. `--log-file` redirects it to a file instead; that is what you want
/// under xinetd, where the inherited stderr would otherwise be the client socket
/// and logging to it would corrupt the connection.
#[cfg(unix)]
fn redirect_streams(log_file: Option<&Path>) {
    use std::fs::OpenOptions;
    use std::os::unix::io::AsRawFd;

    // /dev/null must open: if it doesn't, fd 1 would stay pointed at the client
    // connection and any later output would corrupt the stream. Fail closed —
    // and silently, since stderr may itself still be the connection.
    let devnull = match OpenOptions::new().write(true).open("/dev/null") {
        Ok(f) => f,
        Err(_) => process::exit(1),
    };
    unsafe { libc::dup2(devnull.as_raw_fd(), 1) };

    // Only touch fd 2 when an explicit --log-file is given: send it there, or to
    // /dev/null if it can't be opened — never leave it pointing at the
    // connection. With no --log-file, fd 2 keeps inheriting stunnel's stderr.
    if let Some(path) = log_file {
        let log = OpenOptions::new().create(true).append(true).open(path).ok();
        let fd = log
            .as_ref()
            .map(|f| f.as_raw_fd())
            .unwrap_or(devnull.as_raw_fd());
        unsafe { libc::dup2(fd, 2) };
    }
    // `devnull`/`log` File handles drop here, closing their original fds;
    // the dup2'd descriptors remain valid.
}

#[cfg(not(unix))]
fn redirect_streams(_log_file: Option<&Path>) {}

fn main() {
    let args = parse_args();

    // stdin/stdout/stderr come from stunnel. Move stdout off the connection (and
    // stderr too, if --log-file was given) *first*, before any output, so no
    // diagnostic can corrupt the stream. Without --log-file, stderr is left
    // flowing to stunnel's stderr (the journal under systemd).
    redirect_streams(args.log_file.as_deref());

    let canonical_root = match args.root.canonicalize() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("error: cannot access --root {}: {}", args.root.display(), e);
            process::exit(1);
        }
    };
    if !canonical_root.is_dir() {
        eprintln!(
            "error: --root {} is not a directory",
            canonical_root.display()
        );
        process::exit(1);
    }

    let auth = match build_auth(&args) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("error: cannot load credentials: {}", e);
            process::exit(1);
        }
    };

    // We can't see the TLS layer, but stunnel exports SSL_CLIENT_DN when it has
    // verified a client certificate. Treat that as authentication too, so a
    // cert-only deployment isn't warned at. Warn only when a connection carries
    // neither a verified client cert nor Basic credentials.
    let client_cert = std::env::var("SSL_CLIENT_DN").is_ok_and(|v| !v.is_empty());
    if !auth.is_enabled() && !client_cert {
        eprintln!(
            "WARNING: unauthenticated request — no verified client certificate \
             (SSL_CLIENT_DN unset) and no HTTP Basic auth; anyone who can reach \
             this server can read the served files."
        );
    }

    // Everything that needs the original filesystem is done (credentials are in
    // memory). Confine the process: chroot into the served directory and drop to
    // an unprivileged user. If we lack the privileges (i.e. we were started as a
    // non-root user already), this is skipped. The returned path is the root to
    // serve from afterwards (`/` once chrooted).
    let serve_root = lower_privileges(&canonical_root);

    serve_stdin(&serve_root, &auth, args.timeout);
}

/// Confine the process after startup: `chroot` into `root`, then drop to the
/// unprivileged `nobody` account. Returns the path to serve from afterwards —
/// `/` when the chroot succeeds (the served directory becomes the new root),
/// otherwise `root` unchanged. When not started as root this is skipped;
/// when started as root, a failed privilege drop is fatal.
#[cfg(unix)]
fn lower_privileges(root: &Path) -> PathBuf {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    // If we're not effectively root we can't chroot or change uid; say so once
    // and carry on with current privileges. (stunnel/xinetd typically start the
    // service as an unprivileged user already, in which case this is expected.)
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("not running as root: skipping chroot and privilege drop");
        return root.to_path_buf();
    }

    // Resolve the `nobody` account *before* chrooting, while /etc is reachable.
    let (uid, gid) = unsafe {
        let pw = libc::getpwnam(c"nobody".as_ptr());
        if pw.is_null() {
            (65534, 65534) // conventional nobody / nogroup ids
        } else {
            ((*pw).pw_uid, (*pw).pw_gid)
        }
    };

    let mut serve_root = root.to_path_buf();

    // chroot into the served directory, then make it the working directory.
    // chroot itself is best-effort (we still drop privileges below if it fails).
    match CString::new(root.as_os_str().as_bytes()) {
        Ok(c_root) => unsafe {
            if libc::chroot(c_root.as_ptr()) == 0 && libc::chdir(c"/".as_ptr()) == 0 {
                serve_root = PathBuf::from("/");
                eprintln!("chroot: confined to {}", root.display());
            } else {
                eprintln!(
                    "chroot to {} failed ({}); carrying on without chroot",
                    root.display(),
                    io::Error::last_os_error()
                );
            }
        },
        Err(_) => eprintln!("chroot skipped: root path contains an interior NUL byte"),
    }

    // Drop supplementary groups, then gid, then uid (must be in this order).
    // We are root here, so failing to drop is a hard security failure (we'd keep
    // serving with root privileges) — treat it as fatal rather than carrying on.
    unsafe {
        if libc::setgroups(0, std::ptr::null()) != 0 {
            eprintln!("setgroups failed ({})", io::Error::last_os_error());
        }
        if libc::setgid(gid) != 0 {
            eprintln!(
                "fatal: setgid({}) failed ({})",
                gid,
                io::Error::last_os_error()
            );
            process::exit(1);
        }
        if libc::setuid(uid) != 0 {
            eprintln!(
                "fatal: setuid({}) failed ({})",
                uid,
                io::Error::last_os_error()
            );
            process::exit(1);
        }
    }
    eprintln!("dropped privileges to nobody (uid={}, gid={})", uid, gid);

    serve_root
}

#[cfg(not(unix))]
fn lower_privileges(root: &Path) -> PathBuf {
    eprintln!("chroot/privilege drop not supported on this platform; carrying on");
    root.to_path_buf()
}
