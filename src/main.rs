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
//!
//! Confinement is also stunnel's job: its `chroot` / `setuid` / `setgid` options
//! jail the process and drop privileges before it execs us, so we run already
//! unprivileged. We read the request from stdin, write the reply to stdout, log
//! to stderr, and otherwise touch only the served tree — so the chroot jail
//! needs nothing in it but this (static) binary and the files being served.

mod auth;
mod dav;
mod http;
mod util;

use std::fs::File;
use std::io::{self, Read, Write};
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::process;

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

/// Serve one request: read it from `input` (stdin) and write the reply to
/// `output` (stdout). We make no assumption about what kind of descriptors
/// these are — only that we can read the request from one and write the reply
/// to the other, which is the inetd contract stunnel/xinetd satisfy.
fn serve<R: Read, W: Write + AsRawFd>(
    input: &mut R,
    output: &mut W,
    root: &Path,
    auth: &Auth,
) -> io::Result<()> {
    let req = http::read_request(input)?;
    dav::handle(output, root, auth, &req)?;
    output.flush()
}

/// stunnel/inetd hands us the connection on the standard descriptors. Per the
/// inetd contract we read the request from stdin (fd 0), write the reply to
/// stdout (fd 1), and log to stderr (fd 2) — without assuming any of them is a
/// socket. (Under stunnel/xinetd they all refer to one connection, but nothing
/// here relies on that.)
#[cfg(unix)]
fn serve_stdin(root: &Path, auth: &Auth, timeout: u64) {
    use std::os::unix::io::FromRawFd;

    // Safety: fd 0/1 are the inherited, owned connection descriptors. The File
    // wrappers close them on drop — at process exit, after the one request.
    let mut input = unsafe { File::from_raw_fd(0) };
    let mut output = unsafe { File::from_raw_fd(1) };

    // Best effort: *if* these are sockets, bound how long any single read/write
    // may block (slowloris protection). Silently ignored on non-sockets, so this
    // is opportunistic hardening, not an assumption that they are sockets.
    if timeout != 0 {
        set_socket_timeouts(timeout);
    }

    if let Err(e) = serve(&mut input, &mut output, root, auth) {
        eprintln!("connection error: {}", e);
    }
}

#[cfg(not(unix))]
fn serve_stdin(_root: &Path, _auth: &Auth, _timeout: u64) {
    eprintln!("error: tiny-webdav is only supported on Unix platforms");
    process::exit(1);
}

/// Best-effort `SO_RCVTIMEO` / `SO_SNDTIMEO` on the read (fd 0) and write (fd 1)
/// descriptors. Any error (e.g. the fd isn't a socket) is ignored.
#[cfg(unix)]
fn set_socket_timeouts(secs: u64) {
    let tv = libc::timeval {
        tv_sec: secs as _, // infer tv_sec's width (time_t differs across libcs)
        tv_usec: 0,
    };
    let p = (&tv as *const libc::timeval).cast();
    let len = std::mem::size_of::<libc::timeval>() as libc::socklen_t;
    unsafe {
        libc::setsockopt(0, libc::SOL_SOCKET, libc::SO_RCVTIMEO, p, len);
        libc::setsockopt(1, libc::SOL_SOCKET, libc::SO_SNDTIMEO, p, len);
    }
}

#[cfg(not(unix))]
fn redirect_streams(_log_file: Option<&Path>) {}

fn main() {
    let args = parse_args();

    // Point our diagnostics (stderr) at --log-file, if given, before any output.
    // With no --log-file, stderr stays as stunnel gave it — the systemd journal
    // under a stunnel daemon. Under xinetd stderr is the client socket, so
    // --log-file is required there to keep diagnostics off the wire. We never
    // touch fd 0 (request) or fd 1 (reply).
    if let Some(path) = &args.log_file {
        match std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
        {
            Ok(f) => unsafe {
                libc::dup2(f.as_raw_fd(), 2);
            },
            // Fail fast on a bad log path rather than risk writing diagnostics to
            // the connection (the inherited stderr under xinetd).
            Err(e) => {
                eprintln!("error: cannot open --log-file {}: {}", path.display(), e);
                process::exit(1);
            }
        }
    }

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

    // Confinement (chroot) and dropping to an unprivileged user are stunnel's
    // job (`chroot` / `setuid` / `setgid` in its config), done before it execs
    // us — so by the time we run we're already jailed and unprivileged.
    serve_stdin(&canonical_root, &auth, args.timeout);
}
