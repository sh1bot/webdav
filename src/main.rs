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
//! Confinement: if stunnel execs us as root, we chroot into the served directory
//! and drop to `nobody` ourselves (after reading any command-line files, so they
//! can live outside the chroot). Because the static binary is already in memory
//! and `/etc/passwd` is read before the chroot, the served directory needs
//! nothing added to it. If stunnel already dropped privileges (its own `setuid`),
//! we run unprivileged and this step is a no-op.

mod auth;
mod dav;
mod http;
mod util;

use std::fs::File;
use std::io::{self, Write};
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

    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--root" => root = PathBuf::from(it.next().unwrap_or_else(|| usage())),
            "--auth-file" => auth_file = Some(PathBuf::from(it.next().unwrap_or_else(|| usage()))),
            "--user" => user = Some(it.next().unwrap_or_else(|| usage())),
            "--password" => password = Some(it.next().unwrap_or_else(|| usage())),
            "--realm" => realm = it.next().unwrap_or_else(|| usage()),
            "--log-file" => log_file = Some(PathBuf::from(it.next().unwrap_or_else(|| usage()))),
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

/// Serve the one request stunnel/inetd handed us. Per the inetd contract we read
/// the request from stdin (fd 0), write the reply to stdout (fd 1), and log to
/// stderr (fd 2) — without assuming any of them is a socket. (Under stunnel/xinetd
/// they all refer to one connection, but nothing here relies on that.)
#[cfg(unix)]
fn serve_stdin(root: &Path, auth: &Auth) {
    use std::os::unix::io::FromRawFd;

    // Safety: fd 0/1 are the inherited, owned connection descriptors. The File
    // wrappers close them on drop — at process exit, after the one request.
    let mut input = unsafe { File::from_raw_fd(0) };
    let mut output = unsafe { File::from_raw_fd(1) };

    let result = http::read_request(&mut input)
        .and_then(|req| dav::handle(&mut output, root, auth, &req))
        .and_then(|()| output.flush());
    if let Err(e) = result {
        eprintln!("connection error: {}", e);
    }
}

#[cfg(not(unix))]
fn serve_stdin(_root: &Path, _auth: &Auth) {
    eprintln!("error: tiny-webdav is only supported on Unix platforms");
    process::exit(1);
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

    // Everything taken from the command line is now open: --log-file is dup'd
    // onto fd 2 and --auth-file has been read into memory, both before the chroot
    // below (the served files themselves live inside the chroot and are opened
    // after it). Now confine: if we're root, chroot into the served directory and
    // drop to `nobody`. The returned path is what we serve from afterwards — "/"
    // once chrooted. If we aren't root (e.g. stunnel already dropped us), this is
    // a no-op and we serve the canonical root as-is.
    let serve_root = lower_privileges(&canonical_root);

    serve_stdin(&serve_root, &auth);
}

/// Print a fatal error to stderr and exit non-zero.
fn fatal(msg: &str) -> ! {
    eprintln!("fatal: {}", msg);
    process::exit(1);
}

/// Confine the process and shed privileges. Some hardening applies always (it
/// needs no privilege): `PR_SET_NO_NEW_PRIVS` so we can never *gain* privileges
/// from here on, and `RLIMIT_CORE`/`RLIMIT_NPROC` caps (no core dumps, no
/// forking) to bound the blast radius of any bug.
///
/// When started as root we additionally confine to `root`: look up the `nobody`
/// account (reading `/etc/passwd` *before* the chroot, while it's reachable),
/// `chroot` into `root`, `chdir` to the new `/`, then drop supplementary groups,
/// gid and uid (in that order). A failure while root is fatal — we must never
/// continue with elevated privileges. Returns the path to serve from afterwards:
/// `/` once chrooted, or `root` unchanged when we weren't root (e.g. stunnel
/// already dropped us).
#[cfg(unix)]
fn lower_privileges(root: &Path) -> PathBuf {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    // Hardening that needs no privilege and is safe before any uid change.
    // Best-effort: failures here don't leave us *more* privileged.
    //
    // Both fields are 0 on purpose: zeroing the *hard* limit (rlim_max), not just
    // the soft one, means a later compromised/unprivileged process can't raise it
    // back — raising a hard limit needs CAP_SYS_RESOURCE, which we won't have once
    // dropped (and PR_SET_NO_NEW_PRIVS stops us regaining caps via exec).
    unsafe {
        libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
        let zero = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        libc::setrlimit(libc::RLIMIT_CORE, &zero); // no core dumps (could leak data)
    }

    let serve_root = if unsafe { libc::geteuid() } == 0 {
        // Resolve `nobody` before chrooting, while /etc/passwd is reachable.
        let (uid, gid) = unsafe {
            let pw = libc::getpwnam(c"nobody".as_ptr());
            if pw.is_null() {
                (65534, 65534) // conventional nobody / nogroup ids
            } else {
                ((*pw).pw_uid, (*pw).pw_gid)
            }
        };

        let c_root = CString::new(root.as_os_str().as_bytes())
            .unwrap_or_else(|_| fatal("root path contains an interior NUL byte"));

        unsafe {
            if libc::chroot(c_root.as_ptr()) != 0 {
                fatal(&format!(
                    "chroot to {} failed: {}",
                    root.display(),
                    io::Error::last_os_error()
                ));
            }
            if libc::chdir(c"/".as_ptr()) != 0 {
                fatal(&format!("chdir(/) failed: {}", io::Error::last_os_error()));
            }
            // Drop supplementary groups, then gid, then uid — order matters, and
            // any failure is fatal so we never keep a shred of root.
            if libc::setgroups(0, std::ptr::null()) != 0 {
                fatal(&format!("setgroups failed: {}", io::Error::last_os_error()));
            }
            if libc::setgid(gid) != 0 {
                fatal(&format!(
                    "setgid({}) failed: {}",
                    gid,
                    io::Error::last_os_error()
                ));
            }
            if libc::setuid(uid) != 0 {
                fatal(&format!(
                    "setuid({}) failed: {}",
                    uid,
                    io::Error::last_os_error()
                ));
            }
        }

        PathBuf::from("/")
    } else {
        // Not root: nothing to chroot/drop (the supervisor may already have).
        root.to_path_buf()
    };

    // Forbid forking, done *after* any uid change: setuid to a user already at
    // its RLIMIT_NPROC can fail, and we never fork anyway.
    unsafe {
        let zero = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        libc::setrlimit(libc::RLIMIT_NPROC, &zero);
    }

    serve_root
}

#[cfg(not(unix))]
fn lower_privileges(root: &Path) -> PathBuf {
    root.to_path_buf()
}
