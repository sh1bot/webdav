//! tiny-webdav: a small read-only WebDAV server, run behind stunnel (which
//! terminates TLS) under the inetd contract — the decrypted connection arrives on
//! stdin (fd 0); we serve one request and exit.
//!
//! Auth is layered: client certificates are stunnel's job (we only see the
//! resulting `SSL_CLIENT_DN`), HTTP Basic is ours. Confinement is ours too: run
//! as root we chroot into `--root` and drop to `--run-as` (see `lower_privileges`).
//! See the README for the full picture.

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
    run_as: Option<String>,
}

fn usage() -> ! {
    eprintln!(
        "tiny-webdav — read-only WebDAV over plaintext HTTP, run behind stunnel\n\n\
         USAGE:\n  \
           tiny-webdav [--root <dir>] [options]\n\n\
         OPTIONS:\n  \
           --root <dir>            Directory to serve (default: current directory)\n  \
           --run-as <user>         When started as root, chroot into --root and\n                          \
                       drop to this user (default: nobody)\n  \
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
    let mut run_as: Option<String> = None;

    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--root" => root = PathBuf::from(it.next().unwrap_or_else(|| usage())),
            "--auth-file" => auth_file = Some(PathBuf::from(it.next().unwrap_or_else(|| usage()))),
            "--user" => user = Some(it.next().unwrap_or_else(|| usage())),
            "--password" => password = Some(it.next().unwrap_or_else(|| usage())),
            "--realm" => realm = it.next().unwrap_or_else(|| usage()),
            "--log-file" => log_file = Some(PathBuf::from(it.next().unwrap_or_else(|| usage()))),
            "--run-as" => run_as = Some(it.next().unwrap_or_else(|| usage())),
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
        run_as,
    }
}

/// Parse credentials. `auth_file` is the *already-open* `--auth-file` (opened
/// before the chroot/privilege drop); parsing it happens here, after the drop, so
/// the bug-prone work runs unprivileged. The path string is only for error text.
fn build_auth(args: &Args, auth_file: Option<File>) -> io::Result<Auth> {
    let mut auth = Auth::new(args.realm.clone());
    if let Some(file) = auth_file {
        let source = args.auth_file.as_deref().unwrap_or(Path::new("-"));
        auth.load(file, &source.display().to_string())?;
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

    // Open --auth-file now, before the chroot/drop, while its path is reachable
    // and we still have the privilege to read it — but don't parse it yet. The
    // parsing happens after the drop, so that bug-prone work runs unprivileged.
    let auth_file = match &args.auth_file {
        Some(path) => match File::open(path) {
            Ok(f) => Some(f),
            Err(e) => fatal(&format!(
                "cannot open --auth-file {}: {}",
                path.display(),
                e
            )),
        },
        None => None,
    };

    // Everything taken from the command line is now open: --log-file is dup'd onto
    // fd 2 and --auth-file holds an fd, both before the chroot (the served files
    // live inside the chroot and are opened after it). Now confine: if we're root,
    // chroot into the served directory and drop to `nobody`; the returned path is
    // what we serve from ("/" once chrooted). If we aren't root (e.g. stunnel
    // already dropped us), this is a no-op and we serve the canonical root as-is.
    let serve_root = lower_privileges(&canonical_root, args.run_as.as_deref());

    // Now unprivileged: parse the (already-open) auth file and inline credentials.
    let auth = match build_auth(&args, auth_file) {
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
            "WARNING: serving unauthenticated — no client cert (SSL_CLIENT_DN) and no Basic auth"
        );
    }

    serve_stdin(&serve_root, &auth);
}

/// Print a fatal error to stderr and exit non-zero.
fn fatal(msg: &str) -> ! {
    eprintln!("fatal: {}", msg);
    process::exit(1);
}

/// Set both the soft and **hard** limit of `resource` to 0. Zeroing the *hard*
/// limit is deliberate: a later unprivileged/compromised process can't raise it
/// back (raising a hard limit needs CAP_SYS_RESOURCE, which we won't have once
/// dropped, and PR_SET_NO_NEW_PRIVS blocks regaining caps via exec). Best-effort:
/// a failure leaves us no more privileged.
#[cfg(unix)]
fn deny_rlimit(resource: libc::c_int) {
    let zero = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    unsafe { libc::setrlimit(resource as _, &zero) };
}

/// Confine the process and shed privileges. Some hardening applies always (it
/// needs no privilege): `PR_SET_NO_NEW_PRIVS` so we can never *gain* privileges
/// from here on, and `RLIMIT_CORE`/`RLIMIT_NPROC` caps (no core dumps, no
/// forking) to bound the blast radius of any bug.
///
/// When started as root we confine to `root`: `chroot` into it, `chdir` to the
/// new `/`, and drop supplementary groups, gid and uid to the target account
/// (`run_as`, default `nobody`), whose ids are resolved *before* the chroot while
/// `/etc/passwd` is reachable. Any failure while root is fatal.
///
/// Finally, if `--run-as` was given explicitly, *assert* we actually ended up as
/// that user — this catches the case where we couldn't change uid (not root) and
/// weren't already running as it. Returns the path to serve from: `/` once
/// chrooted, else `root` unchanged.
#[cfg(unix)]
fn lower_privileges(root: &Path, run_as: Option<&str>) -> PathBuf {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    // Hardening that needs no privilege and is safe before any uid change.
    // Best-effort: failures here don't leave us *more* privileged.
    unsafe {
        libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
    }
    deny_rlimit(libc::RLIMIT_CORE as _); // no core dumps (could leak data)

    let euid = unsafe { libc::geteuid() };
    let target = run_as.unwrap_or("nobody");

    // Resolve the target account *before* any chroot (while /etc/passwd is
    // reachable), if we'll need it — to drop to (when root) or to assert against
    // (when --run-as was given). Cached so the post-drop assertion needn't re-read
    // /etc/passwd, which is gone once chrooted.
    let creds = (euid == 0 || run_as.is_some()).then(|| lookup_user(target));

    let serve_root = if euid == 0 {
        let (uid, gid) = creds.unwrap();
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
            // any failure is fatal so we never keep a shred of root. setres*id
            // sets the real, effective AND saved ids in one call, so there's no
            // leftover saved-uid 0 a later exploit could setuid() back to.
            if libc::setgroups(0, std::ptr::null()) != 0 {
                fatal(&format!("setgroups failed: {}", io::Error::last_os_error()));
            }
            if libc::setresgid(gid, gid, gid) != 0 {
                fatal(&format!(
                    "setresgid({}) failed: {}",
                    gid,
                    io::Error::last_os_error()
                ));
            }
            if libc::setresuid(uid, uid, uid) != 0 {
                fatal(&format!(
                    "setresuid({}) failed: {}",
                    uid,
                    io::Error::last_os_error()
                ));
            }
        }

        PathBuf::from("/")
    } else {
        // Not root: can't chroot or change uid (the supervisor may already have).
        root.to_path_buf()
    };

    // Forbid forking, done *after* any uid change: setuid to a user already at
    // its RLIMIT_NPROC can fail, and we never fork anyway.
    deny_rlimit(libc::RLIMIT_NPROC as _);

    // Assert the privilege outcome by reading back the real, effective AND saved
    // uids. We must never end up with any of them as root.
    let (mut ruid, mut euid_now, mut suid) = (0, 0, 0);
    unsafe { libc::getresuid(&mut ruid, &mut euid_now, &mut suid) };
    match run_as {
        // --run-as given: all three uids must actually be that user now (whether
        // we just dropped to it, or were already running as it). Also covers the
        // case where it couldn't be honoured because we weren't root.
        Some(name) => {
            let (uid, _gid) = creds.unwrap();
            if (ruid, euid_now, suid) != (uid, uid, uid) {
                fatal(&format!(
                    "--run-as {:?}: not that user (uids r={} e={} s={}, want {})",
                    name, ruid, euid_now, suid, uid
                ));
            }
        }
        // No target requested: at minimum none of the uids may be root. (Guards
        // against a misconfigured `nobody` mapped to uid 0 — where the drop is a
        // no-op — and against a leftover saved-uid 0.)
        None => {
            if ruid == 0 || euid_now == 0 || suid == 0 {
                fatal("refusing to serve as root; run unprivileged or pass --run-as");
            }
        }
    }

    serve_root
}

#[cfg(not(unix))]
fn lower_privileges(root: &Path, _run_as: Option<&str>) -> PathBuf {
    root.to_path_buf()
}

/// Resolve a user name to its (uid, primary gid) via `getpwnam`. Fatal if the
/// name is unknown or contains a NUL. Must be called before any chroot, while
/// `/etc/passwd` is reachable.
#[cfg(unix)]
fn lookup_user(name: &str) -> (libc::uid_t, libc::gid_t) {
    use std::ffi::CString;

    let c_name =
        CString::new(name).unwrap_or_else(|_| fatal("user name contains an interior NUL byte"));
    let pw = unsafe { libc::getpwnam(c_name.as_ptr()) };
    if pw.is_null() {
        fatal(&format!("user {:?} not found", name));
    }
    unsafe { ((*pw).pw_uid, (*pw).pw_gid) }
}
