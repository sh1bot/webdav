//! tiny-webdav: a small read-only WebDAV server. By default it follows the inetd
//! contract — a connection arrives on stdin (fd 0), typically from stunnel, which
//! terminates TLS. With `--listen <addr>` it instead owns a plaintext TCP socket
//! and forks a child per connection (no TLS). Either way a connection may carry
//! several requests (HTTP keep-alive).
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
    timeout: u64,
    max_requests: u32,
    listen: Option<String>,
    verbose: bool,
    exposes: Vec<String>,
}

fn usage() -> ! {
    eprintln!(
        "tiny-webdav — read-only WebDAV over plaintext HTTP, run behind stunnel

USAGE:
  tiny-webdav [--root <dir>] [options]

OPTIONS:
  --root <dir>            Directory to serve (default: current directory)
  --listen <addr>         Listen on addr (e.g. 127.0.0.1:8080) and fork a
                          child per connection. No TLS. Default: serve one
                          connection from stdin (the inetd/stunnel contract).
  --run-as <user>         When started as root, chroot into --root and
                          drop to this user (default: nobody)
  --timeout <secs>        Per-read/write socket timeout, also bounding an
                          idle keep-alive connection (default: 30, 0 = none)
  --max-requests <n>      Max requests per persistent connection
                          (default: 100, 0 = unlimited)
  -v, --verbose           Log one line per request: method, path, status,
                          and any conditional/range headers (If-Modified-Since,
                          If-None-Match, If-Range, Range, Depth)
  --expose <glob>         Re-expose an otherwise-hidden name (repeatable).
                          Names beginning with . @ $ (dotfiles, @eaDir,
                          $RECYCLE.BIN, …) are hidden AND refused (404).
                          Globs use * and ?, matched per name: e.g.
                          --expose .mpdignore, or --expose '*' for all.
  --log-file <file>       Write diagnostics to this file. Default: stderr
                          (captured by stunnel/systemd). Use this under xinetd,
                          where stderr is the client socket.

  HTTP Basic auth (client certs are handled by stunnel, not here):
  --auth-file <file>      File of 'username:password' lines (# comments)
  --user <name>           A single username (use with --password)
  --password <pass>       Password for --user
  --realm <realm>         Basic-auth realm shown to clients (default: tiny-webdav)
"
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
    let mut timeout: u64 = 30;
    let mut max_requests: u32 = 100;
    let mut listen: Option<String> = None;
    let mut verbose = false;
    let mut exposes: Vec<String> = Vec::new();

    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        let mut val = || it.next().unwrap_or_else(|| usage());
        match arg.as_str() {
            "--root" => root = PathBuf::from(val()),
            "--listen" => listen = Some(val()),
            "-v" | "--verbose" => verbose = true,
            "--expose" => exposes.push(val()),
            "--auth-file" => auth_file = Some(PathBuf::from(val())),
            "--user" => user = Some(val()),
            "--password" => password = Some(val()),
            "--realm" => realm = val(),
            "--log-file" => log_file = Some(PathBuf::from(val())),
            "--run-as" => run_as = Some(val()),
            "--timeout" => timeout = val().parse().unwrap_or_else(|_| usage()),
            "--max-requests" => max_requests = val().parse().unwrap_or_else(|_| usage()),
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
        timeout,
        max_requests,
        listen,
        verbose,
        exposes,
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

/// Everything the serve loop needs, gathered once in `main` and passed by
/// reference so `serve_stdin`/`serve_listener` don't thread six individually
/// growing parameters (this bundle grew one field per feature added).
struct ServeConfig<'a> {
    root: &'a Path,
    auth: &'a Auth,
    timeout: u64,
    max_requests: u32,
    verbose: bool,
    exposes: &'a [String],
}

/// Serve the connection stunnel/inetd handed us. Per the inetd contract we read
/// requests from stdin (fd 0), write replies to stdout (fd 1), and log to stderr
/// (fd 2) — without assuming any of them is a socket. The connection is reused
/// for successive requests (HTTP keep-alive) until the client closes it, asks to
/// close, an error/timeout occurs, or `--max-requests` is reached.
#[cfg(unix)]
fn serve_stdin(cfg: &ServeConfig) {
    use std::io::BufReader;
    use std::os::unix::io::FromRawFd;

    // Safety: fd 0/1 are the inherited, owned connection descriptors; the File
    // wrappers close them on drop, at process exit.
    let input = unsafe { File::from_raw_fd(0) };
    let mut output = unsafe { File::from_raw_fd(1) };

    // Bound how long a single read/write — including the wait for the next
    // keep-alive request — may block. Best-effort: ignored on non-sockets.
    if cfg.timeout != 0 {
        set_socket_timeouts(cfg.timeout);
    }

    let served_root = dav::Served {
        root: cfg.root,
        exposes: cfg.exposes,
    };

    // BufReader gives us cheap byte-at-a-time header parsing (one syscall per
    // bufferful) and holds any bytes already read past one request for the next.
    let mut reader = BufReader::new(input);
    let mut served: u32 = 0;
    // EOF, a read timeout, or a malformed line ends the connection.
    while let Ok(req) = http::read_request(&mut reader) {
        served += 1;
        let keep = req.keep_alive() && (cfg.max_requests == 0 || served < cfg.max_requests);
        http::set_keep_alive(keep);

        let result =
            dav::handle(&mut output, &served_root, cfg.auth, &req).and_then(|()| output.flush());
        if cfg.verbose {
            log_request(&req, http::last_status());
        }
        if let Err(e) = result {
            eprintln!("connection error: {}", e);
            break;
        }
        if !keep {
            break;
        }
    }
}

#[cfg(not(unix))]
fn serve_stdin(_cfg: &ServeConfig) {
    eprintln!("error: tiny-webdav is only supported on Unix platforms");
    process::exit(1);
}

/// One-line request log for `--verbose`: method, path, response status, and any
/// conditional/range headers — the fields that reveal a "changes since <date>"
/// or cached-copy request (so a `304`/`206` shows the client was spared a
/// re-fetch, while a plain `200` for data it already holds stands out).
fn log_request(req: &http::Request, status: u16) {
    use std::fmt::Write as _;
    let mut line = format!("{} {} {} -> {}", req.method, req.path, req.version, status);
    for name in [
        "if-modified-since",
        "if-none-match",
        "if-range",
        "range",
        "depth",
    ] {
        if let Some(v) = req.header(name) {
            let _ = write!(line, " {}={:?}", name, v);
        }
    }
    eprintln!("{}", line);
}

/// Bind a listening TCP socket with `SO_REUSEADDR`, so a quick restart isn't
/// refused while a just-closed connection still lingers in `TIME_WAIT`. Rust's
/// `TcpListener::bind` doesn't set the option, and it must be set *before* bind,
/// so we build the socket by hand. `addr` is `host:port` (a literal IPv4/IPv6
/// address works too); only the first resolved address is tried.
#[cfg(unix)]
fn bind_listener(addr: &str) -> io::Result<std::net::TcpListener> {
    use std::net::{SocketAddr, ToSocketAddrs};
    use std::os::unix::io::FromRawFd;

    let resolved = addr
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "no address to bind"))?;

    // Lay the resolved address into a sockaddr_storage for bind().
    let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let (family, len) = match resolved {
        SocketAddr::V4(v4) => {
            let sin = unsafe { &mut *(&mut storage as *mut _ as *mut libc::sockaddr_in) };
            sin.sin_family = libc::AF_INET as libc::sa_family_t;
            sin.sin_port = v4.port().to_be();
            // octets() are already in network order; from_ne_bytes keeps that
            // byte layout in s_addr regardless of host endianness.
            sin.sin_addr = libc::in_addr {
                s_addr: u32::from_ne_bytes(v4.ip().octets()),
            };
            (libc::AF_INET, std::mem::size_of::<libc::sockaddr_in>())
        }
        SocketAddr::V6(v6) => {
            let sin6 = unsafe { &mut *(&mut storage as *mut _ as *mut libc::sockaddr_in6) };
            sin6.sin6_family = libc::AF_INET6 as libc::sa_family_t;
            sin6.sin6_port = v6.port().to_be();
            sin6.sin6_addr = libc::in6_addr {
                s6_addr: v6.ip().octets(),
            };
            sin6.sin6_scope_id = v6.scope_id();
            (libc::AF_INET6, std::mem::size_of::<libc::sockaddr_in6>())
        }
    };

    unsafe {
        let fd = libc::socket(family, libc::SOCK_STREAM, 0);
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // Own the fd immediately so it's closed on any early return below.
        let listener = std::net::TcpListener::from_raw_fd(fd);

        let one: libc::c_int = 1;
        let ok = libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_REUSEADDR,
            (&one as *const libc::c_int).cast(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        ) == 0
            && libc::bind(
                fd,
                (&storage as *const libc::sockaddr_storage).cast(),
                len as libc::socklen_t,
            ) == 0
            && libc::listen(fd, libc::SOMAXCONN) == 0;
        if !ok {
            return Err(io::Error::last_os_error());
        }
        Ok(listener)
    }
}

#[cfg(not(unix))]
fn bind_listener(addr: &str) -> io::Result<std::net::TcpListener> {
    std::net::TcpListener::bind(addr)
}

/// Standalone daemon mode (`--listen`): own the listening socket and fork a child
/// per connection — no TLS, for running directly rather than behind stunnel.
/// Privileges were already dropped once (before this loop), so each child inherits
/// the chroot and unprivileged uid for free; forking the running image is
/// copy-on-write, with no `exec`. The child moves the connection onto fd 0/1 and
/// runs the very same serve loop as the inetd path.
#[cfg(unix)]
fn serve_listener(listener: std::net::TcpListener, cfg: &ServeConfig) -> ! {
    use std::os::unix::io::{AsRawFd, IntoRawFd};

    // Reap children automatically: with SIGCHLD ignored the kernel discards each
    // child's exit status instead of leaving a zombie, so the accept loop needs
    // no wait() bookkeeping.
    unsafe { libc::signal(libc::SIGCHLD, libc::SIG_IGN) };

    let listen_fd = listener.as_raw_fd();
    loop {
        let stream = match listener.accept() {
            Ok((s, _addr)) => s,
            Err(e) => {
                // A signal (EINTR) is normal; log anything else and keep serving.
                if e.kind() != io::ErrorKind::Interrupted {
                    eprintln!("accept error: {}", e);
                }
                continue;
            }
        };

        match unsafe { libc::fork() } {
            -1 => {
                eprintln!("fork failed: {}", io::Error::last_os_error());
                // Parent: drop this connection (below) and keep accepting.
            }
            0 => {
                // Child: put the connection on fd 0 and fd 1 so the shared serve
                // loop (reads 0, writes 1) works unchanged, release the listening
                // socket, re-forbid forking for this process, then serve and exit.
                let conn_fd = stream.into_raw_fd();
                unsafe {
                    libc::dup2(conn_fd, 0);
                    libc::dup2(conn_fd, 1);
                    if conn_fd > 1 {
                        libc::close(conn_fd);
                    }
                    libc::close(listen_fd);
                }
                deny_rlimit(libc::RLIMIT_NPROC as _);
                serve_stdin(cfg);
                process::exit(0);
            }
            _ => { /* Parent: fall through to drop the connection. */ }
        }
        drop(stream); // Parent's copy of the connection; the child owns its own.
    }
}

#[cfg(not(unix))]
fn serve_listener(_listener: std::net::TcpListener, _cfg: &ServeConfig) -> ! {
    eprintln!("error: --listen is only supported on Unix platforms");
    process::exit(1);
}

/// Best-effort `SO_RCVTIMEO` / `SO_SNDTIMEO` on the connection descriptors, so a
/// slow or idle client can't pin the process forever. Any error (e.g. the fd
/// isn't a socket) is ignored.
#[cfg(unix)]
fn set_socket_timeouts(secs: u64) {
    let tv = libc::timeval {
        tv_sec: secs as _,
        tv_usec: 0,
    };
    let p = (&tv as *const libc::timeval).cast();
    let len = std::mem::size_of::<libc::timeval>() as libc::socklen_t;
    unsafe {
        libc::setsockopt(0, libc::SOL_SOCKET, libc::SO_RCVTIMEO, p, len);
        libc::setsockopt(1, libc::SOL_SOCKET, libc::SO_SNDTIMEO, p, len);
    }
}

fn main() {
    let args = parse_args();

    // Point our diagnostics (stderr) at --log-file, if given, before any output.
    // With no --log-file, stderr stays as stunnel gave it — the systemd journal
    // under a stunnel daemon. Under xinetd stderr is the client socket, so
    // --log-file is required there to keep diagnostics off the wire. We never
    // touch fd 0 (request) or fd 1 (reply).
    if let Some(path) = &args.log_file {
        // Fail fast on a bad log path rather than risk writing diagnostics to
        // the connection (the inherited stderr under xinetd).
        let f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .unwrap_or_else(|e| {
                fatal(&format!("cannot open --log-file {}: {}", path.display(), e))
            });
        unsafe {
            libc::dup2(f.as_raw_fd(), 2);
        }
    }

    let canonical_root = args.root.canonicalize().unwrap_or_else(|e| {
        fatal(&format!(
            "cannot access --root {}: {}",
            args.root.display(),
            e
        ))
    });
    if !canonical_root.is_dir() {
        fatal(&format!(
            "--root {} is not a directory",
            canonical_root.display()
        ));
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

    // In --listen mode, bind the socket *before* dropping privileges, so a
    // privileged port (< 1024) can still be claimed while we're root. The bound
    // socket survives the chroot untouched.
    let listener = args.listen.as_ref().map(|addr| {
        bind_listener(addr).unwrap_or_else(|e| fatal(&format!("cannot listen on {}: {}", addr, e)))
    });

    // Everything taken from the command line is now open: --log-file is dup'd onto
    // fd 2 and --auth-file holds an fd, both before the chroot (the served files
    // live inside the chroot and are opened after it). Now confine: if we're root,
    // chroot into the served directory and drop to `nobody`; the returned path is
    // what we serve from ("/" once chrooted). If we aren't root (e.g. stunnel
    // already dropped us), this is a no-op and we serve the canonical root as-is.
    // The listener forks a child per connection, so it keeps the ability to fork.
    let serve_root = lower_privileges(&canonical_root, args.run_as.as_deref(), listener.is_some());

    // Now unprivileged: parse the (already-open) auth file and inline credentials.
    let auth = build_auth(&args, auth_file)
        .unwrap_or_else(|e| fatal(&format!("cannot load credentials: {}", e)));

    // Warn when nothing authenticates the client. In --listen mode there's no TLS
    // and thus never a client certificate, so only Basic auth counts. Behind
    // stunnel we can't see the TLS, but stunnel exports SSL_CLIENT_DN once it has
    // verified a client cert — treat that as authentication so a cert-only
    // deployment isn't warned at.
    if !auth.is_enabled() {
        match &args.listen {
            Some(addr) => {
                eprintln!("WARNING: serving unauthenticated on {} — no Basic auth", addr)
            }
            None if !std::env::var("SSL_CLIENT_DN").is_ok_and(|v| !v.is_empty()) => eprintln!(
                "WARNING: serving unauthenticated — no client cert (SSL_CLIENT_DN) and no Basic auth"
            ),
            None => {}
        }
    }

    let cfg = ServeConfig {
        root: &serve_root,
        auth: &auth,
        timeout: args.timeout,
        max_requests: args.max_requests,
        verbose: args.verbose,
        exposes: &args.exposes,
    };
    match listener {
        Some(l) => serve_listener(l, &cfg),
        None => serve_stdin(&cfg),
    }
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
fn lower_privileges(root: &Path, run_as: Option<&str>, may_fork: bool) -> PathBuf {
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
    // its RLIMIT_NPROC can fail. Skipped for the --listen accept loop, which must
    // fork a child per connection; each child re-forbids forking for itself.
    if !may_fork {
        deny_rlimit(libc::RLIMIT_NPROC as _);
    }

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
fn lower_privileges(root: &Path, _run_as: Option<&str>, _may_fork: bool) -> PathBuf {
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
