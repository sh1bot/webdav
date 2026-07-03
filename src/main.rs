//! tiny-webdav: a small read-only WebDAV server. By default it follows the inetd
//! contract — a connection arrives on stdin (fd 0), typically from stunnel, which
//! terminates TLS. With `--listen <path>` it instead owns a Unix-domain socket it
//! creates itself and forks a child per connection (no TLS — front it with
//! stunnel, cloudflared, or a reverse proxy). Either way a connection may carry
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
    auth: Vec<String>,
    log_file: Option<PathBuf>,
    run_as: Option<String>,
    timeout: u64,
    max_requests: u32,
    listen: Option<String>,
    socket_mode: u32,
    socket_owner: Option<String>,
    max_connections: u32,
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
  --listen <path>         Create a Unix-domain socket at <path> and fork a
                          child per connection (no TLS; front it with
                          cloudflared/stunnel/a proxy). Default: serve one
                          connection from stdin (the inetd/stunnel contract).
  --socket-mode <octal>   Permission bits for the --listen socket, e.g. 660
                          (owner+group) or 600 (owner only) (default: 660)
  --socket-owner <user>   Give the --listen socket to this user (chown, root
                          only) so a front-end that isn't in our group (e.g.
                          cloudflared) can connect. Default: our own identity
  --max-connections <n>   With --listen, cap concurrent connections; excess
                          wait in the backlog (default: 64, 0 = unlimited)
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
  --auth <user:pass>      An inline credential (repeatable; password may
                          contain ':')
"
    );
    process::exit(2);
}

fn parse_args() -> Args {
    let mut a = Args {
        root: PathBuf::from("."),
        auth_file: None,
        auth: Vec::new(),
        log_file: None,
        run_as: None,
        timeout: 30,
        max_requests: 100,
        listen: None,
        socket_mode: 0o660,
        socket_owner: None,
        max_connections: 64,
        verbose: false,
        exposes: Vec::new(),
    };

    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        let mut val = || it.next().unwrap_or_else(|| usage());
        match arg.as_str() {
            "--root" => a.root = PathBuf::from(val()),
            "--listen" => a.listen = Some(val()),
            "--socket-mode" => {
                a.socket_mode = u32::from_str_radix(val().trim_start_matches("0o"), 8)
                    .unwrap_or_else(|_| usage())
            }
            "--socket-owner" => a.socket_owner = Some(val()),
            "--max-connections" => a.max_connections = val().parse().unwrap_or_else(|_| usage()),
            "-v" | "--verbose" => a.verbose = true,
            "--expose" => a.exposes.push(val()),
            "--auth-file" => a.auth_file = Some(PathBuf::from(val())),
            "--auth" => a.auth.push(val()),
            "--log-file" => a.log_file = Some(PathBuf::from(val())),
            "--run-as" => a.run_as = Some(val()),
            "--timeout" => a.timeout = val().parse().unwrap_or_else(|_| usage()),
            "--max-requests" => a.max_requests = val().parse().unwrap_or_else(|_| usage()),
            "-h" | "--help" => usage(),
            other => {
                eprintln!("error: unexpected argument '{}'\n", other);
                usage();
            }
        }
    }
    a
}

/// Parse credentials. `auth_file` is the *already-open* `--auth-file` (opened
/// before the chroot/privilege drop); parsing it happens here, after the drop, so
/// the bug-prone work runs unprivileged. The path string is only for error text.
fn build_auth(args: &Args, auth_file: Option<File>) -> io::Result<Auth> {
    let mut auth = Auth::new();
    // Both come from `args.auth_file`, so they're Some together; the path is
    // only for error labels.
    if let (Some(file), Some(path)) = (auth_file, &args.auth_file) {
        auth.load(file, &path.display().to_string())?;
    }
    for pair in &args.auth {
        auth.add_pair(pair).map_err(|msg| {
            io::Error::new(io::ErrorKind::InvalidData, format!("--auth: {}", msg))
        })?;
    }
    Ok(auth)
}

/// Everything the serve loop needs, bundled so `serve_stdin`/`serve_listener`
/// take one reference instead of a long parameter list.
struct ServeConfig<'a> {
    root: &'a Path,
    auth: &'a Auth,
    timeout: u64,
    max_requests: u32,
    max_connections: u32,
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

    // Validate the served root here — deliberately after `lower_privileges` has
    // chrooted and dropped to the unprivileged user. Two ordering constraints
    // ride on this: the chroot fixes what `cfg.root` (`/`) resolves to, and the
    // readability check (`access(2)`, real-uid) must reflect the dropped user —
    // as root it would pass via DAC override and mislead a later GET. So this
    // must not be hoisted ahead of the privilege drop.
    let Some(served_root) = dav::Served::new(cfg.root, cfg.exposes) else {
        eprintln!("cannot serve: --root is not a readable directory");
        return;
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
/// conditional/range headers — enough to see whether a cached-copy or "changes
/// since <date>" request was spared a re-fetch (304/206) or not (200).
fn log_request(req: &http::Request, status: u16) {
    use std::fmt::Write as _;
    // Quote the client-supplied tokens ({:?}) so a crafted method/path/version
    // can't inject control bytes (e.g. ESC/CR) into the log stream.
    let mut line = format!(
        "{:?} {:?} {:?} -> {}",
        req.method, req.path, req.version, status
    );
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

/// Create the Unix-domain socket at `path`, `listen()` on it, and return the
/// listener. A stale socket left by a previous run is removed first; a *non*-socket
/// at the path is refused rather than clobbered. The socket is created with
/// permission `mode` by constraining the umask across `bind()`, so there is no
/// window where it exists more permissively than intended. If `owner` is given
/// (only possible as root, before the privilege drop) the socket's *owner* is
/// set to that uid so an unrelated front-end user (e.g. cloudflared) can connect
/// via the owner permission bits; the group is deliberately left unchanged
/// (`root`, since we bound as root). Handing the front-end the *owner* is all it
/// needs — the group grant in the default `660` mode then only reaches `root`,
/// rather than re-exposing the socket to whatever group the front-end user
/// happens to belong to. The pre-chown window is `root`-owned, so re-resolving
/// the path here exposes nothing an unprivileged process could reach.
#[cfg(unix)]
fn bind_listener(
    path: &str,
    mode: u32,
    owner: Option<libc::uid_t>,
) -> io::Result<std::os::unix::net::UnixListener> {
    use std::os::unix::fs::FileTypeExt;
    use std::os::unix::net::UnixListener;

    // Clear a stale socket from a previous run (bind() fails with EADDRINUSE if
    // the path exists). Only remove an actual socket — never a regular file,
    // directory, or symlink sitting at that path.
    match std::fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_socket() => std::fs::remove_file(path)?,
        Ok(_) => fatal(&format!(
            "--listen {}: path exists and is not a socket; refusing to remove it",
            path
        )),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }

    // `bind()` creates the socket with `0o777 & ~umask`; pin the umask so the
    // result is exactly `mode` (no bind-then-chmod race).
    let mode = mode & 0o777;
    let prev = unsafe { libc::umask(0o777 & !mode) };
    let listener = UnixListener::bind(path);
    unsafe { libc::umask(prev) };
    let listener = listener?;

    if let Some(uid) = owner {
        // Must chown the *pathname*, not the fd: fchown on a bound Unix-socket fd
        // targets its anonymous sockfs inode and silently no-ops the directory
        // entry (returns 0, leaves it root-owned). The pre-chown window is
        // root-owned, so re-resolving the path here exposes nothing unprivileged.
        // Pass gid -1 to leave the group unchanged (see the doc comment): only the
        // owner is handed over.
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        let c_path = CString::new(std::path::Path::new(path).as_os_str().as_bytes())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "socket path contains NUL"))?;
        let keep_gid = -1i32 as libc::gid_t; // POSIX: -1 means "don't change the group"
        if unsafe { libc::chown(c_path.as_ptr(), uid, keep_gid) } != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(listener)
}

/// Standalone daemon mode (`--listen <path>`): own a Unix-domain listening socket
/// and fork a child per connection — no TLS, for running directly (e.g. behind
/// cloudflared) rather than behind stunnel. Privileges were already dropped once
/// (before this loop), so each child inherits the chroot and unprivileged uid for
/// free; forking the running image is copy-on-write, with no `exec`. The child
/// puts its connection on fd 0/1 and *returns*, falling through to the same
/// `serve_stdin` loop the inetd path runs; the parent loops here forever.
#[cfg(unix)]
fn serve_listener(listener: std::os::unix::net::UnixListener, cfg: &ServeConfig) {
    use std::os::unix::io::IntoRawFd;

    // We reap children ourselves (no `SIGCHLD` = `SIG_IGN`) so we can count how
    // many are in flight and cap concurrency: otherwise a connection flood forks
    // children without bound and exhausts PIDs/memory. Exited children stay
    // reapable (as zombies) until `reap_dead` collects them each loop.
    let mut live: u32 = 0; // connections currently being served by a child
    loop {
        live = live.saturating_sub(reap_dead());

        // Enforce --max-connections: if every slot is taken, block until a child
        // exits before accepting more (excess connections queue in the kernel
        // backlog, then are refused by the OS). A cap of 0 disables the limit.
        while cfg.max_connections != 0 && live >= cfg.max_connections {
            if unsafe { libc::waitpid(-1, std::ptr::null_mut(), 0) } > 0 {
                live -= 1;
            } else {
                live = 0; // no child left to wait on: our count was stale
            }
        }

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
                // loop (reads 0, writes 1) works unchanged, re-forbid forking, then
                // return — falling through to serve_stdin in `main`. Returning drops
                // our copy of the listening socket, closing it; the parent keeps its
                // own copy open.
                let conn_fd = stream.into_raw_fd();
                unsafe {
                    libc::dup2(conn_fd, 0);
                    libc::dup2(conn_fd, 1);
                    if conn_fd > 1 {
                        libc::close(conn_fd);
                    }
                }
                deny_rlimit(libc::RLIMIT_NPROC as _);
                return;
            }
            _ => live += 1, // Parent: one more child in flight.
        }
        drop(stream); // Parent's copy of the connection; the child owns its own.
    }
}

/// Reap all children that have already exited (non-blocking), returning the
/// count so the accept loop can free their concurrency slots.
#[cfg(unix)]
fn reap_dead() -> u32 {
    let mut n = 0;
    while unsafe { libc::waitpid(-1, std::ptr::null_mut(), libc::WNOHANG) } > 0 {
        n += 1;
    }
    n
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
    let auth_file = args.auth_file.as_ref().map(|path| {
        File::open(path).unwrap_or_else(|e| {
            fatal(&format!(
                "cannot open --auth-file {}: {}",
                path.display(),
                e
            ))
        })
    });

    // In --listen mode, create the socket *before* dropping privileges, so the
    // socket file can be placed in a directory only root can write (e.g. /run)
    // while we're still root. The bound socket survives the chroot untouched.
    #[cfg(unix)]
    let listener = args.listen.as_ref().map(|path| {
        // Resolve --socket-owner while /etc/passwd is still reachable (before the
        // chroot) and we're still root (the only case chown can succeed). Only the
        // uid is used — the group is left as root (see bind_listener).
        let owner = args.socket_owner.as_deref().map(|u| lookup_user(u).0);
        bind_listener(path, args.socket_mode, owner)
            .unwrap_or_else(|e| fatal(&format!("cannot listen on {}: {}", path, e)))
    });

    // Everything taken from the command line is now open: --log-file is dup'd onto
    // fd 2 and --auth-file holds an fd, both before the chroot (the served files
    // live inside the chroot and are opened after it). Now confine: if we're root,
    // chroot into the served directory and drop to `nobody`; the returned path is
    // what we serve from ("/" once chrooted). If we aren't root (e.g. stunnel
    // already dropped us), this is a no-op and we serve the canonical root as-is.
    // The listener forks a child per connection, so it keeps the ability to fork.
    let serve_root = lower_privileges(
        &canonical_root,
        args.run_as.as_deref(),
        args.listen.is_some(),
    );

    // Now unprivileged: parse the (already-open) auth file and inline credentials.
    let auth = build_auth(&args, auth_file)
        .unwrap_or_else(|e| fatal(&format!("cannot load credentials: {}", e)));

    // Warn when nothing authenticates the client. In --listen mode there's no TLS
    // and thus never a client certificate, so only Basic auth counts. Behind
    // stunnel we can't see the TLS, but stunnel exports SSL_CLIENT_DN once it has
    // verified a client cert — treat that as authentication so a cert-only
    // deployment isn't warned at.
    if !auth.is_enabled() {
        if let Some(addr) = &args.listen {
            eprintln!(
                "WARNING: serving unauthenticated on {} — no Basic auth",
                addr
            );
        } else if std::env::var("SSL_CLIENT_DN")
            .unwrap_or_default()
            .is_empty()
        {
            eprintln!(
                "WARNING: serving unauthenticated — no client cert (SSL_CLIENT_DN) and no Basic auth"
            );
        }
    }

    let cfg = ServeConfig {
        root: &serve_root,
        auth: &auth,
        timeout: args.timeout,
        max_requests: args.max_requests,
        max_connections: args.max_connections,
        verbose: args.verbose,
        exposes: &args.exposes,
    };
    // With a listener, the parent loops forever in serve_listener, accepting and
    // forking; each child returns from it (its connection now on fd 0/1) and falls
    // through to serve_stdin below — the same loop the inetd path runs. With no
    // listener we drop straight into serve_stdin on the inherited stdin/stdout.
    #[cfg(unix)]
    if let Some(l) = listener {
        serve_listener(l, &cfg);
    }
    serve_stdin(&cfg);
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
    // uids. We must never end up with any of them as root — checked in *every*
    // case, so an explicit `--run-as root` (or a target account misconfigured to
    // uid 0) can't slip through the target-match branch below.
    let (mut ruid, mut euid_now, mut suid) = (0, 0, 0);
    unsafe { libc::getresuid(&mut ruid, &mut euid_now, &mut suid) };
    if ruid == 0 || euid_now == 0 || suid == 0 {
        fatal("refusing to serve as root; run unprivileged or pass --run-as <non-root user>");
    }
    // With --run-as, also confirm all three uids are actually that user now —
    // this catches the case where we couldn't change uid (not root) and weren't
    // already running as it.
    if let Some(name) = run_as {
        let (uid, _gid) = creds.unwrap();
        if (ruid, euid_now, suid) != (uid, uid, uid) {
            fatal(&format!(
                "--run-as {:?}: not that user (uids r={} e={} s={}, want {})",
                name, ruid, euid_now, suid, uid
            ));
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
