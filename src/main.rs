//! tiny-webdav: a single-threaded, read-only WebDAV server over TLS.
//!
//! Two optional, stackable authentication layers are available: client
//! certificates (mutual TLS — "private key sign-in", where the TLS handshake
//! proves the client holds a private key whose certificate we trust) and HTTP
//! Basic username/password. Either, both, or (with a startup warning) neither
//! can be required.

mod auth;
mod dav;
mod http;
mod util;

use std::fs::File;
use std::io::{self, BufReader};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process;
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig, ServerConnection};

use auth::Auth;

struct Args {
    addr: String,
    root: PathBuf,
    cert: Option<PathBuf>,
    key: Option<PathBuf>,
    self_signed: bool,
    hostnames: Vec<String>,
    write_cert: Option<PathBuf>,
    client_ca: Option<PathBuf>,
    client_cert_optional: bool,
    auth_file: Option<PathBuf>,
    user: Option<String>,
    password: Option<String>,
    realm: String,
    inetd: bool,
    log_file: Option<PathBuf>,
    timeout: u64,
}

fn usage() -> ! {
    eprintln!(
        "tiny-webdav — read-only WebDAV over TLS\n\n\
         USAGE:\n  \
           tiny-webdav (--cert <server.crt> --key <server.key> | --self-signed) \\\n             \
                       [--client-ca <ca.crt>] [--root <dir>] [--addr <host:port>]\n\n\
         OPTIONS:\n  \
           --root                  Directory to serve (default: current directory)\n  \
           --addr                  Listen address (default: 127.0.0.1:4443)\n  \
           --timeout <secs>        Per-read/write socket timeout (default: 30, 0 to\n                          \
                       disable; raise/disable for large transfers to slow links)\n\n  \
           Running under inetd/xinetd (one process per connection):\n  \
           --inetd                 Serve a single connection passed on stdin (fd 0),\n                          \
                       instead of binding/listening. Use the 'nowait' mode.\n  \
           --log-file <file>       In --inetd mode, send diagnostics here instead of\n                          \
                       /dev/null (stdout/stderr are the client socket).\n\n  \
           Server TLS identity (choose one):\n  \
           --cert <file>           PEM server certificate (chain) presented to clients\n  \
           --key <file>            PEM server private key (use with --cert)\n  \
           --self-signed           Generate an in-memory self-signed cert (testing)\n  \
           --hostname <name>       SAN for the self-signed cert; repeatable\n                          \
                       (default: localhost, 127.0.0.1, ::1)\n  \
           --write-cert <file>     Write the self-signed cert (PEM) here so clients\n                          \
                       can trust it (e.g. curl --cacert)\n\n  \
           Client-certificate auth (mTLS):\n  \
           --client-ca <ca.crt>    Verify client certs against this CA. Omit to\n                          \
                       disable client-cert auth entirely.\n  \
           --client-cert-optional  Accept clients without a cert; still verify any\n                          \
                       cert that *is* presented (requires --client-ca).\n\n  \
           HTTP Basic auth (layered on top of any client-cert auth):\n  \
           --auth-file <file>      File of 'username:password' lines (# comments)\n  \
           --user <name>           A single username (use with --password)\n  \
           --password <pass>       Password for --user\n  \
           --realm <realm>         Basic-auth realm shown to clients (default: tiny-webdav)\n"
    );
    process::exit(2);
}

fn parse_args() -> Args {
    let mut addr = "127.0.0.1:4443".to_string();
    let mut root = PathBuf::from(".");
    let mut cert: Option<PathBuf> = None;
    let mut key: Option<PathBuf> = None;
    let mut self_signed = false;
    let mut hostnames: Vec<String> = Vec::new();
    let mut write_cert: Option<PathBuf> = None;
    let mut client_ca: Option<PathBuf> = None;
    let mut client_cert_optional = false;
    let mut auth_file: Option<PathBuf> = None;
    let mut user: Option<String> = None;
    let mut password: Option<String> = None;
    let mut realm = "tiny-webdav".to_string();
    let mut inetd = false;
    let mut log_file: Option<PathBuf> = None;
    let mut timeout: u64 = 30;

    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--addr" => addr = it.next().unwrap_or_else(|| usage()),
            "--root" => root = PathBuf::from(it.next().unwrap_or_else(|| usage())),
            "--cert" => cert = Some(PathBuf::from(it.next().unwrap_or_else(|| usage()))),
            "--key" => key = Some(PathBuf::from(it.next().unwrap_or_else(|| usage()))),
            "--self-signed" => self_signed = true,
            "--hostname" => hostnames.push(it.next().unwrap_or_else(|| usage())),
            "--write-cert" => {
                write_cert = Some(PathBuf::from(it.next().unwrap_or_else(|| usage())))
            }
            "--client-ca" => client_ca = Some(PathBuf::from(it.next().unwrap_or_else(|| usage()))),
            "--client-cert-optional" => client_cert_optional = true,
            "--auth-file" => auth_file = Some(PathBuf::from(it.next().unwrap_or_else(|| usage()))),
            "--user" => user = Some(it.next().unwrap_or_else(|| usage())),
            "--password" => password = Some(it.next().unwrap_or_else(|| usage())),
            "--realm" => realm = it.next().unwrap_or_else(|| usage()),
            "--inetd" => inetd = true,
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

    if client_cert_optional && client_ca.is_none() {
        eprintln!("error: --client-cert-optional requires --client-ca\n");
        usage();
    }

    // A self-signed cert is regenerated per process; under inetd that's a new
    // server identity for every connection. Refuse the combination.
    if self_signed && inetd {
        eprintln!("error: --self-signed cannot be combined with --inetd (use real --cert/--key)\n");
        usage();
    }

    // Validate the server TLS identity: exactly one of (--cert + --key) or
    // --self-signed. The two are mutually exclusive.
    if self_signed {
        if cert.is_some() || key.is_some() {
            eprintln!("error: --self-signed cannot be combined with --cert/--key\n");
            usage();
        }
    } else {
        if !hostnames.is_empty() || write_cert.is_some() {
            eprintln!("error: --hostname/--write-cert only apply with --self-signed\n");
            usage();
        }
        if cert.is_none() || key.is_none() {
            eprintln!("error: provide --cert and --key, or use --self-signed\n");
            usage();
        }
    }

    Args {
        addr,
        root,
        cert,
        key,
        self_signed,
        hostnames,
        write_cert,
        client_ca,
        client_cert_optional,
        auth_file,
        user,
        password,
        realm,
        inetd,
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

fn load_certs(path: &Path) -> io::Result<Vec<CertificateDer<'static>>> {
    let mut reader = BufReader::new(File::open(path)?);
    let certs: Vec<_> = rustls_pemfile::certs(&mut reader).collect::<Result<_, _>>()?;
    if certs.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("no certificates found in {}", path.display()),
        ));
    }
    Ok(certs)
}

fn load_key(path: &Path) -> io::Result<PrivateKeyDer<'static>> {
    let mut reader = BufReader::new(File::open(path)?);
    rustls_pemfile::private_key(&mut reader)?.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("no private key found in {}", path.display()),
        )
    })
}

/// Produce the server's certificate chain and private key, either by loading
/// the supplied PEM files or by generating a fresh self-signed certificate.
fn server_identity(
    args: &Args,
) -> io::Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    if args.self_signed {
        // Default SANs cover the common local-testing names.
        let sans = if args.hostnames.is_empty() {
            vec![
                "localhost".to_string(),
                "127.0.0.1".to_string(),
                "::1".to_string(),
            ]
        } else {
            args.hostnames.clone()
        };
        let generated = rcgen::generate_simple_self_signed(sans.clone())
            .map_err(|e| io::Error::other(e.to_string()))?;

        if let Some(path) = &args.write_cert {
            std::fs::write(path, generated.cert.pem())?;
            eprintln!("wrote self-signed certificate to {}", path.display());
        }

        eprintln!(
            "using a generated self-signed certificate (SANs: {})",
            sans.join(", ")
        );
        let cert_der = generated.cert.der().clone();
        let key_der = PrivateKeyDer::try_from(generated.key_pair.serialize_der())
            .map_err(|e| io::Error::other(e.to_string()))?;
        Ok((vec![cert_der], key_der))
    } else {
        // Validated in parse_args: both are present here.
        let certs = load_certs(args.cert.as_ref().unwrap())?;
        let key = load_key(args.key.as_ref().unwrap())?;
        Ok((certs, key))
    }
}

fn build_tls_config(args: &Args) -> io::Result<ServerConfig> {
    let (server_certs, server_key) = server_identity(args)?;

    let to_invalid = |e: rustls::Error| io::Error::new(io::ErrorKind::InvalidData, e.to_string());

    let builder = ServerConfig::builder();
    let with_certs = match &args.client_ca {
        // No client CA configured: don't request client certificates at all.
        None => builder.with_no_client_auth(),
        Some(ca_path) => {
            // Trust anchors used to verify *client* certificates.
            let mut roots = RootCertStore::empty();
            for ca in load_certs(ca_path)? {
                roots.add(ca).map_err(to_invalid)?;
            }
            let vb = WebPkiClientVerifier::builder(Arc::new(roots));
            // `--client-cert-optional` lets clients connect without a cert,
            // while still verifying any cert that *is* presented. Otherwise a
            // valid client certificate is mandatory.
            let verifier = if args.client_cert_optional {
                vb.allow_unauthenticated().build()
            } else {
                vb.build()
            }
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
            builder.with_client_cert_verifier(verifier)
        }
    };

    with_certs
        .with_single_cert(server_certs, server_key)
        .map_err(to_invalid)
}

fn serve_connection(
    config: Arc<ServerConfig>,
    root: &Path,
    auth: &Auth,
    timeout: u64,
    mut tcp: TcpStream,
) -> io::Result<()> {
    // Bound how long a single (single-threaded!) blocking I/O can stall us.
    // `--timeout 0` disables it (needed for large transfers to slow links,
    // since this is a per-operation timeout, not an idle timeout).
    let to = (timeout != 0).then(|| Duration::from_secs(timeout));
    tcp.set_read_timeout(to)?;
    tcp.set_write_timeout(to)?;

    let mut conn = ServerConnection::new(config).map_err(|e| io::Error::other(e.to_string()))?;

    {
        // rustls::Stream drives the TLS handshake transparently on first I/O.
        let mut tls = rustls::Stream::new(&mut conn, &mut tcp);
        let req = http::read_request(&mut tls)?;
        dav::handle(&mut tls, root, auth, &req)?;
    }

    // Best-effort clean TLS shutdown.
    conn.send_close_notify();
    let _ = conn.complete_io(&mut tcp);
    Ok(())
}

/// Serve the single connection inetd handed us on stdin (fd 0), then return.
#[cfg(unix)]
fn serve_inetd(config: Arc<ServerConfig>, root: &Path, auth: &Auth, timeout: u64) {
    use std::os::unix::io::FromRawFd;

    // Safety: under inetd, fd 0 is the connected, owned TCP socket. We take
    // ownership of it; it is closed when the resulting TcpStream is dropped.
    let sock = unsafe { TcpStream::from_raw_fd(0) };
    let peer = sock
        .peer_addr()
        .map(|a| a.to_string())
        .unwrap_or_else(|_| "?".to_string());
    if let Err(e) = serve_connection(config, root, auth, timeout, sock) {
        eprintln!("[{}] connection error: {}", peer, e);
    }
}

#[cfg(not(unix))]
fn serve_inetd(_config: Arc<ServerConfig>, _root: &Path, _auth: &Auth, _timeout: u64) {
    eprintln!("error: --inetd is only supported on Unix platforms");
    process::exit(1);
}

/// In inetd mode the client socket is duplicated onto stdout and stderr, so
/// point fd 1 (and fd 2) somewhere harmless before we emit anything. fd 1
/// always goes to /dev/null; fd 2 goes to `--log-file` if given, else
/// /dev/null. fd 0 (the socket we actually serve) is left untouched.
#[cfg(unix)]
fn protect_inetd_streams(log_file: Option<&Path>) {
    use std::fs::OpenOptions;
    use std::os::unix::io::AsRawFd;

    // /dev/null must open: if it doesn't, fd 1 would stay pointed at the client
    // socket and any later output would corrupt the TLS stream. Fail closed —
    // and silently, since stderr may itself still be the socket.
    let devnull = match OpenOptions::new().write(true).open("/dev/null") {
        Ok(f) => f,
        Err(_) => process::exit(1),
    };
    unsafe { libc::dup2(devnull.as_raw_fd(), 1) };

    // stderr: a log file if requested and openable, otherwise /dev/null.
    let log = log_file.and_then(|p| OpenOptions::new().create(true).append(true).open(p).ok());
    let stderr_fd = log
        .as_ref()
        .map(|f| f.as_raw_fd())
        .unwrap_or(devnull.as_raw_fd());
    unsafe { libc::dup2(stderr_fd, 2) };
    // `devnull`/`log` File handles drop here, closing their original fds;
    // the dup2'd descriptors 1 and 2 remain valid.
}

#[cfg(not(unix))]
fn protect_inetd_streams(_log_file: Option<&Path>) {}

fn main() {
    let args = parse_args();

    // In inetd mode stdin/stdout/stderr are the client socket. Redirect
    // stdout and stderr away *first* so no diagnostic ever leaks onto the
    // wire and corrupts the TLS stream. Done before any other output.
    if args.inetd {
        protect_inetd_streams(args.log_file.as_deref());
    }

    // Install the `ring` crypto provider as the process default.
    if rustls::crypto::ring::default_provider()
        .install_default()
        .is_err()
    {
        eprintln!("warning: a default crypto provider was already installed");
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

    let config = match build_tls_config(&args) {
        Ok(c) => Arc::new(c),
        Err(e) => {
            eprintln!("error: TLS configuration failed: {}", e);
            process::exit(1);
        }
    };

    let auth = match build_auth(&args) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("error: cannot load credentials: {}", e);
            process::exit(1);
        }
    };

    let cert_required = args.client_ca.is_some() && !args.client_cert_optional;

    // Warn (in BOTH modes, on stderr so it reaches an inetd --log-file) when the
    // server requires no authentication at all.
    if !cert_required && !auth.is_enabled() {
        eprintln!(
            "WARNING: no client-cert requirement and no password — \
             anyone who can reach this server can read the served files."
        );
    }

    // inetd mode: there is no listener. inetd has already accepted the
    // connection and handed us the socket on stdin. Confine the process, serve
    // that one connection, and exit so inetd can fork the next one.
    if args.inetd {
        let serve_root = lower_privileges(&canonical_root);
        serve_inetd(config, &serve_root, &auth, args.timeout);
        return;
    }

    let listener = match TcpListener::bind(&args.addr) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("error: cannot bind {}: {}", args.addr, e);
            process::exit(1);
        }
    };

    let cert_mode = match (&args.client_ca, args.client_cert_optional) {
        (None, _) => "disabled",
        (Some(_), false) => "REQUIRED",
        (Some(_), true) => "optional",
    };

    println!("tiny-webdav listening on https://{}", args.addr);
    println!("serving (read-only): {}", canonical_root.display());
    println!("client-certificate authentication: {}", cert_mode);
    if auth.is_enabled() {
        println!(
            "HTTP Basic authentication: REQUIRED ({} user(s), realm \"{}\")",
            auth.user_count(),
            args.realm
        );
    } else {
        println!("HTTP Basic authentication: disabled");
    }

    // Everything that needs the filesystem or privileged ports is done (certs
    // and credentials are in memory, the socket is bound). Now confine the
    // process: chroot into the served directory and drop to an unprivileged
    // user. If we lack the privileges, this just warns and carries on. The
    // returned path is the root to serve from afterwards (`/` once chrooted).
    let serve_root = lower_privileges(&canonical_root);

    // Single-threaded: handle one connection fully, then move to the next.
    for incoming in listener.incoming() {
        match incoming {
            Ok(tcp) => {
                let peer = tcp
                    .peer_addr()
                    .map(|a| a.to_string())
                    .unwrap_or_else(|_| "?".to_string());
                if let Err(e) =
                    serve_connection(config.clone(), &serve_root, &auth, args.timeout, tcp)
                {
                    // A failed/rejected client handshake lands here too; log briefly.
                    eprintln!("[{}] connection error: {}", peer, e);
                }
            }
            Err(e) => eprintln!("accept error: {}", e),
        }
    }
}

/// Confine the process after startup: `chroot` into `root`, then drop to the
/// unprivileged `nobody` account. Returns the path to serve from afterwards —
/// `/` when the chroot succeeds (the served directory becomes the new root),
/// otherwise `root` unchanged. Any lack of privilege is reported on stderr and
/// is non-fatal.
#[cfg(unix)]
fn lower_privileges(root: &Path) -> PathBuf {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    // If we're not effectively root we can't chroot or change uid; say so once
    // and carry on with current privileges.
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
