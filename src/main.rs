//! tiny-webdav: a single-threaded, read-only WebDAV server over TLS that
//! requires clients to authenticate with a client certificate (mutual TLS).
//!
//! "Private key sign-in" is implemented as mutual TLS: each client holds a
//! private key + certificate signed by a CA we trust. The TLS handshake itself
//! proves the client possesses the private key, so there are no passwords.

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

struct Args {
    addr: String,
    root: PathBuf,
    cert: PathBuf,
    key: PathBuf,
    client_ca: PathBuf,
}

fn usage() -> ! {
    eprintln!(
        "tiny-webdav — read-only WebDAV over TLS with client-certificate auth\n\n\
         USAGE:\n  \
           tiny-webdav --cert <server.crt> --key <server.key> --client-ca <ca.crt> \\\n             \
                       [--root <dir>] [--addr <host:port>]\n\n\
         OPTIONS:\n  \
           --cert       PEM server certificate (chain) presented to clients\n  \
           --key        PEM server private key\n  \
           --client-ca  PEM CA certificate used to verify client certificates\n  \
           --root       Directory to serve (default: current directory)\n  \
           --addr       Listen address (default: 127.0.0.1:4443)\n"
    );
    process::exit(2);
}

fn parse_args() -> Args {
    let mut addr = "127.0.0.1:4443".to_string();
    let mut root = PathBuf::from(".");
    let mut cert: Option<PathBuf> = None;
    let mut key: Option<PathBuf> = None;
    let mut client_ca: Option<PathBuf> = None;

    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--addr" => addr = it.next().unwrap_or_else(|| usage()),
            "--root" => root = PathBuf::from(it.next().unwrap_or_else(|| usage())),
            "--cert" => cert = Some(PathBuf::from(it.next().unwrap_or_else(|| usage()))),
            "--key" => key = Some(PathBuf::from(it.next().unwrap_or_else(|| usage()))),
            "--client-ca" => client_ca = Some(PathBuf::from(it.next().unwrap_or_else(|| usage()))),
            "-h" | "--help" => usage(),
            other => {
                eprintln!("error: unexpected argument '{}'\n", other);
                usage();
            }
        }
    }

    match (cert, key, client_ca) {
        (Some(cert), Some(key), Some(client_ca)) => Args { addr, root, cert, key, client_ca },
        _ => {
            eprintln!("error: --cert, --key and --client-ca are all required\n");
            usage();
        }
    }
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

fn build_tls_config(args: &Args) -> io::Result<ServerConfig> {
    let server_certs = load_certs(&args.cert)?;
    let server_key = load_key(&args.key)?;

    // Trust anchors used to verify *client* certificates.
    let mut roots = RootCertStore::empty();
    for ca in load_certs(&args.client_ca)? {
        roots
            .add(ca)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
    }

    // Mandatory client-certificate verification: the handshake fails for any
    // client that doesn't present a certificate signed by our CA.
    let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

    ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(server_certs, server_key)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))
}

fn serve_connection(config: Arc<ServerConfig>, root: &Path, mut tcp: TcpStream) -> io::Result<()> {
    // Bound how long a single (single-threaded!) connection can stall us.
    tcp.set_read_timeout(Some(Duration::from_secs(30)))?;
    tcp.set_write_timeout(Some(Duration::from_secs(30)))?;

    let mut conn = ServerConnection::new(config)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

    {
        // rustls::Stream drives the TLS handshake transparently on first I/O.
        let mut tls = rustls::Stream::new(&mut conn, &mut tcp);
        let req = http::read_request(&mut tls)?;
        dav::handle(&mut tls, root, &req)?;
    }

    // Best-effort clean TLS shutdown.
    conn.send_close_notify();
    let _ = conn.complete_io(&mut tcp);
    Ok(())
}

fn main() {
    let args = parse_args();

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
        eprintln!("error: --root {} is not a directory", canonical_root.display());
        process::exit(1);
    }

    let config = match build_tls_config(&args) {
        Ok(c) => Arc::new(c),
        Err(e) => {
            eprintln!("error: TLS configuration failed: {}", e);
            process::exit(1);
        }
    };

    let listener = match TcpListener::bind(&args.addr) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("error: cannot bind {}: {}", args.addr, e);
            process::exit(1);
        }
    };

    println!("tiny-webdav listening on https://{}", args.addr);
    println!("serving (read-only): {}", canonical_root.display());
    println!("client-certificate authentication: REQUIRED");

    // Single-threaded: handle one connection fully, then move to the next.
    for incoming in listener.incoming() {
        match incoming {
            Ok(tcp) => {
                let peer = tcp
                    .peer_addr()
                    .map(|a| a.to_string())
                    .unwrap_or_else(|_| "?".to_string());
                if let Err(e) = serve_connection(config.clone(), &canonical_root, tcp) {
                    // A failed/rejected client handshake lands here too; log briefly.
                    eprintln!("[{}] connection error: {}", peer, e);
                }
            }
            Err(e) => eprintln!("accept error: {}", e),
        }
    }
}
