# tiny-webdav

A very small, **read-only** WebDAV server written in Rust. It speaks **plaintext
HTTP** and is meant to run behind **[stunnel](https://www.stunnel.org/)**, which
terminates TLS (and verifies client certificates) and hands each decrypted
connection to a fresh tiny-webdav process on stdin — the classic inetd contract.
That keeps all the crypto in a mature, dedicated tool and keeps this program
tiny (its only dependency is `libc`).

```
client --TLS--> stunnel (terminates TLS, verifies client cert) --plaintext--> tiny-webdav
```

Access control splits across the two layers, and you can use either or both:

1. **Client certificate ("private key sign-in" / mutual TLS)** — enforced by
   **stunnel** (`CAfile` + `verify`). tiny-webdav never sees the TLS itself, but
   stunnel passes it the verified client identity in the `SSL_CLIENT_DN`
   environment variable. Required/optional/disabled is set in stunnel's config.
2. **HTTP Basic username/password** — enforced by **tiny-webdav**, layered on top
   (safe because stunnel has already encrypted the connection).

tiny-webdav can't inspect the TLS handshake, so it judges "is this request
authenticated?" from what it *can* see: the `SSL_CLIENT_DN` env var (a verified
client cert from stunnel) and its own Basic credentials. It logs a warning only
for a request that has **neither** — i.e. genuinely anonymous access. A
cert-only deployment (stunnel `verify = 2`, no Basic auth) is *not* warned about,
because `SSL_CLIENT_DN` is present.

## Features

- Serves a directory read-only over HTTP (TLS supplied by stunnel).
- Supports the WebDAV verbs needed for browsing/reading:
  - `OPTIONS` (advertises `DAV: 1`)
  - `GET` / `HEAD` (files; directories return an HTML index listing each
    entry's name, last-modified time in UTC, and size)
  - `PROPFIND` (`Depth: 0` and `Depth: 1`) returning `207 Multi-Status`
    (a `Depth: infinity` request gets `403` with `DAV:propfind-finite-depth`
    so clients fall back to walking the tree one level at a time)
- Conditional requests: every file response carries an `ETag` and
  `Last-Modified`, and `If-None-Match` / `If-Modified-Since` are honoured with
  `304 Not Modified` so clients can revalidate cheaply.
- HTTP `Range` requests (single `bytes=` ranges) for partial/resumable
  downloads: responds `206 Partial Content` with `Content-Range`, `416` for
  unsatisfiable ranges, and advertises `Accept-Ranges: bytes`. `If-Range` is
  honoured, so a resumed download whose file changed restarts cleanly instead
  of splicing two versions.
- File bodies are sent with the kernel's `sendfile(2)` (offset/length for
  ranges), so bytes go straight from the page cache to the socket without passing
  through userspace — even multi-gigabyte files use near-constant memory.
- Every mutating method (`PUT`, `DELETE`, `MKCOL`, `MOVE`, `COPY`,
  `PROPPATCH`, `LOCK`, …) is rejected with `405 Method Not Allowed`.
- Optional HTTP Basic username/password auth (`401` challenge with
  `WWW-Authenticate` when missing/invalid).
- Rejects path traversal (`..`) and symlink escapes, so only files under
  `--root` are reachable. Confinement (`chroot`) and dropping privileges are
  delegated to stunnel, so the binary itself contains no privileged code.
- Tiny dependency footprint: just `libc`. No TLS stack, no async runtime, no
  HTTP framework.

## Build

The build defaults to a **fully static** binary (musl libc, statically linked) —
a single self-contained executable with no shared-library dependencies, which is
convenient to drop onto a server and run under stunnel/xinetd. Add the target
once, then build:

```sh
rustup target add x86_64-unknown-linux-musl   # one-time
cargo build --release
# -> target/x86_64-unknown-linux-musl/release/tiny-webdav
```

```sh
file target/x86_64-unknown-linux-musl/release/tiny-webdav
# ELF 64-bit ... static-pie linked
```

The default target is set in [`.cargo/config.toml`](.cargo/config.toml). For a
dynamically linked glibc build instead, override it:

```sh
cargo build --release --target x86_64-unknown-linux-gnu
```

## Generate test certificates

stunnel needs a server certificate/key and (for client-cert auth) a CA to verify
clients against; clients need a certificate signed by that CA. The helper script
creates a throwaway CA plus a server and a client certificate:

```sh
./gen-certs.sh certs localhost
```

This writes `ca.crt`, `server.crt`/`server.key` and `client.crt`/`client.key`
into `certs/`.

## Deploy behind stunnel

See [`stunnel.conf.example`](stunnel.conf.example) for an annotated config. The
essentials:

```ini
[tiny-webdav]
accept   = 8443
cert     = /etc/tiny-webdav/server.crt
key      = /etc/tiny-webdav/server.key
CAfile   = /etc/tiny-webdav/ca.crt      ; client-cert auth (mutual TLS)...
verify   = 2                            ; ...require a valid client cert
exec     = /usr/local/bin/tiny-webdav
execargs = tiny-webdav --root /srv/files --auth-file /etc/tiny-webdav/users.txt --log-file /var/log/tiny-webdav.log
```

Then run `stunnel /etc/stunnel/tiny-webdav.conf`. stunnel listens on the port,
terminates TLS, verifies the client certificate, and forks one tiny-webdav
process per connection with the plaintext stream on fd 0.

- To disable client-cert auth, drop the `CAfile`/`verify` lines and rely on
  tiny-webdav's HTTP Basic auth (and/or the network).
- **Confinement** (`chroot` + dropping privileges) is stunnel's job too — see
  the next section.
- **Logging:** by default tiny-webdav writes diagnostics to stderr, which stunnel
  passes through to *its* stderr — i.e. the systemd journal (`journalctl -u
  stunnel`) when stunnel runs as a service. No `--log-file` needed here. (Under
  xinetd, stderr is the client socket, so there you must pass `--log-file`; see
  below.)

### Confinement (chroot + drop privileges)

tiny-webdav does **not** chroot or change uid itself. Instead, stunnel's `chroot`
/ `setuid` / `setgid` options jail the process and drop privileges *before* it
execs tiny-webdav, so the server runs already-confined and unprivileged. Because
the binary is **static** and reads/writes only the standard descriptors and the
served files, the jail needs nothing but the binary and the served tree:

```
/srv/jail/
├── tiny-webdav            # the static binary (exec target, inside the jail)
└── files/                 # the served tree (--root /files)
    └── ...
```

Add to the stunnel config (global section), and run stunnel as root so it can
chroot and drop:

```ini
chroot = /srv/jail
setuid = nobody
setgid = nogroup
; cert/key/CAfile are read before the chroot, so they can live outside the jail:
cert   = /etc/tiny-webdav/server.crt
key    = /etc/tiny-webdav/server.key
exec     = /tiny-webdav                 ; path *inside* the jail
execargs = tiny-webdav --root /files
```

Notes:

- The exec path and `--root` are resolved **inside** the jail.
- `--auth-file` / `--log-file`, if used, must also live inside the jail and be
  readable (the log, writable) by the `setuid` user — they're opened after the
  drop.

### Letting xinetd own the socket (optional)

stunnel's `exec` mode already forks one process per connection, so you usually
don't need inetd/xinetd at all. But if you want **xinetd** to own the listening
socket — e.g. to reuse its `instances` / `per_source` connection limits — run
stunnel in **inetd mode** as the xinetd `server`:

```
xinetd --> stunnel (inetd mode) --> tiny-webdav
```

Inetd mode uses stunnel's **global section** — no `[service]` header and no
`accept` (stunnel reads the connection xinetd hands it on fd 0). See
[`stunnel-inetd.conf.example`](stunnel-inetd.conf.example), and point xinetd at
it:

```
# /etc/xinetd.d/tiny-webdav
service tiny-webdav {
    type        = UNLISTED
    port        = 8443
    socket_type = stream
    protocol    = tcp
    wait        = no                 # one process per connection
    user        = root               # so stunnel can chroot + drop privileges
    instances   = 50                 # cap concurrent connections
    per_source  = 5                  # ...and per client IP
    server      = /usr/bin/stunnel
    server_args = /etc/stunnel/tiny-webdav-inetd.conf
}
```

In inetd mode stunnel's stderr is the client socket, so make sure its logging
goes to syslog or a file (`syslog`/`output`), never stderr — the example config
does this.

### tiny-webdav options

| Flag           | Meaning                                                            | Default            |
|----------------|-------------------------------------------------------------------|--------------------|
| `--root`       | Directory to serve (read-only)                                    | current directory  |
| `--timeout`    | Per-read/write socket timeout in seconds (`0` disables — raise or disable for large transfers over slow links) | `30` |
| `--log-file`   | Write diagnostics to this file instead of stderr. Needed under xinetd, where stderr is the client socket | *(none → stderr)* |
| `--auth-file`  | File of `username:password` lines (`#` comments allowed)          | *(none)*           |
| `--user`       | A single username (use together with `--password`)                | *(none)*           |
| `--password`   | Password for `--user`                                             | *(none)*           |
| `--realm`      | Basic-auth realm shown to clients                                 | `tiny-webdav`      |

Client certificates are **not** a tiny-webdav option — they are configured in
stunnel (`CAfile`/`verify`).

`username:password` lines look like this (the password may itself contain `:`):

```
# users.txt
alice:s3cret
bob:p@ss:word
```

## Connect

With `curl` (when stunnel requires a client cert, omitting it fails the
handshake):

```sh
curl --cacert certs/ca.crt \
     --cert   certs/client.crt \
     --key    certs/client.key \
     https://server.example:8443/hello.txt
```

If username/password auth is enabled, add `-u user:password` as well:

```sh
curl --cacert certs/ca.crt --cert certs/client.crt --key certs/client.key \
     -u alice:s3cret \
     https://server.example:8443/hello.txt
```

List a collection with PROPFIND:

```sh
curl -X PROPFIND -H 'Depth: 1' \
     --cacert certs/ca.crt --cert certs/client.crt --key certs/client.key \
     https://server.example:8443/
```

### Mounting from a desktop client

Most WebDAV clients (macOS Finder, GNOME Files / `davfs2`, Cyberduck,
WinSCP, …) can present a client certificate. You typically import
`client.crt` + `client.key` (often bundled as a PKCS#12 / `.p12` file) into the
OS keychain and trust `ca.crt`. To make a `.p12` for import:

```sh
openssl pkcs12 -export -inkey certs/client.key -in certs/client.crt \
  -certfile certs/ca.crt -out certs/client.p12
```

## Security notes

- This server is intentionally minimal. It is suitable for trusted, low-traffic,
  read-only use — not as a public, high-traffic fileserver.
- **TLS, ciphers, and client-certificate verification are stunnel's
  responsibility.** Keep stunnel configured and patched; tiny-webdav contains no
  TLS code at all.
- Concurrency is whatever stunnel provides (one process per connection). Bound it
  in stunnel (e.g. there is no built-in cap, so use firewalling / `per_source`
  via xinetd, or a connection-limited front end) for any exposed deployment.
- The per-operation read/write timeout (`--timeout`, default 30s) bounds how long
  a slow client can stall a connection. Because it is per-operation rather than
  idle-based, a genuinely slow link pulling a very large file can trip it — raise
  `--timeout` or set it to `0` for those cases.
- **"Read-only" means no client request can modify the served tree** (there is
  no PUT/DELETE/etc.). The process itself only writes the operator-specified
  `--log-file`.
- Symlinks under `--root` are followed, but a symlink whose target resolves
  *outside* the served root is refused (`403`) and omitted from listings, so it
  can't be used to escape the root. (After a successful `chroot` this is moot —
  nothing outside the root exists.)
- **Confinement and privilege drop are stunnel's responsibility** (`chroot` /
  `setuid` / `setgid`), applied before it execs tiny-webdav — see *Confinement*
  above. tiny-webdav contains no `chroot`/`setuid` code and reads no system files
  of its own (no `/etc/passwd`, not even `/dev/null`): being a static binary that
  uses only stdin/stdout/stderr and the served files, it runs in a jail
  containing nothing but itself and the served tree. The served files (and any
  `--auth-file`) must be readable by the user stunnel drops to.
- The example certificates from `gen-certs.sh` are for testing only. Use your
  own PKI in production and keep private keys readable only by their owner.
