# tiny-webdav

A very small, **read-only** WebDAV server in Rust. It speaks **plaintext HTTP**
and runs behind **[stunnel](https://www.stunnel.org/)**, which terminates TLS
(and verifies client certificates) and hands each decrypted connection to a fresh
tiny-webdav process on stdin — the classic inetd contract. All crypto stays in a
mature, dedicated tool; the program's only dependency is `libc`.

```
client --TLS--> stunnel (terminates TLS, verifies client cert) --plaintext--> tiny-webdav
```

## Authentication

Two independent layers; use either, both, or neither:

- **Client certificate (mutual TLS)** — enforced by **stunnel** (`CAfile` +
  `verify`); tiny-webdav never sees the TLS.
- **HTTP Basic** — enforced by **tiny-webdav** (`--auth-file` / `--user`).

With neither configured, access is anonymous and tiny-webdav logs a warning. It
detects a verified client cert from the `SSL_CLIENT_DN` variable stunnel sets, so
a cert-only deployment isn't warned. (`SSL_CLIENT_DN` only drives that warning,
never an access decision.)

## Features

- Read-only `GET`/`HEAD` (directories return an HTML index), `OPTIONS`, and
  `PROPFIND` (`Depth: 0`/`1` → `207`; `infinity` → `403 propfind-finite-depth`).
- Conditional requests (`ETag` / `Last-Modified` / `If-None-Match` /
  `If-Modified-Since` → `304`) and single byte-range requests (`206`/`416`,
  `If-Range`).
- Bodies sent with `sendfile(2)` — straight from page cache to socket, constant
  memory even for huge files.
- Persistent connections (HTTP/1.1 keep-alive): one connection serves many
  requests, capped by `--max-requests` and an idle `--timeout`. Every response is
  `Content-Length`-framed; if a request's body framing is ever uncertain the
  connection is closed rather than risk a desync.
- Mutating methods (`PUT`, `DELETE`, `MKCOL`, …) → `405`.
- Path traversal (`..`) and out-of-root symlinks are rejected (as `404`).
- Run as root, it `chroot`s into `--root` and drops privileges (see below).
- One dependency: `libc`. No TLS stack, async runtime, or HTTP framework.

## Build

`make` builds a fully static (musl) binary for the host architecture — the triple
is derived from `uname -m`, so nothing is hard-coded:

```sh
make setup     # one-time: rustup target add <arch>-unknown-linux-musl
make           # -> target/<arch>-unknown-linux-musl/release/tiny-webdav
```

Plain `cargo build --release` gives a normal host-native (dynamic) dev build.

## Test certificates

`gen-certs.sh` makes a throwaway CA plus server and client certs in `certs/`:

```sh
./gen-certs.sh certs localhost
```

## Run behind stunnel

stunnel listens, terminates TLS, verifies the client cert, and execs one
tiny-webdav per connection. Run **stunnel as root** so tiny-webdav can confine
itself (see [Confinement](#confinement--privilege-drop)). See
[`stunnel.conf.example`](stunnel.conf.example):

```ini
[tiny-webdav]
accept   = 8443
cert     = /etc/tiny-webdav/server.crt
key      = /etc/tiny-webdav/server.key
CAfile   = /etc/tiny-webdav/ca.crt      ; client-cert auth...
verify   = 2                            ; ...require a valid cert (omit both to disable)
exec     = /usr/local/bin/tiny-webdav
execargs = tiny-webdav --root /srv/files --auth-file /etc/tiny-webdav/users.txt
```

With no `--log-file`, diagnostics go to stderr, which stunnel forwards to its own
stderr (the systemd journal) — fine here.

### Options

| Flag | Meaning | Default |
|---|---|---|
| `--root` | Directory to serve (read-only) | current dir |
| `--run-as` | User to chroot+drop to when started as root (must exist) | `nobody` |
| `--log-file` | Write diagnostics here instead of stderr (required under xinetd) | *(stderr)* |
| `--auth-file` | File of `username:password` lines (`#` comments; password may contain `:`) | *(none)* |
| `--user` / `--password` | A single inline credential | *(none)* |
| `--realm` | Basic-auth realm | `tiny-webdav` |
| `--timeout` | Per-read/write timeout in seconds, incl. the wait for the next keep-alive request (`0` disables) | `30` |
| `--max-requests` | Max requests served on one connection before closing (`0` = unlimited) | `100` |

Client certificates are configured in stunnel, not here.

### Under xinetd (optional)

stunnel already forks per connection, so xinetd isn't needed — but if you want it
to own the socket (e.g. for `instances`/`per_source` limits), run stunnel in
**inetd mode** (global section, no `accept`; see
[`stunnel-inetd.conf.example`](stunnel-inetd.conf.example)) as the xinetd
`server`. Under xinetd, stderr is the client socket, so pass `--log-file`.

```
# /etc/xinetd.d/tiny-webdav
service tiny-webdav {
    type = UNLISTED ; port = 8443 ; socket_type = stream ; protocol = tcp
    wait = no              # one process per connection
    user = root           # so tiny-webdav can chroot + drop privileges
    instances = 50 ; per_source = 5
    server = /usr/bin/stunnel
    server_args = /etc/stunnel/tiny-webdav-inetd.conf
}
```

## Connect

```sh
curl --cacert certs/ca.crt --cert certs/client.crt --key certs/client.key \
     [-u alice:s3cret] https://server.example:8443/hello.txt
# list a collection:  curl -X PROPFIND -H 'Depth: 1' ...  https://server.example:8443/
```

GUI file managers vary: Windows Explorer won't mount a class-1 (`DAV: 1`,
read-only) server and macOS Finder is unreliable; `curl`, `davfs2`, `rclone`, and
Cyberduck work. If your client needs the cert, import `client.crt` + `client.key`
as a `.p12`:

```sh
openssl pkcs12 -export -inkey certs/client.key -in certs/client.crt \
  -certfile certs/ca.crt -out certs/client.p12
```

## Confinement & privilege drop

Started **as root**, tiny-webdav confines itself: resolve the `--run-as` account
(default `nobody`), `chroot` into `--root`, `chdir` to `/`, drop
groups/gid/uid with `setres*id`, then verify the result — an incomplete or failed
drop is fatal, and it refuses to ever serve as root. Everything outside the root
(the static binary, `/etc/passwd`, `--auth-file`, `--log-file`) is opened *before*
the chroot, so the served directory itself needs nothing added to it.

Always, as defense-in-depth: `PR_SET_NO_NEW_PRIVS` and zeroed *hard*
`RLIMIT_CORE` / `RLIMIT_NPROC` (no privilege regain, no core dumps, no forking).
seccomp is deliberately omitted. If stunnel drops privileges itself instead,
tiny-webdav runs unprivileged and skips this step.

## Security notes

- Minimal by design: for trusted, low-traffic, read-only use — not a public,
  high-traffic fileserver.
- **TLS, ciphers, and client-cert verification are stunnel's job** — keep it
  patched; tiny-webdav contains no TLS code.
- Concurrency and connection caps are stunnel's job (`per_source`,
  `TIMEOUTidle`/`TIMEOUTbusy`). tiny-webdav adds only a best-effort per-socket
  read/write `--timeout` so an idle kept-alive connection can't pin its process
  forever; a hung connection still only ties up its own process.
- "Read-only" means no request can modify the served tree; the process only ever
  writes the operator's `--log-file`.
- Example certs from `gen-certs.sh` are for testing only; use your own PKI in
  production and keep private keys owner-readable.
