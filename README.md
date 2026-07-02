# tiny-webdav

A very small, **read-only** WebDAV server in Rust. It speaks **plaintext HTTP**
and, by default, runs behind **[stunnel](https://www.stunnel.org/)**, which
terminates TLS (and verifies client certificates) and hands each decrypted
connection to a fresh tiny-webdav process on stdin — the classic inetd contract.
All crypto stays in a mature, dedicated tool; the program's only dependency is
`libc`.

```
client --TLS--> stunnel (terminates TLS, verifies client cert) --plaintext--> tiny-webdav
```

Alternatively, with `--listen <path>` tiny-webdav creates a **Unix-domain socket**
itself and forks a child per connection — no stunnel, no TLS, no TCP. Point a
TLS-terminating front (cloudflared, a reverse proxy) at the socket; see
[Standalone mode](#standalone---listen-mode).

## Authentication

Two independent layers; use either, both, or neither:

- **Client certificate (mutual TLS)** — enforced by **stunnel** (`CAfile` +
  `verify`); tiny-webdav never sees the TLS.
- **HTTP Basic** — enforced by **tiny-webdav** (`--auth-file` / `--auth`).

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
- Hidden system files — any name beginning with `.`, `@`, or `$` (dotfiles,
  `@eaDir`, `$RECYCLE.BIN`, …) — are omitted from listings **and** refused on
  direct access (`404`), so nothing is hidden-but-fetchable. Re-expose individual
  names with `--expose <glob>` (repeatable; `--expose '*'` serves all).
- Two ways to run: behind stunnel on stdin (the inetd contract), or standalone
  with `--listen <addr>`, forking a child per connection.
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

For the smallest binary (~180 KB vs ~525 KB), `make build-min` rebuilds `std`
from source on a **nightly** toolchain, so size-optimization and dead-code
elimination reach `std` itself (the stable build can't touch the precompiled
`std`, which is most of the weight). It uses unstable flags — nightly only:

```sh
make setup-min   # one-time: nightly toolchain + rust-src + musl target
make build-min   # same output path as `make`
```

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
| `--listen` | Create a Unix-domain socket at this path and fork per connection; no TLS. Omit to serve one connection from stdin | *(stdin)* |
| `--socket-mode` | Octal permission bits for the `--listen` socket (`660` owner+group, `600` owner only) | `660` |
| `--max-connections` | With `--listen`, cap concurrent connections (excess wait in the backlog); `0` = unlimited | `64` |
| `--run-as` | User to chroot+drop to when started as root (must exist) | `nobody` |
| `--log-file` | Write diagnostics here instead of stderr (required under xinetd) | *(stderr)* |
| `--auth-file` | File of `username:password` lines (`#` comments; password may contain `:`) | *(none)* |
| `--auth` | An inline `username:password` credential (repeatable) | *(none)* |
| `--timeout` | Per-read/write timeout in seconds, incl. the wait for the next keep-alive request (`0` disables) | `30` |
| `--max-requests` | Max requests served on one connection before closing (`0` = unlimited) | `100` |
| `-v`, `--verbose` | Log one line per request (method, path, status, conditional/range headers) to stderr | *(off)* |
| `--expose` | Re-expose an otherwise-hidden name; glob with `*`/`?`, repeatable (`--expose .mpdignore`, `--expose '*'`) | *(none)* |

Client certificates are configured in stunnel, not here.

### Watching request traffic (`-v`)

`-v` logs one line per request to stderr (so it lands in `--log-file`, the
journal, or stunnel's log), including any conditional/range headers. It's handy
for confirming a syncing client only refetches what actually changed:

```
GET /photos/a.jpg HTTP/1.1 -> 304 if-none-match="\"1a-6a40b279\""
GET /photos/b.jpg HTTP/1.1 -> 304 if-modified-since="Tue, 01 Jul 2026 …"
GET /photos/new.jpg HTTP/1.1 -> 200 if-modified-since="Tue, 01 Jul 2026 …"
PROPFIND /photos/ HTTP/1.1 -> 207 depth="1"
```

- A `304` (or `206` for a resumed range) means the client sent a validator and
  was spared the transfer — the efficient path.
- A plain `200` with **no** `if-*` header for data the client already holds is
  the tell-tale of a client re-scanning instead of asking "changed since?".

Note there's no conditional `PROPFIND` in WebDAV: a directory listing (`207`) is
always regenerated, but it only carries metadata (names, sizes, mtimes, etags),
so the client can diff it and issue conditional `GET`s for just the changed
files.

### Hidden system files

By default the server treats any name beginning with `.`, `@`, or `$` as if it
weren't in the tree — omitted from the HTML index and PROPFIND, and answered with
a reveal-nothing `404` on direct access (so a client can't probe for what wasn't
listed). The rule is applied to every path segment, so `/.git/config` is refused
because of its `.git` ancestor. Those three prefixes cover dotfiles (`.git`,
`.env`, `.htpasswd`, `.ssh`, …), Synology's `@eaDir`, and Windows' `$RECYCLE.BIN`.

Plainly-named junk (`Desktop.ini`, `Thumbs.db`, `CVS`, …) is **not** filtered —
if you want it gone, keep it off the served volume.

To re-expose specific names, pass `--expose <glob>` (repeatable). The glob
supports `*` and `?`, is case-sensitive, and matches a single path segment:

```sh
tiny-webdav --root /srv --expose .mpdignore     # serve just this dotfile
tiny-webdav --root /srv --expose .well-known --expose '.*ignore'
tiny-webdav --root /srv --expose '.*'           # all dotfiles (not metadata dirs)
tiny-webdav --root /srv --expose '*'            # everything — the serve-all escape hatch
```

The match is on the request path, matching how nginx/Apache do it. A non-hidden
**symlink** whose target is a hidden file would still be followed — the filter
doesn't rewrite what a deliberately-placed link points at.

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

## Standalone (`--listen`) mode

Skip stunnel and let tiny-webdav create and own a **Unix-domain socket**, forking
a child per connection:

```sh
tiny-webdav --root /srv/files --listen /run/tiny-webdav/sock
```

There is **no TLS and no TCP** — put a TLS-terminating front in front of the
socket. It pairs naturally with [cloudflared](https://github.com/cloudflare/cloudflared),
which terminates TLS at Cloudflare's edge and tunnels to your machine (no inbound
port, no `exec` contract — it just connects to the socket):

```yaml
# cloudflared config.yml
ingress:
  - hostname: files.example.com
    service: unix:/run/tiny-webdav/sock
  - service: http_status:404
```

**Why a Unix socket, not a TCP port:** a loopback TCP port (`127.0.0.1:…`) is
reachable by *any* local process — nothing stops another user on the box from
bypassing Cloudflare and hitting tiny-webdav directly. A Unix socket is a
filesystem object with an owner, group, and mode, and the kernel enforces them on
connect. `--socket-mode 660` (the default) plus the socket's ownership restricts
who can connect to the owner and group — so only your front-end (e.g. the
`cloudflared` user, in the socket's group) can reach it. Use a real path, not the
abstract namespace, precisely so the permissions apply. The socket permission
controls *which local process* may connect, not *who the end user is* — keep HTTP
Basic auth (`--auth` / `--auth-file`) on for user authentication.

On startup tiny-webdav removes a stale socket left by a previous run (but refuses
to touch a non-socket at that path), and creates the new one with `--socket-mode`
applied atomically (no world-readable window). Concurrency is bounded by
`--max-connections` (default 64): the accept loop serves at most that many at
once and lets the rest wait in the kernel backlog, so a connection flood can't
fork children without limit; exited children are reaped by the loop itself.

Privilege handling mirrors the stunnel path. Started **as root**, it creates the
socket (so you can place it in a root-only directory like `/run/…`) and
self-confines: `chroot` into `--root` and drop to `--run-as` (default `nobody`)
**once**, before the accept loop — every child inherits the chroot and
unprivileged uid and re-forbids forking for itself. Started unprivileged it
simply serves as the current user (no chroot); running it as a dedicated
service user is the simplest setup.

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

Always, as defense-in-depth: `PR_SET_NO_NEW_PRIVS` and zeroed *hard* `RLIMIT_CORE`
/ `RLIMIT_NPROC` (no privilege regain, no core dumps, no forking). seccomp is
deliberately omitted. If stunnel drops privileges itself instead, tiny-webdav
runs unprivileged and skips this step.

In `--listen` mode the drop happens once, before the accept loop, so the forking
parent keeps `RLIMIT_NPROC` (it *must* fork per connection) while each child
zeroes it for itself — the process actually serving a client still can't fork.

## Security notes

- Minimal by design: for trusted, low-traffic, read-only use — not a public,
  high-traffic fileserver.
- **TLS, ciphers, and client-cert verification are stunnel's job** — keep it
  patched; tiny-webdav contains no TLS code. `--listen` mode has **no TLS at all**,
  so only use it on a trusted network or behind a separate TLS terminator.
- Behind stunnel/xinetd, concurrency and connection rate are the supervisor's
  job (`per_source`, `TIMEOUTidle`/`TIMEOUTbusy`, `instances`). In `--listen`
  mode tiny-webdav caps concurrency itself with `--max-connections` (default 64),
  and a best-effort per-socket read/write `--timeout` keeps an idle kept-alive
  connection from pinning its process; a hung connection only ties up its own.
- "Read-only" means no request can modify the served tree; the process only ever
  writes the operator's `--log-file`.
- Example certs from `gen-certs.sh` are for testing only; use your own PKI in
  production and keep private keys owner-readable.
