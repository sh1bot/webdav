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
   **stunnel** (`CAfile` + `verify`). tiny-webdav never sees the TLS. It can be
   required, optional, or disabled, all in stunnel's config.
2. **HTTP Basic username/password** — enforced by **tiny-webdav**, layered on top
   (safe because stunnel has already encrypted the connection).

If you configure neither, the server allows anonymous read access and logs a
warning.

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
- File bodies are streamed in 64 KiB chunks (seeking for ranges), so even
  multi-gigabyte files are served with near-constant memory.
- Every mutating method (`PUT`, `DELETE`, `MKCOL`, `MOVE`, `COPY`,
  `PROPPATCH`, `LOCK`, …) is rejected with `405 Method Not Allowed`.
- Optional HTTP Basic username/password auth (`401` challenge with
  `WWW-Authenticate` when missing/invalid).
- Rejects path traversal (`..`) and symlink escapes, so only files under
  `--root` are reachable. Optionally `chroot`s and drops to `nobody` after setup.
- Tiny dependency footprint: just `libc`. No TLS stack, no async runtime, no
  HTTP framework.

## Build

```sh
cargo build --release
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
- Run stunnel **as root** if you want tiny-webdav to `chroot` + drop to `nobody`
  per connection (it inherits stunnel's privileges); otherwise that step is
  skipped.
- Prefer fronting stunnel with xinetd? Run stunnel in inetd mode (a config with
  no `accept`) as the xinetd `server`, so xinetd owns the socket and execs
  stunnel, which execs tiny-webdav.

### tiny-webdav options

| Flag           | Meaning                                                            | Default            |
|----------------|-------------------------------------------------------------------|--------------------|
| `--root`       | Directory to serve (read-only)                                    | current directory  |
| `--timeout`    | Per-read/write socket timeout in seconds (`0` disables — raise or disable for large transfers over slow links) | `30` |
| `--log-file`   | Send diagnostics here (stdout/stderr are the client connection, so they are otherwise discarded) | *(none → `/dev/null`)* |
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
- **Privilege dropping:** once setup is done (credentials are in memory), the
  process tries to `chroot` into the served directory and drop to the `nobody`
  user/group; after a successful `chroot` the served directory becomes `/`. This
  requires being started as root (have stunnel run as root). If it isn't root it
  logs a note and carries on unconfined; if it *is* root and the `setgid`/`setuid`
  drop fails, that is fatal (it will not keep serving with root privileges). For
  the dropped `nobody` user to read the files, they must be readable by that
  account.
- The example certificates from `gen-certs.sh` are for testing only. Use your
  own PKI in production and keep private keys readable only by their owner.
