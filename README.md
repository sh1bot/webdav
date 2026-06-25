# tiny-webdav

A very small, **read-only** WebDAV server written in Rust, served over TLS and
run under **inetd / xinetd**. There is no standalone listening mode: xinetd (in
`nowait` mode) accepts each connection and hands the socket to a fresh process
on stdin; tiny-webdav performs the TLS handshake itself, serves the one request,
and exits. That gives per-connection concurrency (one process per client) for
free, and keeps the program tiny.

Two independent authentication layers are available, and you can use either or
both:

1. **Client certificate ("private key sign-in" / mutual TLS).** Each client
   holds a private key + certificate signed by a CA the server trusts, and the
   TLS handshake itself proves the client possesses that private key. It can be
   **required**, **optional** (verify a cert if presented, but also accept
   clients without one), or **disabled**.
2. **HTTP Basic username/password.** Safe here because the whole connection is
   already encrypted by TLS.

When both are configured, a request must satisfy **both** the client certificate
**and** valid credentials. If you configure neither, the server allows anonymous
read access and logs a warning.

## Features

- Serves a directory read-only over HTTPS.
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
- Client-certificate auth that can be required, optional, or disabled, plus
  optional HTTP Basic username/password (`401` challenge with `WWW-Authenticate`
  when missing/invalid).
- Rejects path traversal (`..`) and symlink escapes, so only files under
  `--root` are reachable. Optionally `chroot`s and drops to `nobody` after setup.
- Tiny dependency footprint: just `rustls` (with the `ring` provider),
  `rustls-pemfile`, and `libc`. No async runtime, no HTTP framework.

## Build

```sh
cargo build --release
```

## Generate test certificates

A helper script creates a throwaway CA plus a server and a client certificate:

```sh
./gen-certs.sh certs localhost
```

This writes `ca.crt`, `server.crt`/`server.key` and `client.crt`/`client.key`
into `certs/`.

## Options

| Flag                     | Meaning                                                            | Default            |
|--------------------------|-------------------------------------------------------------------|--------------------|
| `--cert`                 | PEM server certificate (chain) presented to clients               | *(required)*       |
| `--key`                  | PEM server private key                                            | *(required)*       |
| `--root`                 | Directory to serve (read-only)                                    | current directory  |
| `--timeout`              | Per-read/write socket timeout in seconds (`0` disables — raise or disable for large transfers over slow links) | `30` |
| `--log-file`             | Send diagnostics here (stdout/stderr are the client socket, so they are otherwise discarded) | *(none → `/dev/null`)* |
| `--client-ca`            | PEM CA used to verify **client** certificates. Omit to disable client-cert auth. | *(none → disabled)* |
| `--client-cert-optional` | Accept clients without a cert, but verify any cert presented (needs `--client-ca`) | off |
| `--auth-file`            | File of `username:password` lines (`#` comments allowed)          | *(none)*           |
| `--user`                 | A single username (use together with `--password`)                | *(none)*           |
| `--password`             | Password for `--user`                                             | *(none)*           |
| `--realm`                | Basic-auth realm shown to clients                                 | `tiny-webdav`      |

### Choosing an authentication mode

| Goal                                   | Flags                                                        |
|----------------------------------------|-------------------------------------------------------------|
| Client cert required (mTLS only)       | `--client-ca ca.crt`                                         |
| Username/password only (no client cert)| *(omit `--client-ca`)* `--auth-file users.txt`              |
| Either works, but a login is always required | `--client-ca ca.crt --client-cert-optional --auth-file users.txt` |
| Cert **and** password both required    | `--client-ca ca.crt --auth-file users.txt`                  |
| Anonymous read access (no auth)        | *(omit both — logs a warning)*                              |

`username:password` lines look like this (the password may itself contain `:`):

```
# users.txt
alice:s3cret
bob:p@ss:word
```

## Running under inetd / xinetd

tiny-webdav reads the connection from **stdin (fd 0)**, serves it, and exits, so
it must be launched per-connection in `nowait` mode. inetd does **not** speak
TLS — it just hands over the raw TCP socket; tiny-webdav does the TLS handshake.

`/etc/xinetd.d/tiny-webdav`:

```
service tiny-webdav {
    type        = UNLISTED
    port        = 8443
    socket_type = stream
    protocol    = tcp
    wait        = no
    user        = root
    server      = /usr/local/bin/tiny-webdav
    server_args = --cert /etc/tiny-webdav/server.crt --key /etc/tiny-webdav/server.key --client-ca /etc/tiny-webdav/ca.crt --root /srv/files --log-file /var/log/tiny-webdav.log
}
```

`/etc/inetd.conf` equivalent (one line):

```
8443 stream tcp nowait root /usr/local/bin/tiny-webdav tiny-webdav \
  --cert /etc/tiny-webdav/server.crt --key /etc/tiny-webdav/server.key \
  --client-ca /etc/tiny-webdav/ca.crt --root /srv/files \
  --log-file /var/log/tiny-webdav.log
```

Notes:

- Use `nowait` so a fresh process is forked per connection (`wait` would serve
  only one connection at a time).
- The client socket is also duplicated onto stdout/stderr, so the program
  redirects those away on startup to avoid corrupting the TLS stream. Use
  `--log-file <path>` to capture diagnostics; otherwise they go to `/dev/null`.
- Run it **as root** (as above) if you want the post-startup `chroot` +
  `setuid(nobody)` confinement; if xinetd starts it as an unprivileged user,
  that step is simply skipped.
- Unix only.

## Connect

With `curl` (when a client cert is required, omitting it fails the handshake):

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
- Concurrency is whatever xinetd provides (one process per connection). Cap it in
  the xinetd config (`instances`, `per_source`) for any exposed deployment, since
  `nowait` otherwise forks unboundedly.
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
- **Privilege dropping:** once setup is done (certificates and credentials are in
  memory), the process tries to `chroot` into the served directory and drop to
  the `nobody` user/group; after a successful `chroot` the served directory
  becomes `/`. This requires being started as root. If it isn't root it logs a
  note and carries on unconfined; if it *is* root and the `setgid`/`setuid` drop
  fails, that is fatal (it will not keep serving with root privileges). For the
  dropped `nobody` user to read the files, they must be readable by that account.
- The example certificates from `gen-certs.sh` are for testing only. Use your
  own PKI in production and keep private keys readable only by their owner.
