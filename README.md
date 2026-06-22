# tiny-webdav

A very small, **single-threaded, read-only** WebDAV server written in Rust, with
**TLS client-certificate authentication** (mutual TLS).

The primary authentication is "private key sign-in": each client holds a private
key + certificate signed by a CA the server trusts, and the TLS handshake itself
proves the client possesses that private key. This is a native feature of
TLS/HTTPS — usually called **mutual TLS (mTLS)** or client-certificate
authentication.

Optionally, you can also require **HTTP Basic username/password** on top of the
client certificate. When configured, a request must satisfy **both** the client
certificate **and** valid credentials. Basic auth is safe here because the whole
connection is already encrypted by TLS.

## Features

- Serves a directory read-only over HTTPS.
- Supports the WebDAV verbs needed for browsing/reading:
  - `OPTIONS` (advertises `DAV: 1`)
  - `GET` / `HEAD` (files; directories return a simple HTML index)
  - `PROPFIND` (`Depth: 0` and `Depth: 1`) returning `207 Multi-Status`
- HTTP `Range` requests (single `bytes=` ranges) for partial/resumable
  downloads: responds `206 Partial Content` with `Content-Range`, `416` for
  unsatisfiable ranges, and advertises `Accept-Ranges: bytes`.
- File bodies are streamed in 64 KiB chunks (seeking for ranges), so even
  multi-gigabyte files are served with near-constant memory — the whole file
  is never read into RAM.
- Every mutating method (`PUT`, `DELETE`, `MKCOL`, `MOVE`, `COPY`,
  `PROPPATCH`, `LOCK`, …) is rejected with `405 Method Not Allowed`.
- Requires a valid client certificate for every connection.
- Optional HTTP Basic username/password auth, layered on top of the client
  certificate (`401` challenge with `WWW-Authenticate` when missing/invalid).
- Rejects path traversal (`..`) so only files under `--root` are reachable.
- Tiny dependency footprint: just `rustls` (with the `ring` provider) and
  `rustls-pemfile`. No async runtime, no HTTP framework.

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

## Run

```sh
./target/release/tiny-webdav \
  --cert      certs/server.crt \
  --key       certs/server.key \
  --client-ca certs/ca.crt \
  --root      ./served \
  --addr      127.0.0.1:4443
```

| Flag          | Meaning                                                        | Default            |
|---------------|---------------------------------------------------------------|--------------------|
| `--cert`      | PEM server certificate (chain) presented to clients           | *(required)*       |
| `--key`       | PEM server private key                                        | *(required)*       |
| `--client-ca` | PEM CA used to verify **client** certificates                 | *(required)*       |
| `--root`      | Directory to serve (read-only)                                | current directory  |
| `--addr`      | Listen address                                                | `127.0.0.1:4443`   |
| `--auth-file` | File of `username:password` lines (`#` comments allowed)      | *(none)*           |
| `--user`      | A single username (use together with `--password`)            | *(none)*           |
| `--password`  | Password for `--user`                                         | *(none)*           |
| `--realm`     | Basic-auth realm shown to clients                             | `tiny-webdav`      |

If no credentials are configured, Basic auth is disabled and only the client
certificate is required.

### Username/password auth

Either point at a credentials file...

```sh
cat > users.txt <<'EOF'
# username:password   (the password may itself contain ':')
alice:s3cret
bob:p@ss:word
EOF

./target/release/tiny-webdav \
  --cert certs/server.crt --key certs/server.key --client-ca certs/ca.crt \
  --root ./served --auth-file users.txt
```

...or pass a single user inline (note: arguments are visible in `ps`, so prefer
`--auth-file` for anything real):

```sh
./target/release/tiny-webdav ... --user alice --password s3cret
```

## Connect

With `curl` (note: a client cert is mandatory — omitting it fails the handshake):

```sh
curl --cacert certs/ca.crt \
     --cert   certs/client.crt \
     --key    certs/client.key \
     https://localhost:4443/hello.txt
```

If username/password auth is enabled, add `-u user:password` as well — the
client certificate alone is no longer sufficient:

```sh
curl --cacert certs/ca.crt --cert certs/client.crt --key certs/client.key \
     -u alice:s3cret \
     https://localhost:4443/hello.txt
```

List a collection with PROPFIND:

```sh
curl -X PROPFIND -H 'Depth: 1' \
     --cacert certs/ca.crt --cert certs/client.crt --key certs/client.key \
     https://localhost:4443/
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
  read-only use behind client-certificate auth — not as a public, high-traffic
  fileserver.
- It is single-threaded: one connection is fully handled before the next is
  accepted. A read/write timeout (30s) bounds how long a slow client can stall
  the loop, but a hostile client can still reduce throughput.
- Symlinks under `--root` are followed; don't place symlinks that point outside
  the served tree if that matters to you.
- The example certificates from `gen-certs.sh` are for testing only. Use your
  own PKI in production and keep private keys readable only by their owner.
```
