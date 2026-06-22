# tiny-webdav

A very small, **single-threaded, read-only** WebDAV server written in Rust, with
**TLS client-certificate authentication** (mutual TLS).

Two independent authentication layers are available, and you can use either or
both:

1. **Client certificate ("private key sign-in" / mutual TLS).** Each client
   holds a private key + certificate signed by a CA the server trusts, and the
   TLS handshake itself proves the client possesses that private key. This is a
   native feature of TLS/HTTPS. It can be **required**, **optional** (verify a
   cert if presented, but also accept clients without one), or **disabled**.
2. **HTTP Basic username/password.** Safe here because the whole connection is
   already encrypted by TLS.

When both are configured, a request must satisfy **both** the client certificate
**and** valid credentials. If you configure neither, the server allows anonymous
read access and prints a warning at startup.

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
- Bring your own server certificate, or generate a self-signed one on the fly
  with `--self-signed` (handy for quick local testing).
- Client-certificate auth that can be required, optional, or disabled.
- Optional HTTP Basic username/password auth, layered on top of any
  client-certificate auth (`401` challenge with `WWW-Authenticate` when
  missing/invalid).
- Rejects path traversal (`..`) so only files under `--root` are reachable.
- Tiny dependency footprint: just `rustls` (with the `ring` provider) and
  `rustls-pemfile`. No async runtime, no HTTP framework.

## Build

```sh
cargo build --release
```

## Quick start with a self-signed certificate

For local testing you don't need to create a server certificate at all — let the
server generate one and write it out so your client can trust it:

```sh
./target/release/tiny-webdav \
  --self-signed --write-cert /tmp/srv.pem \
  --root ./served --user alice --password s3cret

# in another terminal:
curl --cacert /tmp/srv.pem -u alice:s3cret https://localhost:4443/
# ...or skip trust entirely for throwaway testing:
curl -k -u alice:s3cret https://localhost:4443/
```

Add `--hostname <name>` (repeatable) if you need the certificate to be valid for
names other than `localhost`/`127.0.0.1`/`::1`. A self-signed server certificate
is fine for testing, but clients can't verify it against a public CA, so use a
real certificate (or your own CA) for anything beyond local use.

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

| Flag                     | Meaning                                                            | Default            |
|--------------------------|-------------------------------------------------------------------|--------------------|
| `--cert`                 | PEM server certificate (chain) presented to clients               | *(required unless `--self-signed`)* |
| `--key`                  | PEM server private key                                            | *(required unless `--self-signed`)* |
| `--self-signed`          | Generate an in-memory self-signed server cert (testing)           | off                |
| `--hostname`             | SAN for the self-signed cert; repeatable                          | `localhost`, `127.0.0.1`, `::1` |
| `--write-cert`           | Write the generated self-signed cert (PEM) to this path           | *(none)*           |
| `--root`                 | Directory to serve (read-only)                                    | current directory  |
| `--addr`                 | Listen address                                                    | `127.0.0.1:4443`   |
| `--client-ca`            | PEM CA used to verify **client** certificates. Omit to disable client-cert auth. | *(none → disabled)* |
| `--client-cert-optional` | Accept clients without a cert, but verify any cert presented (needs `--client-ca`) | required           |
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
| Anonymous read access (no auth)        | *(omit both — prints a warning)*                            |

If no credentials are configured, Basic auth is disabled. If `--client-ca` is
omitted, client-certificate auth is disabled. With both disabled the server
serves anyone who can reach it (and says so at startup).

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
