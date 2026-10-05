# Semio's line of zenoh-ts

This fork carries Semio's changes on top of upstream releases of
[eclipse-zenoh/zenoh-ts](https://github.com/eclipse-zenoh/zenoh-ts). Each release
line is a branch `semio/<version>` that starts at the upstream tag `<version>`;
Semio's commits sit on top of it.

The changes will be offered upstream, as an answer to
[eclipse-zenoh/zenoh-ts#414](https://github.com/eclipse-zenoh/zenoh-ts/issues/414),
once they have run in Semio's deployments.

## What the Semio commits do

### Authenticated client sessions in the remote-api plugin

Stock, the remote-api plugin gives every WebSocket client a session on the
router's own runtime. Such a session is local to the router, so the router's
`access_control` never sees it, and the plugin does not authenticate anyone:
every browser can do whatever the router itself can.

With the plugin's `authentication` section set:

- Every WebSocket upgrade request must carry a **ticket** in its `ticket`
  query parameter: a compact JWT signed with ES256, with the claims `iss`,
  `aud`, `sub`, `iat`, `exp` and `jti` (a `kid` header is allowed and not
  used). The plugin verifies the signature against each configured public key,
  then `iss`, `aud`, `exp`, `nbf` (if present) and `iat`, with the configured
  leeway. A request without a ticket, or with one that fails any check, is
  refused with HTTP 401 before any session is created.
- The ticket's **principal** is `principal_prefix` followed by `sub`. It must be
  a single key-expression chunk: it may not be empty or contain `/`, `*`, `$`,
  `#` or `?`. It may not contain control characters either.
- Once upgraded, the WebSocket gets its **own client session** to the router,
  over the TLS endpoint `client_session.connect`. The plugin mints a client
  certificate for it (see below), so the router authenticates the session as
  the principal and applies its access-control rules for that Common Name to
  everything the browser does. The session is closed when the WebSocket closes.
  If it cannot be opened, the plugin logs why and closes the WebSocket with
  status 1011.
- The plugin never logs the ticket, private keys or certificates. It logs each
  admission with the client's address, the principal and the ticket's `jti`,
  and each refusal with the client's address and the check that failed.
  Zenoh itself logs a TLS connector's settings, its private key included, when
  it cannot build the connector from them; the plugin checks at start the
  inputs of that build it does not generate itself (see below).

Without `authentication`, the plugin behaves as upstream's.

#### Client certificates

For each WebSocket, the plugin generates a fresh EC P-256 key and a certificate
with:

- subject: `CN=<principal>` and nothing else;
- validity: from one minute before issuance (clock skew between the plugin
  and a router on another host) to `certificate_validity_secs` after it;
- key usage `digitalSignature` (critical), extended key usage `clientAuth`,
  `basicConstraints CA:FALSE` (critical), and, as authority key identifier,
  the signing certificate's subject key identifier when it has one;
- signature by `client_session.signing_private_key`.

The session presents the client certificate followed by every certificate in
`client_session.signing_certificate`. The signing certificate may be an
intermediate CA: the router's own `root_ca_certificate` must anchor the chain.

At start, the plugin checks:

- that each ticket key is a valid EC P-256 public key, and that `leeway_secs`
  is at most 300;
- that `connect` is a bare `tls/<host>:<port>`, without metadata or endpoint
  configuration, and that every certificate in `root_ca_certificate` is usable
  as a trust anchor;
- that the signing certificate is a currently valid CA allowed to sign
  certificates, whose extended key usage, if restricted, includes
  `clientAuth`, and that it matches the signing key;
- that a certificate it issues verifies against the signing certificate, which
  fails for a CA whose subject repeats an attribute type (such as two `DC`s):
  the certificates it would issue could not name it as their issuer.

Any of these errors stops the plugin from starting.

#### What bounds a session

- A ticket is accepted any number of times until it expires: keep its lifetime
  short. It travels in the URL, which proxies in front of the plugin may log.
- The session lasts as long as the server side of the WebSocket. The plugin
  sends no WebSocket pings and has no idle timeout, so a client that vanishes
  without closing its connection keeps its session until writing to it fails,
  which never happens if nothing is sent to it.
- Neither the ticket's `exp` nor the certificate's expiry ends a live session.
  If the router drops the link, Zenoh's client session tries to reconnect with
  the same certificate, which fails once that certificate has expired; the
  WebSocket then stays open on a session that reaches nothing.
- Zenoh's TLS connector trusts the public Web PKI roots as well as
  `root_ca_certificate`. With `verify_name_on_connect: true` and a loopback
  `connect` address, as in the example below, no public certificate can stand
  in for the router's.

## Configuration

The `authentication` section of `plugins/remote_api`:

| Field | Default | Meaning |
| --- | --- | --- |
| `ticket.public_keys` | required | Ticket verification keys, SPKI PEM (`-----BEGIN PUBLIC KEY-----`), EC P-256. A ticket verified by any of them passes, which allows key rotation. |
| `ticket.issuer` | required | The only accepted `iss`. |
| `ticket.audience` | required | The only accepted `aud`. |
| `ticket.principal_prefix` | required | Prepended to `sub` to form the principal. May be empty, which lets a subject name any certificate Common Name the router's rules know, devices' included. |
| `ticket.leeway_secs` | `30` | Clock skew tolerated on `exp`, `nbf` and `iat`; at most 300. |
| `client_session.connect` | required | The router's `tls/<host>:<port>` endpoint for these sessions. |
| `client_session.root_ca_certificate` | required | Path to the PEM trust anchors for the router's certificate (on top of the public Web PKI roots). |
| `client_session.signing_certificate` | required | Path to the PEM certificate of the CA that signs client certificates, optionally followed by its intermediates. |
| `client_session.signing_private_key` | required | Path to that CA's private key, unencrypted PKCS#8 PEM (`-----BEGIN PRIVATE KEY-----`). Convert a SEC1 key with `openssl pkcs8 -topk8 -nocrypt`. |
| `client_session.certificate_validity_secs` | `86400` | Lifetime of each client certificate. |
| `client_session.verify_name_on_connect` | `true` | Whether the router's certificate must name the host in `connect`. |

`ticket` and `client_session` are both required inside `authentication`.

A complete router configuration, with the TLS listener the client sessions use
and a rule for one principal:

```json5
{
  mode: "router",
  listen: {
    endpoints: [
      // Reached only by the plugin's client sessions.
      "tls/127.0.0.1:7448",
    ],
  },
  transport: {
    link: {
      tls: {
        // Anchors both the router's certificate and the client certificates'
        // chain (the gateway CA is an intermediate under this root).
        root_ca_certificate: "/certs/ca.pem",
        listen_certificate: "/certs/router.pem",
        listen_private_key: "/certs/router.key",
        // Require a client certificate on every TLS link.
        enable_mtls: true,
      },
    },
  },
  access_control: {
    enabled: true,
    default_permission: "deny",
    rules: [
      {
        id: "alice-state",
        messages: ["put", "delete", "declare_subscriber"],
        flows: ["ingress", "egress"],
        permission: "allow",
        key_exprs: ["state/u:alice/**"],
      },
    ],
    subjects: [{ id: "alice", cert_common_names: ["u:alice"] }],
    policies: [{ rules: ["alice-state"], subjects: ["alice"] }],
  },
  plugins_loading: { enabled: true },
  plugins: {
    remote_api: {
      websocket_port: "127.0.0.1:8080",
      authentication: {
        ticket: {
          public_keys: [
            "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE…\n-----END PUBLIC KEY-----\n",
          ],
          issuer: "semio-studio",
          audience: "semio-bridge",
          principal_prefix: "u:",
          leeway_secs: 30,
        },
        client_session: {
          connect: "tls/127.0.0.1:7448",
          root_ca_certificate: "/certs/ca.pem",
          signing_certificate: "/certs/gateway-ca.pem",
          signing_private_key: "/certs/gateway-ca.key",
          certificate_validity_secs: 86400,
          verify_name_on_connect: true,
        },
      },
    },
  },
}
```

Set this way, the router's `transport/link/tls` settings apply to each of its
TLS listeners, so the `root_ca_certificate` there must anchor the client
certificates' chain as well as the certificates of anything else that connects
to the router over TLS.

### Connecting from zenoh-ts

Pass the locator as a full URL so that the query string reaches the plugin:

```ts
const session = await Session.open(new Config(`wss://bridge.example/?ticket=${ticket}`));
```

The shorthand `ws/host:port` keeps only `host:port` and drops anything after
it. zenoh-ts logs the URL it connects to, ticket included, with
`console.warn`. When the upgrade is refused, `Session.open` retries the WebSocket ten times,
waiting 2 s, then twice as long each time, before it fails; a client that needs
to notice a refused ticket sooner bounds it with its own timeout.

## Carrying the changes to a new upstream release

With `upstream` pointing at `https://github.com/eclipse-zenoh/zenoh-ts.git`:

```sh
# 1. The new release line, at the upstream tag.
git fetch upstream --tags
git switch -c semio/<new> <new>
git push origin semio/<new>

# 2. Semio's commits, replayed onto it on a branch of their own.
git log --oneline <old>..origin/semio/<old>          # what is being carried
git switch -c carry/<new> origin/semio/<old>
git rebase --onto semio/<new> <old> carry/<new>

# 3. The checks CI runs.
cargo fmt --check -- --config "unstable_features=true,imports_granularity=Crate,group_imports=StdExternalCrate"
cargo clippy --all -- -D warnings
cargo test
```

Then open a pull request from `carry/<new>` into `semio/<new>` in this fork and
let CI run the TypeScript tests as well. Never force-push a `semio/*` branch.
