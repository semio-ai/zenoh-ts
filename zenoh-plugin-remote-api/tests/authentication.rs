//
// Copyright (c) 2026 Semio
//
// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0, or the Apache License, Version 2.0
// which is available at https://www.apache.org/licenses/LICENSE-2.0.
//
// SPDX-License-Identifier: EPL-2.0 OR Apache-2.0
//

//! The plugin inside a router whose TLS listener requires client certificates and whose
//! access control matches certificate Common Names exactly, letting `u:alice` put and
//! subscribe on `demo/alice` and nothing else.
//!
//! WebSocket clients speak just enough of the remote-api wire protocol to subscribe and put;
//! a session on the router's own runtime, which access control does not filter, observes.

use std::{
    net::TcpListener,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use futures::{SinkExt, StreamExt};
use jsonwebtoken::{encode, get_current_timestamp, Algorithm, EncodingKey, Header};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, SanType,
};
use serde_json::{json, Value};
use tokio::net::TcpStream;
use tokio_tungstenite::{
    connect_async,
    tungstenite::{self, http::StatusCode, protocol::frame::coding::CloseCode, Message},
    MaybeTlsStream, WebSocketStream,
};
use zenoh::{
    bytes::ZBytes,
    internal::{
        plugins::PluginsManager,
        runtime::{DynamicRuntime, RuntimeBuilder},
    },
    Session,
};
use zenoh_ext::{ZDeserializer, ZSerializer};
use zenoh_plugin_remote_api::RemoteApiPlugin;
use zenoh_plugin_trait::Plugin;

const ISSUER: &str = "semio-studio";
const AUDIENCE: &str = "semio-bridge";
const PATIENCE: Duration = Duration::from_secs(10);

/// What the router allows `u:alice`, and nobody else.
fn access_control() -> Value {
    json!({
        "enabled": true,
        "default_permission": "deny",
        "rules": [{
            "id": "alice-demo",
            "messages": ["put", "delete", "declare_subscriber"],
            "flows": ["ingress", "egress"],
            "permission": "allow",
            "key_exprs": ["demo/alice"],
        }],
        "subjects": [{ "id": "alice", "cert_common_names": ["u:alice"] }],
        "policies": [{ "rules": ["alice-demo"], "subjects": ["alice"] }],
    })
}

/// Certificates and keys written to a directory removed on drop: a root CA, an intermediate
/// CA under it that signs client certificates, the router's certificate under the root, and
/// the key that signs tickets.
struct Fixture {
    dir: PathBuf,
    ticket_key: KeyPair,
}

impl Fixture {
    fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "zenoh-remote-api-{name}-{}-{}",
            std::process::id(),
            get_current_timestamp()
        ));
        std::fs::create_dir_all(&dir).unwrap();

        let root_key = KeyPair::generate().unwrap();
        let root_params = ca_params("Test Root CA");
        let root = root_params.self_signed(&root_key).unwrap();
        let root_issuer = Issuer::new(root_params, &root_key);

        let gateway_key = KeyPair::generate().unwrap();
        let gateway = ca_params("Test Gateway CA")
            .signed_by(&gateway_key, &root_issuer)
            .unwrap();

        let router_key = KeyPair::generate().unwrap();
        let mut router_params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        router_params
            .subject_alt_names
            .push(SanType::IpAddress([127, 0, 0, 1].into()));
        router_params
            .distinguished_name
            .push(DnType::CommonName, "test-router");
        let router = router_params.signed_by(&router_key, &root_issuer).unwrap();

        let fixture = Fixture {
            dir,
            ticket_key: KeyPair::generate().unwrap(),
        };
        fixture.write("root.pem", &root.pem());
        fixture.write("gateway-ca.pem", &gateway.pem());
        fixture.write("gateway-ca.key", &gateway_key.serialize_pem());
        fixture.write("router.pem", &router.pem());
        fixture.write("router.key", &router_key.serialize_pem());
        fixture
    }

    fn write(&self, file: &str, contents: &str) {
        std::fs::write(self.dir.join(file), contents).unwrap();
    }

    fn path(&self, file: &str) -> String {
        self.dir.join(file).to_str().unwrap().to_string()
    }

    /// The plugin's `authentication` section, its client sessions connecting to `port`.
    fn authentication(&self, port: u16) -> Value {
        json!({
            "ticket": {
                "public_keys": [self.ticket_key.public_key_pem()],
                "issuer": ISSUER,
                "audience": AUDIENCE,
                "principal_prefix": "u:",
                "leeway_secs": 30,
            },
            "client_session": {
                "connect": format!("tls/127.0.0.1:{port}"),
                "root_ca_certificate": self.path("root.pem"),
                "signing_certificate": self.path("gateway-ca.pem"),
                "signing_private_key": self.path("gateway-ca.key"),
                "certificate_validity_secs": 3600,
                "verify_name_on_connect": true,
            },
        })
    }

    /// A ticket for `sub`, signed by `key`, expiring `ttl_secs` from now.
    fn ticket_signed_by(key: &KeyPair, sub: &str, ttl_secs: i64) -> String {
        let now = get_current_timestamp() as i64;
        let claims = json!({
            "iss": ISSUER,
            "aud": AUDIENCE,
            "sub": sub,
            "iat": now.min(now + ttl_secs - 60),
            "exp": now + ttl_secs,
            "jti": format!("{sub}-{now}"),
        });
        let key = EncodingKey::from_ec_pem(key.serialize_pem().as_bytes()).unwrap();
        encode(&Header::new(Algorithm::ES256), &claims, &key).unwrap()
    }

    fn ticket(&self, sub: &str) -> String {
        Self::ticket_signed_by(&self.ticket_key, sub, 300)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn ca_params(name: &str) -> CertificateParams {
    let mut params = CertificateParams::default();
    params.distinguished_name = DistinguishedName::new();
    params.distinguished_name.push(DnType::CommonName, name);
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// A router with a TLS listener that requires client certificates and the ACL above, running
/// the plugin with `plugin_config`, and a session on its runtime that observes.
///
/// The router is left running when a test ends: closing a runtime while the plugin's tasks
/// still hold sessions on it makes Zenoh panic when the test's executor drops those tasks.
struct Router {
    observer: Session,
    ws_port: u16,
}

impl Router {
    async fn start(fixture: &Fixture, tls_port: u16, plugin_config: Value) -> Router {
        let ws_port = free_port();
        let mut plugin_config = plugin_config;
        plugin_config["websocket_port"] = json!(format!("127.0.0.1:{ws_port}"));
        let config = json!({
            "mode": "router",
            "listen": { "endpoints": [format!("tls/127.0.0.1:{tls_port}")] },
            "scouting": { "multicast": { "enabled": false }, "gossip": { "enabled": false } },
            "transport": { "link": { "tls": {
                "root_ca_certificate": fixture.path("root.pem"),
                "listen_certificate": fixture.path("router.pem"),
                "listen_private_key": fixture.path("router.key"),
                "enable_mtls": true,
            } } },
            "access_control": access_control(),
            "plugins_loading": { "enabled": true },
            "plugins": { "remote_api": plugin_config },
        });
        let config = zenoh::Config::from_json5(&config.to_string()).unwrap();

        let mut plugins = PluginsManager::static_plugins_only();
        plugins.declare_static_plugin::<RemoteApiPlugin, &str>("remote_api", true);
        let mut runtime = RuntimeBuilder::new(config)
            .plugins_manager(plugins)
            .build()
            .await
            .unwrap();
        runtime.start().await.unwrap();
        let observer = zenoh::session::init(DynamicRuntime::from(runtime.clone()))
            .await
            .unwrap();

        let deadline = Instant::now() + PATIENCE;
        while TcpStream::connect(("127.0.0.1", ws_port)).await.is_err() {
            assert!(Instant::now() < deadline, "the WebSocket port never opened");
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        Router { observer, ws_port }
    }

    fn url(&self, ticket: Option<&str>) -> String {
        match ticket {
            Some(ticket) => format!("ws://127.0.0.1:{}/?ticket={ticket}", self.ws_port),
            None => format!("ws://127.0.0.1:{}/", self.ws_port),
        }
    }

    /// The Common Names of the client certificates on the router's links.
    async fn authenticated_links(&self) -> Vec<String> {
        self.observer
            .info()
            .links()
            .await
            .filter_map(|link| link.auth_identifier().map(str::to_string))
            .collect()
    }

    /// Records every sample on `demo/alice` and `demo/bob` that reaches the router.
    async fn observe(&self) -> Arc<Mutex<Vec<(String, String)>>> {
        let seen = Arc::new(Mutex::new(Vec::new()));
        for key in ["demo/alice", "demo/bob"] {
            let sink = seen.clone();
            self.observer
                .declare_subscriber(key)
                .callback(move |sample| {
                    sink.lock().unwrap().push((
                        sample.key_expr().to_string(),
                        sample.payload().try_to_string().unwrap().into_owned(),
                    ))
                })
                .background()
                .await
                .unwrap();
        }
        seen
    }
}

/// Just enough of the remote-api wire protocol to subscribe and put.
mod wire {
    use super::*;

    const DECLARE_SUBSCRIBER: u8 = 2;
    const PUT: u8 = 14;
    const ACK_REQUESTED: u8 = 0b1000_0000;
    const OK: u8 = 1;
    const ERROR: u8 = 2;
    const SAMPLE: u8 = 5;
    const LOCALITY_ANY: u8 = 2;
    /// Priority `Data`, reliable, any locality.
    const QOS: u8 = 5 | (1 << 5) | (LOCALITY_ANY << 6);

    pub(super) fn declare_subscriber(sequence: u32, id: u32, key: &str) -> Vec<u8> {
        let mut s = ZSerializer::new();
        s.serialize(DECLARE_SUBSCRIBER | ACK_REQUESTED);
        s.serialize(sequence);
        s.serialize(id);
        s.serialize(key);
        s.serialize(LOCALITY_ANY);
        s.finish().to_bytes().to_vec()
    }

    pub(super) fn put(sequence: u32, key: &str, payload: &str) -> Vec<u8> {
        let mut s = ZSerializer::new();
        s.serialize(PUT | ACK_REQUESTED);
        s.serialize(sequence);
        s.serialize(key);
        s.serialize(payload.as_bytes().to_vec());
        s.serialize((0u16, String::new()));
        s.serialize(false); // no attachment
        s.serialize(false); // no timestamp
        s.serialize(QOS);
        s.finish().to_bytes().to_vec()
    }

    pub(super) enum Reply {
        Ok(u32),
        Error(u32, String),
        Sample { key: String, payload: String },
        Other,
    }

    pub(super) fn parse(bytes: Vec<u8>) -> Reply {
        let bytes = ZBytes::from(bytes);
        let mut d = ZDeserializer::new(&bytes);
        let header: u8 = d.deserialize().unwrap();
        let sequence = (header & ACK_REQUESTED != 0).then(|| d.deserialize::<u32>().unwrap());
        match header & !ACK_REQUESTED {
            OK => Reply::Ok(sequence.unwrap()),
            ERROR => Reply::Error(sequence.unwrap(), d.deserialize().unwrap()),
            SAMPLE => {
                let _subscriber: u32 = d.deserialize().unwrap();
                let key: String = d.deserialize().unwrap();
                let payload: Vec<u8> = d.deserialize().unwrap();
                Reply::Sample {
                    key,
                    payload: String::from_utf8(payload).unwrap(),
                }
            }
            _ => Reply::Other,
        }
    }
}

/// A WebSocket client of the plugin.
struct Client {
    ws: WebSocketStream<MaybeTlsStream<TcpStream>>,
    sequence: u32,
    samples: Vec<(String, String)>,
}

impl Client {
    async fn connect(url: &str) -> Result<Client, tungstenite::Error> {
        let (ws, response) = connect_async(url).await?;
        assert_eq!(response.status(), StatusCode::SWITCHING_PROTOCOLS);
        Ok(Client {
            ws,
            sequence: 0,
            samples: Vec::new(),
        })
    }

    /// Sends a request built for the next sequence number and waits for its acknowledgement.
    async fn request(&mut self, build: impl FnOnce(u32) -> Vec<u8>) {
        self.sequence += 1;
        let sequence = self.sequence;
        self.ws
            .send(Message::binary(build(sequence)))
            .await
            .unwrap();
        let deadline = Instant::now() + PATIENCE;
        loop {
            let message = tokio::time::timeout_at(deadline.into(), self.ws.next())
                .await
                .expect("no acknowledgement")
                .expect("WebSocket closed")
                .unwrap();
            match wire::parse(message.into_data().to_vec()) {
                wire::Reply::Ok(s) if s == sequence => return,
                wire::Reply::Error(s, error) if s == sequence => panic!("request refused: {error}"),
                wire::Reply::Sample { key, payload } => self.samples.push((key, payload)),
                _ => {}
            }
        }
    }

    /// Collects samples for `duration`.
    async fn receive_for(&mut self, duration: Duration) {
        let deadline = Instant::now() + duration;
        while let Ok(Some(Ok(message))) =
            tokio::time::timeout_at(deadline.into(), self.ws.next()).await
        {
            if let Message::Binary(data) = message {
                if let wire::Reply::Sample { key, payload } = wire::parse(data.to_vec()) {
                    self.samples.push((key, payload));
                }
            }
        }
    }

    fn received(&self, key: &str, payload: &str) -> bool {
        self.samples.iter().any(|(k, p)| k == key && p == payload)
    }
}

fn status_of(result: Result<Client, tungstenite::Error>) -> StatusCode {
    match result {
        Ok(_) => StatusCode::SWITCHING_PROTOCOLS,
        Err(tungstenite::Error::Http(response)) => response.status(),
        Err(e) => panic!("unexpected WebSocket error: {e}"),
    }
}

/// Subscribes to and puts on `demo/alice` and `demo/bob` through `client`, while the
/// observer puts on both, until the allowed exchange has happened both ways or `PATIENCE`
/// runs out. Returns what the observer saw.
async fn exchange(router: &Router, client: &mut Client) -> Arc<Mutex<Vec<(String, String)>>> {
    let observed = router.observe().await;
    client
        .request(|s| wire::declare_subscriber(s, 1, "demo/alice"))
        .await;
    client
        .request(|s| wire::declare_subscriber(s, 2, "demo/bob"))
        .await;

    let deadline = Instant::now() + PATIENCE;
    loop {
        client
            .request(|s| wire::put(s, "demo/alice", "from client"))
            .await;
        client
            .request(|s| wire::put(s, "demo/bob", "from client"))
            .await;
        router
            .observer
            .put("demo/alice", "from router")
            .await
            .unwrap();
        router
            .observer
            .put("demo/bob", "from router")
            .await
            .unwrap();
        client.receive_for(Duration::from_millis(200)).await;

        let observer_got_alice = observed
            .lock()
            .unwrap()
            .contains(&("demo/alice".into(), "from client".into()));
        if observer_got_alice && client.received("demo/alice", "from router") {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the allowed exchange never happened"
        );
    }
    // Give anything denied the same time again to show up.
    client.receive_for(Duration::from_millis(500)).await;
    observed
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn upgrade_requires_a_valid_ticket_and_the_session_is_subject_to_the_acl() {
    zenoh::init_log_from_env_or("error");
    let fixture = Fixture::new("acl");
    let tls_port = free_port();
    let router = Router::start(
        &fixture,
        tls_port,
        json!({ "authentication": fixture.authentication(tls_port) }),
    )
    .await;

    // Refused before any session exists.
    assert_eq!(
        status_of(Client::connect(&router.url(None)).await),
        StatusCode::UNAUTHORIZED
    );
    let stranger = KeyPair::generate().unwrap();
    for bad in [
        "not-a-ticket".to_string(),
        Fixture::ticket_signed_by(&stranger, "alice", 300),
        Fixture::ticket_signed_by(&fixture.ticket_key, "alice", -120),
        fixture.ticket("a/b"),
    ] {
        assert_eq!(
            status_of(Client::connect(&router.url(Some(&bad))).await),
            StatusCode::UNAUTHORIZED
        );
    }
    assert!(router.authenticated_links().await.is_empty());

    // Admitted, and seen by the router as u:alice.
    let mut alice = Client::connect(&router.url(Some(&fixture.ticket("alice"))))
        .await
        .unwrap();
    let deadline = Instant::now() + PATIENCE;
    while router.authenticated_links().await != ["u:alice"] {
        assert!(
            Instant::now() < deadline,
            "no link authenticated as u:alice"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // The router's access control applies: demo/alice flows both ways, demo/bob neither.
    let observed = exchange(&router, &mut alice).await.lock().unwrap().clone();
    assert!(observed.contains(&("demo/alice".into(), "from client".into())));
    assert!(
        !observed.contains(&("demo/bob".into(), "from client".into())),
        "a denied put reached the router: {observed:?}"
    );
    assert!(alice.received("demo/alice", "from router"));
    assert!(
        !alice.received("demo/bob", "from router"),
        "a denied subscription received: {:?}",
        alice.samples
    );

    // The session closes with the WebSocket.
    alice.ws.close(None).await.unwrap();
    let deadline = Instant::now() + PATIENCE;
    while !router.authenticated_links().await.is_empty() {
        assert!(
            Instant::now() < deadline,
            "the session outlived its WebSocket"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn websocket_closes_with_an_error_when_the_session_cannot_open() {
    zenoh::init_log_from_env_or("error");
    let fixture = Fixture::new("unreachable");
    let tls_port = free_port();
    // Client sessions aim at a port nothing listens on.
    let router = Router::start(
        &fixture,
        tls_port,
        json!({ "authentication": fixture.authentication(free_port()) }),
    )
    .await;

    let mut client = Client::connect(&router.url(Some(&fixture.ticket("alice"))))
        .await
        .unwrap();
    let close = tokio::time::timeout(PATIENCE, async {
        loop {
            match client.ws.next().await {
                Some(Ok(Message::Close(frame))) => return frame,
                Some(Ok(_)) => continue,
                other => panic!("expected a close frame, got {other:?}"),
            }
        }
    })
    .await
    .expect("the WebSocket stayed open");
    assert_eq!(close.unwrap().code, CloseCode::Error);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn plugin_refuses_to_start_with_unusable_authentication() {
    zenoh::init_log_from_env_or("error");
    let fixture = Fixture::new("misconfigured");
    let start = |mut plugin_config: Value| {
        plugin_config["websocket_port"] = json!(format!("127.0.0.1:{}", free_port()));
        let config = json!({
            "mode": "router",
            "listen": { "endpoints": [] },
            "scouting": { "multicast": { "enabled": false }, "gossip": { "enabled": false } },
            "plugins": { "remote_api": plugin_config },
        });
        async move {
            let config = zenoh::Config::from_json5(&config.to_string()).unwrap();
            let runtime = RuntimeBuilder::new(config).build().await.unwrap();
            RemoteApiPlugin::start("remote_api", &DynamicRuntime::from(runtime))
                .err()
                .map(|e| e.to_string())
        }
    };

    let mut authentication = fixture.authentication(free_port());
    authentication
        .as_object_mut()
        .unwrap()
        .remove("client_session");
    let error = start(json!({ "authentication": authentication })).await;
    assert!(error.is_some_and(|e| e.contains("client_session")));

    let mut authentication = fixture.authentication(free_port());
    authentication.as_object_mut().unwrap().remove("ticket");
    let error = start(json!({ "authentication": authentication })).await;
    assert!(error.is_some_and(|e| e.contains("ticket")));

    let mut authentication = fixture.authentication(free_port());
    authentication["client_session"]["signing_private_key"] = json!(fixture.path("router.key"));
    let error = start(json!({ "authentication": authentication }))
        .await
        .unwrap();
    assert!(error.contains("signing_private_key"), "{error}");
    assert!(!error.contains("BEGIN"), "{error}");

    let mut authentication = fixture.authentication(free_port());
    authentication["client_session"]["connect"] = json!("tcp/127.0.0.1:7447");
    let error = start(json!({ "authentication": authentication }))
        .await
        .unwrap();
    assert!(error.contains("connect"), "{error}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn without_authentication_sessions_bypass_the_acl() {
    zenoh::init_log_from_env_or("error");
    let fixture = Fixture::new("stock");
    let router = Router::start(&fixture, free_port(), json!({})).await;

    // No ticket needed, and nothing the router's access control can see.
    let mut client = Client::connect(&router.url(None)).await.unwrap();
    let observed = exchange(&router, &mut client).await.lock().unwrap().clone();
    assert!(observed.contains(&("demo/bob".into(), "from client".into())));
    assert!(client.received("demo/bob", "from router"));
    assert!(router.authenticated_links().await.is_empty());
}
