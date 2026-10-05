//
// Copyright (c) 2024 ZettaScale Technology
//
// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0, or the Apache License, Version 2.0
// which is available at https://www.apache.org/licenses/LICENSE-2.0.
//
// SPDX-License-Identifier: EPL-2.0 OR Apache-2.0
//
// Contributors:
//   ZettaScale Zenoh Team, <zenoh@zettascale.tech>
//
use std::fmt;

use schemars::JsonSchema;
use serde::{
    de,
    de::{Unexpected, Visitor},
    Deserialize, Deserializer,
};

const DEFAULT_HTTP_INTERFACE: &str = "[::]";
const DEFAULT_WEBSOCKET_PORT: &str = "10000";

#[derive(JsonSchema, Deserialize, serde::Serialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(
        default = "default_websocket_port",
        deserialize_with = "deserialize_ws_port"
    )]
    pub websocket_port: String,

    pub secure_websocket: Option<SecureWebsocket>,

    /// When present, every WebSocket client must present a ticket, and gets its own client
    /// session to the router, authenticated as the ticket's principal. When absent, every
    /// client gets a session on the router's own runtime, which no access control sees.
    pub authentication: Option<Authentication>,

    #[serde(default, deserialize_with = "deserialize_path")]
    __path__: Option<Vec<String>>,
    __required__: Option<bool>,
    __config__: Option<String>,
}

#[derive(JsonSchema, Deserialize, serde::Serialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct SecureWebsocket {
    pub certificate_path: String,
    pub private_key_path: String,
}

#[derive(JsonSchema, Deserialize, serde::Serialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct Authentication {
    pub ticket: TicketConfig,
    pub client_session: ClientSessionConfig,
}

/// How the `ticket` query parameter of a WebSocket upgrade request is verified. A ticket is a
/// compact JWT signed with ES256 that carries `iss`, `aud`, `sub`, `iat`, `exp` and `jti`.
#[derive(JsonSchema, Deserialize, serde::Serialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct TicketConfig {
    /// EC P-256 public keys as SPKI PEM (`-----BEGIN PUBLIC KEY-----`). A ticket is accepted
    /// when any of them verifies its signature, so a new key can be added before the old one
    /// is retired.
    pub public_keys: Vec<String>,
    /// The only accepted `iss` claim.
    pub issuer: String,
    /// The only accepted `aud` claim.
    pub audience: String,
    /// Prepended to the `sub` claim to form the principal: the Common Name of the client
    /// certificate, which the router's access control matches.
    pub principal_prefix: String,
    /// Clock skew tolerated on `exp`, `iat` and `nbf`, at most 300.
    #[serde(default = "default_leeway_secs")]
    pub leeway_secs: u64,
}

/// The client session opened to the router for each authenticated WebSocket.
#[derive(JsonSchema, Deserialize, serde::Serialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct ClientSessionConfig {
    /// The router's TLS endpoint for these sessions, e.g. `tls/127.0.0.1:7448`, without
    /// metadata or configuration. The router authenticates the principal only if this
    /// listener requires client certificates.
    pub connect: String,
    /// Path to the PEM trust anchors for the router's certificate. Zenoh's TLS connector
    /// trusts the public Web PKI roots as well.
    pub root_ca_certificate: String,
    /// Path to the PEM certificate of the CA that signs the client certificates, optionally
    /// followed by the intermediates between it and the router's trust anchor. Every
    /// certificate in the file is sent after the client certificate.
    pub signing_certificate: String,
    /// Path to the signing CA's private key, as unencrypted PKCS#8 PEM
    /// (`-----BEGIN PRIVATE KEY-----`).
    pub signing_private_key: String,
    /// Lifetime of each client certificate.
    #[serde(default = "default_certificate_validity_secs")]
    pub certificate_validity_secs: u64,
    /// Whether the router's certificate must name the host in `connect`.
    #[serde(default = "default_verify_name_on_connect")]
    pub verify_name_on_connect: bool,
}

fn default_leeway_secs() -> u64 {
    30
}

fn default_certificate_validity_secs() -> u64 {
    86400
}

fn default_verify_name_on_connect() -> bool {
    true
}

impl From<&Config> for serde_json::Value {
    fn from(c: &Config) -> Self {
        serde_json::to_value(c).unwrap()
    }
}

fn default_websocket_port() -> String {
    format!("{}:{}", DEFAULT_HTTP_INTERFACE, DEFAULT_WEBSOCKET_PORT)
}

fn deserialize_ws_port<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    deserializer.deserialize_any(WebsocketVisitor)
}

struct WebsocketVisitor;

impl Visitor<'_> for WebsocketVisitor {
    type Value = String;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str(r#"either a port number as an integer or a string, either a string with format "<local_ip>:<port_number>""#)
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(format!("{DEFAULT_HTTP_INTERFACE}:{value}"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        let parts: Vec<&str> = value.split(':').collect();
        if parts.len() > 2 {
            return Err(E::invalid_value(Unexpected::Str(value), &self));
        }
        let (interface, port) = if parts.len() == 1 {
            (DEFAULT_HTTP_INTERFACE, parts[0])
        } else {
            (parts[0], parts[1])
        };
        if port.parse::<u32>().is_err() {
            return Err(E::invalid_value(Unexpected::Str(port), &self));
        }
        Ok(format!("{interface}:{port}"))
    }
}

fn deserialize_path<'de, D>(deserializer: D) -> Result<Option<Vec<String>>, D::Error>
where
    D: Deserializer<'de>,
{
    deserializer.deserialize_option(OptPathVisitor)
}

struct OptPathVisitor;

impl<'de> serde::de::Visitor<'de> for OptPathVisitor {
    type Value = Option<Vec<String>>;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(formatter, "none or a string or an array of strings")
    }

    fn visit_none<E>(self) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(None)
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(PathVisitor).map(Some)
    }
}

struct PathVisitor;

impl<'de> serde::de::Visitor<'de> for PathVisitor {
    type Value = Vec<String>;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(formatter, "a string or an array of strings")
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(vec![v.into()])
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: de::SeqAccess<'de>,
    {
        let mut v = seq.size_hint().map_or_else(Vec::new, Vec::with_capacity);

        while let Some(s) = seq.next_element()? {
            v.push(s);
        }
        Ok(v)
    }
}

#[cfg(test)]
mod tests {
    use super::{Config, DEFAULT_HTTP_INTERFACE, DEFAULT_WEBSOCKET_PORT};

    #[test]
    fn test_path_field() {
        // See: https://github.com/eclipse-zenoh/zenoh-plugin-webserver/issues/19
        let config = serde_json::from_str::<Config>(
            r#"{"__path__": "/example/path", "websocket_port": 8080}"#,
        );

        assert!(config.is_ok());
        let Config {
            websocket_port,
            __required__,
            __path__,
            ..
        } = config.unwrap();

        assert_eq!(websocket_port, format!("{DEFAULT_HTTP_INTERFACE}:8080"));
        assert_eq!(__path__, Some(vec![String::from("/example/path")]));
        assert_eq!(__required__, None);
    }

    #[test]
    fn test_required_field() {
        // See: https://github.com/eclipse-zenoh/zenoh-plugin-webserver/issues/19
        let config =
            serde_json::from_str::<Config>(r#"{"__required__": true, "websocket_port": 8080}"#);
        assert!(config.is_ok());
        let Config {
            websocket_port,
            __required__,
            __path__,
            ..
        } = config.unwrap();

        assert_eq!(websocket_port, format!("{DEFAULT_HTTP_INTERFACE}:8080"));
        assert_eq!(__path__, None);
        assert_eq!(__required__, Some(true));
    }

    #[test]
    fn test_path_field_and_required_field() {
        // See: https://github.com/eclipse-zenoh/zenoh-plugin-webserver/issues/19
        let config = serde_json::from_str::<Config>(
            r#"{"__path__": "/example/path", "__required__": true, "websocket_port": 8080}"#,
        );

        assert!(config.is_ok());
        let Config {
            websocket_port,
            __required__,
            __path__,
            ..
        } = config.unwrap();

        assert_eq!(websocket_port, format!("{DEFAULT_HTTP_INTERFACE}:8080"));
        assert_eq!(__path__, Some(vec![String::from("/example/path")]));
        assert_eq!(__required__, Some(true));
    }

    #[test]
    fn test_no_path_field_and_no_required_field() {
        // See: https://github.com/eclipse-zenoh/zenoh-plugin-webserver/issues/19
        let config = serde_json::from_str::<Config>(r#"{"websocket_port": 8080}"#);

        assert!(config.is_ok());
        let Config {
            websocket_port,
            __required__,
            __path__,
            ..
        } = config.unwrap();

        assert_eq!(websocket_port, format!("{DEFAULT_HTTP_INTERFACE}:8080"));
        assert_eq!(__path__, None);
        assert_eq!(__required__, None);
    }

    #[test]
    fn test_default_websocket_port() {
        // Test that the default websocket_port is used when not specified
        let config = serde_json::from_str::<Config>(r#"{}"#);

        assert!(config.is_ok());
        let Config {
            websocket_port,
            __required__,
            __path__,
            ..
        } = config.unwrap();

        assert_eq!(
            websocket_port,
            format!("{DEFAULT_HTTP_INTERFACE}:{DEFAULT_WEBSOCKET_PORT}")
        );
        assert_eq!(__path__, None);
        assert_eq!(__required__, None);
    }

    const AUTHENTICATION: &str = r#"{
        "websocket_port": "127.0.0.1:8080",
        "authentication": {
            "ticket": {
                "public_keys": ["-----BEGIN PUBLIC KEY-----\nA\n-----END PUBLIC KEY-----\n"],
                "issuer": "semio-studio",
                "audience": "semio-bridge",
                "principal_prefix": "u:",
                "leeway_secs": 30
            },
            "client_session": {
                "connect": "tls/127.0.0.1:7448",
                "root_ca_certificate": "/certs/ca.pem",
                "signing_certificate": "/certs/gateway-ca.pem",
                "signing_private_key": "/certs/gateway-ca.key",
                "certificate_validity_secs": 86400,
                "verify_name_on_connect": true
            }
        }
    }"#;

    #[test]
    fn authentication_is_absent_by_default() {
        let config = serde_json::from_str::<Config>(r#"{"websocket_port": 8080}"#).unwrap();
        assert!(config.authentication.is_none());
    }

    #[test]
    fn authentication_fields() {
        let config = serde_json::from_str::<Config>(AUTHENTICATION).unwrap();
        let authentication = config.authentication.unwrap();
        let ticket = authentication.ticket;
        assert_eq!(ticket.public_keys.len(), 1);
        assert_eq!(ticket.issuer, "semio-studio");
        assert_eq!(ticket.audience, "semio-bridge");
        assert_eq!(ticket.principal_prefix, "u:");
        assert_eq!(ticket.leeway_secs, 30);
        let session = authentication.client_session;
        assert_eq!(session.connect, "tls/127.0.0.1:7448");
        assert_eq!(session.root_ca_certificate, "/certs/ca.pem");
        assert_eq!(session.signing_certificate, "/certs/gateway-ca.pem");
        assert_eq!(session.signing_private_key, "/certs/gateway-ca.key");
        assert_eq!(session.certificate_validity_secs, 86400);
        assert!(session.verify_name_on_connect);
    }

    #[test]
    fn authentication_defaults() {
        let mut config: serde_json::Value = serde_json::from_str(AUTHENTICATION).unwrap();
        let authentication = &mut config["authentication"];
        authentication["ticket"]
            .as_object_mut()
            .unwrap()
            .remove("leeway_secs");
        let session = authentication["client_session"].as_object_mut().unwrap();
        session.remove("certificate_validity_secs");
        session.remove("verify_name_on_connect");
        let authentication = serde_json::from_value::<Config>(config)
            .unwrap()
            .authentication
            .unwrap();
        assert_eq!(authentication.ticket.leeway_secs, 30);
        assert_eq!(
            authentication.client_session.certificate_validity_secs,
            86400
        );
        assert!(authentication.client_session.verify_name_on_connect);
    }

    #[test]
    fn authentication_requires_both_ticket_and_client_session() {
        for part in ["ticket", "client_session"] {
            let mut config: serde_json::Value = serde_json::from_str(AUTHENTICATION).unwrap();
            config["authentication"]
                .as_object_mut()
                .unwrap()
                .remove(part);
            assert!(
                serde_json::from_value::<Config>(config).is_err(),
                "authentication without {part}"
            );
        }
    }

    #[test]
    fn authentication_rejects_unknown_fields() {
        let mut config: serde_json::Value = serde_json::from_str(AUTHENTICATION).unwrap();
        config["authentication"]["ticket"]["kid"] = "x".into();
        assert!(serde_json::from_value::<Config>(config).is_err());
    }
}
