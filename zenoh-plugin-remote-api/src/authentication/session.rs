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

//! The client session opened to the router for one authenticated WebSocket.

use std::{str::FromStr, time::Duration};

use base64::{engine::general_purpose::STANDARD, Engine};
use rustls::RootCertStore;
use serde_json::json;
use zenoh::{config::EndPoint, Session};
use zenoh_result::{bail, zerror, ZResult};
use zeroize::Zeroizing;

use super::{
    certificate::{ClientCertificateIssuer, ClientIdentity},
    principal::Principal,
};
use crate::config::ClientSessionConfig;

/// Opens client sessions to the router, each authenticated by a certificate minted for its
/// principal.
pub(crate) struct ClientSessionOpener {
    endpoint: String,
    root_ca_certificate_base64: String,
    verify_name_on_connect: bool,
    certificates: ClientCertificateIssuer,
}

impl ClientSessionOpener {
    /// Reads the files `config` names. Errors name the field at fault, never file contents.
    ///
    /// Everything Zenoh's TLS connector parses from the endpoint and the trust anchors is
    /// checked here: when the connector fails to build its configuration, Zenoh logs the
    /// endpoint with every TLS setting, the client's private key included.
    pub(crate) fn new(config: &ClientSessionConfig) -> ZResult<Self> {
        let endpoint = EndPoint::from_str(&config.connect)
            .map_err(|e| zerror!("`client_session.connect`: {e}"))?;
        if endpoint.protocol().as_str() != "tls" {
            bail!("`client_session.connect` must be a `tls/` endpoint, for the router to authenticate the client certificate");
        }
        if !endpoint.metadata().as_str().is_empty() || !endpoint.config().as_str().is_empty() {
            bail!("`client_session.connect` must be a bare `tls/<host>:<port>`, without `?` metadata or `#` configuration");
        }

        let root_ca_certificate = read(&config.root_ca_certificate, "root_ca_certificate")?;
        check_trust_anchors(&root_ca_certificate)?;

        let signing_certificate = read(&config.signing_certificate, "signing_certificate")?;
        let signing_private_key =
            Zeroizing::new(read(&config.signing_private_key, "signing_private_key")?);
        let certificates = ClientCertificateIssuer::new(
            &signing_certificate,
            &signing_private_key,
            Duration::from_secs(config.certificate_validity_secs),
        )
        .map_err(|e| zerror!("`client_session`: {e}"))?;

        Ok(ClientSessionOpener {
            endpoint: endpoint.to_string(),
            root_ca_certificate_base64: STANDARD.encode(&root_ca_certificate),
            verify_name_on_connect: config.verify_name_on_connect,
            certificates,
        })
    }

    /// Opens a client session to the router as `principal`.
    pub(crate) async fn open(&self, principal: &Principal) -> ZResult<Session> {
        let identity = self.certificates.issue(principal)?;
        zenoh::open(self.session_config(&identity)?).await
    }

    /// A client-mode configuration that connects to the router's endpoint only, presenting
    /// `identity`. Zenoh's TLS connector trusts the configured root for the router's
    /// certificate, on top of the public Web PKI roots it always trusts.
    fn session_config(&self, identity: &ClientIdentity) -> ZResult<zenoh::Config> {
        let mut config = zenoh::Config::default();
        let mut set = |key: &str, json: &str| {
            config
                .insert_json5(key, json)
                .map_err(|e| zerror!("client session configuration `{key}`: {e}"))
        };
        set("mode", &json!("client").to_string())?;
        set("scouting/multicast/enabled", "false")?;
        set("scouting/gossip/enabled", "false")?;
        set("connect/endpoints", &json!([self.endpoint]).to_string())?;
        set(
            "transport/link/tls/root_ca_certificate_base64",
            &json!(self.root_ca_certificate_base64).to_string(),
        )?;
        // A Zenoh TLS connector presents a client certificate only when its own
        // configuration enables mTLS.
        set("transport/link/tls/enable_mtls", "true")?;
        set(
            "transport/link/tls/connect_certificate_base64",
            &json!(STANDARD.encode(&identity.certificate_chain_pem)).to_string(),
        )?;
        // Base64 needs no JSON escaping, so the key's JSON is built directly, in a buffer that
        // is wiped on drop.
        let private_key_base64 =
            Zeroizing::new(STANDARD.encode(identity.private_key_pem.as_bytes()));
        let private_key_json = Zeroizing::new(format!("\"{}\"", *private_key_base64));
        set(
            "transport/link/tls/connect_private_key_base64",
            &private_key_json,
        )?;
        set(
            "transport/link/tls/verify_name_on_connect",
            &json!(self.verify_name_on_connect).to_string(),
        )?;
        Ok(config)
    }
}

/// Checks that `pem` holds certificates, all usable as trust anchors, as Zenoh's TLS
/// connector requires.
fn check_trust_anchors(pem: &[u8]) -> ZResult<()> {
    let certificates = rustls_pemfile::certs(&mut &*pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| zerror!("`client_session.root_ca_certificate` is not valid PEM"))?;
    if certificates.is_empty() {
        bail!("`client_session.root_ca_certificate` holds no certificate");
    }
    let mut roots = RootCertStore::empty();
    for (index, certificate) in certificates.into_iter().enumerate() {
        roots.add(certificate).map_err(|e| {
            zerror!("`client_session.root_ca_certificate`: certificate {index} is not a usable trust anchor: {e}")
        })?;
    }
    Ok(())
}

fn read(path: &str, field: &str) -> ZResult<Vec<u8>> {
    std::fs::read(path)
        .map_err(|e| zerror!("`client_session.{field}`: cannot read {path}: {e}").into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authentication::certificate::tests::TestPki;

    fn opener(pki: &TestPki) -> ClientSessionOpener {
        ClientSessionOpener {
            endpoint: "tls/127.0.0.1:7448".into(),
            root_ca_certificate_base64: STANDARD.encode(pki.root.pem()),
            verify_name_on_connect: true,
            certificates: pki.issuer(Duration::from_secs(3600)),
        }
    }

    fn identity(opener: &ClientSessionOpener) -> ClientIdentity {
        opener
            .certificates
            .issue(&Principal::new("u:", "alice").unwrap())
            .unwrap()
    }

    #[test]
    fn session_connects_to_the_router_only_presenting_its_certificate() {
        let pki = TestPki::new();
        let opener = opener(&pki);
        let config = opener.session_config(&identity(&opener)).unwrap();
        let get = |key: &str| config.get_json(key).unwrap();
        assert_eq!(get("mode"), r#""client""#);
        assert_eq!(get("connect/endpoints"), r#"["tls/127.0.0.1:7448"]"#);
        assert_eq!(get("scouting/multicast/enabled"), "false");
        assert_eq!(get("scouting/gossip/enabled"), "false");
        assert_eq!(get("transport/link/tls/enable_mtls"), "true");
        assert_eq!(get("transport/link/tls/verify_name_on_connect"), "true");
        for key in [
            "root_ca_certificate_base64",
            "connect_certificate_base64",
            "connect_private_key_base64",
        ] {
            assert_ne!(get(&format!("transport/link/tls/{key}")), "null", "{key}");
        }
    }

    #[test]
    fn session_configuration_never_shows_its_key_material() {
        let pki = TestPki::new();
        let opener = opener(&pki);
        let identity = identity(&opener);
        let config = opener.session_config(&identity).unwrap();
        let key = STANDARD.encode(identity.private_key_pem.as_bytes());
        let chain = STANDARD.encode(&identity.certificate_chain_pem);
        for shown in [
            format!("{config:?}"),
            config.get_json("transport/link/tls").unwrap(),
        ] {
            assert!(!shown.contains(&key[..32]));
            assert!(!shown.contains(&chain[..32]));
        }
    }

    #[test]
    fn connect_must_be_a_tls_endpoint() {
        let config = |connect: &str| ClientSessionConfig {
            connect: connect.into(),
            root_ca_certificate: "/nonexistent/ca.pem".into(),
            signing_certificate: "/nonexistent/gateway-ca.pem".into(),
            signing_private_key: "/nonexistent/gateway-ca.key".into(),
            certificate_validity_secs: 3600,
            verify_name_on_connect: true,
        };
        for connect in [
            "tcp/127.0.0.1:7448",
            "quic/127.0.0.1:7448",
            "not an endpoint",
            "tls/127.0.0.1:7448#so_sndbuf=65000",
            "tls/127.0.0.1:7448?prio=1-7",
        ] {
            let error = ClientSessionOpener::new(&config(connect))
                .err()
                .unwrap()
                .to_string();
            assert!(error.contains("client_session.connect"), "{error}");
        }
        let error = ClientSessionOpener::new(&config("tls/127.0.0.1:7448"))
            .err()
            .unwrap()
            .to_string();
        assert!(error.contains("root_ca_certificate"), "{error}");
    }

    #[test]
    fn trust_anchors_are_checked_one_by_one() {
        let pki = TestPki::new();
        let root = pki.root.pem();
        assert!(check_trust_anchors(root.as_bytes()).is_ok());
        assert!(
            check_trust_anchors(format!("{root}{}", pki.intermediate.pem()).as_bytes()).is_ok()
        );
        assert!(check_trust_anchors(b"").is_err());
        let corrupt = pem::encode(&pem::Pem::new("CERTIFICATE", vec![0x30, 0x03, 1, 2, 3]));
        let error = check_trust_anchors(format!("{root}{corrupt}").as_bytes())
            .err()
            .unwrap()
            .to_string();
        assert!(error.contains("certificate 1"), "{error}");
    }
}
