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

//! Client certificates minted for one principal each, signed by the configured CA.

use std::time::Duration;

use rcgen::{
    CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, PKCS_ECDSA_P256_SHA256,
};
use time::OffsetDateTime;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use x509_parser::prelude::{FromDer, X509Certificate};
use zenoh_result::{bail, zerror, ZResult};
use zeroize::Zeroizing;

use super::principal::Principal;

/// How far back a client certificate's validity starts, so that a router whose clock runs
/// slightly behind this one still accepts it.
const CLOCK_SKEW_ALLOWANCE: Duration = Duration::from_secs(60);

/// Signs client certificates with the configured CA.
pub(crate) struct ClientCertificateIssuer {
    issuer: Issuer<'static, KeyPair>,
    /// The signing certificate and any intermediates, as PEM, sent after each client
    /// certificate.
    chain_pem: String,
    validity: Duration,
}

/// A client certificate and its private key, as the PEM a Zenoh TLS connector takes.
pub(crate) struct ClientIdentity {
    /// The client certificate followed by the signing certificate and any intermediates.
    pub(crate) certificate_chain_pem: String,
    /// The client certificate's PKCS#8 private key.
    pub(crate) private_key_pem: Zeroizing<String>,
}

impl ClientCertificateIssuer {
    /// An issuer for the CA certificate first in `signing_certificate_pem`, whose private key
    /// is `signing_private_key_pem`. Errors describe what is wrong without quoting either.
    pub(crate) fn new(
        signing_certificate_pem: &[u8],
        signing_private_key_pem: &[u8],
        validity: Duration,
    ) -> ZResult<Self> {
        let chain = rustls_pemfile::certs(&mut &*signing_certificate_pem)
            .collect::<Result<Vec<CertificateDer<'static>>, _>>()
            .map_err(|_| zerror!("`signing_certificate` is not valid PEM"))?;
        let Some(signing_certificate) = chain.first() else {
            bail!("`signing_certificate` holds no certificate");
        };

        let key = match rustls_pemfile::private_key(&mut &*signing_private_key_pem) {
            Ok(Some(key @ PrivateKeyDer::Pkcs8(_))) => KeyPair::try_from(&key)
                .map_err(|_| zerror!("`signing_private_key` is not a supported key type"))?,
            Ok(Some(_)) => bail!(
                "`signing_private_key` must be PKCS#8 (-----BEGIN PRIVATE KEY-----); \
                 convert it with `openssl pkcs8 -topk8 -nocrypt`"
            ),
            Ok(None) | Err(_) => bail!("`signing_private_key` holds no private key"),
        };

        check_signing_certificate(signing_certificate, &key)?;

        if validity.is_zero() {
            bail!("`certificate_validity_secs` must be positive");
        }

        let chain_pem = chain
            .iter()
            .map(|der| pem::encode(&pem::Pem::new("CERTIFICATE", der.to_vec())))
            .collect();
        let issuer = Issuer::from_ca_cert_der(signing_certificate, key)
            .map_err(|_| zerror!("`signing_certificate` cannot be read as a CA certificate"))?;

        Ok(ClientCertificateIssuer {
            issuer,
            chain_pem,
            validity,
        })
    }

    /// A fresh EC P-256 key and a certificate for it, whose Common Name is `principal`,
    /// usable only for TLS client authentication, valid for the configured lifetime.
    pub(crate) fn issue(&self, principal: &Principal) -> ZResult<ClientIdentity> {
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
            .map_err(|e| zerror!("cannot generate a client key: {e}"))?;

        let mut params = CertificateParams::default();
        params.distinguished_name = DistinguishedName::new();
        params
            .distinguished_name
            .push(DnType::CommonName, principal.as_str());
        params.is_ca = IsCa::ExplicitNoCa;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        params.use_authority_key_identifier_extension = true;
        let now = OffsetDateTime::now_utc();
        params.not_before = now - CLOCK_SKEW_ALLOWANCE;
        params.not_after = now + self.validity;

        let certificate = params
            .signed_by(&key, &self.issuer)
            .map_err(|e| zerror!("cannot sign a client certificate: {e}"))?;

        Ok(ClientIdentity {
            certificate_chain_pem: certificate.pem() + &self.chain_pem,
            private_key_pem: Zeroizing::new(key.serialize_pem()),
        })
    }
}

/// Checks that `certificate` is a CA certificate allowed to sign certificates, and that
/// `key` is its private key.
fn check_signing_certificate(certificate: &CertificateDer<'_>, key: &KeyPair) -> ZResult<()> {
    let (_, certificate) = X509Certificate::from_der(certificate)
        .map_err(|_| zerror!("`signing_certificate` is not a valid X.509 certificate"))?;
    if !certificate.is_ca() {
        bail!("`signing_certificate` is not a CA certificate (basicConstraints CA:TRUE)");
    }
    match certificate.key_usage() {
        Ok(Some(usage)) if !usage.value.key_cert_sign() => {
            bail!("`signing_certificate` does not allow signing certificates (keyCertSign)")
        }
        Ok(_) => {}
        Err(_) => bail!("`signing_certificate` has an invalid key usage extension"),
    }
    if !certificate.validity().is_valid() {
        bail!("`signing_certificate` is not valid now (notBefore/notAfter)");
    }
    if certificate.public_key().subject_public_key.data.as_ref() != key.public_key_raw() {
        bail!("`signing_private_key` is not the key of `signing_certificate`");
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use std::sync::Arc;

    use rcgen::{BasicConstraints, Certificate, KeyUsagePurpose, SanType};
    use tokio_rustls::rustls::{
        crypto::ring::default_provider, pki_types::UnixTime, server::WebPkiClientVerifier,
        RootCertStore,
    };
    use x509_parser::{extensions::ParsedExtension, prelude::X509Certificate};

    use super::*;

    /// A test PKI: a root CA, an intermediate CA under it that signs client certificates, and
    /// a server certificate for 127.0.0.1 under the root.
    pub(crate) struct TestPki {
        pub(crate) root: Certificate,
        pub(crate) intermediate: Certificate,
        pub(crate) intermediate_key: KeyPair,
        pub(crate) server: Certificate,
        pub(crate) server_key: KeyPair,
    }

    impl TestPki {
        pub(crate) fn new() -> Self {
            let root_key = KeyPair::generate().unwrap();
            let mut root_params = ca_params("Test Root CA");
            root_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
            let root = root_params.self_signed(&root_key).unwrap();
            let root_issuer = Issuer::new(root_params, &root_key);

            let intermediate_key = KeyPair::generate().unwrap();
            let mut intermediate_params = ca_params("Test Gateway CA");
            intermediate_params.key_usages =
                vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
            intermediate_params.use_authority_key_identifier_extension = true;
            let intermediate = intermediate_params
                .signed_by(&intermediate_key, &root_issuer)
                .unwrap();

            let server_key = KeyPair::generate().unwrap();
            let mut server_params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
            server_params
                .subject_alt_names
                .push(SanType::IpAddress([127, 0, 0, 1].into()));
            server_params
                .distinguished_name
                .push(DnType::CommonName, "test-router");
            let server = server_params.signed_by(&server_key, &root_issuer).unwrap();

            TestPki {
                root,
                intermediate,
                intermediate_key,
                server,
                server_key,
            }
        }

        pub(crate) fn issuer(&self, validity: Duration) -> ClientCertificateIssuer {
            ClientCertificateIssuer::new(
                self.intermediate.pem().as_bytes(),
                self.intermediate_key.serialize_pem().as_bytes(),
                validity,
            )
            .unwrap()
        }
    }

    fn ca_params(name: &str) -> CertificateParams {
        let mut params = CertificateParams::default();
        params.distinguished_name = DistinguishedName::new();
        params.distinguished_name.push(DnType::CommonName, name);
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params
    }

    fn principal() -> Principal {
        Principal::new("u:", "alice").unwrap()
    }

    fn pem_certificates(pem: &str) -> Vec<CertificateDer<'static>> {
        rustls_pemfile::certs(&mut pem.as_bytes())
            .collect::<Result<_, _>>()
            .unwrap()
    }

    #[test]
    fn certificate_names_the_principal_for_client_authentication_only() {
        let pki = TestPki::new();
        let identity = pki
            .issuer(Duration::from_secs(3600))
            .issue(&principal())
            .unwrap();
        let chain = pem_certificates(&identity.certificate_chain_pem);
        let (_, leaf) = X509Certificate::from_der(&chain[0]).unwrap();

        let common_names: Vec<_> = leaf
            .subject()
            .iter_common_name()
            .map(|cn| cn.as_str().unwrap())
            .collect();
        assert_eq!(common_names, ["u:alice"]);
        assert_eq!(
            leaf.subject().iter().count(),
            1,
            "the subject is the CN alone"
        );
        let constraints = leaf.basic_constraints().unwrap().unwrap();
        assert!(constraints.critical && !constraints.value.ca);

        let usage = leaf.key_usage().unwrap().unwrap();
        assert!(usage.critical);
        assert!(usage.value.digital_signature());
        assert!(!usage.value.key_cert_sign());
        let extended = leaf.extended_key_usage().unwrap().unwrap().value;
        assert!(extended.client_auth);
        assert!(!extended.server_auth && !extended.any && extended.other.is_empty());

        assert_eq!(
            leaf.public_key().algorithm.algorithm,
            x509_parser::oid_registry::OID_KEY_TYPE_EC_PUBLIC_KEY
        );
        assert_eq!(
            leaf.public_key()
                .algorithm
                .parameters
                .as_ref()
                .unwrap()
                .as_oid()
                .unwrap(),
            x509_parser::oid_registry::OID_EC_P256
        );
        assert!(leaf.subject_alternative_name().unwrap().is_none());
    }

    #[test]
    fn certificate_names_its_issuer_key() {
        let pki = TestPki::new();
        let identity = pki
            .issuer(Duration::from_secs(3600))
            .issue(&principal())
            .unwrap();
        let chain = pem_certificates(&identity.certificate_chain_pem);
        let (_, leaf) = X509Certificate::from_der(&chain[0]).unwrap();
        let (_, intermediate) = X509Certificate::from_der(pki.intermediate.der()).unwrap();

        let subject_key_id = intermediate
            .iter_extensions()
            .find_map(|ext| match ext.parsed_extension() {
                ParsedExtension::SubjectKeyIdentifier(id) => Some(id.0.to_vec()),
                _ => None,
            })
            .unwrap();
        let authority_key_id = leaf
            .iter_extensions()
            .find_map(|ext| match ext.parsed_extension() {
                ParsedExtension::AuthorityKeyIdentifier(aki) => {
                    aki.key_identifier.as_ref().map(|id| id.0.to_vec())
                }
                _ => None,
            })
            .unwrap();
        assert_eq!(authority_key_id, subject_key_id);
        assert_eq!(leaf.issuer(), intermediate.subject());
    }

    #[test]
    fn certificate_is_valid_for_the_configured_lifetime() {
        let pki = TestPki::new();
        let validity = Duration::from_secs(86400);
        let before = OffsetDateTime::now_utc().unix_timestamp();
        let identity = pki.issuer(validity).issue(&principal()).unwrap();
        let after = OffsetDateTime::now_utc().unix_timestamp();
        let chain = pem_certificates(&identity.certificate_chain_pem);
        let (_, leaf) = X509Certificate::from_der(&chain[0]).unwrap();

        let not_before = leaf.validity().not_before.timestamp();
        let not_after = leaf.validity().not_after.timestamp();
        assert!(not_before <= before - CLOCK_SKEW_ALLOWANCE.as_secs() as i64 + 1);
        assert!(not_before >= before - CLOCK_SKEW_ALLOWANCE.as_secs() as i64 - 1);
        assert!(not_after >= before + 86400 - 1 && not_after <= after + 86400);
    }

    #[test]
    fn chain_verifies_against_the_root_through_the_intermediate() {
        let pki = TestPki::new();
        let identity = pki
            .issuer(Duration::from_secs(3600))
            .issue(&principal())
            .unwrap();
        let chain = pem_certificates(&identity.certificate_chain_pem);
        assert_eq!(
            chain.len(),
            2,
            "client certificate, then the signing certificate"
        );
        assert_eq!(chain[1].as_ref(), pki.intermediate.der().as_ref());

        // The verifier a Zenoh TLS listener with `enable_mtls` builds from its root CA.
        let mut roots = RootCertStore::empty();
        roots.add(pki.root.der().clone()).unwrap();
        let verifier = WebPkiClientVerifier::builder_with_provider(
            Arc::new(roots),
            Arc::new(default_provider()),
        )
        .build()
        .unwrap();
        verifier
            .verify_client_cert(&chain[0], &chain[1..], UnixTime::now())
            .unwrap();

        // Without the intermediate, the client certificate does not reach the root.
        assert!(verifier
            .verify_client_cert(&chain[0], &[], UnixTime::now())
            .is_err());
    }

    #[test]
    fn private_key_matches_the_certificate() {
        let pki = TestPki::new();
        let identity = pki
            .issuer(Duration::from_secs(3600))
            .issue(&principal())
            .unwrap();
        let key = KeyPair::from_pem(&identity.private_key_pem).unwrap();
        let chain = pem_certificates(&identity.certificate_chain_pem);
        let (_, leaf) = X509Certificate::from_der(&chain[0]).unwrap();
        assert_eq!(
            leaf.public_key().subject_public_key.data.as_ref(),
            key.public_key_raw()
        );
        assert!(identity
            .private_key_pem
            .starts_with("-----BEGIN PRIVATE KEY-----"));
    }

    #[test]
    fn every_certificate_has_its_own_key() {
        let issuer = TestPki::new().issuer(Duration::from_secs(3600));
        let a = issuer.issue(&principal()).unwrap();
        let b = issuer.issue(&principal()).unwrap();
        assert_ne!(*a.private_key_pem, *b.private_key_pem);
        assert_ne!(a.certificate_chain_pem, b.certificate_chain_pem);
    }

    #[test]
    fn signing_material_is_checked() {
        let pki = TestPki::new();
        let validity = Duration::from_secs(3600);
        let cert = pki.intermediate.pem();
        let key = pki.intermediate_key.serialize_pem();

        // A key that is not the certificate's.
        let other = KeyPair::generate().unwrap().serialize_pem();
        assert!(ClientCertificateIssuer::new(cert.as_bytes(), other.as_bytes(), validity).is_err());
        // A certificate that is not a CA.
        let server = pki.server.pem();
        let server_key = pki.server_key.serialize_pem();
        assert!(
            ClientCertificateIssuer::new(server.as_bytes(), server_key.as_bytes(), validity)
                .is_err()
        );
        // No certificate, no key, no lifetime.
        assert!(ClientCertificateIssuer::new(b"", key.as_bytes(), validity).is_err());
        assert!(ClientCertificateIssuer::new(cert.as_bytes(), b"", validity).is_err());
        assert!(
            ClientCertificateIssuer::new(cert.as_bytes(), key.as_bytes(), Duration::ZERO).is_err()
        );
        // A SEC1 key, which must be converted to PKCS#8 first.
        let sec1 = pem::encode(&pem::Pem::new("EC PRIVATE KEY", vec![0u8; 8]));
        let error = ClientCertificateIssuer::new(cert.as_bytes(), sec1.as_bytes(), validity)
            .err()
            .unwrap()
            .to_string();
        assert!(error.contains("PKCS#8"), "{error}");
    }

    #[test]
    fn errors_never_quote_the_signing_material() {
        let pki = TestPki::new();
        let key = pki.intermediate_key.serialize_pem();
        let other = KeyPair::generate().unwrap().serialize_pem();
        let error = ClientCertificateIssuer::new(
            pki.intermediate.pem().as_bytes(),
            other.as_bytes(),
            Duration::from_secs(1),
        )
        .err()
        .unwrap()
        .to_string();
        assert!(!error.contains("BEGIN"));
        assert!(!error.contains(key.lines().nth(1).unwrap()));
    }
}
