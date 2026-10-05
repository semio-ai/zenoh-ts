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

//! Verification of the ticket a WebSocket client presents: a compact JWT signed with ES256.

use std::fmt;

use jsonwebtoken::{
    crypto::rust_crypto::DEFAULT_PROVIDER, decode, errors::ErrorKind, get_current_timestamp,
    Algorithm, DecodingKey, Validation,
};
use rcgen::{PublicKeyData, SubjectPublicKeyInfo, PKCS_ECDSA_P256_SHA256};
use serde::Deserialize;
use zenoh_result::{bail, zerror, ZResult};

use super::principal::{is_valid_prefix, Principal};
use crate::config::TicketConfig;

/// The largest clock skew tolerated. Anything beyond it is a misconfiguration, and the
/// arithmetic on timestamps stays far from overflow.
const MAX_LEEWAY_SECS: u64 = 300;

/// Verifies tickets against the configured keys and claims.
pub(crate) struct TicketVerifier {
    keys: Vec<DecodingKey>,
    validation: Validation,
    leeway_secs: u64,
    principal_prefix: String,
}

/// What a valid ticket establishes.
#[derive(Debug)]
pub(crate) struct VerifiedTicket {
    pub(crate) principal: Principal,
    /// The ticket's `jti`, which identifies it in logs without revealing it.
    pub(crate) id: String,
}

/// Why a ticket was refused. Its text names the check that failed and nothing of the ticket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TicketRejection {
    Missing,
    Malformed,
    BadSignature,
    Expired,
    NotYetValid,
    WrongIssuer,
    WrongAudience,
    InvalidPrincipal,
}

impl fmt::Display for TicketRejection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            TicketRejection::Missing => "no ticket",
            TicketRejection::Malformed => "malformed ticket",
            TicketRejection::BadSignature => "ticket signature not verified by any configured key",
            TicketRejection::Expired => "ticket expired",
            TicketRejection::NotYetValid => "ticket not yet valid",
            TicketRejection::WrongIssuer => "ticket from another issuer",
            TicketRejection::WrongAudience => "ticket for another audience",
            TicketRejection::InvalidPrincipal => "ticket subject does not form a valid principal",
        })
    }
}

/// The claims read from a ticket beyond those `Validation` checks (`iss`, `aud`, `exp`, `nbf`).
#[derive(Deserialize)]
struct Claims {
    sub: String,
    /// A JWT NumericDate, which may have a fractional part.
    iat: f64,
    jti: String,
}

impl TicketVerifier {
    pub(crate) fn new(config: &TicketConfig) -> ZResult<Self> {
        if config.public_keys.is_empty() {
            bail!("`ticket.public_keys` is empty");
        }
        let keys = config
            .public_keys
            .iter()
            .enumerate()
            .map(|(index, pem)| {
                decoding_key(pem).map_err(|e| zerror!("`ticket.public_keys[{index}]`: {e}").into())
            })
            .collect::<ZResult<Vec<_>>>()?;
        if config.issuer.is_empty() {
            bail!("`ticket.issuer` is empty");
        }
        if config.audience.is_empty() {
            bail!("`ticket.audience` is empty");
        }
        if config.leeway_secs > MAX_LEEWAY_SECS {
            bail!("`ticket.leeway_secs` exceeds {MAX_LEEWAY_SECS}");
        }
        if !is_valid_prefix(&config.principal_prefix) {
            bail!("`ticket.principal_prefix` contains a control character or one forbidden in a key-expression chunk (/ * $ # ?)");
        }

        let mut validation = Validation::new(Algorithm::ES256);
        validation.set_issuer(&[&config.issuer]);
        validation.set_audience(&[&config.audience]);
        validation.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
        validation.leeway = config.leeway_secs;
        validation.validate_exp = true;
        validation.validate_nbf = true;
        validation.validate_aud = true;

        Ok(TicketVerifier {
            keys,
            validation,
            leeway_secs: config.leeway_secs,
            principal_prefix: config.principal_prefix.clone(),
        })
    }

    /// Verifies `ticket`: its signature against each configured key in turn, then its issuer,
    /// audience, expiry and issue time, then the principal its subject forms.
    pub(crate) fn verify(&self, ticket: &str) -> Result<VerifiedTicket, TicketRejection> {
        let claims = self.verified_claims(ticket)?;
        if claims.iat > get_current_timestamp().saturating_add(self.leeway_secs) as f64 {
            return Err(TicketRejection::NotYetValid);
        }
        if claims.jti.is_empty() {
            return Err(TicketRejection::Malformed);
        }
        let principal = Principal::new(&self.principal_prefix, &claims.sub)
            .ok_or(TicketRejection::InvalidPrincipal)?;
        Ok(VerifiedTicket {
            principal,
            id: claims.jti,
        })
    }

    fn verified_claims(&self, ticket: &str) -> Result<Claims, TicketRejection> {
        for key in &self.keys {
            match decode::<Claims>(ticket, key, &self.validation) {
                Ok(data) => return Ok(data.claims),
                // Another key may have signed it. Claims are checked only once a signature
                // verifies, so any other error stands whichever key is tried.
                Err(e) if matches!(e.kind(), ErrorKind::InvalidSignature) => continue,
                Err(e) => return Err(rejection(e.kind())),
            }
        }
        Err(TicketRejection::BadSignature)
    }
}

fn rejection(kind: &ErrorKind) -> TicketRejection {
    match kind {
        ErrorKind::InvalidSignature => TicketRejection::BadSignature,
        ErrorKind::ExpiredSignature => TicketRejection::Expired,
        ErrorKind::ImmatureSignature => TicketRejection::NotYetValid,
        ErrorKind::InvalidIssuer => TicketRejection::WrongIssuer,
        ErrorKind::InvalidAudience => TicketRejection::WrongAudience,
        _ => TicketRejection::Malformed,
    }
}

/// An ES256 verification key from an SPKI PEM, which must hold an EC P-256 public key.
fn decoding_key(pem: &str) -> ZResult<DecodingKey> {
    let spki = SubjectPublicKeyInfo::from_pem(pem)
        .map_err(|_| zerror!("not an SPKI PEM public key (-----BEGIN PUBLIC KEY-----)"))?;
    if spki.algorithm() != &PKCS_ECDSA_P256_SHA256 {
        bail!("not an EC P-256 public key, which ES256 requires");
    }
    let key = DecodingKey::from_ec_pem(pem.as_bytes())
        .map_err(|_| zerror!("not usable as an ES256 verification key"))?;
    // Building the verifier that `decode` builds checks that the point is on the curve.
    (DEFAULT_PROVIDER.verifier_factory)(&Algorithm::ES256, &key)
        .map_err(|_| zerror!("not a valid EC P-256 public key"))?;
    Ok(key)
}

#[cfg(test)]
pub(crate) mod tests {
    use jsonwebtoken::{encode, EncodingKey, Header};
    use rcgen::KeyPair;
    use serde_json::{json, Value};

    use super::*;

    pub(crate) const ISSUER: &str = "semio-studio";
    pub(crate) const AUDIENCE: &str = "semio-bridge";

    /// A ticket signing key: the issuer's private half and the public PEM to configure.
    pub(crate) struct SigningKey(KeyPair);

    impl SigningKey {
        pub(crate) fn generate() -> Self {
            SigningKey(KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap())
        }

        pub(crate) fn public_pem(&self) -> String {
            self.0.public_key_pem()
        }

        pub(crate) fn sign(&self, claims: &Value) -> String {
            let key = EncodingKey::from_ec_pem(self.0.serialize_pem().as_bytes()).unwrap();
            encode(&Header::new(Algorithm::ES256), claims, &key).unwrap()
        }
    }

    pub(crate) fn config(public_keys: Vec<String>) -> TicketConfig {
        TicketConfig {
            public_keys,
            issuer: ISSUER.into(),
            audience: AUDIENCE.into(),
            principal_prefix: "u:".into(),
            leeway_secs: 30,
        }
    }

    /// Valid claims for subject `alice`, issued now and expiring in five minutes.
    pub(crate) fn claims() -> Value {
        let now = get_current_timestamp();
        json!({
            "iss": ISSUER,
            "aud": AUDIENCE,
            "sub": "alice",
            "iat": now,
            "exp": now + 300,
            "jti": "ticket-1",
        })
    }

    fn with(mut claims: Value, field: &str, value: Value) -> Value {
        claims[field] = value;
        claims
    }

    fn without(mut claims: Value, field: &str) -> Value {
        claims.as_object_mut().unwrap().remove(field);
        claims
    }

    fn verifier(key: &SigningKey) -> TicketVerifier {
        TicketVerifier::new(&config(vec![key.public_pem()])).unwrap()
    }

    #[test]
    fn valid_ticket_names_the_principal() {
        let key = SigningKey::generate();
        let verified = verifier(&key).verify(&key.sign(&claims())).unwrap();
        assert_eq!(verified.principal.as_str(), "u:alice");
        assert_eq!(verified.id, "ticket-1");
    }

    #[test]
    fn ticket_signed_by_any_configured_key_is_accepted() {
        let (old, new) = (SigningKey::generate(), SigningKey::generate());
        let verifier =
            TicketVerifier::new(&config(vec![old.public_pem(), new.public_pem()])).unwrap();
        assert!(verifier.verify(&old.sign(&claims())).is_ok());
        assert!(verifier.verify(&new.sign(&claims())).is_ok());
    }

    #[test]
    fn key_id_header_is_optional() {
        let key = SigningKey::generate();
        let encoding = EncodingKey::from_ec_pem(key.0.serialize_pem().as_bytes()).unwrap();
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some("2026-10".into());
        let ticket = encode(&header, &claims(), &encoding).unwrap();
        assert!(verifier(&key).verify(&ticket).is_ok());
    }

    #[test]
    fn expired_ticket_is_refused() {
        let key = SigningKey::generate();
        let now = get_current_timestamp();
        let ticket = key.sign(&with(
            with(claims(), "iat", json!(now - 600)),
            "exp",
            json!(now - 60),
        ));
        assert_eq!(
            verifier(&key).verify(&ticket).unwrap_err(),
            TicketRejection::Expired
        );
    }

    #[test]
    fn expiry_within_leeway_is_tolerated() {
        let key = SigningKey::generate();
        let ticket = key.sign(&with(claims(), "exp", json!(get_current_timestamp() - 10)));
        assert!(verifier(&key).verify(&ticket).is_ok());
    }

    #[test]
    fn ticket_issued_in_the_future_is_refused() {
        let key = SigningKey::generate();
        let now = get_current_timestamp();
        let ticket = key.sign(&with(
            with(claims(), "iat", json!(now + 120)),
            "exp",
            json!(now + 600),
        ));
        assert_eq!(
            verifier(&key).verify(&ticket).unwrap_err(),
            TicketRejection::NotYetValid
        );
    }

    #[test]
    fn issue_time_within_leeway_is_tolerated() {
        let key = SigningKey::generate();
        let ticket = key.sign(&with(claims(), "iat", json!(get_current_timestamp() + 10)));
        assert!(verifier(&key).verify(&ticket).is_ok());
    }

    #[test]
    fn ticket_before_its_not_before_time_is_refused() {
        let key = SigningKey::generate();
        let ticket = key.sign(&with(claims(), "nbf", json!(get_current_timestamp() + 120)));
        assert_eq!(
            verifier(&key).verify(&ticket).unwrap_err(),
            TicketRejection::NotYetValid
        );
    }

    #[test]
    fn wrong_issuer_is_refused() {
        let key = SigningKey::generate();
        let ticket = key.sign(&with(claims(), "iss", json!("someone-else")));
        assert_eq!(
            verifier(&key).verify(&ticket).unwrap_err(),
            TicketRejection::WrongIssuer
        );
    }

    #[test]
    fn wrong_audience_is_refused() {
        let key = SigningKey::generate();
        let ticket = key.sign(&with(claims(), "aud", json!("another-bridge")));
        assert_eq!(
            verifier(&key).verify(&ticket).unwrap_err(),
            TicketRejection::WrongAudience
        );
    }

    #[test]
    fn missing_claims_are_refused() {
        let key = SigningKey::generate();
        let verifier = verifier(&key);
        for claim in ["iss", "aud", "sub", "iat", "exp", "jti"] {
            let ticket = key.sign(&without(claims(), claim));
            assert!(verifier.verify(&ticket).is_err(), "without {claim}");
        }
        let ticket = key.sign(&with(claims(), "jti", json!("")));
        assert_eq!(
            verifier.verify(&ticket).unwrap_err(),
            TicketRejection::Malformed
        );
    }

    #[test]
    fn bad_signature_is_refused() {
        let key = SigningKey::generate();
        let ticket = key.sign(&claims());
        let (signed, signature) = ticket.rsplit_once('.').unwrap();
        // Flip one bit of the signature's first byte, which the encoding always carries whole.
        let mut flipped = signature.as_bytes().to_vec();
        flipped[0] = if flipped[0] == b'A' { b'B' } else { b'A' };
        let tampered = format!("{signed}.{}", String::from_utf8(flipped).unwrap());
        assert_eq!(
            verifier(&key).verify(&tampered).unwrap_err(),
            TicketRejection::BadSignature
        );
    }

    #[test]
    fn tampered_claims_are_refused() {
        let key = SigningKey::generate();
        let ticket = key.sign(&claims());
        let forged = key.sign(&with(claims(), "sub", json!("mallory")));
        let (header, rest) = ticket.split_once('.').unwrap();
        let (_, signature) = rest.split_once('.').unwrap();
        let forged_payload = forged.split('.').nth(1).unwrap();
        let spliced = format!("{header}.{forged_payload}.{signature}");
        assert_eq!(
            verifier(&key).verify(&spliced).unwrap_err(),
            TicketRejection::BadSignature
        );
    }

    #[test]
    fn ticket_from_an_unconfigured_key_is_refused() {
        let (configured, other) = (SigningKey::generate(), SigningKey::generate());
        assert_eq!(
            verifier(&configured)
                .verify(&other.sign(&claims()))
                .unwrap_err(),
            TicketRejection::BadSignature
        );
    }

    #[test]
    fn other_algorithms_are_refused() {
        let key = SigningKey::generate();
        let verifier = verifier(&key);
        let hs256 = encode(
            &Header::new(Algorithm::HS256),
            &claims(),
            &EncodingKey::from_secret(key.public_pem().as_bytes()),
        )
        .unwrap();
        assert!(verifier.verify(&hs256).is_err());

        let ticket = key.sign(&claims());
        let payload = ticket.split('.').nth(1).unwrap();
        let unsigned = format!("{}.{payload}.", base64_url(br#"{"alg":"none"}"#));
        assert!(verifier.verify(&unsigned).is_err());
    }

    #[test]
    fn empty_signature_is_refused() {
        let key = SigningKey::generate();
        let ticket = key.sign(&claims());
        let (signed, _) = ticket.rsplit_once('.').unwrap();
        assert_eq!(
            verifier(&key).verify(&format!("{signed}.")).unwrap_err(),
            TicketRejection::BadSignature
        );
    }

    #[test]
    fn malformed_tickets_are_refused() {
        let key = SigningKey::generate();
        let verifier = verifier(&key);
        for ticket in ["", "abc", "a.b", "a.b.c", "...."] {
            assert_eq!(
                verifier.verify(ticket).unwrap_err(),
                TicketRejection::Malformed,
                "{ticket:?}"
            );
        }
    }

    #[test]
    fn subject_with_a_forbidden_character_is_refused() {
        let key = SigningKey::generate();
        let verifier = verifier(&key);
        for subject in ["a/b", "*", "**", "$*", "a#b", "a?b", ""] {
            let ticket = key.sign(&with(claims(), "sub", json!(subject)));
            assert_eq!(
                verifier.verify(&ticket).unwrap_err(),
                TicketRejection::InvalidPrincipal,
                "{subject:?}"
            );
        }
    }

    #[test]
    fn configuration_is_checked() {
        let key = SigningKey::generate();
        assert!(TicketVerifier::new(&config(vec![])).is_err());
        assert!(TicketVerifier::new(&config(vec!["not a key".into()])).is_err());
        let p384 = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap();
        assert!(TicketVerifier::new(&config(vec![p384.public_key_pem()])).is_err());
        let mut prefix = config(vec![key.public_pem()]);
        prefix.principal_prefix = "u/".into();
        assert!(TicketVerifier::new(&prefix).is_err());
        let mut issuer = config(vec![key.public_pem()]);
        issuer.issuer.clear();
        assert!(TicketVerifier::new(&issuer).is_err());
        let mut audience = config(vec![key.public_pem()]);
        audience.audience.clear();
        assert!(TicketVerifier::new(&audience).is_err());
        let mut leeway = config(vec![key.public_pem()]);
        leeway.leeway_secs = MAX_LEEWAY_SECS + 1;
        assert!(TicketVerifier::new(&leeway).is_err());
    }

    #[test]
    fn key_whose_point_is_off_the_curve_is_refused() {
        let key = SigningKey::generate();
        let mut spki = pem::parse(key.public_pem()).unwrap().into_contents();
        // The last byte belongs to the point's y coordinate.
        *spki.last_mut().unwrap() ^= 1;
        let off_curve = pem::encode(&pem::Pem::new("PUBLIC KEY", spki));
        let error = TicketVerifier::new(&config(vec![off_curve, key.public_pem()]))
            .err()
            .unwrap()
            .to_string();
        assert!(error.contains("public_keys[0]"), "{error}");
    }

    #[test]
    fn rejections_never_quote_the_ticket() {
        let key = SigningKey::generate();
        let ticket = key.sign(&with(claims(), "aud", json!("another-bridge")));
        let rejection = verifier(&key).verify(&ticket).unwrap_err().to_string();
        assert!(!rejection.contains(&ticket));
        assert!(!rejection.contains("another-bridge"));
    }

    fn base64_url(bytes: &[u8]) -> String {
        use base64::Engine;
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    }
}
