use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use jsonwebtoken::{Algorithm, DecodingKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

use crate::firewall::allowed::OidcProviderList;
use crate::primitives::InternalAccountId;
use crate::sign_node::oidc::OidcToken;

// Specs for ID token verification:
// Google: https://developers.google.com/identity/openid-connect/openid-connect#validatinganidtoken
// Firebase: https://firebase.google.com/docs/auth/admin/verify-id-tokens#verify_id_tokens_using_a_third-party_jwt_library
pub async fn verify_oidc_token(
    token: &OidcToken,
    oidc_providers: Option<&OidcProviderList>,
    client: &reqwest::Client,
    jwt_signature_pk_urls: &HashMap<String, String>,
) -> anyhow::Result<IdTokenClaims> {
    let (_, claims, _) = token.decode_unverified()?;
    let issuer = &claims.iss;

    let jwks_url = jwt_signature_pk_urls
        .get(issuer)
        .ok_or_else(|| anyhow::anyhow!("No JWKS URL found for issuer: {}", issuer))?;

    let public_keys = get_public_keys(client, jwks_url)
        .await
        .map_err(|e| anyhow::anyhow!("failed to get public keys: {e}"))?;
    tracing::info!("verify_oidc_token public keys: {public_keys:?}");

    let mut last_occured_error = anyhow::anyhow!("Unexpected error. Public keys not found");
    for public_key in public_keys {
        match validate_jwt(token, public_key.as_bytes(), oidc_providers) {
            Ok(claims) => {
                tracing::info!("Access token is valid");
                return Ok(claims);
            }
            Err(e) => {
                tracing::info!("Access token verification failed: {}", e);
                last_occured_error = e;
            }
        }
    }
    Err(last_occured_error)
}

/// This function validates JWT (OIDC ID token) by checking the signature received
/// from the issuer, issuer, audience, and expiration time.
fn validate_jwt(
    token: &OidcToken,
    public_key: &[u8],
    oidc_providers: Option<&OidcProviderList>,
) -> anyhow::Result<IdTokenClaims> {
    tracing::info!(
        oidc_token = format!("{:.5}...", token),
        public_key = String::from_utf8(public_key.to_vec()).unwrap_or_default(),
        "validate_jwt call"
    );

    let decoding_key = DecodingKey::from_rsa_pem(public_key)?;
    let (header, claims, _sig) = token.decode(&decoding_key)?;
    let IdTokenClaims {
        iss: issuer,
        aud: audience,
        ..
    } = &claims;

    // If no OIDC providers are specified in the allowlist, we allow any issuer and audience.
    // Should be used in signing nodes only.
    if let Some(oidc_providers) = oidc_providers {
        if !oidc_providers.contains(issuer, audience) {
            anyhow::bail!("UnauthorizedTokenIssuerOrAudience: iss={issuer}, aud={audience}");
        }
    }

    tracing::info!(
        issuer = issuer,
        audience = audience,
        "validate_jwt call decoded"
    );

    // algorithm used by jsonwebtoken library
    if header.alg != Algorithm::RS256 {
        anyhow::bail!("InvalidAlgorithm: {:?}", header.alg);
    }

    tracing::info!(
        claims = format!("{:?}", claims),
        "validate_jwt call successful"
    );

    Ok(claims)
}

#[derive(Debug, Serialize, Deserialize)]
pub struct IdTokenClaims {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub exp: usize,
}

impl IdTokenClaims {
    pub fn get_internal_account_id(&self) -> InternalAccountId {
        format!("{}:{}", self.iss, self.sub)
    }
}

pub async fn get_public_keys(client: &reqwest::Client, jwks_url: &str) -> Result<Vec<String>> {
    let response = client
        .get(jwks_url)
        .send()
        .await
        .context("Failed to send request")?;

    let json: Value = response.json().await.context("Failed to parse JSON")?;

    match json {
        Value::Object(obj) if obj.contains_key("keys") => parse_jwks_format(&obj),
        Value::Object(obj) => parse_firebase_format(&obj),
        _ => {
            tracing::warn!("Unexpected response format from {}", jwks_url);
            Ok(vec![])
        }
    }
}

fn parse_jwks_format(obj: &serde_json::Map<String, Value>) -> Result<Vec<String>> {
    obj["keys"]
        .as_array()
        .context("'keys' is not an array")?
        .iter()
        .filter_map(|key| match (key["n"].as_str(), key["e"].as_str()) {
            (Some(n), Some(e)) => Some(format_rsa_key(n, e)),
            _ => None,
        })
        .collect::<Result<Vec<_>>>()
}

fn parse_firebase_format(obj: &serde_json::Map<String, Value>) -> Result<Vec<String>> {
    Ok(obj
        .values()
        .filter_map(|value| value.as_str().map(String::from))
        .collect())
}

fn format_rsa_key(n: &str, e: &str) -> Result<String> {
    Ok(format!(
        "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----",
        BASE64.encode(format!("{}:{}", n, e))
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};
    use jsonwebtoken::{encode, EncodingKey, Header};
    use rand::rngs::OsRng;
    use rsa::{
        pkcs1::{EncodeRsaPrivateKey, EncodeRsaPublicKey},
        RsaPrivateKey, RsaPublicKey,
    };

    #[tokio::test]
    async fn test_get_pagoda_firebase_public_key() {
        let url =
        "https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com";
        let client = reqwest::Client::new();
        let pk = get_public_keys(&client, url).await.unwrap();

        assert!(!pk.is_empty());
    }

    #[test]
    fn test_validate_jwt() {
        let (private_key_der, public_key_der): (Vec<u8>, Vec<u8>) = get_rsa_pem_key_pair();

        let my_claims = IdTokenClaims {
            iss: "test_issuer".to_string(),
            sub: "test_subject".to_string(),
            aud: "test_audience".to_string(),
            exp: (Utc::now() + Duration::hours(1)).timestamp() as usize,
        };
        let oidc_providers = allowlist_from_claims(&my_claims);

        let token = match encode(
            &Header::new(Algorithm::RS256),
            &my_claims,
            &EncodingKey::from_rsa_pem(&private_key_der).unwrap(),
        ) {
            Ok(t) => OidcToken::new(t.as_str()),
            Err(e) => panic!("Failed to encode token: {}", e),
        };

        // Valid token and claims
        validate_jwt(&token, &public_key_der, Some(&oidc_providers)).unwrap();

        // Invalid public key
        let (invalid_public_key, _invalid_private_key) = get_rsa_pem_key_pair();
        match validate_jwt(&token, &invalid_public_key, Some(&oidc_providers)) {
            Ok(_) => panic!("Token validation should fail"),
            Err(e) => assert_eq!(e.to_string(), "InvalidSignature"),
        }

        // Invalid issuer or audience
        let new_claims = IdTokenClaims {
            iss: "unauthorized_issuer".to_string(),
            sub: "unauthorized_subject".to_string(),
            aud: "unauthorized_audience".to_string(),
            exp: (Utc::now() + Duration::hours(1)).timestamp() as usize,
        };
        let token = match encode(
            &Header::new(Algorithm::RS256),
            &new_claims,
            &EncodingKey::from_rsa_pem(&private_key_der).unwrap(),
        ) {
            Ok(t) => OidcToken::new(t.as_str()),
            Err(e) => panic!("Failed to encode token: {}", e),
        };
        match validate_jwt(&token, &public_key_der, Some(&oidc_providers)) {
            Ok(_) => panic!("Token validation should fail on invalid issuer or audience"),
            Err(e) => assert_eq!(e.to_string(), "UnauthorizedTokenIssuerOrAudience: iss=unauthorized_issuer, aud=unauthorized_audience", "{:?}", e),
        }
    }

    #[test]
    fn test_validate_jwt_without_oidc() {
        let (private_key_der, public_key_der): (Vec<u8>, Vec<u8>) = get_rsa_pem_key_pair();

        let my_claims = IdTokenClaims {
            iss: "test_issuer".to_string(),
            sub: "test_subject".to_string(),
            aud: "test_audience".to_string(),
            exp: (Utc::now() + Duration::hours(1)).timestamp() as usize,
        };

        let token = match encode(
            &Header::new(Algorithm::RS256),
            &my_claims,
            &EncodingKey::from_rsa_pem(&private_key_der).unwrap(),
        ) {
            Ok(t) => OidcToken::new(t.as_str()),
            Err(e) => panic!("Failed to encode token: {}", e),
        };

        // Valid token and claims
        match validate_jwt(&token, &public_key_der, None) {
            Ok(_) => (),
            Err(e) => panic!("Token validation should succeed: {}", e),
        }
    }

    pub fn get_rsa_pem_key_pair() -> (Vec<u8>, Vec<u8>) {
        let mut rng = OsRng;
        let bits: usize = 2048;
        let private_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
        let public_key = RsaPublicKey::from(&private_key);

        let private_key_der = private_key
            .to_pkcs1_pem(rsa::pkcs8::LineEnding::LF)
            .expect("Failed to encode private key")
            .as_bytes()
            .to_vec();
        let public_key_der = public_key
            .to_pkcs1_pem(rsa::pkcs8::LineEnding::LF)
            .expect("Failed to encode public key")
            .as_bytes()
            .to_vec();

        (private_key_der, public_key_der)
    }

    fn allowlist_from_claims(claims: &IdTokenClaims) -> OidcProviderList {
        let mut oidc_providers = OidcProviderList::default();
        oidc_providers.insert(crate::firewall::allowed::OidcProvider {
            issuer: claims.iss.clone(),
            audience: claims.aud.clone(),
        });
        oidc_providers
    }
}
