use std::collections::HashMap;

use borsh::{self, BorshDeserialize, BorshSerialize};
use chrono::{Duration, Utc};
use google_datastore1::api::{Key, PathElement};
use hex::FromHex;
use jsonwebtoken as jwt;
use jwt::{encode, Algorithm, DecodingKey, EncodingKey, Header};
use near_primitives::utils::generate_random_string;
use serde::{Deserialize, Serialize};

use near_crypto::PublicKey;

use crate::{
    error::MpcError,
    gcp::{
        error::ConvertError,
        value::{FromValue, IntoValue, Value},
        KeyKind,
    },
    oauth::IdTokenClaims,
};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct OidcHash([u8; 32]);

impl AsRef<[u8]> for OidcHash {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl FromHex for OidcHash {
    type Error = anyhow::Error;

    fn from_hex<T: AsRef<[u8]>>(hex: T) -> anyhow::Result<Self> {
        let bytes = <[u8; 32]>::from_hex(hex)?;
        Ok(Self(bytes))
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
#[serde(transparent)]
pub struct OidcToken {
    data: String,
}

impl OidcToken {
    pub fn new(data: &str) -> Self {
        Self { data: data.into() }
    }

    pub fn digest_hash(&self) -> OidcHash {
        let hasher = sha2::Digest::chain(sha2::Sha256::default(), self.data.as_bytes());
        let hash = <[u8; 32]>::try_from(sha2::Digest::finalize(hasher).as_slice())
            .expect("Hash is the wrong size");
        OidcHash(hash)
    }

    pub fn random_valid() -> Self {
        // This key corresponds to the public key in test-oidc-provider/src/main.rs
        let rsa_pem_key = "-----BEGIN RSA PRIVATE KEY-----MIIJKAIBAAKCAgEAg6UuFBM3QmtQID8cOHltjM8WF/XpFj2d5feVShG19jan76n6kEQPIhbqC4gweqWWdKdwbOmJKvDzV7qER5BC2tKB7ViKRFpsEc5pSp2vc4w81Wni9Dzicpz1R0Qr2p3lkqLuG6G/nJaD6s0KMfiyPiIBSBOgd1gaGIZcN2MtZm4bT2cVBxgBBW9L3bkpyONf0JHtia+6M7LPwzKwd29LYuirPFU31psCBejXwuWst/KBncEeHASEW/LK0UJS4tJVH05mNuicBjKkYJ8Q+UTVZPA+8bgkrWEzScAoedVn+QwbwUxZ+C0r1NunllwU+e29s9rpf9wifzX43vA4FGPYdDuEPiGmaNqFTsV/Z8oOMLDuAt/QqFVrp24S6DyHy/aWAZcJzcAbwckP0B5GsrvbAogcWzPpRzFLFkPmsQ1IMG/MK382AJ04rh+u0jomXxImLYiDFvzEXTelNsiDICHY6PQ1Fd/OfxuKVFl4cVVx5VeyWOIAjRePaeMaijHr0KrxKDZiz+Umx8UJTwbjAfPx9fM5mvBXlmsXYAm/hmnp74xDlr/s8c4fAyXmuqRocu8jq0GkMDjYJKj2QQSZSLQUMxmeF6gRIFpjK8mawsSvM88Kiu6o/pZD3i0e3QL5OBwYjcd0muxY23yvcmdVmLeTds+wB0xAtA8wkWEu8N8SGXcCAwEAAQKCAgBaJCHAF0RQU4DjA7PEK8lKkIY1U+oNk5Vp4TS1KhlphRVK8x4h6KhgFEagLNndMUMrj3dY7DRDVgeaO5nWEr7kbR4QMf9DPJMhQjAwqnZ37T++dim0SXhZOIZvDQvmPxXyaWQXQZMdmqargUiI3RzXlJtCCkZnUclUn7PHLT7qE1zZ6uCoIdSZLxNIuEAXUTHLdBCtpckfG0JOC4hvz6JUELMntcZtSWiCOWR8DJ5OulvsdE60qpcjCsW7sellbNZigGFXGcG0MLsDege6V1qzKho/k3Jx0cu3pT9R5UGzc4oRusEkQXHw55MCTv0CAbtSywP1y/tHFeLabKxJsfCE6BciR7PCIuB0DD+4cP82AD3xu2HbJuw1ata8PnDSk1SwgCHnnj1Qh5ExVyPLQa6vlEqRI7gA52xB6q56YNWpEiLeEPWvnky4rq/w3xTEFoG9N4XkjQGD3PRLngdm/u3YKQ4uVrp2GwiNTsjN6eOcZYfffH2YNH4qf4tKmDInBmig4dQE/brXLAU7mh7x6gUH8EMm5lUaeQhKYfpSnJPdAJEKFZ5UYnMEKuDYUDIhs9yn9Vlzr4acIlnRvu/nM00NUwjZfWJDTbmbktRQANKQdnC41WcqCh9p1+zSbBlzmTSSIGXu+dnfTtKzswU7fFoMgS8FWfV+u5v1wjPO6GXUIQKCAQEA9ZbiE3oghHK3qQHseHllyxWShUY0xVa4K1nd1fHUDOwWR9/qW8V/m+c7tu8yya95DngWvK5zFhzgygP49QRc30W+CTZPTQ5UHEvmyzD3CuL5XCAXPSi+C+hpt6vAdM4ZkHSwAT5Ce1KjzN49xQS33H0QZA9CR6/gcnUoJJx1tdMPghHjJAOTlQaNPJVK+OXJmQIxDvJL7MB0UK084ELYeP+o6Qlt0aC+zAfMwMVAxpc+O/4QBig6d2a1+mi6jJYvFtH1UAWbE8WbQtEX1Lql2rxkJCGe6TYCY2rm2muVuYda5yYbr4CkzUCM8vNecgpuU82aVIsp/p0n7zO2FZ29BwKCAQEAiTnIqEfNmdX3a5rRNfX78c8A3rAK5jiiBiHHcu40Fd5ETGT/Fm2BsY+xfX+Ldgv4oc7RDTZReJPXr1Y0l9ht+0LUvY4BX5ym3ADImxwQ/tCV+U/El0ffDL+cNtuIR8XOHMP9WnuajqSo2I33a79r09jGbAMZNAAmoUTIsFXtB51CVEcHM/mMZpGMddpu6yvtEW9XhorCxANIAzqdyqB9/e9jChkIG/bGqMLzv2vZYxUxNTfnhYYhK5xmqvTyGxPKOLHa61e561FBnbom3EslIq8IkorkGqUtRby7w+NiSGpr+ChkmQiyfzSOhBs5Pc7areUXqLvQ9+MyO9/aG4wUEQKCAQAXtZxX0weGoeiXOWdR7i5kn82IblGz535aOQ/QksstADHaeISQnY2HSJicPZWCoR0nx3Iyfwj/ToRpHF8RkH1C1OHW09ZuEv8NyEocvbpr46O9QB/eOKu4TJTANaWb4TXYm1tOk2spqr3DjoUaGy2A7NYDQvHcJ9+cTTE176Dxj9HEdeOe23WJApvqCGO3ib+ftPV1gvDPh3jzPPZOlEV/0PbGoLFodoNVAT/EMIbjZUCN3CZB4epbEqBo72lrHyimpFhxhEkHbKFjnvoVAHv4lQ1564EC9MLgRDbLSW2n/qhI/oXXuKywYBX7coFgsx8ZmhTXKqRAP33WewCOL69LAoIBAE2nM1N2/nPVTuPHgihFAMN/XoCloiVRWu6ZYuI4xaSyWHfalzc71K6EH+5ipKqyb4oxHL+bQ1M2ZlFEORLMWMBcu0Jg/4n5fbr1fo+3vC5WHugsKZVqCGCQdXfdlyr2VoKUrePsGjQqHZoeDCse8Ye6Hd61iieRBkswP1j55t3uMcC7SOoyhy7rok52w1m1S7wYA7GRCFIfgTrCitRFKcbvFl56d8pLRXPujjx+bU/SiDwTXKKEmnSxVq/bWL3V3xNiIf4XcJAnNThqRN9YbrVH01QJ4LbrTcku2hoprE5KWrrdMMAg2dF+Dj/Xn/bH/Zt2DoNfdQsxuBWFwUjhZeECggEBANTpwOCTpEIv9AwFs7q3vvYl/dqVcjAliQLk7fq7U0C1pL5f51jrLQWwWLhpJhkQvnmVhUFAOqWxKFvvpJ4NQbjHldQzIou9rBofsHPju42yo0NC1zwyQy4SGl644Fg5jL5KxE2AdOsTkk47uBxdPfEcZOaF5oqY6yVk3x4qNOqfxqt/MUwyDviEHgd/TfHIvNcpLl7l1CcaHv/eobSB3XPjNXcXy1MTyolH0pg662eW8Su3h7qAhP4m7ArizpgnFgHEdarXF/g3OrMDgj2IPAzalHnGSuuSjLYE7fdjGcqZ9R6+ZUpk4Vwaba6tjzB1f/SU2Myampd4H+tkHbLyJJE=-----END RSA PRIVATE KEY-----";

        Self {
            data: create_jwt_token(rsa_pem_key),
        }
    }

    pub fn invalid() -> Self {
        // This key does not correspond to the public key in test-oidc-provider/src/main.rs
        let rsa_pem_key = "-----BEGIN RSA PRIVATE KEY-----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-----END RSA PRIVATE KEY-----";

        Self {
            data: create_jwt_token(rsa_pem_key),
        }
    }

    // NOTE: code taken directly from jsonwebtoken::verify_signature and modified to suit
    // our needs (i.e. not knowing audience and issuer ahead of time).
    pub fn decode(
        &self,
        key: &DecodingKey,
    ) -> anyhow::Result<(jwt::Header, IdTokenClaims, String)> {
        let mut parts = self.as_ref().rsplitn(2, '.');
        let (Some(signature), Some(message)) = (parts.next(), parts.next()) else {
            anyhow::bail!("could not split into signature and message for OIDC token");
        };
        let mut parts = message.rsplitn(2, '.');
        let (Some(payload), Some(header)) = (parts.next(), parts.next()) else {
            anyhow::bail!("could not split into payload and header for OIDC token");
        };
        let header: jwt::Header = serde_json::from_slice(&b64_decode(header)?)?;
        let claims: IdTokenClaims = serde_json::from_slice(&b64_decode(payload)?)?;

        if !jwt::crypto::verify(signature, message.as_bytes(), key, header.alg)? {
            anyhow::bail!("InvalidSignature");
        }

        Ok((header, claims, signature.into()))
    }

    // NOTE: code taken directly from our implementation of token.decode but without the verification step
    pub fn decode_unverified(&self) -> anyhow::Result<(jwt::Header, IdTokenClaims, String)> {
        let mut parts = self.as_ref().rsplitn(2, '.');
        let (Some(signature), Some(message)) = (parts.next(), parts.next()) else {
            anyhow::bail!("could not split into signature and message for OIDC token");
        };
        let mut parts = message.rsplitn(2, '.');
        let (Some(payload), Some(header)) = (parts.next(), parts.next()) else {
            anyhow::bail!("could not split into payload and header for OIDC token");
        };
        let header: jwt::Header = serde_json::from_slice(&b64_decode(header)?)?;
        let claims: IdTokenClaims = serde_json::from_slice(&b64_decode(payload)?)?;
        Ok((header, claims, signature.to_string()))
    }
}

fn b64_decode<T: AsRef<[u8]>>(input: T) -> anyhow::Result<Vec<u8>> {
    base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, input)
        .map_err(Into::into)
}

fn create_jwt_token(rsa_pem_key: &str) -> String {
    let private_key_der = rsa_pem_key.as_bytes().to_vec();

    let aud = "test_audience".to_string();

    let my_claims = IdTokenClaims {
        iss: format!("https://securetoken.google.com/{}", aud),
        sub: generate_random_string(7),
        aud,
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
    token.to_string()
}

impl std::str::FromStr for OidcToken {
    type Err = MpcError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self::new(s))
    }
}

impl std::fmt::Display for OidcToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.data)
    }
}

impl AsRef<str> for OidcToken {
    fn as_ref(&self) -> &str {
        &self.data
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct OidcDigest {
    pub node_id: usize,
    pub digest: OidcHash,
    pub public_key: PublicKey,
}

impl KeyKind for OidcDigest {
    fn kind() -> String {
        "OidcDigest".to_string()
    }
}

impl IntoValue for OidcDigest {
    fn into_value(self) -> Value {
        let mut properties = HashMap::new();
        properties.insert(
            "node_id".to_string(),
            Value::IntegerValue(self.node_id as i64),
        );
        properties.insert(
            "digest".to_string(),
            Value::StringValue(hex::encode(&self.digest)),
        );
        properties.insert(
            "public_key".to_string(),
            Value::StringValue(serde_json::to_string(&self.public_key).unwrap()),
        );

        Value::EntityValue {
            key: Key {
                path: Some(vec![PathElement {
                    kind: Some(Self::kind()),
                    name: Some(self.to_name()),
                    id: None,
                }]),
                partition_id: None,
            },
            properties,
        }
    }
}

impl FromValue for OidcDigest {
    fn from_value(value: Value) -> Result<Self, ConvertError> {
        match value {
            Value::EntityValue { mut properties, .. } => {
                let (_, node_id) = properties
                    .remove_entry("node_id")
                    .ok_or_else(|| ConvertError::MissingProperty("node_id".to_string()))?;
                let node_id = i64::from_value(node_id)? as usize;
                let (_, digest) = properties
                    .remove_entry("digest")
                    .ok_or_else(|| ConvertError::MissingProperty("digest".to_string()))?;
                let digest = hex::decode(String::from_value(digest)?)
                    .map_err(|_| ConvertError::MalformedProperty("digest".to_string()))?;
                let digest = <[u8; 32]>::try_from(digest)
                    .map_err(|_| ConvertError::MalformedProperty("digest".to_string()))?;
                let digest = OidcHash(digest);

                let (_, public_key) = properties
                    .remove_entry("public_key")
                    .ok_or_else(|| ConvertError::MissingProperty("public_key".to_string()))?;
                let public_key = String::from_value(public_key)?;
                let public_key = serde_json::from_str(&public_key)
                    .map_err(|_| ConvertError::MalformedProperty("public_key".to_string()))?;

                Ok(Self {
                    node_id,
                    digest,
                    public_key,
                })
            }
            error => Err(ConvertError::UnexpectedPropertyType {
                expected: "entity".to_string(),
                got: format!("{:?}", error),
            }),
        }
    }
}

impl OidcDigest {
    pub fn to_name(&self) -> String {
        format!("{}/{}", self.node_id, hex::encode(&self.digest))
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use crate::utils::claim_oidc_request_digest;

    use super::*;

    #[test]
    fn test_oidc_digest_from_and_to_value() {
        let oidc_token = OidcToken::random_valid();
        let oidc_token_hash = oidc_token.digest_hash();
        let user_pk =
            PublicKey::from_str("ed25519:J75xXmF7WUPS3xCm3hy2tgwLCKdYM1iJd4BWF8sWVnae").unwrap();

        let oidc_request_digest = match claim_oidc_request_digest(&oidc_token_hash, &user_pk) {
            Ok(digest) => digest,
            Err(err) => panic!("Failed to create digest: {:?}", err),
        };

        let digest = <[u8; 32]>::try_from(oidc_request_digest).expect("Hash was wrong size");
        let digest = OidcHash(digest);

        let oidc_digest = OidcDigest {
            node_id: 1,
            digest: digest.clone(),
            public_key: user_pk,
        };

        let val = oidc_digest.clone().into_value();

        let reconstructed_oidc_digest = match OidcDigest::from_value(val) {
            Ok(oidc_digest) => oidc_digest,
            Err(err) => panic!("Failed to reconstruct OidcDigest: {:?}", err),
        };

        // Wrong digest for comparison
        let public_key_2 = "ed25519:EBNJGHctB2LuDsCyMWrfwW87QrAob2kKzoS98PR5vjJn";
        let oidc_digest_2 = OidcDigest {
            node_id: 1,
            digest,
            public_key: public_key_2.parse().expect("Failed to parse public key"),
        };

        assert_eq!(oidc_digest, reconstructed_oidc_digest);
        assert_ne!(oidc_digest_2, reconstructed_oidc_digest);
    }

    #[test]
    fn test_oidc_to_name() {
        let oidc_token = OidcToken::random_valid();
        let user_pk =
            PublicKey::from_str("ed25519:J75xXmF7WUPS3xCm3hy2tgwLCKdYM1iJd4BWF8sWVnae").unwrap();
        let oidc_token_hash = oidc_token.digest_hash();

        let digest = match claim_oidc_request_digest(&oidc_token_hash, &user_pk) {
            Ok(digest) => digest,
            Err(err) => panic!("Failed to create digest: {:?}", err),
        };

        let digest = <[u8; 32]>::try_from(digest).expect("Hash was wrong size");
        let digest = OidcHash(digest);

        let oidc_digest = OidcDigest {
            node_id: 1,
            digest,
            public_key: user_pk,
        };

        let name = oidc_digest.to_name();

        assert_eq!(
            name,
            format!(
                "{}/{}",
                oidc_digest.node_id,
                hex::encode(oidc_digest.digest)
            )
        );
    }
}
