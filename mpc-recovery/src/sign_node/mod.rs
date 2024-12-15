use self::aggregate_signer::{NodeInfo, Reveal, SignedCommitment, SigningState};
use self::oidc::OidcDigest;
use self::user_credentials::EncryptedUserCredentials;
use crate::error::{MpcError, SignNodeError};
use crate::gcp::GcpService;
use crate::msg::{AcceptNodePublicKeysRequest, PublicKeyNodeRequest, SignNodeRequest};
use crate::oauth::verify_oidc_token;
use crate::primitives::InternalAccountId;
use crate::sign_node::pk_set::SignerNodePkSet;
use crate::utils::{
    check_digest_signature, claim_oidc_request_digest, claim_oidc_response_digest,
    sign_request_digest, user_credentials_request_digest,
};
use crate::NodeId;

use aes_gcm::Aes256Gcm;
use axum::routing::get;
use axum::{http::StatusCode, routing::post, Extension, Json, Router};
use axum_extra::extract::WithRejection;
use borsh::BorshSerialize;
use curv::elliptic::curves::{Ed25519, Point};
use multi_party_eddsa::protocols::{self, ExpandedKeyPair};

use near_primitives::hash::hash;
use near_primitives::signable_message::{SignableMessage, SignableMessageType};

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

pub mod aggregate_signer;
pub mod migration;
pub mod oidc;
pub mod pk_set;
pub mod user_credentials;

pub struct Config {
    pub gcp_service: GcpService,
    pub our_index: NodeId,
    pub node_key: ExpandedKeyPair,
    pub cipher: Aes256Gcm,
    pub port: u16,
    pub jwt_signature_pk_urls: HashMap<String, String>,
}

pub async fn run(config: Config) {
    tracing::debug!("running a sign node");
    let Config {
        gcp_service,
        our_index,
        node_key,
        cipher,
        port,
        jwt_signature_pk_urls,
    } = config;
    let our_index = usize::try_from(our_index).expect("This index is way to big");

    let pk_set = gcp_service
        .get::<_, SignerNodePkSet>(format!("{}/{}", our_index, pk_set::MAIN_KEY))
        .await
        .unwrap_or_default();

    let state = Arc::new(SignNodeState {
        gcp_service,
        reqwest_client: reqwest::Client::new(),
        node_key,
        cipher,
        signing_state: SigningState::new(),
        node_info: NodeInfo::new(our_index, pk_set.map(|set| set.public_keys)),
        jwt_signature_pk_urls,
    });

    let app = Router::new()
        // healthcheck endpoint
        .route(
            "/",
            get(|| async move {
                tracing::info!("node is ready to accept connections");
                StatusCode::OK
            }),
        )
        .route("/commit", post(commit))
        .route("/reveal", post(reveal))
        .route("/signature_share", post(signature_share))
        .route("/public_key", post(public_key))
        .route("/public_key_node", post(public_key_node))
        .route("/accept_pk_set", post(accept_pk_set))
        .layer(Extension(state));

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    tracing::debug!(?addr, "starting http server");
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}

struct SignNodeState {
    gcp_service: GcpService,
    reqwest_client: reqwest::Client,
    node_key: ExpandedKeyPair,
    cipher: Aes256Gcm,
    signing_state: SigningState,
    node_info: NodeInfo,
    jwt_signature_pk_urls: HashMap<String, String>,
}

async fn get_or_generate_user_creds(
    state: &SignNodeState,
    internal_account_id: InternalAccountId,
) -> anyhow::Result<EncryptedUserCredentials> {
    match state
        .gcp_service
        .get::<_, EncryptedUserCredentials>(format!(
            "{}/{}",
            state.node_info.our_index, internal_account_id
        ))
        .await
    {
        Ok(Some(user_credentials)) => {
            tracing::debug!(internal_account_id, "found an existing user");
            Ok(user_credentials)
        }
        Ok(None) => {
            let user_credentials = EncryptedUserCredentials::random(
                state.node_info.our_index,
                internal_account_id.clone(),
                &state.cipher,
            )?;
            tracing::debug!(
                internal_account_id,
                public_key = ?user_credentials.public_key,
                "generating credentials for a new user"
            );
            state.gcp_service.insert(user_credentials.clone()).await?;
            Ok(user_credentials)
        }
        Err(e) => Err(e),
    }
}

async fn process_commit(
    state: Arc<SignNodeState>,
    request: SignNodeRequest,
) -> Result<SignedCommitment, SignNodeError> {
    tracing::info!(?request, "processing commit request");
    match request {
        SignNodeRequest::ClaimOidc(request) => {
            tracing::debug!(?request, "processing oidc claim request");
            // Check ID token hash signature
            let public_key = request.public_key;
            let request_digest = claim_oidc_request_digest(&request.oidc_token_hash, &public_key)?;

            match check_digest_signature(&public_key, &request.signature, &request_digest) {
                Ok(()) => tracing::debug!("claim oidc token digest signature verified"),
                Err(e) => return Err(SignNodeError::DigestSignatureVerificationFailed(e)),
            };

            // Save info about token in the database, if it's present, throw an error
            let oidc_digest = OidcDigest {
                node_id: state.node_info.our_index,
                digest: request.oidc_token_hash,
                public_key,
            };

            match state
                .gcp_service
                .get::<_, OidcDigest>(oidc_digest.to_name())
                .await
            {
                Ok(Some(stored_digest)) => {
                    if stored_digest == oidc_digest {
                        tracing::info!(?oidc_digest, "oidc token with this key is already claimed");
                    } else {
                        tracing::error!(
                            ?oidc_digest,
                            ?stored_digest,
                            "oidc token already claimed with another key"
                        );
                        return Err(SignNodeError::OidcTokenAlreadyClaimed(oidc_digest));
                    }
                }
                Ok(None) => {
                    tracing::info!(?oidc_digest, "adding oidc token digest to the database");
                    state.gcp_service.insert(oidc_digest).await?;
                }
                Err(e) => {
                    tracing::error!(
                        ?oidc_digest,
                        "failed to get oidc token digest from the database"
                    );
                    return Err(SignNodeError::Other(e));
                }
            };

            // Returned signed commitment (signature of the signature)
            let payload = match claim_oidc_response_digest(request.signature) {
                Ok(payload) => payload,
                Err(e) => return Err(e),
            };
            let response = state
                .signing_state
                .get_commitment(&state.node_key, &state.node_key, payload)
                .await
                .map_err(|e| anyhow::anyhow!(e))?;
            tracing::info!("returning signed commitment");
            Ok(response)
        }
        SignNodeRequest::SignShare(request) => {
            tracing::debug!(?request, "processing sign share request");

            // Check OIDC Token
            let oidc_token_claims = verify_oidc_token(
                &request.oidc_token,
                None,
                &state.reqwest_client,
                &state.jwt_signature_pk_urls,
            )
            .await
            .map_err(SignNodeError::OidcVerificationFailed)?;
            tracing::debug!(?oidc_token_claims, "oidc token verified");

            let frp_pk = request.frp_public_key;

            // Check request FRP signature
            let digest =
                sign_request_digest(&request.delegate_action, &request.oidc_token, &frp_pk)?;
            match check_digest_signature(&frp_pk, &request.frp_signature, &digest) {
                Ok(()) => tracing::debug!("sign request digest signature verified"),
                Err(e) => return Err(SignNodeError::DigestSignatureVerificationFailed(e)),
            };

            // Check if this OIDC token was claimed
            let oidc_hash = request.oidc_token.digest_hash();

            let oidc_digest = OidcDigest {
                node_id: state.node_info.our_index,
                digest: oidc_hash,
                public_key: frp_pk,
            };

            match state
                .gcp_service
                .get::<_, OidcDigest>(oidc_digest.to_name())
                .await
            {
                Ok(Some(stored_digest)) => {
                    if stored_digest == oidc_digest {
                        tracing::info!(?oidc_digest, "oidc token was claimed with provided pk");
                    } else {
                        tracing::error!(?oidc_digest, "oidc token was claimed with another key");
                        return Err(SignNodeError::OidcTokenClaimedWithAnotherKey(oidc_digest));
                    }
                }
                Ok(None) => {
                    tracing::info!(?oidc_digest, "oidc token was not claimed");
                    return Err(SignNodeError::OidcTokenNotClaimed(oidc_digest));
                }
                Err(e) => {
                    tracing::error!(
                        ?oidc_digest,
                        "failed to get oidc token digest from the database"
                    );
                    return Err(SignNodeError::Other(e));
                }
            };

            // Get user credentials
            let internal_account_id = oidc_token_claims.get_internal_account_id();
            let user_credentials = get_or_generate_user_creds(&state, internal_account_id).await?;
            tracing::debug!("user credentials retrieved");

            // Get commitment
            let signable_message = SignableMessage::new(
                &request.delegate_action,
                SignableMessageType::DelegateAction,
            );
            let bytes = match signable_message.try_to_vec() {
                Ok(bytes) => bytes,
                Err(e) => return Err(SignNodeError::Other(e.into())),
            };
            let hash = hash(&bytes).as_bytes().to_vec();

            let response = state
                .signing_state
                .get_commitment(
                    &user_credentials.decrypt_key_pair(&state.cipher)?,
                    &state.node_key,
                    hash,
                )
                .await
                .map_err(|e| anyhow::anyhow!(e))?;
            tracing::info!("returning signed commitment");
            Ok(response)
        }
    }
}

#[tracing::instrument(level = "debug", skip_all, fields(id = state.node_info.our_index))]
async fn commit(
    Extension(state): Extension<Arc<SignNodeState>>,
    WithRejection(Json(request), _): WithRejection<Json<SignNodeRequest>, MpcError>,
) -> (StatusCode, Json<Result<SignedCommitment, String>>) {
    if let Err(msg) = check_if_ready(&state).await {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(Err(msg)));
    }

    match process_commit(state, request).await {
        Ok(signed_commitment) => (StatusCode::OK, Json(Ok(signed_commitment))),
        Err(e) => (e.code(), Json(Err(e.to_string()))),
    }
}

#[tracing::instrument(level = "debug", skip_all, fields(id = state.node_info.our_index))]
async fn reveal(
    Extension(state): Extension<Arc<SignNodeState>>,
    WithRejection(Json(request), _): WithRejection<Json<Vec<SignedCommitment>>, MpcError>,
) -> (StatusCode, Json<Result<Reveal, String>>) {
    if let Err(msg) = check_if_ready(&state).await {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(Err(msg)));
    }

    match state
        .signing_state
        .get_reveal(&state.node_info, request)
        .await
    {
        Ok(r) => {
            tracing::debug!("Successful reveal");
            (StatusCode::OK, Json(Ok(r)))
        }
        Err(e) => {
            tracing::error!("Reveal failed: {}", e);
            (e.code(), Json(Err(e.to_string())))
        }
    }
}

#[tracing::instrument(level = "debug", skip_all, fields(id = state.node_info.our_index))]
async fn signature_share(
    Extension(state): Extension<Arc<SignNodeState>>,
    WithRejection(Json(request), _): WithRejection<Json<Vec<Reveal>>, MpcError>,
) -> (StatusCode, Json<Result<protocols::Signature, String>>) {
    if let Err(msg) = check_if_ready(&state).await {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(Err(msg)));
    }

    match state
        .signing_state
        .get_signature_share(&state.node_info, request)
        .await
    {
        Ok(r) => {
            tracing::debug!("Successful signature share");
            (StatusCode::OK, Json(Ok(r)))
        }
        Err(e) => {
            tracing::error!("Signature share failed: {}", e);
            (e.code(), Json(Err(e.to_string())))
        }
    }
}

async fn process_public_key(
    state: Arc<SignNodeState>,
    request: PublicKeyNodeRequest,
) -> Result<Point<Ed25519>, SignNodeError> {
    // Check OIDC Token
    let oidc_token_claims = verify_oidc_token(
        &request.oidc_token,
        None,
        &state.reqwest_client,
        &state.jwt_signature_pk_urls,
    )
    .await
    .map_err(SignNodeError::OidcVerificationFailed)?;

    let frp_pk = request.frp_public_key;
    // Check the request signature
    let digest = user_credentials_request_digest(&request.oidc_token, &frp_pk)?;
    match check_digest_signature(&frp_pk, &request.frp_signature, &digest) {
        Ok(()) => tracing::debug!("user credentials digest signature verified"),
        Err(e) => return Err(SignNodeError::DigestSignatureVerificationFailed(e)),
    };

    // Check if this OIDC token was claimed
    let oidc_hash = request.oidc_token.digest_hash();

    let oidc_digest = OidcDigest {
        node_id: state.node_info.our_index,
        digest: oidc_hash,
        public_key: frp_pk,
    };

    match state
        .gcp_service
        .get::<_, OidcDigest>(oidc_digest.to_name())
        .await
    {
        Ok(Some(stored_digest)) => {
            if stored_digest == oidc_digest {
                tracing::info!(?oidc_digest, "oidc token was claimed with provided pk");
            } else {
                tracing::error!(?oidc_digest, "oidc token was claimed with another key");
                return Err(SignNodeError::OidcTokenClaimedWithAnotherKey(oidc_digest));
            }
        }
        Ok(None) => {
            tracing::info!(?oidc_digest, "oidc token was not claimed");
            return Err(SignNodeError::OidcTokenNotClaimed(oidc_digest));
        }
        Err(e) => {
            tracing::error!(
                ?oidc_digest,
                "failed to get oidc token digest from the database"
            );
            return Err(SignNodeError::Other(e));
        }
    };

    let internal_acc_id = oidc_token_claims.get_internal_account_id();
    match get_or_generate_user_creds(&state, internal_acc_id).await {
        Ok(user_credentials) => Ok(user_credentials.public_key().clone()),
        Err(err) => Err(SignNodeError::Other(err)),
    }
}

#[tracing::instrument(level = "debug", skip_all, fields(id = state.node_info.our_index))]
async fn public_key(
    Extension(state): Extension<Arc<SignNodeState>>,
    WithRejection(Json(request), _): WithRejection<Json<PublicKeyNodeRequest>, MpcError>,
) -> (StatusCode, Json<Result<Point<Ed25519>, String>>) {
    let result = process_public_key(state, request).await;
    match result {
        Ok(pk_point) => (StatusCode::OK, Json(Ok(pk_point))),
        Err(e) => (e.code(), Json(Err(e.to_string()))),
    }
}

#[allow(clippy::type_complexity)]
#[tracing::instrument(level = "debug", skip_all, fields(id = state.node_info.our_index))]
async fn public_key_node(
    Extension(state): Extension<Arc<SignNodeState>>,
    WithRejection(Json(_), _): WithRejection<Json<()>, MpcError>,
) -> (StatusCode, Json<Result<(usize, Point<Ed25519>), String>>) {
    (
        StatusCode::OK,
        Json(Ok((
            state.node_info.our_index,
            state.node_key.public_key.clone(),
        ))),
    )
}

#[tracing::instrument(level = "debug", skip_all, fields(id = state.node_info.our_index))]
async fn accept_pk_set(
    Extension(state): Extension<Arc<SignNodeState>>,
    WithRejection(Json(request), _): WithRejection<Json<AcceptNodePublicKeysRequest>, MpcError>,
) -> (StatusCode, Json<Result<String, String>>) {
    let index = state.node_info.our_index;
    if request.public_keys.get(index) != Some(&state.node_key.public_key) {
        tracing::error!("provided secret share does not match the node id");
        return (StatusCode::BAD_REQUEST, Json(Err(format!(
            "Sign node could not accept the public keys: current node index={index} does not match up"))));
    }

    let mut public_keys = state.node_info.nodes_public_keys.write().await;
    if let Some(pk_set) = public_keys.as_ref() {
        if pk_set == &request.public_keys {
            return (
                StatusCode::OK,
                Json(Ok(
                    "This node is already initialized with provided public keys".to_string(),
                )),
            );
        } else {
            return (
                StatusCode::BAD_REQUEST,
                Json(Err(
                    "This node is already initialized with different public keys".to_string(),
                )),
            );
        }
    }
    tracing::debug!("Setting node public keys => {:?}", request.public_keys);
    public_keys.replace(request.public_keys.clone());
    match state
        .gcp_service
        .insert(SignerNodePkSet {
            node_id: state.node_info.our_index,
            public_keys: request.public_keys,
        })
        .await
    {
        Ok(_) => (
            StatusCode::OK,
            Json(Ok("Successfully set node public keys".to_string())),
        ),
        Err(err) => {
            tracing::error!("Failed to save pk set due to GCP error: {err}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(Ok("failed to save node public keys".to_string())),
            )
        }
    }
}

/// Validate whether the current state of the sign node is useable or not.
async fn check_if_ready(state: &SignNodeState) -> Result<(), String> {
    let public_keys = state.node_info.nodes_public_keys.read().await;
    if public_keys.is_none() {
        return Err(
            "Sign node is not ready yet: waiting on all public keys from leader node".into(),
        );
    }

    Ok(())
}
