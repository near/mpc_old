pub mod wait_for;

use crate::MultichainTestContext;

use cait_sith::FullSignature;
use crypto_shared::ScalarExt;
use crypto_shared::SerializableAffinePoint;
use crypto_shared::{derive_epsilon, derive_key, SerializableScalar, SignatureResponse};
use elliptic_curve::sec1::ToEncodedPoint;
use k256::ecdsa::VerifyingKey;
use k256::elliptic_curve::ops::{Invert, Reduce};
use k256::elliptic_curve::point::AffineCoordinates;
use k256::elliptic_curve::sec1::FromEncodedPoint;
use k256::elliptic_curve::ProjectivePoint;
use k256::{AffinePoint, EncodedPoint, Scalar, Secp256k1};
use mpc_contract::errors;
use mpc_contract::errors::SignError;
use mpc_contract::primitives::SignRequest;
use mpc_contract::primitives::SignatureRequest;
use mpc_contract::RunningContractState;
use mpc_node::kdf::into_eth_sig;
use near_crypto::InMemorySigner;
use near_fetch::ops::AsyncTransactionStatus;
use near_fetch::ops::Function;
use near_workspaces::types::Gas;
use near_workspaces::types::NearToken;
use near_workspaces::Account;
use rand::Rng;
use secp256k1::XOnlyPublicKey;
use wait_for::{SignatureError, WaitForError};

use std::time::Duration;

const CHAIN_ID_ETH: u64 = 31337;

use integration_tests_chain_signatures::containers::LakeIndexer;
use k256::{
    ecdsa::{Signature as RecoverableSignature, Signature as K256Signature},
    PublicKey as K256PublicKey,
};
use serde_json::json;

pub async fn request_sign(
    ctx: &MultichainTestContext<'_>,
) -> anyhow::Result<([u8; 32], [u8; 32], Account, AsyncTransactionStatus)> {
    let worker = &ctx.nodes.ctx().worker;
    let account = worker.dev_create_account().await?;
    let payload: [u8; 32] = rand::thread_rng().gen();
    let payload_hashed = web3::signing::keccak256(&payload);

    let signer = InMemorySigner {
        account_id: account.id().clone(),
        public_key: account.secret_key().public_key().to_string().parse()?,
        secret_key: account.secret_key().to_string().parse()?,
    };

    let request = SignRequest {
        payload: payload_hashed,
        path: "test".to_string(),
        key_version: 0,
    };
    let status = ctx
        .rpc_client
        .call(&signer, ctx.contract().id(), "sign")
        .args_json(serde_json::json!({
            "request": request,
        }))
        .gas(Gas::from_tgas(50))
        .deposit(NearToken::from_yoctonear(1))
        .transact_async()
        .await?;
    tokio::time::sleep(Duration::from_secs(1)).await;
    Ok((payload, payload_hashed, account, status))
}

pub async fn request_batch_random_sign(
    ctx: &MultichainTestContext<'_>,
) -> anyhow::Result<(Vec<([u8; 32], [u8; 32])>, Account, AsyncTransactionStatus)> {
    let worker = &ctx.nodes.ctx().worker;
    let account = worker.dev_create_account().await?;
    let signer = InMemorySigner {
        account_id: account.id().clone(),
        public_key: account.secret_key().public_key().to_string().parse()?,
        secret_key: account.secret_key().to_string().parse()?,
    };

    let mut payloads: Vec<([u8; 32], [u8; 32])> = vec![];
    let mut tx = ctx.rpc_client.batch(&signer, ctx.contract().id());
    for _ in 0..3 {
        let payload: [u8; 32] = rand::thread_rng().gen();
        let payload_hashed = web3::signing::keccak256(&payload);
        payloads.push((payload, payload_hashed));
        let request = SignRequest {
            payload: payload_hashed,
            path: "test".to_string(),
            key_version: 0,
        };
        let function = Function::new("sign")
            .args_json(serde_json::json!({
                "request": request,
            }))
            .gas(Gas::from_tgas(50))
            .deposit(NearToken::from_yoctonear(1));
        tx = tx.call(function);
    }

    let status = tx.transact_async().await?;
    tokio::time::sleep(Duration::from_secs(3)).await;
    Ok((payloads, account, status))
}

pub async fn request_batch_duplicate_sign(
    ctx: &MultichainTestContext<'_>,
) -> anyhow::Result<([u8; 32], u32, Account, AsyncTransactionStatus)> {
    let worker = &ctx.nodes.ctx().worker;
    let account = worker.dev_create_account().await?;
    let signer = InMemorySigner {
        account_id: account.id().clone(),
        public_key: account.secret_key().public_key().to_string().parse()?,
        secret_key: account.secret_key().to_string().parse()?,
    };

    let mut tx = ctx.rpc_client.batch(&signer, ctx.contract().id());
    let payload: [u8; 32] = rand::thread_rng().gen();
    let payload_hashed = web3::signing::keccak256(&payload);
    let sign_call_cnt = 2;
    for _ in 0..sign_call_cnt {
        let request = SignRequest {
            payload: payload_hashed,
            path: "test".to_string(),
            key_version: 0,
        };
        let function = Function::new("sign")
            .args_json(serde_json::json!({
                "request": request,
            }))
            .gas(Gas::from_tgas(50))
            .deposit(NearToken::from_yoctonear(1));
        tx = tx.call(function);
    }

    let status = tx.transact_async().await?;
    tokio::time::sleep(Duration::from_secs(3)).await;
    Ok((payload_hashed, sign_call_cnt, account, status))
}

pub async fn assert_signature(
    account_id: &near_workspaces::AccountId,
    mpc_pk_bytes: &[u8],
    payload: [u8; 32],
    signature: &FullSignature<Secp256k1>,
) {
    let mpc_point = EncodedPoint::from_bytes(mpc_pk_bytes).unwrap();
    let mpc_pk = AffinePoint::from_encoded_point(&mpc_point).unwrap();
    let epsilon = derive_epsilon(account_id, "test");
    let user_pk = derive_key(mpc_pk, epsilon);
    assert!(signature.verify(&user_pk, &Scalar::from_bytes(payload).unwrap(),));
}

// A normal signature, but we try to insert a bad response which fails and the signature is generated
pub async fn single_signature_rogue_responder(
    ctx: &MultichainTestContext<'_>,
    state: &RunningContractState,
) -> anyhow::Result<()> {
    let (_, payload_hash, account, status) = request_sign(ctx).await?;

    // We have to use seperate transactions because one could fail.
    // This leads to a potential race condition where this transaction could get sent after the signature completes, but I think that's unlikely
    let rogue_status = rogue_respond(ctx, payload_hash, account.id(), "test").await?;
    let err = wait_for::rogue_message_responded(rogue_status).await?;

    assert!(err.contains(&errors::RespondError::InvalidSignature.to_string()));
    let signature = wait_for::signature_responded(status).await?;

    let mut mpc_pk_bytes = vec![0x04];
    mpc_pk_bytes.extend_from_slice(&state.public_key.as_bytes()[1..]);

    // Useful for populating the "signatures_havent_changed" test's hardcoded values
    // dbg!(
    //     hex::encode(signature.big_r.to_encoded_point(true).to_bytes()),
    //     hex::encode(signature.s.to_bytes()),
    //     hex::encode(&mpc_pk_bytes),
    //     hex::encode(&payload_hash),
    //     account.id(),
    // );
    assert_signature(account.id(), &mpc_pk_bytes, payload_hash, &signature).await;

    Ok(())
}

pub async fn single_signature_production(
    ctx: &MultichainTestContext<'_>,
    state: &RunningContractState,
) -> anyhow::Result<()> {
    let (_, payload_hash, account, status) = request_sign(ctx).await?;
    let signature = wait_for::signature_responded(status).await?;

    let mut mpc_pk_bytes = vec![0x04];
    mpc_pk_bytes.extend_from_slice(&state.public_key.as_bytes()[1..]);
    assert_signature(account.id(), &mpc_pk_bytes, payload_hash, &signature).await;

    Ok(())
}

pub async fn rogue_respond(
    ctx: &MultichainTestContext<'_>,
    payload_hash: [u8; 32],
    predecessor: &near_workspaces::AccountId,
    path: &str,
) -> anyhow::Result<AsyncTransactionStatus> {
    let worker = &ctx.nodes.ctx().worker;
    let account = worker.dev_create_account().await?;

    let signer = InMemorySigner {
        account_id: account.id().clone(),
        public_key: account.secret_key().public_key().clone().into(),
        secret_key: account.secret_key().to_string().parse()?,
    };
    let epsilon = derive_epsilon(predecessor, path);

    let request = SignatureRequest {
        payload_hash: Scalar::from_bytes(payload_hash).unwrap().into(),
        epsilon: SerializableScalar { scalar: epsilon },
    };

    let big_r = serde_json::from_value(
        "02EC7FA686BB430A4B700BDA07F2E07D6333D9E33AEEF270334EB2D00D0A6FEC6C".into(),
    )?; // Fake BigR
    let s = serde_json::from_value(
        "20F90C540EE00133C911EA2A9ADE2ABBCC7AD820687F75E011DFEEC94DB10CD6".into(),
    )?; // Fake S

    let response = SignatureResponse {
        big_r: SerializableAffinePoint {
            affine_point: big_r,
        },
        s: SerializableScalar { scalar: s },
        recovery_id: 0,
    };

    let status = ctx
        .rpc_client
        .call(&signer, ctx.contract().id(), "respond")
        .args_json(serde_json::json!({
            "request": request,
            "response": response,
        }))
        .max_gas()
        .transact_async()
        .await?;

    tokio::time::sleep(Duration::from_secs(1)).await;
    Ok(status)
}

pub async fn request_sign_non_random(
    ctx: &MultichainTestContext<'_>,
    account: Account,
    payload: [u8; 32],
    payload_hashed: [u8; 32],
) -> Result<([u8; 32], [u8; 32], Account, AsyncTransactionStatus), WaitForError> {
    let signer = InMemorySigner {
        account_id: account.id().clone(),
        public_key: account
            .secret_key()
            .public_key()
            .to_string()
            .parse()
            .map_err(|_| WaitForError::Parsing)?,
        secret_key: account
            .secret_key()
            .to_string()
            .parse()
            .map_err(|_| WaitForError::Parsing)?,
    };

    let request = SignRequest {
        payload: payload_hashed,
        path: "test".to_string(),
        key_version: 0,
    };

    let status = ctx
        .rpc_client
        .call(&signer, ctx.contract().id(), "sign")
        .args_json(serde_json::json!({
            "request": request,
        }))
        .gas(Gas::from_tgas(50))
        .deposit(NearToken::from_yoctonear(1))
        .transact_async()
        .await
        .map_err(|error| WaitForError::JsonRpc(format!("{error:?}")))?;
    tokio::time::sleep(Duration::from_secs(1)).await;
    Ok((payload, payload_hashed, account, status))
}

pub async fn single_payload_signature_production(
    ctx: &MultichainTestContext<'_>,
    state: &RunningContractState,
) -> anyhow::Result<()> {
    let (payload, payload_hash, account, status) = request_sign(ctx).await?;
    let first_tx_result = wait_for::signature_responded(status).await;
    let signature = match first_tx_result {
        Ok(sig) => sig,
        Err(error) => {
            println!("single_payload_signature_production: first sign tx err out with {error:?}");
            wait_for::signature_payload_responded(ctx, account.clone(), payload, payload_hash)
                .await?
        }
    };
    let mut mpc_pk_bytes = vec![0x04];
    mpc_pk_bytes.extend_from_slice(&state.public_key.as_bytes()[1..]);
    assert_signature(
        account.clone().id(),
        &mpc_pk_bytes,
        payload_hash,
        &signature,
    )
    .await;

    Ok(())
}

// add one of toxic to the toxiproxy-server to make indexer rpc slow down, congested, or unstable
// available toxics and params: https://github.com/Shopify/toxiproxy?tab=readme-ov-file#toxic-fields
pub async fn add_toxic(proxy: &str, host: bool, toxic: serde_json::Value) -> anyhow::Result<()> {
    let toxi_server_address = if host {
        LakeIndexer::TOXI_SERVER_PROCESS_ADDRESS
    } else {
        LakeIndexer::TOXI_SERVER_EXPOSE_ADDRESS
    };
    let toxiproxy_client = reqwest::Client::default();
    toxiproxy_client
        .post(format!("{}/proxies/{}/toxics", toxi_server_address, proxy))
        .header("Content-Type", "application/json")
        .body(toxic.to_string())
        .send()
        .await?;
    Ok(())
}

// Add a delay to all data going through the proxy. The delay is equal to latency +/- jitter.
pub async fn add_latency(
    proxy: &str,
    host: bool,
    probability: f32,
    latency: u32,
    jitter: u32,
) -> anyhow::Result<()> {
    add_toxic(
        proxy,
        host,
        json!({
            "type": "latency",
            "toxicity": probability,
            "attributes": {
                "latency": latency,
                "jitter": jitter
            }
        }),
    )
    .await
}

// clear all toxics. Does not need to be called between tests since each test will drop toxiproxy-server
// Only need if you want to clear all toxics in middle of a test
#[allow(dead_code)]
pub async fn clear_toxics() -> anyhow::Result<()> {
    let toxi_server_address = "http://127.0.0.1:8474";
    let toxiproxy_client = reqwest::Client::default();
    toxiproxy_client
        .post(format!("{}/reset", toxi_server_address))
        .send()
        .await?;
    Ok(())
}

pub async fn batch_random_signature_production(
    ctx: &MultichainTestContext<'_>,
    state: &RunningContractState,
) -> anyhow::Result<()> {
    let (payloads, account, status) = request_batch_random_sign(ctx).await?;
    let signatures = wait_for::batch_signature_responded(status).await?;

    let mut mpc_pk_bytes = vec![0x04];
    mpc_pk_bytes.extend_from_slice(&state.public_key.as_bytes()[1..]);
    assert_eq!(payloads.len(), signatures.len());
    for i in 0..payloads.len() {
        let (_, payload_hash) = payloads.get(i).unwrap();
        let signature = signatures.get(i).unwrap();
        assert_signature(account.id(), &mpc_pk_bytes, *payload_hash, signature).await;
    }

    Ok(())
}

pub async fn batch_duplicate_signature_production(
    ctx: &MultichainTestContext<'_>,
    _state: &RunningContractState,
) -> anyhow::Result<()> {
    let (_, _, _, status) = request_batch_duplicate_sign(ctx).await?;
    let result = wait_for::batch_signature_responded(status).await;
    match result {
        Err(WaitForError::Signature(SignatureError::Failed(err_msg))) => {
            assert!(err_msg.contains(&SignError::RequestCollision.to_string()));
        }
        _ => panic!("Should have failed with PayloadCollision"),
    }
    Ok(())
}

// This test hardcodes the output of the signing process and checks that everything verifies as expected
// If you find yourself changing the constants in this test you are likely breaking backwards compatibility
#[tokio::test]
async fn signatures_havent_changed() {
    let big_r = "03f13a99141ce0a4043a7c02afdec6d52f25c6b3de01967acc5cf4a3fa43801589";
    let s = "39e5631fcc06ffccf8469a3cdcdce0651ebafd998a4280ebbf5dc24a749c98fb";
    let mpc_key = "04b5695a882aeaf36bf3933e21911b5cbcceae7fd7cb424f3ea221c7e8d390aad4ad2c1a427faec960f22a5442739c0a04fd64ab7ce4c93980417bd3d1d8bc04ea";
    let account_id = "dev-20240719125040-80075249096169.test.near";
    let payload_hash: [u8; 32] =
        hex::decode("49f32740939bfdcbd8d1786075df7aca384381ec203975c3a6c1fd80acddcd4c")
            .unwrap()
            .try_into()
            .unwrap();

    let payload_hash_scalar = Scalar::from_bytes(payload_hash).unwrap();

    // Derive and convert user pk
    let mpc_pk = hex::decode(mpc_key).unwrap();
    let mpc_pk = EncodedPoint::from_bytes(mpc_pk).unwrap();
    let mpc_pk = AffinePoint::from_encoded_point(&mpc_pk).unwrap();

    let account_id = account_id.parse().unwrap();
    let derivation_epsilon: k256::Scalar = derive_epsilon(&account_id, "test");
    let user_pk: AffinePoint = derive_key(mpc_pk, derivation_epsilon);
    let user_pk_y_parity = match user_pk.y_is_odd().unwrap_u8() {
        0 => secp256k1::Parity::Even,
        1 => secp256k1::Parity::Odd,
        _ => unreachable!(),
    };
    let user_pk_x = x_coordinate::<k256::Secp256k1>(&user_pk);
    let user_pk_x: XOnlyPublicKey = XOnlyPublicKey::from_slice(&user_pk_x.to_bytes()).unwrap();
    let user_secp_pk: secp256k1::PublicKey =
        secp256k1::PublicKey::from_x_only_public_key(user_pk_x, user_pk_y_parity);
    let user_address_from_pk = public_key_to_address(&user_secp_pk);

    // Prepare R ans s signature values
    let big_r = hex::decode(big_r).unwrap();
    let big_r = EncodedPoint::from_bytes(big_r).unwrap();
    let big_r = AffinePoint::from_encoded_point(&big_r).unwrap();
    let big_r_y_parity = big_r.y_is_odd().unwrap_u8() as i32;
    assert!(big_r_y_parity == 0 || big_r_y_parity == 1);

    let s = hex::decode(s).unwrap().try_into().unwrap();
    let s = k256::Scalar::from_bytes(s).unwrap();
    let r = x_coordinate::<k256::Secp256k1>(&big_r);

    let signature = cait_sith::FullSignature::<Secp256k1> { big_r, s };

    let multichain_sig = into_eth_sig(
        &user_pk,
        &signature.big_r,
        &signature.s,
        payload_hash_scalar,
    )
    .unwrap();

    // Check signature using cait-sith tooling
    let is_signature_valid_for_user_pk = signature.verify(&user_pk, &payload_hash_scalar);
    let is_signature_valid_for_mpc_pk = signature.verify(&mpc_pk, &payload_hash_scalar);
    let another_user_pk = derive_key(mpc_pk, derivation_epsilon + k256::Scalar::ONE);
    let is_signature_valid_for_another_user_pk =
        signature.verify(&another_user_pk, &payload_hash_scalar);
    assert!(is_signature_valid_for_user_pk);
    assert!(!is_signature_valid_for_mpc_pk);
    assert!(!is_signature_valid_for_another_user_pk);

    // Check signature using ecdsa tooling
    let k256_sig = k256::ecdsa::Signature::from_scalars(r, s).unwrap();
    let user_pk_k256: k256::elliptic_curve::PublicKey<Secp256k1> =
        k256::PublicKey::from_affine(user_pk).unwrap();

    let ecdsa_local_verify_result = verify(
        &k256::ecdsa::VerifyingKey::from(&user_pk_k256),
        &payload_hash,
        &k256_sig,
    );
    assert!(ecdsa_local_verify_result.is_ok());

    // TODO: fix
    // let ecdsa_signature: ecdsa::Signature<Secp256k1> =
    //     ecdsa::Signature::from_scalars(r, s).unwrap();
    // let ecdsa_verify_result = ecdsa::signature::Verifier::verify(
    //     &k256::ecdsa::VerifyingKey::from(&user_pk_k256),
    //     &payload_hash_reversed,
    //     &ecdsa_signature,
    // );
    // assert!(ecdsa_verify_result.is_ok());
    // let k256_verify_key = k256::ecdsa::VerifyingKey::from(&user_pk_k256);
    // let k256_verify_result = k256_verify_key.verify(&payload_hash_reversed, &k256_sig);
    // assert!(k256_verify_result.is_ok());

    // Check signature using etheres tooling
    let ethers_r = ethers_core::types::U256::from_big_endian(r.to_bytes().as_slice());
    let ethers_s = ethers_core::types::U256::from_big_endian(s.to_bytes().as_slice());
    let ethers_v = to_eip155_v(multichain_sig.recovery_id, CHAIN_ID_ETH);

    let signature = ethers_core::types::Signature {
        r: ethers_r,
        s: ethers_s,
        v: ethers_v,
    };

    let verifying_user_pk = ecdsa::VerifyingKey::from(&user_pk_k256);
    let user_address_ethers: ethers_core::types::H160 =
        ethers_core::utils::public_key_to_address(&verifying_user_pk);

    assert!(signature.verify(payload_hash, user_address_ethers).is_ok());

    // Check if recovered address is the same as the user address
    let signature_for_recovery: [u8; 64] = {
        let mut signature = [0u8; 64]; // TODO: is there a better way to get these bytes?
        signature[..32].copy_from_slice(&r.to_bytes());
        signature[32..].copy_from_slice(&s.to_bytes());
        signature
    };

    let recovered_from_signature_address_web3 = web3::signing::recover(
        &payload_hash,
        &signature_for_recovery,
        multichain_sig.recovery_id as i32,
    )
    .unwrap();
    assert_eq!(user_address_from_pk, recovered_from_signature_address_web3);

    let recovered_from_signature_address_ethers = signature.recover(payload_hash).unwrap();
    assert_eq!(
        user_address_from_pk,
        recovered_from_signature_address_ethers
    );

    let recovered_from_signature_address_local_function = recover(signature, payload_hash).unwrap();
    assert_eq!(
        user_address_from_pk,
        recovered_from_signature_address_local_function
    );

    assert_eq!(user_address_from_pk, user_address_ethers);
}

/// Get the x coordinate of a point, as a scalar
pub(crate) fn x_coordinate<C: cait_sith::CSCurve>(point: &C::AffinePoint) -> C::Scalar {
    <C::Scalar as k256::elliptic_curve::ops::Reduce<<C as k256::elliptic_curve::Curve>::Uint>>::reduce_bytes(&point.x())
}

pub fn recover<M>(
    signature: ethers_core::types::Signature,
    message: M,
) -> Result<ethers_core::types::Address, ethers_core::types::SignatureError>
where
    M: Into<ethers_core::types::RecoveryMessage>,
{
    let message_hash = match message.into() {
        ethers_core::types::RecoveryMessage::Data(ref message) => {
            println!("identified as data");
            ethers_core::utils::hash_message(message)
        }
        ethers_core::types::RecoveryMessage::Hash(hash) => hash,
    };
    println!("message_hash {message_hash:#?}");

    let (recoverable_sig, recovery_id) = as_signature(signature)?;
    let verifying_key =
        VerifyingKey::recover_from_prehash(message_hash.as_ref(), &recoverable_sig, recovery_id)?;
    println!("verifying_key {verifying_key:#?}");

    let public_key = K256PublicKey::from(&verifying_key);
    //println!("ethercore public key from verifying key {public_key:#?}");

    let public_key = public_key.to_encoded_point(/* compress = */ false);
    println!("ethercore recover encoded point pk {public_key:#?}");
    let public_key = public_key.as_bytes();
    debug_assert_eq!(public_key[0], 0x04);
    let hash = ethers_core::utils::keccak256(&public_key[1..]);
    let result = ethers_core::types::Address::from_slice(&hash[12..]);
    println!("ethercore recover result {result:#?}");
    Ok(ethers_core::types::Address::from_slice(&hash[12..]))
}

/// Retrieves the recovery signature.
fn as_signature(
    signature: ethers_core::types::Signature,
) -> Result<(RecoverableSignature, k256::ecdsa::RecoveryId), ethers_core::types::SignatureError> {
    let mut recovery_id = signature.recovery_id()?;
    let mut signature = {
        let mut r_bytes = [0u8; 32];
        let mut s_bytes = [0u8; 32];
        signature.r.to_big_endian(&mut r_bytes);
        signature.s.to_big_endian(&mut s_bytes);
        let gar: &generic_array::GenericArray<u8, elliptic_curve::consts::U32> =
            generic_array::GenericArray::from_slice(&r_bytes);
        let gas: &generic_array::GenericArray<u8, elliptic_curve::consts::U32> =
            generic_array::GenericArray::from_slice(&s_bytes);
        K256Signature::from_scalars(*gar, *gas)?
    };

    // Normalize into "low S" form. See:
    // - https://github.com/RustCrypto/elliptic-curves/issues/988
    // - https://github.com/bluealloy/revm/pull/870
    if let Some(normalized) = signature.normalize_s() {
        signature = normalized;
        recovery_id = k256::ecdsa::RecoveryId::from_byte(recovery_id.to_byte() ^ 1).unwrap();
    }

    Ok((signature, recovery_id))
}

pub fn public_key_to_address(public_key: &secp256k1::PublicKey) -> web3::types::Address {
    let public_key = public_key.serialize_uncompressed();

    debug_assert_eq!(public_key[0], 0x04);
    let hash: [u8; 32] = web3::signing::keccak256(&public_key[1..]);

    web3::types::Address::from_slice(&hash[12..])
}

fn verify(
    key: &VerifyingKey,
    msg: &[u8],
    sig: &k256::ecdsa::Signature,
) -> Result<(), &'static str> {
    let q = ProjectivePoint::<Secp256k1>::from(key.as_affine());
    let z = ecdsa::hazmat::bits2field::<Secp256k1>(msg).unwrap();

    // &k256::FieldBytes::from_slice(&k256::Scalar::from_bytes(msg).to_bytes()),
    verify_prehashed(&q, &z, sig)
}

fn verify_prehashed(
    q: &ProjectivePoint<Secp256k1>,
    z: &k256::FieldBytes,
    sig: &k256::ecdsa::Signature,
) -> Result<(), &'static str> {
    // let z: Scalar = Scalar::reduce_bytes(z);
    let z =
        <Scalar as Reduce<<k256::Secp256k1 as k256::elliptic_curve::Curve>::Uint>>::reduce_bytes(z);
    let (r, s) = sig.split_scalars();
    let s_inv = *s.invert_vartime();
    let u1 = z * s_inv;
    let u2 = *r * s_inv;
    let reproduced = lincomb(&ProjectivePoint::<Secp256k1>::GENERATOR, &u1, q, &u2).to_affine();
    let x = reproduced.x();

    // println!("------------- verify_prehashed[beg] -------------");
    // println!("z: {z:#?}");
    // // println!("r: {r:#?}");
    // // println!("s: {s:#?}");
    // println!("s_inv {s_inv:#?}");
    // println!("u1 {u1:#?}");
    // println!("u2 {u2:#?}");
    // println!("reproduced {reproduced:#?}");
    // println!("reproduced_x {x:?}");
    // println!("------------- verify_prehashed[end] -------------");

    let reduced =
        <Scalar as Reduce<<k256::Secp256k1 as k256::elliptic_curve::Curve>::Uint>>::reduce_bytes(
            &x,
        );

    //println!("reduced {reduced:#?}");

    if *r == reduced {
        Ok(())
    } else {
        Err("error")
    }
}

fn lincomb(
    x: &ProjectivePoint<Secp256k1>,
    k: &Scalar,
    y: &ProjectivePoint<Secp256k1>,
    l: &Scalar,
) -> ProjectivePoint<Secp256k1> {
    (*x * k) + (*y * l)
}

pub fn to_eip155_v(recovery_id: u8, chain_id: u64) -> u64 {
    (recovery_id as u64) + 35 + chain_id * 2
}
