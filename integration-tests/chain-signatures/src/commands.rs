use std::str::FromStr;

use crypto_shared::{ScalarExt, SerializableAffinePoint, SerializableScalar, SignatureResponse};
use k256::Scalar;
use mpc_contract::{
    config::Config,
    primitives::{CandidateInfo, Candidates, Participants, SignRequest, SignatureRequest},
    update::ProposeUpdateArgs,
};
use mpc_keys::hpke;
use near_account_id::AccountId;
use near_primitives::borsh;
use near_sdk::PublicKey;
use serde_json::json;

const PAYLOAD: [u8; 32] = [
    12, 1, 2, 0, 4, 5, 6, 8, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
    26, 27, 28, 29, 30, 44,
];

const SIGN_PK: &str = "ed25519:J75xXmF7WUPS3xCm3hy2tgwLCKdYM1iJd4BWF8sWVnae";

pub fn sing_command(contract_id: &AccountId, caller_id: &AccountId) -> anyhow::Result<String> {
    let sign_request = SignRequest {
        payload: PAYLOAD,
        path: "test".into(),
        key_version: 0,
    };

    let request_json = format!(
        "'{}'",
        serde_json::to_string(&json!({"request": sign_request}))?
    );

    Ok(format!(
        "near call {} sign {} --accountId {} --gas 300000000000000 --deposit 1",
        contract_id, request_json, caller_id
    ))
}

pub fn respond_command(contract_id: &AccountId, caller_id: &AccountId) -> anyhow::Result<String> {
    let payload_hashed = web3::signing::keccak256(&PAYLOAD);

    let request = SignatureRequest::new(
        Scalar::from_bytes(payload_hashed)
            .ok_or_else(|| anyhow::anyhow!("Failed to convert bytes to Scalar"))?,
        caller_id,
        "test",
    );

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

    let request_json = format!(
        "'{}'",
        serde_json::to_string(&json!({"request": request, "response": response})).unwrap()
    );

    Ok(format!(
        "near call {} respond {} --accountId {} --gas 300000000000000",
        contract_id, request_json, caller_id
    ))
}

pub fn join_command(contract_id: &AccountId, caller_id: &AccountId) -> anyhow::Result<String> {
    let url = "http://localhost:3030";
    let (_, cipher_pk) = hpke::generate();
    let sign_pk = PublicKey::from_str(SIGN_PK)?;

    let join_json = format!(
        "'{}'",
        serde_json::to_string(&json!({"url": url, "cipher_pk": cipher_pk, "sign_pk": sign_pk}))?
    );

    Ok(format!(
        "near call {} join {} --accountId {} --gas 300000000000000",
        contract_id, join_json, caller_id
    ))
}

pub fn proposed_updates_command(
    contract_id: &AccountId,
    caller_id: &AccountId,
) -> anyhow::Result<String> {
    let args = ProposeUpdateArgs {
        code: None,
        config: Some(Config::default()),
    };

    let borsh_args = borsh::to_vec(&args)?;

    let base64_encoded = near_primitives::serialize::to_base64(borsh_args.as_slice());

    Ok(format!(
        "near call {} propose_update --base64 {:?} --accountId {} --gas 300000000000000",
        contract_id, base64_encoded, caller_id
    ))
}

pub fn init_command(contract_id: &AccountId, caller_id: &AccountId) -> anyhow::Result<String> {
    let threshold: usize = 1;
    let candidates: Candidates = dummy_candidates();

    let init_json = format!(
        "'{}'",
        serde_json::to_string(&json!({"threshold": threshold, "candidates": candidates}))?
    );

    Ok(format!(
        "near call {} init {} --accountId {} --gas 300000000000000",
        contract_id, init_json, caller_id
    ))
}

pub fn init_running_command(
    contract_id: &AccountId,
    caller_id: &AccountId,
) -> anyhow::Result<String> {
    let init_running_json = format!(
        "'{}'",
        serde_json::to_string(
            &json!({"epoch": 0, "participants": Participants::from(dummy_candidates()), "threshold": 2,"public_key": PublicKey::from_str(SIGN_PK)? })
        )?
    );

    Ok(format!(
        "near call {} init_running {} --accountId {} --gas 300000000000000",
        contract_id, init_running_json, caller_id
    ))
}

pub fn dummy_candidates() -> Candidates {
    let mut candidates = Candidates::new();
    let names: Vec<AccountId> = vec![
        "alice.near".parse().unwrap(),
        "bob.near".parse().unwrap(),
        "caesar.near".parse().unwrap(),
    ];

    for account_id in names {
        candidates.insert(
            account_id.clone(),
            CandidateInfo {
                account_id,
                url: "127.0.0.1".into(),
                cipher_pk: [0; 32],
                sign_pk: PublicKey::from_str(SIGN_PK).unwrap(),
            },
        );
    }
    candidates
}
