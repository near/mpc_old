use anyhow::Context;
use crypto_shared::{kdf::recover, x_coordinate, ScalarExt, SignatureResponse};
use hkdf::Hkdf;
use k256::{ecdsa::RecoveryId, elliptic_curve::sec1::ToEncodedPoint, AffinePoint, Scalar};
use near_primitives::hash::CryptoHash;
use sha3::Sha3_256;

// In case there are multiple requests in the same block (hence same entropy), we need to ensure
// that we generate different random scalars as delta tweaks.
// Receipt ID should be unique inside of a block, so it serves us as the request identifier.
pub fn derive_delta(
    request_id: [u8; 32],
    entropy: [u8; 32],
    presignature_big_r: AffinePoint,
) -> Scalar {
    let hk = Hkdf::<Sha3_256>::new(None, &entropy);
    let info = format!("{DELTA_DERIVATION_PREFIX}:{}", CryptoHash(request_id));
    let mut okm = [0u8; 32];
    hk.expand(info.as_bytes(), &mut okm).unwrap();
    hk.expand(
        presignature_big_r.to_encoded_point(true).as_bytes(),
        &mut okm,
    )
    .unwrap();
    Scalar::from_non_biased(okm)
}

// Constant prefix that ensures delta derivation values are used specifically for
// near-mpc-recovery with key derivation protocol vX.Y.Z.
const DELTA_DERIVATION_PREFIX: &str = "near-mpc-recovery v0.1.0 delta derivation:";

// try to get the correct recovery id for this signature by brute force.
pub fn into_eth_sig(
    public_key: &k256::AffinePoint,
    big_r: &k256::AffinePoint,
    s: &k256::Scalar,
    msg_hash: Scalar,
) -> anyhow::Result<SignatureResponse> {
    let public_key = public_key.to_encoded_point(false);
    let signature = k256::ecdsa::Signature::from_scalars(x_coordinate(big_r), s)
        .context("cannot create signature from cait_sith signature")?;
    let pk0 = recover(
        &msg_hash.to_bytes()[..],
        &signature,
        RecoveryId::try_from(0).context("cannot create recovery_id=0")?,
    )
    .context("unable to use 0 as recovery_id to recover public key")?
    .to_encoded_point(false);
    if public_key == pk0 {
        return Ok(SignatureResponse::new(*big_r, *s, 0));
    }

    let pk1 = recover(
        &msg_hash.to_bytes()[..],
        &signature,
        RecoveryId::try_from(1).context("cannot create recovery_id=1")?,
    )
    .context("unable to use 1 as recovery_id to recover public key")?
    .to_encoded_point(false);
    if public_key == pk1 {
        return Ok(SignatureResponse::new(*big_r, *s, 1));
    }

    anyhow::bail!("cannot use either recovery id (0 or 1) to recover pubic key")
}
