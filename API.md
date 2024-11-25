# Chain Signatures API

## `sign()`
This is the main function of the contract API. It is used to sign a request with the MPC service.
```rust
pub fn sign(&mut self, request: SignRequest) -> Result<near_sdk::Promise, Error>
```
Arguments and return type:
```rust
pub struct SignRequest {
    pub payload: [u8; 32],
    pub path: String,
    pub key_version: u32,
}

pub struct SignatureResponse {
    pub big_r: SerializableAffinePoint,
    pub s: SerializableScalar,
    pub recovery_id: u8,
}
```
- `key_version` must be less than or equal to the value at `latest_key_version`.
- `path` is a derivation path for the key that will be used to sign the payload.
- To avoid overloading the network with too many requests, we ask for a small deposit for each signature request. The fee changes based on how busy the network is.

## `public_key()`
This is the root public key combined from all the public keys of the participants.
```rust
pub fn public_key(&self) -> Result<PublicKey, Error>
```

## `derived_public_key()`
This is the derived public key of the caller given path and predecessor. If the predecessor is not provided, it will be the caller of the contract.
```rust
pub fn derived_public_key(
        &self,
        path: String,
        predecessor: Option<AccountId>,
    ) -> Result<PublicKey, Error>
```

## `latest_key_version()`
Key versions refer new versions of the root key that we may choose to generate on cohort changes. Older key versions will always work but newer key versions were never held by older signers. Newer key versions may also add new security features, like only existing within a secure enclave. Currently only 0 is a valid key version.
```rust
pub const fn latest_key_version(&self) -> u32
```

## `experimantal_signature_deposit()`
This experimantal function calculates the fee for a signature request. The fee is volatile and depends on the number of pending requests. If used on a client side, it can give outdate results.
```rust
pub fn experimantal_signature_deposit(&self) -> u128
```

For more details check `User contract API` impl block in the [chain-signatures/contracts/src/lib.rs](./chain-signatures/contracts/src/lib.rs) file.

# Environments
1. Mainnet: `v1.signer`
2. Testnet: `v1.sigenr-prod.testnet`

# Interact using NEAR CLI 

There is an `Example Commands` in the [chain-signatures/contract/example.md](./chain-signature/contract/EXAMPLE.md) file.

These commands were tested on [near-cli](https://github.com/near/near-cli) 4.0.0.
