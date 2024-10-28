use std::borrow::Cow;
mod impls;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SignError {
    #[error("Signature request has timed out.")]
    Timeout,
    #[error("Signature request has already been submitted. Please try again later.")]
    RequestCollision,
    #[error(
        "This key version is not supported. Call latest_key_version() to get the latest supported version."
    )]
    UnsupportedKeyVersion,
    #[error("Too many pending requests. Please try again later.")]
    RequestLimitExceeded,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RespondError {
    #[error("The provided signature is invalid.")]
    InvalidSignature,
}

#[derive(Debug, PartialEq, Eq, Clone, thiserror::Error)]
pub enum JoinError {
    #[error("Account to join is already in the participant set.")]
    JoinAlreadyParticipant,
}

#[derive(Debug, PartialEq, Eq, Clone, thiserror::Error)]
pub enum PublicKeyError {
    #[error("Derived key conversion failed.")]
    DerivedKeyConversionFailed,
}

#[derive(Debug, PartialEq, Eq, Clone, thiserror::Error)]
pub enum InitError {
    #[error("Threshold cannot be greater than the number of candidates")]
    ThresholdTooHigh,
}

#[derive(Debug, PartialEq, Eq, Clone, thiserror::Error)]
pub enum VoteError {
    #[error("Voting account is not in the participant set.")]
    VoterNotParticipant,
    #[error("Account to be kicked is not in the participant set.")]
    KickNotParticipant,
    #[error("Account to join is not in the candidate set.")]
    JoinNotCandidate,
    #[error("Number of participants cannot go below threshold.")]
    ParticipantsBelowThreshold,
}

#[derive(Debug, PartialEq, Eq, Clone, thiserror::Error)]
pub enum InvalidParameters {
    #[error("Malformed payload.")]
    MalformedPayload,
    #[error("Attached deposit is lower than required.")]
    InsufficientDeposit,
    #[error("Provided gas is lower than required.")]
    InsufficientGas,
    #[error("This sign request has timed out, was completed, or never existed.")]
    RequestNotFound,
    #[error("Update not found.")]
    UpdateNotFound,
}

#[derive(Debug, PartialEq, Eq, Clone, thiserror::Error)]
pub enum InvalidState {
    #[error("The protocol is not Running.")]
    ProtocolStateNotRunning,
    #[error("Protocol state is not running or resharing.")]
    ProtocolStateNotRunningOrResharing,
    #[error("Unexpected protocol state.")]
    UnexpectedProtocolState,
    #[error("Cannot load in contract due to missing state")]
    ContractStateIsMissing,
    #[error("Mismatched epoch.")]
    EpochMismatch,
}

#[derive(Debug, PartialEq, Eq, Clone, thiserror::Error)]
pub enum ConversionError {
    #[error("Data conversion error.")]
    DataConversion,
}

/// A list specifying general categories of MPC Contract errors.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum ErrorKind {
    /// An error occurred while user is performing sign request.
    #[error("{0}")]
    Sign(#[from] SignError),
    /// An error occurred while node is performing respond call.
    #[error("{0}")]
    Respond(#[from] RespondError),
    /// An error occurred while node is performing join call.
    #[error("{0}")]
    Join(#[from] JoinError),
    /// An error occurred while user is performing public_key_* call.
    #[error("{0}")]
    PublicKey(#[from] PublicKeyError),
    /// An error occurred while developer is performing init_* call.
    #[error("{0}")]
    Init(#[from] InitError),
    /// An error occurred while node is performing vote_* call.
    #[error("{0}")]
    Vote(#[from] VoteError),
    // Invalid parameters errors
    #[error("{0}")]
    InvalidParameters(#[from] InvalidParameters),
    // Invalid state errors
    #[error("{0}")]
    InvalidState(#[from] InvalidState),
    // Conversion errors
    #[error("{0}")]
    ConversionError(#[from] ConversionError),
}

#[derive(Debug, thiserror::Error)]
enum ErrorRepr {
    #[error("{0}")]
    Simple(ErrorKind),
    #[error("{message}")]
    Message {
        kind: ErrorKind,
        message: Cow<'static, str>,
    },
}

/// Error type that this contract will make use of for all the errors
/// returned from this library
#[derive(Debug)]
pub struct Error {
    repr: ErrorRepr,
}

impl near_sdk::FunctionError for Error {
    fn panic(&self) -> ! {
        crate::env::panic_str(&self.to_string())
    }
}
