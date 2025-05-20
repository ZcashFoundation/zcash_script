use thiserror::Error;

use crate::{script::Disabled, signature};

#[derive(Copy, Clone, PartialEq, Eq, Debug, Error)]
pub enum ScriptNumError {
    #[error("non-minimal encoding of script number")]
    NonMinimalEncoding,

    #[error("script number overflow: max: {max_num_size}, actual: {actual}")]
    Overflow { max_num_size: usize, actual: usize },
}

#[derive(Clone, PartialEq, Eq, Debug, Error)]
pub enum ScriptError {
    /// A error external to the script validation code. This can come from the stepper.
    ///
    /// __TODO__: Replace the `str` with a type parameter, which will be `Void` in validation code,
    /// but can be different in the steppers.
    #[error("external error: {}", .0)]
    ExternalError(&'static str),

    #[error("script evaluation failed")]
    EvalFalse,

    #[error("OP_RETURN encountered")]
    OpReturn,

    // Max sizes
    #[error("Script size exceeded maximum")]
    ScriptSize,

    #[error("push size exceeded maximum")]
    PushSize,

    #[error("operation count exceeded maximum")]
    OpCount,

    #[error("stack size exceeded maximum")]
    StackSize,

    #[error("signature count exceeded maximum")]
    SigCount,

    #[error("public key count exceeded maximum")]
    PubKeyCount,

    // Failed verify operations
    #[error("verify operation failed")]
    Verify,

    #[error("equal verify operation failed")]
    EqualVerify,

    #[error("check multisig verify operation failed")]
    CheckMultisigVerify,

    #[error("check sig verify operation failed")]
    CheckSigVerify,

    #[error("num equal verfiy operation failed")]
    NumEqualVerify,

    // Logical/Format/Canonical errors
    #[error("bad opcode encountered")]
    BadOpcode(Option<u8>),

    /// __TODO__: `Option` can go away once C++ support is removed.
    #[error("disabled opcode encountered: {}", .0.map_or("unknown".to_owned(), |op| format!("{:?}", op)))]
    DisabledOpcode(Option<Disabled>),

    #[error("invalid stack operation encountered")]
    InvalidStackOperation,

    #[error("invalid altstack operation encountered")]
    InvalidAltstackOperation,

    #[error("unbalanced conditional encountered")]
    UnbalancedConditional,

    // OP_CHECKLOCKTIMEVERIFY
    #[error("negative lock time encountered")]
    NegativeLockTime,

    #[error("unsatisfied locktime condition")]
    UnsatisfiedLockTime,

    #[error("signature encoding error: {}", .0)]
    SignatureEncoding(signature::Error),

    #[error("minimal data requirement not met")]
    MinimalData,

    #[error("signature push only requirement not met")]
    SigPushOnly,

    #[error("signature null dummy error")]
    SigNullDummy,

    #[error("public key type error")]
    PubKeyType,

    #[error("clean stack requirement not met")]
    CleanStack,

    // softfork safeness
    #[error("discouraged upgradable NOPs encountered")]
    DiscourageUpgradableNOPs,

    // extensions (these don’t exist in C++, and thus map to `UnknownError`)
    #[error(
        "read error: expected {expected_bytes} bytes, but only {available_bytes} bytes available"
    )]
    ReadError {
        expected_bytes: usize,
        available_bytes: usize,
    },

    /// Corresponds to the `scriptnum_error` exception in C++.
    #[error("script number error: {0}")]
    ScriptNumError(ScriptNumError),
}

impl From<ScriptNumError> for ScriptError {
    fn from(value: ScriptNumError) -> Self {
        ScriptError::ScriptNumError(value)
    }
}

impl From<signature::Error> for ScriptError {
    fn from(value: signature::Error) -> Self {
        ScriptError::SignatureEncoding(value)
    }
}
