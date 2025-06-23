use thiserror::Error;

#[derive(Copy, Clone, PartialEq, Eq, Debug, Error)]
pub enum ScriptNumError {
    #[error("non-minimal encoding of script number")]
    NonMinimalEncoding,

    #[error("script number overflow: max: {max_num_size}, actual: {actual}")]
    Overflow { max_num_size: usize, actual: usize },
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Error)]
#[repr(i32)]
pub enum ScriptError {
    #[error("Ok")]
    Ok = 0, // Unused (except in converting the C++ error to Rust)

    #[error("unknown error")]
    UnknownError,

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
    BadOpcode,

    #[error("disabled opcode encountered")]
    DisabledOpcode,

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

    // BIP62
    #[error("signature hash type error")]
    SigHashType,

    #[error("signature DER encoding error")]
    SigDER,

    #[error("minimal data requirement not met")]
    MinimalData,

    #[error("signature push only requirement not met")]
    SigPushOnly,

    #[error("signature s value is too high")]
    SigHighS,

    #[error("signature null dummy error")]
    SigNullDummy,

    #[error("public key type error")]
    PubKeyType,

    #[error("clean stack requirement not met")]
    CleanStack,

    // softfork safeness
    #[error("discouraged upgradable NOPs encountered")]
    DiscourageUpgradableNOPs,

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
