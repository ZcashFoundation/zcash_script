use std::num::TryFromIntError;

use thiserror::Error;

use crate::{
    interpreter,
    script::{self, Bad, Disabled},
    signature,
};

#[derive(Clone, PartialEq, Eq, Debug, Error)]
pub enum ScriptNumError {
    #[error("non-minimal encoding of script number")]
    NonMinimalEncoding(Option<Vec<u8>>),

    #[error("script number overflow: max: {max_num_size}, actual: {actual}")]
    Overflow { max_num_size: usize, actual: usize },
}

#[derive(Clone, PartialEq, Eq, Debug, Error)]
pub enum ScriptError {
    /// A error external to the script validation code. This can come from the stepper.
    ///
    /// __TODO__: Replace the `str` with a type parameter, which will be `Void` in validation code,
    /// but can be different in the steppers.
    #[error("external error: {0}")]
    ExternalError(&'static str),

    #[error("script evaluation failed")]
    EvalFalse,

    #[error("OP_RETURN encountered")]
    OpReturn,

    // Max sizes
    #[error(
        "Script size{} exceeded maxmimum ({} bytes)",
        .0.map_or("", |size| " ({size} bytes)"),
        script::MAX_SCRIPT_SIZE
    )]
    ScriptSize(Option<usize>),

    #[error(
        "push size{} exceeded maxmimum ({} bytes)",
        .0.map_or("", |size| " ({size} bytes)"),
        script::MAX_SCRIPT_ELEMENT_SIZE
    )]
    PushSize(Option<usize>),

    /// __NB__: This doesn’t take an “actual count” argument, because `OpCount` depends on
    ///         conditional execution and thus can only be checked incrementally. However, we could
    ///         statically check a “minimum operation count” for a script, which could then include
    ///         the minimum in the error.
    #[error("operation count exceeded maxmimum of {}", interpreter::MAX_OP_COUNT)]
    OpCount,

    #[error(
        "stack depth exceeded maxmimum of {} entries",
        interpreter::MAX_STACK_DEPTH
    )]
    StackSize(Option<TryFromIntError>),

    #[error("signature count wasn’t in the range [1, {}]{}",
            interpreter::MAX_PUBKEY_COUNT,
            .0.map_or("", |e| ": {e}"),    )]
    SigCount(Option<TryFromIntError>),

    #[error("public key count wasn’t in the range [1, {}]{}", interpreter::MAX_PUBKEY_COUNT, .0.map_or("", |e| ": {e}"))]
    PubKeyCount(Option<TryFromIntError>),

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
    #[error("bad opcode encountered: {}", .0.map_or("unknown".to_owned(), |op| format!("{:?}", op)))]
    BadOpcode(Option<Bad>),

    /// __TODO__: `Option` can go away once C++ support is removed.
    #[error("disabled opcode encountered: {}", .0.map_or("unknown".to_owned(), |op| format!("{:?}", op)))]
    DisabledOpcode(Option<Disabled>),

    #[error("{}", .0.map_or("invalid stack operation encountered", |(elem, max)| "tried to retrieve element {elem} from a stack with {max} elements"))]
    InvalidStackOperation(Option<(usize, usize)>),

    #[error("{}", .0.map_or("invalid altstack operation encountered", |(elem, max)| "tried to retrieve element {elem} from an altstack with {max} elements"))]
    InvalidAltstackOperation(Option<(usize, usize)>),

    #[error("unbalanced conditional encountered")]
    UnbalancedConditional,

    // OP_CHECKLOCKTIMEVERIFY
    #[error("negative lock time encountered")]
    NegativeLockTime,

    #[error("unsatisfied locktime condition")]
    UnsatisfiedLockTime,

    #[error("signature encoding error: {0}")]
    SignatureEncoding(signature::Error),

    #[error("non-minimal data encountered when minimal data required")]
    MinimalData,

    #[error("non-push opcode encountered in script sig when push-only required")]
    SigPushOnly,

    #[error("signature null dummy error")]
    SigNullDummy,

    #[error("public key type error")]
    PubKeyType,

    #[error("clean stack requirement not met")]
    CleanStack,

    // softfork safeness
    #[error("discouraged upgradable NOP encountered")]
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

impl ScriptError {
    /// This case is only generated in comparisons. It merges the `interpreter::Error::OpCount` case
    /// with the `opcode::Error::DisabledOpcode` case. This is because there is an edge case when
    /// there is a disabled opcode as the `MAX_OP_COUNT + 1` operation (not opcode) in a script. In
    /// this case, the C++ implementation checks the op_count first, while the Rust implementation
    /// fails on disabled opcodes as soon as they’re read (since the script is guaranteed to fail if
    /// they occur, even in an inactive branch). To allow comparison tests to pass (especially
    /// property & fuzz tests), we need these two failure cases to be seen as identical.
    pub const AMBIGUOUS_COUNT_DISABLED: Self =
        Self::ExternalError("ambiguous OpCount or DisabledOpcode error");

    /// This case is only generated in comparisons. It merges `Self::ScriptNumError` and
    /// `Self::SigHighS`, which can only come from the Rust implementation, with
    /// `ScriptError_t_SCRIPT_ERR_UNKNOWN_ERROR`, which can only come from the C++ implementation,
    /// but in at least all of the cases that either of the Rust error cases would happen.
    pub const AMBIGUOUS_UNKNOWN_NUM_HIGHS: Self =
        Self::ExternalError("ambiguous Unknown, or ScriptNum, or HighS error");

    /// Convert errors that don’t exist in the C++ code into the cases that do.
    pub fn normalize(&self) -> Self {
        match self {
            Self::OpCount => Self::AMBIGUOUS_COUNT_DISABLED,
            Self::InvalidStackOperation(Some(_)) => Self::InvalidStackOperation(None),
            Self::InvalidAltstackOperation(Some(_)) => Self::InvalidAltstackOperation(None),
            Self::PushSize(Some(_)) => Self::PushSize(None),
            Self::ScriptSize(Some(_)) => Self::ScriptSize(None),
            Self::StackSize(Some(_)) => Self::StackSize(None),
            Self::SigCount(Some(_)) => Self::SigCount(None),
            Self::PubKeyCount(Some(_)) => Self::PubKeyCount(None),
            Self::BadOpcode(Some(_)) => Self::BadOpcode(None),
            Self::DisabledOpcode(_) => Self::AMBIGUOUS_COUNT_DISABLED,
            Self::SignatureEncoding(sig_err) => match sig_err {
                signature::Error::SigHashType(Some(_)) => {
                    signature::Error::SigHashType(None).into()
                }
                signature::Error::SigDER(Some(_)) => signature::Error::SigDER(None).into(),
                signature::Error::SigHighS => Self::AMBIGUOUS_UNKNOWN_NUM_HIGHS,
                _ => sig_err.clone().into(),
            },
            Self::ReadError { .. } => Self::BadOpcode(None),
            Self::ScriptNumError(_) => Self::AMBIGUOUS_UNKNOWN_NUM_HIGHS,
            _ => self.clone(),
        }
    }
}

impl From<ScriptNumError> for ScriptError {
    fn from(value: ScriptNumError) -> Self {
        Self::ScriptNumError(value)
    }
}

impl From<signature::Error> for ScriptError {
    fn from(value: signature::Error) -> Self {
        Self::SignatureEncoding(value)
    }
}
