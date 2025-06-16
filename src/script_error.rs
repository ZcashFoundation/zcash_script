use thiserror::Error;

#[derive(Copy, Clone, PartialEq, Eq, Debug, Error)]
pub enum ScriptNumError {
    NonMinimalEncoding,
    Overflow { max_num_size: usize, actual: usize },
}

impl std::fmt::Display for ScriptNumError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScriptNumError::NonMinimalEncoding => {
                write!(f, "Non-minimal encoding of script number")
            }
            ScriptNumError::Overflow {
                max_num_size,
                actual,
            } => write!(
                f,
                "Script number overflow: max: {max_num_size}, actual: {actual}",
            ),
        }
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[repr(i32)]
pub enum ScriptError {
    Ok = 0, // Unused (except in converting the C++ error to Rust)
    UnknownError,
    EvalFalse,
    OpReturn,

    // Max sizes
    ScriptSize,
    PushSize,
    OpCount,
    StackSize,
    SigCount,
    PubKeyCount,

    // Failed verify operations
    Verify,
    EqualVerify,
    CheckMultisigVerify,
    CheckSigVerify,
    NumEqualVerify,

    // Logical/Format/Canonical errors
    BadOpcode,
    DisabledOpcode,
    InvalidStackOperation,
    InvalidAltstackOperation,
    UnbalancedConditional,

    // OP_CHECKLOCKTIMEVERIFY
    NegativeLockTime,
    UnsatisfiedLockTime,

    // BIP62
    SigHashType,
    SigDER,
    MinimalData,
    SigPushOnly,
    SigHighS,
    SigNullDummy,
    PubKeyType,
    CleanStack,

    // softfork safeness
    DiscourageUpgradableNOPs,

    ReadError {
        expected_bytes: usize,
        available_bytes: usize,
    },

    /// Corresponds to the `scriptnum_error` exception in C++.
    ScriptNumError(ScriptNumError),
}

impl From<ScriptNumError> for ScriptError {
    fn from(value: ScriptNumError) -> Self {
        ScriptError::ScriptNumError(value)
    }
}

impl std::fmt::Display for ScriptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScriptError::Ok => write!(f, "Ok"),
            ScriptError::UnknownError => write!(f, "Unknown error"),
            ScriptError::EvalFalse => write!(f, "Script evaluation failed"),
            ScriptError::OpReturn => write!(f, "OP_RETURN encountered"),

            // Max sizes
            ScriptError::ScriptSize => write!(f, "Script size exceeded maximum"),
            ScriptError::PushSize => write!(f, "Push size exceeded maximum"),
            ScriptError::OpCount => write!(f, "Operation count exceeded maximum"),
            ScriptError::StackSize => write!(f, "Stack size exceeded maximum"),
            ScriptError::SigCount => write!(f, "Signature count exceeded maximum"),
            ScriptError::PubKeyCount => write!(f, "Public key count exceeded maximum"),

            // Failed verify operations
            ScriptError::Verify => write!(f, "Verify operation failed"),
            ScriptError::EqualVerify => write!(f, "Equal verify operation failed"),
            ScriptError::CheckMultisigVerify => write!(f, "Check multisig verify operation failed"),
            ScriptError::CheckSigVerify => write!(f, "Check signature verify operation failed"),
            ScriptError::NumEqualVerify => write!(f, "Number equal verify operation failed"),

            // Logical/Format/Canonical errors
            ScriptError::BadOpcode => write!(f, "Bad opcode encountered"),
            ScriptError::DisabledOpcode => write!(f, "Disabled opcode encountered"),
            ScriptError::InvalidStackOperation => write!(f, "Invalid stack operation"),
            ScriptError::InvalidAltstackOperation => write!(f, "Invalid altstack operation"),
            ScriptError::UnbalancedConditional => write!(f, "Unbalanced conditional encountered"),

            // OP_CHECKLOCKTIMEVERIFY
            ScriptError::NegativeLockTime => write!(f, "Negative lock time encountered"),
            ScriptError::UnsatisfiedLockTime => write!(f, "Unsatisfied lock time condition"),

            // BIP62
            ScriptError::SigHashType => write!(f, "Signature hash type error"),
            ScriptError::SigDER => write!(f, "Signature DER encoding error"),
            ScriptError::MinimalData => write!(f, "Minimal data requirement not met"),
            ScriptError::SigPushOnly => write!(f, "Signature push only requirement not met"),
            ScriptError::SigHighS => write!(f, "Signature S value is too high"),
            ScriptError::SigNullDummy => write!(f, "Signature null dummy error"),
            ScriptError::PubKeyType => write!(f, "Public key type error"),
            ScriptError::CleanStack => write!(f, "Clean stack requirement not met"),

            // softfork safeness
            ScriptError::DiscourageUpgradableNOPs => {
                write!(f, "Discouraged upgradable NOPs encountered")
            }

            ScriptError::ReadError {
                expected_bytes,
                available_bytes,
            } => {
                write!(
                    f,
                    "Read error: expected {expected_bytes} bytes, but only {available_bytes} bytes available",
                )
            }

            ScriptError::ScriptNumError(script_num_error) => {
                write!(f, "Script number error: {}", script_num_error)
            }
        }
    }
}
