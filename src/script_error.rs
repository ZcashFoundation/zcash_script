#[derive(Copy, Clone, PartialEq, Eq, Debug)]
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
