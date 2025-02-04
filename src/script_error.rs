#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum ScriptNumError {
    NegativeZero,
    NonMinimalEncoding,
    Overflow { max_num_size: usize, actual: usize },
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[repr(i32)]
pub enum ScriptError {
    // Ok = 0,
    UnknownError = 1,
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
