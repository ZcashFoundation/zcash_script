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
    // SigHighS,
    SigNullDummy = 27,
    PubKeyType,
    CleanStack,

    // softfork safeness
    DiscourageUpgradableNOPs,

    ReadError {
        expected_bytes: usize,
        available_bytes: usize,
    },
}
