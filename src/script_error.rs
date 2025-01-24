use std::num::TryFromIntError;

use secp256k1;

use crate::script::num;

/// Things that can go wrong when constructing a `HashType` from bit flags.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum InvalidHashType {
    /// Either or both of the two least-significant bits must be set.
    UnknownSignedOutputs,
    /// With v5 transactions, bits other than those specified for `HashType` must be 0. The `i32`
    /// includes only the bits that are undefined by `HashType`.
    ExtraBitsSet(i32),
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
    PushSize(Option<TryFromIntError>),
    OpCount,
    StackSize(Option<TryFromIntError>),
    SigCount(Option<TryFromIntError>),
    PubKeyCount(Option<TryFromIntError>),

    // Failed verify operations
    Verify,
    EqualVerify,
    CheckMultisigVerify,
    CheckSigVerify,
    NumEqualVerify,

    // Logical/Format/Canonical errors
    BadOpcode(Option<u8>),
    DisabledOpcode(Option<u8>),
    InvalidStackOperation,
    InvalidAltstackOperation,
    UnbalancedConditional,

    // OP_CHECKLOCKTIMEVERIFY
    NegativeLockTime,
    UnsatisfiedLockTime,

    // BIP62
    SigHashType(Option<InvalidHashType>),
    SigDER(Option<secp256k1::Error>),
    MinimalData,
    SigPushOnly,
    SigHighS,
    SigNullDummy,
    PubKeyType,
    CleanStack,

    // softfork safeness
    DiscourageUpgradableNOPs,

    // extensions (these don’t exist in C++, and thus map to `UnknownError`)
    ReadError {
        expected_bytes: usize,
        available_bytes: usize,
    },

    /// Corresponds to the `scriptnum_error` exception in C++.
    NumError(num::Error),
}

impl From<num::Error> for ScriptError {
    fn from(value: num::Error) -> Self {
        ScriptError::NumError(value)
    }
}
