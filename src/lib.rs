//! Zcash transparent script implementations.

#![doc(html_logo_url = "https://www.zfnd.org/images/zebra-icon.png")]
#![doc(html_root_url = "https://docs.rs/zcash_script/0.3.0")]
#![allow(non_snake_case)]
#![allow(unsafe_code)]
#[macro_use]
extern crate enum_primitive;

mod cxx;
mod external;
mod interpreter;
mod script;
pub mod script_error;
mod zcash_script;

use std::os::raw::{c_int, c_uint, c_void};

use tracing::warn;

pub use cxx::*;
pub use interpreter::{HashType, SighashCalculator, SignedOutputs, VerificationFlags};
pub use zcash_script::*;

/// A tag to indicate that the C++ implementation of zcash_script should be used.
pub enum CxxInterpreter {}

impl From<cxx::ScriptError> for Error {
    #[allow(non_upper_case_globals)]
    fn from(err_code: cxx::ScriptError) -> Self {
        match err_code {
            ScriptError_t_SCRIPT_ERR_OK => Error::Ok(script_error::ScriptError::Ok),
            ScriptError_t_SCRIPT_ERR_UNKNOWN_ERROR => {
                Error::Ok(script_error::ScriptError::UnknownError)
            }
            ScriptError_t_SCRIPT_ERR_EVAL_FALSE => Error::Ok(script_error::ScriptError::EvalFalse),
            ScriptError_t_SCRIPT_ERR_OP_RETURN => Error::Ok(script_error::ScriptError::OpReturn),

            ScriptError_t_SCRIPT_ERR_SCRIPT_SIZE => {
                Error::Ok(script_error::ScriptError::ScriptSize)
            }
            ScriptError_t_SCRIPT_ERR_PUSH_SIZE => Error::Ok(script_error::ScriptError::PushSize),
            ScriptError_t_SCRIPT_ERR_OP_COUNT => Error::Ok(script_error::ScriptError::OpCount),
            ScriptError_t_SCRIPT_ERR_STACK_SIZE => Error::Ok(script_error::ScriptError::StackSize),
            ScriptError_t_SCRIPT_ERR_SIG_COUNT => Error::Ok(script_error::ScriptError::SigCount),
            ScriptError_t_SCRIPT_ERR_PUBKEY_COUNT => {
                Error::Ok(script_error::ScriptError::PubKeyCount)
            }

            ScriptError_t_SCRIPT_ERR_VERIFY => Error::Ok(script_error::ScriptError::Verify),
            ScriptError_t_SCRIPT_ERR_EQUALVERIFY => {
                Error::Ok(script_error::ScriptError::EqualVerify)
            }
            ScriptError_t_SCRIPT_ERR_CHECKMULTISIGVERIFY => {
                Error::Ok(script_error::ScriptError::CheckMultisigVerify)
            }
            ScriptError_t_SCRIPT_ERR_CHECKSIGVERIFY => {
                Error::Ok(script_error::ScriptError::CheckSigVerify)
            }
            ScriptError_t_SCRIPT_ERR_NUMEQUALVERIFY => {
                Error::Ok(script_error::ScriptError::NumEqualVerify)
            }

            ScriptError_t_SCRIPT_ERR_BAD_OPCODE => Error::Ok(script_error::ScriptError::BadOpcode),
            ScriptError_t_SCRIPT_ERR_DISABLED_OPCODE => {
                Error::Ok(script_error::ScriptError::DisabledOpcode)
            }
            ScriptError_t_SCRIPT_ERR_INVALID_STACK_OPERATION => {
                Error::Ok(script_error::ScriptError::InvalidStackOperation)
            }
            ScriptError_t_SCRIPT_ERR_INVALID_ALTSTACK_OPERATION => {
                Error::Ok(script_error::ScriptError::InvalidAltstackOperation)
            }
            ScriptError_t_SCRIPT_ERR_UNBALANCED_CONDITIONAL => {
                Error::Ok(script_error::ScriptError::UnbalancedConditional)
            }

            ScriptError_t_SCRIPT_ERR_NEGATIVE_LOCKTIME => {
                Error::Ok(script_error::ScriptError::NegativeLockTime)
            }
            ScriptError_t_SCRIPT_ERR_UNSATISFIED_LOCKTIME => {
                Error::Ok(script_error::ScriptError::UnsatisfiedLockTime)
            }

            ScriptError_t_SCRIPT_ERR_SIG_HASHTYPE => {
                Error::Ok(script_error::ScriptError::SigHashType)
            }
            ScriptError_t_SCRIPT_ERR_SIG_DER => Error::Ok(script_error::ScriptError::SigDER),
            ScriptError_t_SCRIPT_ERR_MINIMALDATA => {
                Error::Ok(script_error::ScriptError::MinimalData)
            }
            ScriptError_t_SCRIPT_ERR_SIG_PUSHONLY => {
                Error::Ok(script_error::ScriptError::SigPushOnly)
            }
            ScriptError_t_SCRIPT_ERR_SIG_HIGH_S => Error::Ok(script_error::ScriptError::SigHighS),
            ScriptError_t_SCRIPT_ERR_SIG_NULLDUMMY => {
                Error::Ok(script_error::ScriptError::SigNullDummy)
            }
            ScriptError_t_SCRIPT_ERR_PUBKEYTYPE => Error::Ok(script_error::ScriptError::PubKeyType),
            ScriptError_t_SCRIPT_ERR_CLEANSTACK => Error::Ok(script_error::ScriptError::CleanStack),

            ScriptError_t_SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS => {
                Error::Ok(script_error::ScriptError::DiscourageUpgradableNOPs)
            }

            ScriptError_t_SCRIPT_ERR_VERIFY_SCRIPT => Error::VerifyScript,
            unknown => Error::Unknown(unknown.into()),
        }
    }
}

/// The sighash callback to use with zcash_script.
extern "C" fn sighash_callback(
    sighash_out: *mut u8,
    sighash_out_len: c_uint,
    ctx: *const c_void,
    script_code: *const u8,
    script_code_len: c_uint,
    hash_type: c_int,
) {
    let checked_script_code_len = usize::try_from(script_code_len)
        .expect("This was converted from a `usize` in the first place");
    // SAFETY: `script_code` is created from a Rust slice in `verify_callback`, passed through the
    // C++ code, eventually to `CallbackTransactionSignatureChecker::CheckSig`, which calls this
    // function.
    let script_code_vec =
        unsafe { std::slice::from_raw_parts(script_code, checked_script_code_len) };
    // SAFETY: `ctx` is a valid `SighashCalculator` constructed in `verify_callback`
    // which forwards it to the `CallbackTransactionSignatureChecker`.
    let callback = unsafe { *(ctx as *const SighashCalculator) };
    // We don’t need to handle strictness here, because it is checked (when necessary) by
    // `CheckSignatureEncoding` before `CallbackTransactionSignatureChecker` calls this callback.
    // And we don’t have access to the flags here to determine if it should be checked.
    if let Some(sighash) = HashType::from_bits(hash_type, false)
        .ok()
        .and_then(|ht| callback(script_code_vec, ht))
    {
        assert_eq!(sighash_out_len, sighash.len().try_into().unwrap());
        // SAFETY: `sighash_out` is a valid buffer created in
        // `CallbackTransactionSignatureChecker::CheckSig`.
        unsafe { std::ptr::copy_nonoverlapping(sighash.as_ptr(), sighash_out, sighash.len()) };
    }
}

/// This steals a bit of the wrapper code from zebra_script, to provide the API that they want.
impl ZcashScript for CxxInterpreter {
    fn verify_callback(
        sighash: SighashCalculator,
        lock_time: u32,
        is_final: bool,
        script_pub_key: &[u8],
        signature_script: &[u8],
        flags: VerificationFlags,
    ) -> Result<(), Error> {
        let mut err = 0;

        // SAFETY: The `script` fields are created from a valid Rust `slice`.
        let ret = unsafe {
            zcash_script_verify_callback(
                (&sighash as *const SighashCalculator) as *const c_void,
                Some(sighash_callback),
                lock_time.into(),
                if is_final { 1 } else { 0 },
                script_pub_key.as_ptr(),
                script_pub_key
                    .len()
                    .try_into()
                    .map_err(Error::InvalidScriptSize)?,
                signature_script.as_ptr(),
                signature_script
                    .len()
                    .try_into()
                    .map_err(Error::InvalidScriptSize)?,
                flags.bits(),
                &mut err,
            )
        };

        if ret == 1 {
            Ok(())
        } else {
            Err(Error::from(err))
        }
    }

    /// Returns the number of transparent signature operations in the
    /// transparent inputs and outputs of this transaction.
    fn legacy_sigop_count_script(script: &[u8]) -> Result<u32, Error> {
        script
            .len()
            .try_into()
            .map_err(Error::InvalidScriptSize)
            .map(|script_len| unsafe {
                zcash_script_legacy_sigop_count_script(script.as_ptr(), script_len)
            })
    }
}

/// Runs both the C++ and Rust implementations `ZcashScript::legacy_sigop_count_script` and returns
/// both results. This is more useful for testing than the impl that logs a warning if the results
/// differ and always returns the C++ result.
fn check_legacy_sigop_count_script<T: ZcashScript, U: ZcashScript>(
    script: &[u8],
) -> (Result<u32, Error>, Result<u32, Error>) {
    (
        T::legacy_sigop_count_script(script),
        U::legacy_sigop_count_script(script),
    )
}

/// Runs two implementations of `ZcashScript::verify_callback` with the same arguments and returns
/// both results. This is more useful for testing than the impl that logs a warning if the results
/// differ and always returns the `T` result.
pub fn check_verify_callback<T: ZcashScript, U: ZcashScript>(
    sighash: SighashCalculator,
    lock_time: u32,
    is_final: bool,
    script_pub_key: &[u8],
    script_sig: &[u8],
    flags: VerificationFlags,
) -> (Result<(), Error>, Result<(), Error>) {
    (
        T::verify_callback(
            sighash,
            lock_time,
            is_final,
            script_pub_key,
            script_sig,
            flags,
        ),
        U::verify_callback(
            sighash,
            lock_time,
            is_final,
            script_pub_key,
            script_sig,
            flags,
        ),
    )
}

/// Convert errors that don’t exist in the C++ code into the cases that do.
pub fn normalize_error(err: Error) -> Error {
    match err {
        Error::Ok(serr) => Error::Ok(match serr {
            script_error::ScriptError::ReadError { .. } => script_error::ScriptError::BadOpcode,
            script_error::ScriptError::ScriptNumError(_) => script_error::ScriptError::UnknownError,
            _ => serr,
        }),
        _ => err,
    }
}

/// A tag to indicate that both the C++ and Rust implementations of zcash_script should be used,
/// with their results compared.
pub enum CxxRustComparisonInterpreter {}

/// This implementation is functionally equivalent to the `T` impl, but it also runs a second (`U`)
/// impl and logs a warning if they disagree.
impl ZcashScript for CxxRustComparisonInterpreter {
    fn legacy_sigop_count_script(script: &[u8]) -> Result<u32, Error> {
        let (cxx, rust) =
            check_legacy_sigop_count_script::<CxxInterpreter, RustInterpreter>(script);
        if rust != cxx {
            warn!(
                "The Rust Zcash Script interpreter had a different sigop count ({:?}) from the C++ one ({:?}).",
                rust,
                cxx)
        };
        cxx
    }

    fn verify_callback(
        sighash: SighashCalculator,
        lock_time: u32,
        is_final: bool,
        script_pub_key: &[u8],
        script_sig: &[u8],
        flags: VerificationFlags,
    ) -> Result<(), Error> {
        let (cxx, rust) = check_verify_callback::<CxxInterpreter, RustInterpreter>(
            sighash,
            lock_time,
            is_final,
            script_pub_key,
            script_sig,
            flags,
        );
        if rust.map_err(normalize_error) != cxx {
            // probably want to distinguish between
            // - one succeeding when the other fails (bad), and
            // - differing error codes (maybe not bad).
            warn!(
                "The Rust Zcash Script interpreter had a different result ({:?}) from the C++ one ({:?}).",
                rust,
                cxx)
        };
        cxx
    }
}

#[cfg(any(test, feature = "test-dependencies"))]
pub mod testing {
    use super::*;

    /// Ensures that flags represent a supported state. This avoids crashes in the C++ code, which
    /// break various tests.
    pub fn repair_flags(flags: VerificationFlags) -> VerificationFlags {
        // TODO: The C++ implementation fails an assert (interpreter.cpp:1097) if `CleanStack` is
        //       set without `P2SH`.
        if flags.contains(VerificationFlags::CleanStack) {
            flags & VerificationFlags::P2SH
        } else {
            flags
        }
    }

    /// A `usize` one larger than the longest allowed script, for testing bounds.
    pub const OVERFLOW_SCRIPT_SIZE: usize = script::MAX_SCRIPT_SIZE + 1;
}

#[cfg(test)]
mod tests {
    use super::{testing::*, *};
    use hex::FromHex;
    use proptest::prelude::*;

    lazy_static::lazy_static! {
        pub static ref SCRIPT_PUBKEY: Vec<u8> = <Vec<u8>>::from_hex("a914c117756dcbe144a12a7c33a77cfa81aa5aeeb38187").unwrap();
        pub static ref SCRIPT_SIG: Vec<u8> = <Vec<u8>>::from_hex("00483045022100d2ab3e6258fe244fa442cfb38f6cef9ac9a18c54e70b2f508e83fa87e20d040502200eead947521de943831d07a350e45af8e36c2166984a8636f0a8811ff03ed09401473044022013e15d865010c257eef133064ef69a780b4bc7ebe6eda367504e806614f940c3022062fdbc8c2d049f91db2042d6c9771de6f1ef0b3b1fea76c1ab5542e44ed29ed8014c69522103b2cc71d23eb30020a4893982a1e2d352da0d20ee657fa02901c432758909ed8f21029d1e9a9354c0d2aee9ffd0f0cea6c39bbf98c4066cf143115ba2279d0ba7dabe2103e32096b63fd57f3308149d238dcbb24d8d28aad95c0e4e74e3e5e6a11b61bcc453ae").expect("Block bytes are in valid hex representation");
    }

    fn sighash(_script_code: &[u8], _hash_type: HashType) -> Option<[u8; 32]> {
        hex::decode("e8c7bdac77f6bb1f3aba2eaa1fada551a9c8b3b5ecd1ef86e6e58a5f1aab952c")
            .unwrap()
            .as_slice()
            .first_chunk::<32>()
            .copied()
    }

    fn invalid_sighash(_script_code: &[u8], _hash_type: HashType) -> Option<[u8; 32]> {
        hex::decode("08c7bdac77f6bb1f3aba2eaa1fada551a9c8b3b5ecd1ef86e6e58a5f1aab952c")
            .unwrap()
            .as_slice()
            .first_chunk::<32>()
            .copied()
    }

    fn missing_sighash(_script_code: &[u8], _hash_type: HashType) -> Option<[u8; 32]> {
        None
    }

    #[test]
    fn it_works() {
        let n_lock_time: u32 = 2410374;
        let is_final: bool = true;
        let script_pub_key = &SCRIPT_PUBKEY;
        let script_sig = &SCRIPT_SIG;
        let flags = VerificationFlags::P2SH | VerificationFlags::CHECKLOCKTIMEVERIFY;

        let ret = check_verify_callback::<CxxInterpreter, RustInterpreter>(
            &sighash,
            n_lock_time,
            is_final,
            script_pub_key,
            script_sig,
            flags,
        );

        assert_eq!(ret.0, ret.1.map_err(normalize_error));
        assert!(ret.0.is_ok());
    }

    #[test]
    fn it_fails_on_invalid_sighash() {
        let n_lock_time: u32 = 2410374;
        let is_final: bool = true;
        let script_pub_key = &SCRIPT_PUBKEY;
        let script_sig = &SCRIPT_SIG;
        let flags = VerificationFlags::P2SH | VerificationFlags::CHECKLOCKTIMEVERIFY;

        let ret = check_verify_callback::<CxxInterpreter, RustInterpreter>(
            &invalid_sighash,
            n_lock_time,
            is_final,
            script_pub_key,
            script_sig,
            flags,
        );

        assert_eq!(ret.0, ret.1.map_err(normalize_error));
        assert_eq!(ret.0, Err(Error::Ok(script_error::ScriptError::EvalFalse)));
    }

    #[test]
    fn it_fails_on_missing_sighash() {
        let n_lock_time: u32 = 2410374;
        let is_final: bool = true;
        let script_pub_key = &SCRIPT_PUBKEY;
        let script_sig = &SCRIPT_SIG;
        let flags = VerificationFlags::P2SH | VerificationFlags::CHECKLOCKTIMEVERIFY;

        let ret = check_verify_callback::<CxxInterpreter, RustInterpreter>(
            &missing_sighash,
            n_lock_time,
            is_final,
            script_pub_key,
            script_sig,
            flags,
        );

        assert_eq!(ret.0, ret.1.map_err(normalize_error));
        assert_eq!(ret.0, Err(Error::Ok(script_error::ScriptError::EvalFalse)));
    }

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: 20_000, .. ProptestConfig::default()
        })]

        #[test]
        fn test_arbitrary_scripts(
            lock_time in prop::num::u32::ANY,
            is_final in prop::bool::ANY,
            pub_key in prop::collection::vec(0..=0xffu8, 0..=OVERFLOW_SCRIPT_SIZE),
            sig in prop::collection::vec(0..=0xffu8, 1..=OVERFLOW_SCRIPT_SIZE),
            flags in prop::bits::u32::masked(VerificationFlags::all().bits()),
        ) {
            let ret = check_verify_callback::<CxxInterpreter, RustInterpreter>(
                &missing_sighash,
                lock_time,
                is_final,
                &pub_key[..],
                &sig[..],
                repair_flags(VerificationFlags::from_bits_truncate(flags)),
            );
            prop_assert_eq!(ret.0, ret.1.map_err(normalize_error),
                            "original Rust result: {:?}", ret.1);
        }

        /// Similar to `test_arbitrary_scripts`, but ensures the `sig` only contains pushes.
        #[test]
        fn test_restricted_sig_scripts(
            lock_time in prop::num::u32::ANY,
            is_final in prop::bool::ANY,
            pub_key in prop::collection::vec(0..=0xffu8, 0..=OVERFLOW_SCRIPT_SIZE),
            sig in prop::collection::vec(0..=0x60u8, 0..=OVERFLOW_SCRIPT_SIZE),
            flags in prop::bits::u32::masked(
                // Don’t waste test cases on whether or not `SigPushOnly` is set.
                (VerificationFlags::all() - VerificationFlags::SigPushOnly).bits()),
        ) {
            let ret = check_verify_callback::<CxxInterpreter, RustInterpreter>(
                &missing_sighash,
                lock_time,
                is_final,
                &pub_key[..],
                &sig[..],
                repair_flags(VerificationFlags::from_bits_truncate(flags))
                    | VerificationFlags::SigPushOnly,
            );
            prop_assert_eq!(ret.0, ret.1.map_err(normalize_error),
                            "original Rust result: {:?}", ret.1);
        }
    }
}
