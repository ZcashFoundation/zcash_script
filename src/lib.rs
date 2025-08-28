//! Zcash transparent script implementations.

#![doc(html_logo_url = "https://www.zfnd.org/images/zebra-icon.png")]
#![doc(html_root_url = "https://docs.rs/zcash_script/0.3.2")]
#![allow(non_snake_case)]
#![allow(unsafe_code)]
#![deny(missing_docs)]
#[macro_use]
extern crate enum_primitive;

pub mod cxx;
mod external;
pub mod interpreter;
mod num;
pub mod op;
mod opcode;
pub mod pattern;
pub mod pv;
mod script;
pub mod script_error;
pub mod signature;
mod zcash_script;

#[cfg(any(test, feature = "test-dependencies"))]
pub mod test_vectors;

use std::os::raw::{c_int, c_uint, c_void};

use enum_primitive::FromPrimitive;
use tracing::warn;

use interpreter::{
    CallbackTransactionSignatureChecker, DefaultStepEvaluator, SighashCalculator, VerificationFlags,
};
use script_error::ScriptError;
use signature::HashType;
pub use zcash_script::{
    rust_interpreter, ComparisonStepEvaluator, Error, StepResults, StepwiseInterpreter, ZcashScript,
};

/// Script opcodes
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Opcode {
    /// Opcodes that represent constants to be pushed onto the stack.
    PushValue(opcode::PushValue),
    /// - always evaluated
    /// - can be cast to its discriminant
    Control(opcode::Control),
    /// - only evaluated on active branch
    /// - can be cast to its discriminant
    Operation(opcode::Operation),
}

impl Opcode {
    /// This parses a single opcode from a byte stream.
    pub fn parse(script: &[u8]) -> Result<opcode::Parsed<'_>, ScriptError> {
        match opcode::push_value::LargeValue::parse(script)? {
            None => match script.split_first() {
                None => Err(ScriptError::ReadError {
                    expected_bytes: 1,
                    available_bytes: 0,
                }),
                Some((leading_byte, remaining_code)) => opcode::Disabled::from_u8(*leading_byte)
                    .map_or(
                        Ok(opcode::Parsed {
                            opcode: if let Some(sv) =
                                opcode::push_value::SmallValue::from_u8(*leading_byte)
                            {
                                opcode::PossiblyBad::Good(Opcode::PushValue(
                                    opcode::PushValue::SmallValue(sv),
                                ))
                            } else if let Some(ctl) = opcode::Control::from_u8(*leading_byte) {
                                opcode::PossiblyBad::Good(Opcode::Control(ctl))
                            } else if let Some(op) = opcode::Operation::from_u8(*leading_byte) {
                                opcode::PossiblyBad::Good(Opcode::Operation(op))
                            } else {
                                opcode::PossiblyBad::Bad(opcode::Bad::from(*leading_byte))
                            },
                            remaining_code,
                        }),
                        |disabled| Err(ScriptError::DisabledOpcode(Some(disabled))),
                    ),
            },
            Some((v, remaining_code)) => Ok(opcode::Parsed {
                opcode: opcode::PossiblyBad::Good(Opcode::PushValue(
                    opcode::PushValue::LargeValue(v),
                )),
                remaining_code,
            }),
        }
    }
}

impl From<&Opcode> for Vec<u8> {
    fn from(value: &Opcode) -> Self {
        match value {
            Opcode::PushValue(v) => v.into(),
            Opcode::Control(v) => vec![(*v).into()],
            Opcode::Operation(v) => vec![(*v).into()],
        }
    }
}

/// An interpreter that calls the original C++ implementation via FFI.
pub struct CxxInterpreter<'a> {
    /// A callback to determine the sighash for a particular UTXO.
    pub sighash: SighashCalculator<'a>,
    /// The value of the locktime field of the transaction.
    pub lock_time: u32,
    /// Whether this is the final UTXO for the transaction.
    pub is_final: bool,
}

impl From<cxx::ScriptError> for Error {
    #[allow(non_upper_case_globals)]
    fn from(err_code: cxx::ScriptError) -> Self {
        match err_code {
            cxx::ScriptError_t_SCRIPT_ERR_UNKNOWN_ERROR => {
                Self::Script(ScriptError::AMBIGUOUS_UNKNOWN_NUM_HIGHS)
            }
            cxx::ScriptError_t_SCRIPT_ERR_EVAL_FALSE => Self::Script(ScriptError::EvalFalse),
            cxx::ScriptError_t_SCRIPT_ERR_OP_RETURN => Self::Script(ScriptError::OpReturn),

            cxx::ScriptError_t_SCRIPT_ERR_SCRIPT_SIZE => {
                Self::Script(ScriptError::ScriptSize(None))
            }
            cxx::ScriptError_t_SCRIPT_ERR_PUSH_SIZE => Self::Script(ScriptError::PushSize(None)),
            cxx::ScriptError_t_SCRIPT_ERR_OP_COUNT => Self::Script(ScriptError::OpCount),
            cxx::ScriptError_t_SCRIPT_ERR_STACK_SIZE => Self::Script(ScriptError::StackSize(None)),
            cxx::ScriptError_t_SCRIPT_ERR_SIG_COUNT => Self::Script(ScriptError::SigCount(None)),
            cxx::ScriptError_t_SCRIPT_ERR_PUBKEY_COUNT => {
                Self::Script(ScriptError::PubKeyCount(None))
            }

            cxx::ScriptError_t_SCRIPT_ERR_VERIFY => Self::Script(ScriptError::Verify),
            cxx::ScriptError_t_SCRIPT_ERR_EQUALVERIFY => Self::Script(ScriptError::EqualVerify),
            cxx::ScriptError_t_SCRIPT_ERR_CHECKMULTISIGVERIFY => {
                Self::Script(ScriptError::CheckMultisigVerify)
            }
            cxx::ScriptError_t_SCRIPT_ERR_CHECKSIGVERIFY => {
                Self::Script(ScriptError::CheckSigVerify)
            }
            cxx::ScriptError_t_SCRIPT_ERR_NUMEQUALVERIFY => {
                Self::Script(ScriptError::NumEqualVerify)
            }

            cxx::ScriptError_t_SCRIPT_ERR_BAD_OPCODE => Self::Script(ScriptError::BadOpcode(None)),
            cxx::ScriptError_t_SCRIPT_ERR_DISABLED_OPCODE => {
                Self::Script(ScriptError::DisabledOpcode(None))
            }
            cxx::ScriptError_t_SCRIPT_ERR_INVALID_STACK_OPERATION => {
                Self::Script(ScriptError::InvalidStackOperation(None))
            }
            cxx::ScriptError_t_SCRIPT_ERR_INVALID_ALTSTACK_OPERATION => {
                Self::Script(ScriptError::InvalidAltstackOperation(None))
            }
            cxx::ScriptError_t_SCRIPT_ERR_UNBALANCED_CONDITIONAL => {
                Self::Script(ScriptError::UnbalancedConditional)
            }

            cxx::ScriptError_t_SCRIPT_ERR_NEGATIVE_LOCKTIME => {
                Self::Script(ScriptError::NegativeLockTime)
            }
            cxx::ScriptError_t_SCRIPT_ERR_UNSATISFIED_LOCKTIME => {
                Self::Script(ScriptError::UnsatisfiedLockTime)
            }

            cxx::ScriptError_t_SCRIPT_ERR_SIG_HASHTYPE => {
                Self::Script(signature::Error::SigHashType(None).into())
            }
            cxx::ScriptError_t_SCRIPT_ERR_SIG_DER => {
                Self::Script(signature::Error::SigDER(None).into())
            }
            cxx::ScriptError_t_SCRIPT_ERR_MINIMALDATA => Self::Script(ScriptError::MinimalData),
            cxx::ScriptError_t_SCRIPT_ERR_SIG_PUSHONLY => Self::Script(ScriptError::SigPushOnly),
            cxx::ScriptError_t_SCRIPT_ERR_SIG_HIGH_S => {
                Self::Script(signature::Error::SigHighS.into())
            }
            cxx::ScriptError_t_SCRIPT_ERR_SIG_NULLDUMMY => Self::Script(ScriptError::SigNullDummy),
            cxx::ScriptError_t_SCRIPT_ERR_PUBKEYTYPE => Self::Script(ScriptError::PubKeyType),
            cxx::ScriptError_t_SCRIPT_ERR_CLEANSTACK => Self::Script(ScriptError::CleanStack),

            cxx::ScriptError_t_SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS => {
                Self::Script(ScriptError::DiscourageUpgradableNOPs)
            }

            cxx::ScriptError_t_SCRIPT_ERR_VERIFY_SCRIPT => Self::CaughtException,
            unknown => Self::Unknown(unknown.into()),
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
        .and_then(|ht| callback(script_code_vec, &ht))
    {
        assert_eq!(sighash_out_len, sighash.len().try_into().unwrap());
        // SAFETY: `sighash_out` is a valid buffer created in
        // `CallbackTransactionSignatureChecker::CheckSig`.
        unsafe { std::ptr::copy_nonoverlapping(sighash.as_ptr(), sighash_out, sighash.len()) };
    }
}

/// This steals a bit of the wrapper code from zebra_script, to provide the API that they want.
impl<'a> ZcashScript for CxxInterpreter<'a> {
    fn verify_callback(
        &self,
        script_pub_key: &[u8],
        signature_script: &[u8],
        flags: VerificationFlags,
    ) -> Result<(), Error> {
        let mut err = 0;

        // SAFETY: The `script` fields are created from a valid Rust `slice`.
        let ret = unsafe {
            cxx::zcash_script_verify_callback(
                (&self.sighash as *const SighashCalculator) as *const c_void,
                Some(sighash_callback),
                self.lock_time.into(),
                if self.is_final { 1 } else { 0 },
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
    fn legacy_sigop_count_script(&self, script: &[u8]) -> Result<u32, Error> {
        script
            .len()
            .try_into()
            .map_err(Error::InvalidScriptSize)
            .map(|script_len| unsafe {
                cxx::zcash_script_legacy_sigop_count_script(script.as_ptr(), script_len)
            })
    }
}

/// Runs both the C++ and Rust implementations `ZcashScript::legacy_sigop_count_script` and returns
/// both results. This is more useful for testing than the impl that logs a warning if the results
/// differ and always returns the C++ result.
fn check_legacy_sigop_count_script<T: ZcashScript, U: ZcashScript>(
    first: &T,
    second: &U,
    script: &[u8],
) -> (Result<u32, Error>, Result<u32, Error>) {
    (
        first.legacy_sigop_count_script(script),
        second.legacy_sigop_count_script(script),
    )
}

// FIXME: This shouldn’t be public, but is currently used by both `ZcashScript for
//        ComparisonInterpreter` and the fuzz tests, so it can’t easily be non-`pub` or moved to
//        `testing`.
/// Runs two implementations of `ZcashScript::verify_callback` with the same arguments and returns
/// both results. This is more useful for testing than the impl that logs a warning if the results
/// differ and always returns the `T` result.
pub fn check_verify_callback<T: ZcashScript, U: ZcashScript>(
    first: &T,
    second: &U,
    script_pub_key: &[u8],
    script_sig: &[u8],
    flags: VerificationFlags,
) -> (Result<(), Error>, Result<(), Error>) {
    (
        first.verify_callback(script_pub_key, script_sig, flags),
        second.verify_callback(script_pub_key, script_sig, flags),
    )
}

/// A tag to indicate that both the C++ and Rust implementations of zcash_script should be used,
/// with their results compared.
pub struct ComparisonInterpreter<T, U> {
    first: T,
    second: U,
}

/// An interpreter that compares the results of the C++ and Rust implementations. In the case where
/// they differ, a warning will be logged, and the C++ interpreter will be treated as the correct
/// result.
pub fn cxx_rust_comparison_interpreter(
    sighash: SighashCalculator,
    lock_time: u32,
    is_final: bool,
    flags: VerificationFlags,
) -> ComparisonInterpreter<
    CxxInterpreter,
    StepwiseInterpreter<DefaultStepEvaluator<CallbackTransactionSignatureChecker>>,
> {
    ComparisonInterpreter {
        first: CxxInterpreter {
            sighash,
            lock_time,
            is_final,
        },
        second: rust_interpreter(
            flags,
            CallbackTransactionSignatureChecker {
                sighash,
                lock_time: lock_time.into(),
                is_final,
            },
        ),
    }
}

/// This implementation is functionally equivalent to the `T` impl, but it also runs a second (`U`)
/// impl and logs a warning if they disagree.
impl<T: ZcashScript, U: ZcashScript> ZcashScript for ComparisonInterpreter<T, U> {
    fn legacy_sigop_count_script(&self, script: &[u8]) -> Result<u32, Error> {
        let (cxx, rust) = check_legacy_sigop_count_script(&self.first, &self.second, script);
        if rust != cxx {
            warn!(
                "The Rust Zcash Script interpreter had a different sigop count ({:?}) from the C++ one ({:?}).",
                rust,
                cxx)
        };
        cxx
    }

    fn verify_callback(
        &self,
        script_pub_key: &[u8],
        script_sig: &[u8],
        flags: VerificationFlags,
    ) -> Result<(), Error> {
        let (cxx, rust) =
            check_verify_callback(&self.first, &self.second, script_pub_key, script_sig, flags);
        if rust.clone().map_err(|e| e.normalize()) != cxx.clone().map_err(|e| e.normalize()) {
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

/// Utilities useful for tests in other modules and crates.
#[cfg(any(test, feature = "test-dependencies"))]
pub mod testing {
    use crate::{
        interpreter::{State, StepFn, VerificationFlags},
        opcode::Operation,
        pattern::*,
        pv, script,
        script_error::ScriptError,
        signature::HashType,
        test_vectors::TestVector,
        zcash_script::Error,
        Opcode,
    };
    use hex::FromHex;

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
    pub const OVERFLOW_SCRIPT_SIZE: usize = script::Code::MAX_SIZE + 1;

    /// This is the same as `DefaultStepEvaluator`, except that it skips `OP_EQUAL`, allowing us to
    /// test comparison failures.
    #[derive(Copy, Clone, Debug, PartialEq, Eq)]
    pub struct BrokenStepEvaluator<T>(pub T);

    impl<T: StepFn> StepFn for BrokenStepEvaluator<T> {
        type Payload = T::Payload;
        fn call<'a>(
            &self,
            pc: &'a [u8],
            script: &script::Code,
            state: &mut State,
            payload: &mut T::Payload,
        ) -> Result<&'a [u8], ScriptError> {
            self.0.call(
                if pc[0] == Operation::OP_EQUAL.into() {
                    &pc[1..]
                } else {
                    pc
                },
                script,
                state,
                payload,
            )
        }
    }

    lazy_static::lazy_static! {
        /// The P2SH redeem script used for the static test case.
        pub static ref REDEEM_SCRIPT: Vec<Opcode> = check_multisig(
            2,
            &[
                &<[u8; 0x21]>::from_hex("03b2cc71d23eb30020a4893982a1e2d352da0d20ee657fa02901c432758909ed8f").expect("valid key"),
                &<[u8; 0x21]>::from_hex("029d1e9a9354c0d2aee9ffd0f0cea6c39bbf98c4066cf143115ba2279d0ba7dabe").expect("valid key"),
                &<[u8; 0x21]>::from_hex("03e32096b63fd57f3308149d238dcbb24d8d28aad95c0e4e74e3e5e6a11b61bcc4").expect("valid key")
            ],
            false).expect("all keys are valid and there’s not more than 20 of them");
        /// The scriptPubkey used for the static test case.
        pub static ref SCRIPT_PUBKEY: Vec<u8> = script::Code::serialize(&pay_to_script_hash(&REDEEM_SCRIPT));
        /// The scriptSig used for the static test case.
        pub static ref SCRIPT_SIG: Vec<u8> = script::Code::serialize(&[
            push_num(0),
            pv::push_value(&<[u8; 0x48]>::from_hex("3045022100d2ab3e6258fe244fa442cfb38f6cef9ac9a18c54e70b2f508e83fa87e20d040502200eead947521de943831d07a350e45af8e36c2166984a8636f0a8811ff03ed09401").expect("valid sig")).expect("fits into a PushValue"),
            pv::push_value(&<[u8; 0x47]>::from_hex("3044022013e15d865010c257eef133064ef69a780b4bc7ebe6eda367504e806614f940c3022062fdbc8c2d049f91db2042d6c9771de6f1ef0b3b1fea76c1ab5542e44ed29ed801").expect("valid sig")).expect("fits into a PushValue"),
            push_script(&REDEEM_SCRIPT).expect("fits into a PushValue"),
        ].map(Opcode::PushValue));
    }

    /// The correct sighash for the static test case.
    pub fn sighash(_script_code: &[u8], _hash_type: &HashType) -> Option<[u8; 32]> {
        <[u8; 32]>::from_hex("e8c7bdac77f6bb1f3aba2eaa1fada551a9c8b3b5ecd1ef86e6e58a5f1aab952c")
            .ok()
    }

    /// An incorrect sighash for the static test case – for checking failure cases.
    pub fn invalid_sighash(_script_code: &[u8], _hash_type: &HashType) -> Option<[u8; 32]> {
        <[u8; 32]>::from_hex("08c7bdac77f6bb1f3aba2eaa1fada551a9c8b3b5ecd1ef86e6e58a5f1aab952c")
            .ok()
    }

    /// A callback that returns no sighash at all – another failure case.
    pub fn missing_sighash(_script_code: &[u8], _hash_type: &HashType) -> Option<[u8; 32]> {
        None
    }

    /// Run a single test case against some function.
    ///
    /// `try_normalized_error` indicates whether the results should be normalized before being
    /// compared. In particular, the C++ implementation doesn’t carry much failure information, so
    /// the results need to be normalized to discard the corresponding information from the expected
    /// results.
    pub fn run_test_vector(
        tv: &TestVector,
        try_normalized_error: bool,
        f: &dyn Fn(&[u8], &[u8], VerificationFlags) -> Result<(), Error>,
    ) -> () {
        match tv.run(&|sig, pubkey, flags| match f(sig, pubkey, flags) {
            Ok(()) => Ok(()),
            Err(Error::Script(err)) => Err(err),
            Err(err) => panic!("failed in a very bad way: {:?}", err),
        }) {
            Ok(()) => (),
            Err(actual) => {
                if try_normalized_error
                    && tv.result.clone().normalized() == actual.clone().map_err(|e| e.normalize())
                {
                    ()
                } else {
                    panic!(
                        "{:?} didn’t match the result in

    {:?}
",
                        actual, tv
                    );
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::{prop, prop_assert_eq, proptest, ProptestConfig};

    use super::{
        check_verify_callback, rust_interpreter,
        test_vectors::test_vectors,
        testing::{
            invalid_sighash, missing_sighash, repair_flags, run_test_vector, sighash,
            OVERFLOW_SCRIPT_SIZE, SCRIPT_PUBKEY, SCRIPT_SIG,
        },
        CxxInterpreter, Error, ZcashScript,
    };
    use crate::{
        interpreter::{CallbackTransactionSignatureChecker, VerificationFlags},
        script_error::ScriptError,
    };

    #[test]
    fn it_works() {
        let lock_time: u32 = 2410374;
        let is_final: bool = true;
        let script_pub_key = &SCRIPT_PUBKEY;
        let script_sig = &SCRIPT_SIG;
        let flags = VerificationFlags::P2SH | VerificationFlags::CHECKLOCKTIMEVERIFY;

        let ret = check_verify_callback(
            &CxxInterpreter {
                sighash: &sighash,
                lock_time,
                is_final,
            },
            &rust_interpreter(
                flags,
                CallbackTransactionSignatureChecker {
                    sighash: &sighash,
                    lock_time: lock_time.into(),
                    is_final,
                },
            ),
            script_pub_key,
            script_sig,
            flags,
        );

        assert_eq!(
            ret.0.clone().map_err(|e| e.normalize()),
            ret.1.map_err(|e| e.normalize())
        );
        assert!(ret.0.is_ok());
    }

    #[test]
    fn it_fails_on_invalid_sighash() {
        let lock_time: u32 = 2410374;
        let is_final: bool = true;
        let script_pub_key = &SCRIPT_PUBKEY;
        let script_sig = &SCRIPT_SIG;
        let flags = VerificationFlags::P2SH | VerificationFlags::CHECKLOCKTIMEVERIFY;
        let ret = check_verify_callback(
            &CxxInterpreter {
                sighash: &invalid_sighash,
                lock_time,
                is_final,
            },
            &rust_interpreter(
                flags,
                CallbackTransactionSignatureChecker {
                    sighash: &invalid_sighash,
                    lock_time: lock_time.into(),
                    is_final,
                },
            ),
            script_pub_key,
            script_sig,
            flags,
        );

        assert_eq!(
            ret.0.clone().map_err(|e| e.normalize()),
            ret.1.map_err(|e| e.normalize())
        );
        assert_eq!(ret.0, Err(Error::Script(ScriptError::EvalFalse)));
    }

    #[test]
    fn it_fails_on_missing_sighash() {
        let lock_time: u32 = 2410374;
        let is_final: bool = true;
        let script_pub_key = &SCRIPT_PUBKEY;
        let script_sig = &SCRIPT_SIG;
        let flags = VerificationFlags::P2SH | VerificationFlags::CHECKLOCKTIMEVERIFY;

        let ret = check_verify_callback(
            &CxxInterpreter {
                sighash: &missing_sighash,
                lock_time,
                is_final,
            },
            &rust_interpreter(
                flags,
                CallbackTransactionSignatureChecker {
                    sighash: &missing_sighash,
                    lock_time: lock_time.into(),
                    is_final,
                },
            ),
            script_pub_key,
            script_sig,
            flags,
        );

        assert_eq!(
            ret.0.clone().map_err(|e| e.normalize()),
            ret.1.map_err(|e| e.normalize())
        );
        assert_eq!(ret.0, Err(Error::Script(ScriptError::EvalFalse)));
    }

    #[test]
    fn test_vectors_for_cxx() {
        for tv in test_vectors() {
            run_test_vector(&tv, true, &|sig, pubkey, flags| {
                CxxInterpreter {
                    sighash: &missing_sighash,
                    lock_time: 0,
                    is_final: false,
                }
                .verify_callback(pubkey, sig, flags)
            })
        }
    }

    #[test]
    fn test_vectors_for_rust() {
        for tv in test_vectors() {
            run_test_vector(&tv, false, &|sig, pubkey, flags| {
                rust_interpreter(
                    flags,
                    CallbackTransactionSignatureChecker {
                        sighash: &missing_sighash,
                        lock_time: 0,
                        is_final: false,
                    },
                )
                .verify_callback(&pubkey, &sig, flags)
            })
        }
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
            flag_bits in prop::bits::u32::masked(VerificationFlags::all().bits()),
        ) {
            let flags = repair_flags(VerificationFlags::from_bits_truncate(flag_bits));
            let ret = check_verify_callback(
            &CxxInterpreter {
                sighash: &sighash,
                lock_time,
                is_final,
            },
            &rust_interpreter(
                flags,
                CallbackTransactionSignatureChecker {
                    sighash: &sighash,
                    lock_time: lock_time.into(),
                    is_final,
                },
            ),
                &pub_key[..],
                &sig[..],
                flags,
            );
            prop_assert_eq!(ret.0.map_err(|e| e.normalize()), ret.1.clone().map_err(|e| e.normalize()),
                            "original Rust result: {:?}", ret.1);
        }

        /// Similar to `test_arbitrary_scripts`, but ensures the `sig` only contains pushes.
        #[test]
        fn test_restricted_sig_scripts(
            lock_time in prop::num::u32::ANY,
            is_final in prop::bool::ANY,
            pub_key in prop::collection::vec(0..=0xffu8, 0..=OVERFLOW_SCRIPT_SIZE),
            sig in prop::collection::vec(0..=0x60u8, 0..=OVERFLOW_SCRIPT_SIZE),
            flag_bits in prop::bits::u32::masked(
                // Don’t waste test cases on whether or not `SigPushOnly` is set.
                (VerificationFlags::all() - VerificationFlags::SigPushOnly).bits()),
        ) {
            let flags = repair_flags(VerificationFlags::from_bits_truncate(flag_bits))
                    | VerificationFlags::SigPushOnly;
            let ret = check_verify_callback(
            &CxxInterpreter {
                sighash: &sighash,
                lock_time,
                is_final,
            },
            &rust_interpreter(
                flags,
                CallbackTransactionSignatureChecker {
                    sighash: &sighash,
                    lock_time: lock_time.into(),
                    is_final,
                },
            ),
                &pub_key[..],
                &sig[..],
                flags,
            );
            prop_assert_eq!(ret.0.map_err(|e| e.normalize()), ret.1.clone().map_err(|e| e.normalize()),
                            "original Rust result: {:?}", ret.1);
        }
    }
}
