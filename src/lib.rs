//! Zcash transparent script implementations.

#![no_std]
#![doc(html_logo_url = "https://www.zfnd.org/images/zebra-icon.png")]
#![doc(html_root_url = "https://docs.rs/zcash_script/0.3.2")]
#![allow(clippy::unit_arg)]
#![allow(non_snake_case)]
#![allow(unsafe_code)]
#![deny(missing_docs)]

#[macro_use]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

pub mod cxx;
mod external;
pub mod interpreter;
mod num;
pub mod op;
mod opcode;
pub mod pattern;
pub mod pv;
pub mod script;
pub mod signature;
pub mod solver;
mod zcash_script;

#[cfg(any(test, feature = "test-dependencies"))]
pub mod test_vectors;

use alloc::vec::Vec;

#[cfg(feature = "std")]
use std::os::raw::{c_int, c_uint, c_void};

#[cfg(feature = "std")]
use tracing::warn;

use interpreter::SighashCalculator;

#[cfg(feature = "std")]
use signature::HashType;

pub use zcash_script::{AnnError, Error, RustInterpreter, ZcashScript};

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
    ///
    /// This always returns the unparsed bytes, because parsing failures don’t invalidate the
    /// remainder of the stream (if any).
    ///
    /// __NB__: This is stricter than the parsing allowed by script verification. For that, use
    ///         [`opcode::PossiblyBad::parse`].
    pub fn parse(script: &[u8]) -> (Result<Opcode, script::Error>, &[u8]) {
        let (res, rem) = opcode::PossiblyBad::parse(script);
        (
            res.map_err(script::Error::Opcode).and_then(|pb| match pb {
                opcode::PossiblyBad::Bad(_) => Err(script::Error::Interpreter(
                    Some(pb),
                    interpreter::Error::BadOpcode,
                )),
                opcode::PossiblyBad::Good(op) => Ok(op),
            }),
            rem,
        )
    }

    /// Statically analyze an opcode. That is, this identifies potential runtime errors without
    /// needing to evaluate the script.
    ///
    /// __NB__: [`opcode::Operation::OP_RETURN`] isn’t tracked by this function because it’s
    ///         functionally more like a `break` then an error.
    pub fn analyze(&self, flags: &interpreter::Flags) -> Result<(), Vec<interpreter::Error>> {
        match self {
            Opcode::PushValue(pv) => pv.analyze(flags),
            Opcode::Operation(op) => op.analyze(flags),
            Opcode::Control(_) => Ok(()),
        }
    }
}

impl opcode::Evaluable for Opcode {
    fn byte_len(&self) -> usize {
        match self {
            Opcode::PushValue(pv) => pv.byte_len(),
            Opcode::Control(_) => 1,
            Opcode::Operation(_) => 1,
        }
    }

    fn to_bytes(&self) -> Vec<u8> {
        Vec::<u8>::from(self)
    }

    fn restrict(pb: opcode::PossiblyBad) -> Result<Self, script::Error> {
        match pb {
            opcode::PossiblyBad::Good(op) => Ok(op),
            opcode::PossiblyBad::Bad(_) => Err(script::Error::Interpreter(
                Some(pb),
                interpreter::Error::BadOpcode,
            )),
        }
    }

    fn eval(
        &self,
        flags: interpreter::Flags,
        script: &script::Code,
        checker: &dyn interpreter::SignatureChecker,
        mut state: interpreter::State,
    ) -> Result<interpreter::State, interpreter::Error> {
        match self {
            Self::PushValue(pv) => {
                if interpreter::should_exec(&state.vexec) {
                    pv.eval(flags, script, checker, state)
                } else {
                    Ok(state)
                }
            }
            Self::Control(control) => {
                state.increment_op_count(1)?;
                (state.stack, state.vexec) = control.eval(state.stack, state.vexec)?;
                Ok(state)
            }
            Self::Operation(normal) => {
                state.increment_op_count(1)?;
                if interpreter::should_exec(&state.vexec) {
                    normal.eval(flags, script, checker, state)
                } else {
                    Ok(state)
                }
            }
        }
        .and_then(|final_state| {
            // Size limits
            if final_state.stack.len() + final_state.altstack().len() > interpreter::MAX_STACK_DEPTH
            {
                Err(interpreter::Error::StackSize(None))
            } else {
                Ok(final_state)
            }
        })
    }

    fn extract_push_value(&self) -> Result<&opcode::PushValue, script::Error> {
        match self {
            Self::PushValue(pv) => Ok(pv),
            _ => Err(script::Error::SigPushOnly),
        }
    }

    fn sig_op_count(&self, last_opcode: Option<opcode::PossiblyBad>) -> u32 {
        match self {
            Self::Operation(op) => op.sig_op_count(last_opcode),
            _ => 0,
        }
    }
}

impl From<opcode::PushValue> for Opcode {
    fn from(value: opcode::PushValue) -> Self {
        Opcode::PushValue(value)
    }
}

impl From<opcode::Control> for Opcode {
    fn from(value: opcode::Control) -> Self {
        Opcode::Control(value)
    }
}

impl From<opcode::Operation> for Opcode {
    fn from(value: opcode::Operation) -> Self {
        Opcode::Operation(value)
    }
}

impl From<&Opcode> for Vec<u8> {
    fn from(value: &Opcode) -> Self {
        match value {
            Opcode::PushValue(v) => v.into(),
            Opcode::Control(v) => vec![(*v).encode()],
            Opcode::Operation(v) => vec![(*v).encode()],
        }
    }
}

/// A Zcash script consists of a sig and a pubkey. The first type parameter is the type of opcodes
/// in the script sig, and the second is the type of opcodes in the script pubkey.
///
/// - Script<opcode::PossiblyBad, opcode::PossiblyBad> – from the chain
/// - Script<opcode::PushValue, Opcode> – authoring sig_push_only
/// - Script<Opcode, Opcode> – authoring non-sig_push_only
pub struct Script<Sig = opcode::PushValue, PubKey = Opcode> {
    sig: script::Component<Sig>,
    pub_key: script::Component<PubKey>,
}

impl<
        Sig: Into<opcode::PossiblyBad> + opcode::Evaluable + Clone,
        PubKey: Into<opcode::PossiblyBad> + opcode::Evaluable + Clone,
    > Script<Sig, PubKey>
{
    /// Evaluate an entire script.
    pub fn eval(
        &self,
        flags: interpreter::Flags,
        checker: &dyn interpreter::SignatureChecker,
    ) -> Result<bool, (script::ComponentType, script::Error)> {
        script::iter::eval_script(&self.sig, &self.pub_key, flags, checker)
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
                Self::from(script::Error::AMBIGUOUS_UNKNOWN_NUM_HIGHS)
            }
            cxx::ScriptError_t_SCRIPT_ERR_OP_RETURN => Self::from(script::Error::Interpreter(
                None,
                interpreter::Error::OpReturn,
            )),

            cxx::ScriptError_t_SCRIPT_ERR_SCRIPT_SIZE => {
                Self::from(script::Error::ScriptSize(None))
            }
            cxx::ScriptError_t_SCRIPT_ERR_PUSH_SIZE => {
                Self::from(script::Error::from(opcode::Error::PushSize(None)))
            }
            cxx::ScriptError_t_SCRIPT_ERR_OP_COUNT => Self::from(script::Error::Interpreter(
                None,
                interpreter::Error::OpCount,
            )),
            cxx::ScriptError_t_SCRIPT_ERR_STACK_SIZE => Self::from(script::Error::Interpreter(
                None,
                interpreter::Error::StackSize(None),
            )),
            cxx::ScriptError_t_SCRIPT_ERR_SIG_COUNT => Self::from(script::Error::Interpreter(
                None,
                interpreter::Error::SigCount(None),
            )),
            cxx::ScriptError_t_SCRIPT_ERR_PUBKEY_COUNT => Self::from(script::Error::Interpreter(
                None,
                interpreter::Error::PubKeyCount(None),
            )),

            cxx::ScriptError_t_SCRIPT_ERR_VERIFY => Self::from(script::Error::Interpreter(
                Some(opcode::PossiblyBad::from(op::VERIFY)),
                interpreter::Error::Verify,
            )),
            cxx::ScriptError_t_SCRIPT_ERR_EQUALVERIFY => Self::from(script::Error::Interpreter(
                Some(opcode::PossiblyBad::from(op::EQUALVERIFY)),
                interpreter::Error::Verify,
            )),
            cxx::ScriptError_t_SCRIPT_ERR_CHECKMULTISIGVERIFY => {
                Self::from(script::Error::Interpreter(
                    Some(opcode::PossiblyBad::from(op::CHECKMULTISIGVERIFY)),
                    interpreter::Error::Verify,
                ))
            }
            cxx::ScriptError_t_SCRIPT_ERR_CHECKSIGVERIFY => Self::from(script::Error::Interpreter(
                Some(opcode::PossiblyBad::from(op::CHECKSIGVERIFY)),
                interpreter::Error::Verify,
            )),
            cxx::ScriptError_t_SCRIPT_ERR_NUMEQUALVERIFY => Self::from(script::Error::Interpreter(
                Some(opcode::PossiblyBad::from(op::NUMEQUALVERIFY)),
                interpreter::Error::Verify,
            )),

            cxx::ScriptError_t_SCRIPT_ERR_BAD_OPCODE => Self::from(script::Error::Interpreter(
                None,
                interpreter::Error::BadOpcode,
            )),
            cxx::ScriptError_t_SCRIPT_ERR_DISABLED_OPCODE => {
                Self::from(script::Error::from(opcode::Error::Disabled(None)))
            }
            cxx::ScriptError_t_SCRIPT_ERR_INVALID_STACK_OPERATION => Self::from(
                script::Error::Interpreter(None, interpreter::Error::InvalidStackOperation(None)),
            ),
            cxx::ScriptError_t_SCRIPT_ERR_INVALID_ALTSTACK_OPERATION => {
                Self::from(script::Error::Interpreter(
                    Some(opcode::PossiblyBad::from(op::FROMALTSTACK)),
                    interpreter::Error::InvalidStackOperation(None),
                ))
            }
            cxx::ScriptError_t_SCRIPT_ERR_UNBALANCED_CONDITIONAL => Self::from(
                script::Error::Interpreter(None, interpreter::Error::UnbalancedConditional),
            ),

            cxx::ScriptError_t_SCRIPT_ERR_NEGATIVE_LOCKTIME => Self::from(
                script::Error::Interpreter(None, interpreter::Error::NegativeLockTime),
            ),
            cxx::ScriptError_t_SCRIPT_ERR_UNSATISFIED_LOCKTIME => Self::from(
                script::Error::Interpreter(None, interpreter::Error::UnsatisfiedLockTime),
            ),

            cxx::ScriptError_t_SCRIPT_ERR_SIG_HASHTYPE => Self::from(script::Error::Interpreter(
                None,
                interpreter::Error::from(signature::Error::SigHashType(None)),
            )),
            cxx::ScriptError_t_SCRIPT_ERR_SIG_DER => Self::from(script::Error::Interpreter(
                None,
                interpreter::Error::from(signature::Error::SigDER(None)),
            )),
            cxx::ScriptError_t_SCRIPT_ERR_MINIMALDATA => Self::from(script::Error::Interpreter(
                None,
                interpreter::Error::MinimalData,
            )),
            cxx::ScriptError_t_SCRIPT_ERR_SIG_PUSHONLY => Self::from(script::Error::SigPushOnly),
            cxx::ScriptError_t_SCRIPT_ERR_SIG_HIGH_S => Self::from(script::Error::Interpreter(
                None,
                interpreter::Error::from(signature::Error::SigHighS),
            )),
            cxx::ScriptError_t_SCRIPT_ERR_SIG_NULLDUMMY => Self::from(script::Error::Interpreter(
                None,
                interpreter::Error::SigNullDummy,
            )),
            cxx::ScriptError_t_SCRIPT_ERR_PUBKEYTYPE => Self::from(script::Error::Interpreter(
                None,
                interpreter::Error::PubKeyType,
            )),
            cxx::ScriptError_t_SCRIPT_ERR_CLEANSTACK => Self::from(script::Error::CleanStack),

            cxx::ScriptError_t_SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS => Self::from(
                script::Error::Interpreter(None, interpreter::Error::DiscourageUpgradableNOPs),
            ),

            cxx::ScriptError_t_SCRIPT_ERR_VERIFY_SCRIPT => Self::CaughtException,
            unknown => Self::Unknown(i64::from(unknown)),
        }
    }
}

#[cfg(feature = "std")]
fn cxx_result(err_code: cxx::ScriptError) -> Result<bool, (Option<script::ComponentType>, Error)> {
    match err_code {
        cxx::ScriptError_t_SCRIPT_ERR_OK => Ok(true),
        cxx::ScriptError_t_SCRIPT_ERR_EVAL_FALSE => Ok(false),
        _ => Err((None, Error::from(err_code))),
    }
}

/// The sighash callback to use with zcash_script.
#[cfg(feature = "std")]
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
        .and_then(|ht| callback(&script::Code(script_code_vec.to_vec()), &ht))
    {
        assert_eq!(sighash_out_len, sighash.len().try_into().unwrap());
        // SAFETY: `sighash_out` is a valid buffer created in
        // `CallbackTransactionSignatureChecker::CheckSig`.
        unsafe { std::ptr::copy_nonoverlapping(sighash.as_ptr(), sighash_out, sighash.len()) };
    }
}

/// This steals a bit of the wrapper code from zebra_script, to provide the API that they want.
#[cfg(feature = "std")]
impl ZcashScript for CxxInterpreter<'_> {
    fn verify_callback(
        &self,
        script: &script::Raw,
        flags: interpreter::Flags,
    ) -> Result<bool, AnnError> {
        let mut err = 0;

        // SAFETY: The `script` fields are created from a valid Rust `slice`.
        let ret = unsafe {
            cxx::zcash_script_verify_callback(
                (&self.sighash as *const SighashCalculator) as *const c_void,
                Some(sighash_callback),
                self.lock_time.into(),
                if self.is_final { 1 } else { 0 },
                script.pub_key.0.as_ptr(),
                script.pub_key.0.len().try_into().map_err(|_| {
                    (
                        Some(script::ComponentType::PubKey),
                        Error::from(script::Error::ScriptSize(Some(script.pub_key.0.len()))),
                    )
                })?,
                script.sig.0.as_ptr(),
                script.sig.0.len().try_into().map_err(|_| {
                    (
                        Some(script::ComponentType::Sig),
                        Error::from(script::Error::ScriptSize(Some(script.sig.0.len()))),
                    )
                })?,
                flags.bits(),
                &mut err,
            )
        };

        if ret == 1 {
            Ok(true)
        } else {
            cxx_result(err)
        }
    }

    /// Returns the number of transparent signature operations in the
    /// transparent inputs and outputs of this transaction.
    fn legacy_sigop_count_script(&self, script: &script::Code) -> Result<u32, Error> {
        script
            .0
            .len()
            .try_into()
            .map_err(|_| Error::from(script::Error::ScriptSize(Some(script.0.len()))))
            .map(|script_len| unsafe {
                cxx::zcash_script_legacy_sigop_count_script(script.0.as_ptr(), script_len)
            })
    }
}

/// Runs both the C++ and Rust implementations `ZcashScript::legacy_sigop_count_script` and returns
/// both results. This is more useful for testing than the impl that logs a warning if the results
/// differ and always returns the C++ result.
#[cfg(feature = "std")]
fn check_legacy_sigop_count_script<T: ZcashScript, U: ZcashScript>(
    first: &T,
    second: &U,
    script: &script::Code,
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
    script: &script::Raw,
    flags: interpreter::Flags,
) -> (Result<bool, AnnError>, Result<bool, AnnError>) {
    (
        first.verify_callback(script, flags),
        second.verify_callback(script, flags),
    )
}

/// A tag to indicate that both the C++ and Rust implementations of zcash_script should be used,
/// with their results compared.
#[cfg(feature = "std")]
pub struct ComparisonInterpreter<T, U> {
    first: T,
    second: U,
}

/// An interpreter that compares the results of the C++ and Rust implementations. In the case where
/// they differ, a warning will be logged, and the C++ interpreter will be treated as the correct
/// result.
#[cfg(all(feature = "signature-validation", feature = "std"))]
pub fn cxx_rust_comparison_interpreter(
    sighash: SighashCalculator,
    lock_time: u32,
    is_final: bool,
) -> ComparisonInterpreter<
    CxxInterpreter,
    RustInterpreter<interpreter::CallbackTransactionSignatureChecker>,
> {
    ComparisonInterpreter {
        first: CxxInterpreter {
            sighash,
            lock_time,
            is_final,
        },
        second: RustInterpreter::new(interpreter::CallbackTransactionSignatureChecker {
            sighash,
            lock_time: lock_time.into(),
            is_final,
        }),
    }
}

/// Convert errors that don’t exist in the C++ code into the cases that do.
pub fn normalize_err(err: AnnError) -> Error {
    err.1.normalize()
}

/// This implementation is functionally equivalent to the `T` impl, but it also runs a second (`U`)
/// impl and logs a warning if they disagree.
#[cfg(feature = "std")]
impl<T: ZcashScript, U: ZcashScript> ZcashScript for ComparisonInterpreter<T, U> {
    fn legacy_sigop_count_script(&self, script: &script::Code) -> Result<u32, Error> {
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
        script: &script::Raw,
        flags: interpreter::Flags,
    ) -> Result<bool, AnnError> {
        let (cxx, rust) = check_verify_callback(&self.first, &self.second, script, flags);
        if rust.clone().map_err(normalize_err) != cxx.clone().map_err(normalize_err) {
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
    use alloc::vec::Vec;

    use crate::{
        interpreter,
        pattern::*,
        pv,
        script::{self, Evaluable},
        signature::HashType,
        test_vectors::TestVector,
        zcash_script::{AnnError, Error},
        Opcode, Script,
    };
    use hex::FromHex;

    /// Ensures that flags represent a supported state. This avoids crashes in the C++ code, which
    /// break various tests.
    pub fn repair_flags(flags: interpreter::Flags) -> interpreter::Flags {
        // TODO: The C++ implementation fails an assert (interpreter.cpp:1097) if `CleanStack` is
        //       set without `P2SH`.
        if flags.contains(interpreter::Flags::CleanStack) {
            flags & interpreter::Flags::P2SH
        } else {
            flags
        }
    }

    /// A `usize` one larger than the longest allowed script, for testing bounds.
    pub const OVERFLOW_SCRIPT_SIZE: usize = script::Code::MAX_SIZE + 1;

    lazy_static::lazy_static! {
        /// The P2SH redeem script used for the static test case.
        pub static ref REDEEM_SCRIPT: script::Redeem = script::Component(check_multisig(
            2,
            &[
                &<[u8; 0x21]>::from_hex("03b2cc71d23eb30020a4893982a1e2d352da0d20ee657fa02901c432758909ed8f").expect("valid key"),
                &<[u8; 0x21]>::from_hex("029d1e9a9354c0d2aee9ffd0f0cea6c39bbf98c4066cf143115ba2279d0ba7dabe").expect("valid key"),
                &<[u8; 0x21]>::from_hex("03e32096b63fd57f3308149d238dcbb24d8d28aad95c0e4e74e3e5e6a11b61bcc4").expect("valid key")
            ],
            false).expect("all keys are valid and there’s not more than 20 of them"));
        /// The scriptPubkey used for the static test case.
        pub static ref SCRIPT_PUBKEY: script::PubKey = script::Component(pay_to_script_hash(&REDEEM_SCRIPT));
        /// The scriptSig used for the static test case.
        pub static ref SCRIPT_SIG: script::Sig = script::Component(vec![
            push_num(0),
            pv::push_value(&<[u8; 0x48]>::from_hex("3045022100d2ab3e6258fe244fa442cfb38f6cef9ac9a18c54e70b2f508e83fa87e20d040502200eead947521de943831d07a350e45af8e36c2166984a8636f0a8811ff03ed09401").expect("valid sig")).expect("fits into a PushValue"),
            pv::push_value(&<[u8; 0x47]>::from_hex("3044022013e15d865010c257eef133064ef69a780b4bc7ebe6eda367504e806614f940c3022062fdbc8c2d049f91db2042d6c9771de6f1ef0b3b1fea76c1ab5542e44ed29ed801").expect("valid sig")).expect("fits into a PushValue"),
            push_script(&REDEEM_SCRIPT).expect("fits into a PushValue"),
        ]);
        /// The combined script used for the static test case.
        pub static ref SCRIPT: script::Raw =
            script::Raw::from_raw_parts(SCRIPT_SIG.to_bytes(), SCRIPT_PUBKEY.to_bytes());
        /// The same script as `SCRIPT`, but using the “authoring” types.
        pub static ref AUTHORED_SCRIPT: Script =
            Script{ sig : SCRIPT_SIG.clone(), pub_key : SCRIPT_PUBKEY.clone() };
    }

    /// The correct sighash for the static test case.
    pub fn sighash(_script_code: &script::Code, _hash_type: &HashType) -> Option<[u8; 32]> {
        <[u8; 32]>::from_hex("e8c7bdac77f6bb1f3aba2eaa1fada551a9c8b3b5ecd1ef86e6e58a5f1aab952c")
            .ok()
    }

    /// An incorrect sighash for the static test case – for checking failure cases.
    pub fn invalid_sighash(_script_code: &script::Code, _hash_type: &HashType) -> Option<[u8; 32]> {
        <[u8; 32]>::from_hex("08c7bdac77f6bb1f3aba2eaa1fada551a9c8b3b5ecd1ef86e6e58a5f1aab952c")
            .ok()
    }

    /// A callback that returns no sighash at all – another failure case.
    pub fn missing_sighash(_script_code: &script::Code, _hash_type: &HashType) -> Option<[u8; 32]> {
        None
    }

    /// Returns a script annotated with errors that could occur during evaluation.
    pub fn annotate_script(
        script: &script::Raw,
        flags: &interpreter::Flags,
    ) -> (
        Vec<Result<Opcode, Vec<script::Error>>>,
        Vec<Result<Opcode, Vec<script::Error>>>,
    ) {
        script.map(&|c| c.parse_strict(&flags).collect::<Vec<_>>())
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
        interpreter_fn: &dyn Fn(&script::Raw, interpreter::Flags) -> Result<bool, AnnError>,
        sigop_count_fn: &dyn Fn(&script::Code) -> Result<u32, Error>,
    ) {
        match tv.run(
            &|script, flags| {
                interpreter_fn(script, flags).map_err(|err| match err {
                    (t, Error::Script(serr)) => (t, serr),
                    _ => panic!("failed in a very bad way: {:?}", err),
                })
            },
            &|pubkey| {
                sigop_count_fn(pubkey).unwrap_or_else(|e| panic!("something bad happened: {:?}", e))
            },
        ) {
            Ok(()) => (),
            Err((actual_res, actual_count)) => {
                if try_normalized_error
                    && tv.result.clone().normalized()
                        == actual_res.clone().map_err(|(_, e)| e.normalize())
                    && tv.sigop_count == actual_count
                {
                    ()
                } else {
                    panic!(
                        "Either {:?} didn’t match the result or {} didn’t match the sigop_count in

    {:?}
",
                        actual_res, actual_count, tv
                    );
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "signature-validation")]
    use proptest::prelude::{prop, prop_assert_eq, proptest, ProptestConfig};

    use super::{
        check_verify_callback, normalize_err,
        test_vectors::test_vectors,
        testing::{invalid_sighash, missing_sighash, run_test_vector, SCRIPT},
        CxxInterpreter, RustInterpreter, ZcashScript,
    };
    #[cfg(feature = "signature-validation")]
    use super::{
        testing::{annotate_script, repair_flags, sighash, OVERFLOW_SCRIPT_SIZE},
        Error,
    };
    use crate::interpreter;
    #[cfg(feature = "signature-validation")]
    use crate::{script, Script};

    #[test]
    fn it_works_in_cxx() {
        let lock_time: u32 = 2410374;
        let is_final: bool = true;
        let flags = interpreter::Flags::P2SH | interpreter::Flags::CHECKLOCKTIMEVERIFY;

        let ret = CxxInterpreter {
            sighash: &sighash,
            lock_time,
            is_final,
        }
        .verify_callback(&SCRIPT, flags);

        assert_eq!(ret, Ok(true));
    }

    #[cfg(feature = "signature-validation")]
    #[test]
    fn it_works_in_rust() {
        let lock_time: u32 = 2410374;
        let is_final: bool = true;
        let flags = interpreter::Flags::P2SH | interpreter::Flags::CHECKLOCKTIMEVERIFY;

        let ret = RustInterpreter::new(interpreter::CallbackTransactionSignatureChecker {
            sighash: &sighash,
            lock_time: lock_time.into(),
            is_final,
        })
        .verify_callback(&SCRIPT, flags);
        assert_eq!(ret, Ok(true));
    }

    #[test]
    fn it_fails_with_null_checker() {
        let flags = interpreter::Flags::P2SH | interpreter::Flags::CHECKLOCKTIMEVERIFY;

        let ret = RustInterpreter::new(interpreter::NullSignatureChecker())
            .verify_callback(&SCRIPT, flags);
        assert_eq!(ret, Ok(false));
    }

    #[test]
    fn it_fails_on_invalid_sighash_in_cxx() {
        let lock_time: u32 = 2410374;
        let is_final: bool = true;
        let flags = interpreter::Flags::P2SH | interpreter::Flags::CHECKLOCKTIMEVERIFY;
        let ret = CxxInterpreter {
            sighash: &invalid_sighash,
            lock_time,
            is_final,
        }
        .verify_callback(&SCRIPT, flags);

        assert_eq!(ret, Ok(false));
    }

    #[cfg(feature = "signature-validation")]
    #[test]
    fn it_fails_on_invalid_sighash_in_rust() {
        let lock_time: u32 = 2410374;
        let is_final: bool = true;
        let flags = interpreter::Flags::P2SH | interpreter::Flags::CHECKLOCKTIMEVERIFY;
        let ret = RustInterpreter::new(interpreter::CallbackTransactionSignatureChecker {
            sighash: &invalid_sighash,
            lock_time: lock_time.into(),
            is_final,
        })
        .verify_callback(&SCRIPT, flags);

        assert_eq!(ret, Ok(false));
    }

    #[test]
    fn it_fails_on_invalid_sighash_with_null_checker() {
        let flags = interpreter::Flags::P2SH | interpreter::Flags::CHECKLOCKTIMEVERIFY;
        let ret = RustInterpreter::new(interpreter::NullSignatureChecker())
            .verify_callback(&SCRIPT, flags);

        assert_eq!(ret, Ok(false));
    }

    #[test]
    fn it_fails_on_missing_sighash_in_cxx() {
        let lock_time: u32 = 2410374;
        let is_final: bool = true;
        let flags = interpreter::Flags::P2SH | interpreter::Flags::CHECKLOCKTIMEVERIFY;

        let ret = CxxInterpreter {
            sighash: &missing_sighash,
            lock_time,
            is_final,
        }
        .verify_callback(&SCRIPT, flags);

        assert_eq!(ret, Ok(false));
    }

    #[cfg(feature = "signature-validation")]
    #[test]
    fn it_fails_on_missing_sighash_in_rust() {
        let lock_time: u32 = 2410374;
        let is_final: bool = true;
        let flags = interpreter::Flags::P2SH | interpreter::Flags::CHECKLOCKTIMEVERIFY;

        let ret = RustInterpreter::new(interpreter::CallbackTransactionSignatureChecker {
            sighash: &missing_sighash,
            lock_time: lock_time.into(),
            is_final,
        })
        .verify_callback(&SCRIPT, flags);

        assert_eq!(ret, Ok(false));
    }

    #[test]
    fn it_fails_on_missing_sighash_with_null_checker() {
        let flags = interpreter::Flags::P2SH | interpreter::Flags::CHECKLOCKTIMEVERIFY;

        let ret = RustInterpreter::new(interpreter::NullSignatureChecker())
            .verify_callback(&SCRIPT, flags);

        assert_eq!(ret, Ok(false));
    }

    #[test]
    fn test_vectors_for_cxx() {
        for tv in test_vectors() {
            let interp = CxxInterpreter {
                sighash: &missing_sighash,
                lock_time: 0,
                is_final: false,
            };

            run_test_vector(
                &tv,
                true,
                &|script, flags| interp.verify_callback(&script, flags),
                &|pubkey| interp.legacy_sigop_count_script(pubkey),
            )
        }
    }

    #[cfg(feature = "signature-validation")]
    #[test]
    fn test_vectors_for_rust() {
        for tv in test_vectors() {
            run_test_vector(
                &tv,
                false,
                &|script, flags| {
                    RustInterpreter::new(interpreter::CallbackTransactionSignatureChecker {
                        sighash: &missing_sighash,
                        lock_time: 0,
                        is_final: false,
                    })
                    .verify_callback(&script, flags)
                },
                &|pubkey| {
                    RustInterpreter::new(interpreter::CallbackTransactionSignatureChecker {
                        sighash: &missing_sighash,
                        lock_time: 0,
                        is_final: false,
                    })
                    .legacy_sigop_count_script(&pubkey)
                },
            )
        }
    }

    #[cfg(feature = "signature-validation")]
    #[test]
    fn test_vectors_for_pure_rust() {
        for tv in test_vectors() {
            run_test_vector(
                &tv,
                false,
                &|script, flags| {
                    script
                        .eval(
                            flags,
                            &interpreter::CallbackTransactionSignatureChecker {
                                sighash: &missing_sighash,
                                lock_time: 0,
                                is_final: false,
                            },
                        )
                        .map_err(|(t, e)| (Some(t), Error::from(e)))
                },
                &|pubkey| Ok(pubkey.sig_op_count(false)),
            )
        }
    }

    #[cfg(feature = "signature-validation")]
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
            flag_bits in prop::bits::u32::masked(interpreter::Flags::all().bits()),
        ) {
            let flags = repair_flags(interpreter::Flags::from_bits_truncate(flag_bits));
            let script = script::Raw::from_raw_parts(sig, pub_key);
            let ret = check_verify_callback(
                &CxxInterpreter {
                    sighash: &sighash,
                    lock_time,
                    is_final,
                },
                &RustInterpreter::new(
                    interpreter::CallbackTransactionSignatureChecker {
                        sighash: &sighash,
                        lock_time: lock_time.into(),
                        is_final,
                    },
                ),
                &script,
                flags,
            );
            prop_assert_eq!(
                ret.0.clone().map_err(normalize_err),
                ret.1.clone().map_err(normalize_err),
                "\n• original Rust result: {:?}\n• parsed script: {:?}",
                ret.1,
                annotate_script(&script, &flags)
            );
        }

        #[test]
        /// These tests are more subtle than the others, because while the implementations should
        /// always succeed or fail in the same cases, they don’t always fail the same way. See the
        /// comments in the definition for details.
        fn test_arbitrary_scripts_new_api(
            lock_time in prop::num::u32::ANY,
            is_final in prop::bool::ANY,
            pub_key_ in prop::collection::vec(0..=0xffu8, 0..=OVERFLOW_SCRIPT_SIZE),
            sig_ in prop::collection::vec(0..=0xffu8, 1..=OVERFLOW_SCRIPT_SIZE),
            flag_bits in prop::bits::u32::masked(interpreter::Flags::all().bits()),
        ) {
            let flags = repair_flags(interpreter::Flags::from_bits_truncate(flag_bits));
            let script = script::Raw::from_raw_parts(sig_.clone(), pub_key_.clone());
            let cxx_ret = CxxInterpreter {
                    sighash: &sighash,
                    lock_time,
                    is_final,
            }.verify_callback(&script, flags);
            match (script::Code(sig_).to_component(), script::Code(pub_key_).to_component()) {
                // Parsing of the script components succeeded, so we can evaluate & compare as
                // normal.
                (Ok(sig), Ok(pub_key)) => {
                    let rust_ret = Script {sig, pub_key}.eval(flags, &interpreter::CallbackTransactionSignatureChecker {
                        sighash: &sighash,
                        lock_time: lock_time.into(),
                        is_final,
                    });
                    prop_assert_eq!(
                        cxx_ret.clone().map_err(normalize_err),
                        rust_ret.clone().map_err(|(_, e)| Error::Script(e).normalize()),
                        "\n• original Rust result: {:?}\n• parsed script: {:?}",
                        rust_ret,
                        annotate_script(&script, &flags)
                    )
                }
                // Parsing of at least one script component failed. This checks that C++ evaluation
                // also failed. If the C++ failure was also a parse failure, it compares them as
                // normal.
                (Err(oerr), _) | (Ok(_), Err(oerr)) => {
                    if matches!(cxx_ret, Ok(_) | Err((_, Error::Script(script::Error::Opcode(_))))) {
                        let rust_ret = Err(Error::Script(script::Error::Opcode(oerr)));
                        prop_assert_eq!(
                            cxx_ret.clone().map_err(normalize_err),
                            rust_ret.clone().map_err(|e| e.normalize()),
                            "\n• original Rust result: {:?}\n• parsed script: {:?}",
                            rust_ret,
                            annotate_script(&script, &flags),
                        )
                    }
                }
            }
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
                (interpreter::Flags::all() - interpreter::Flags::SigPushOnly).bits()),
        ) {
            let flags = repair_flags(interpreter::Flags::from_bits_truncate(flag_bits))
                | interpreter::Flags::SigPushOnly;
            let script = script::Raw::from_raw_parts(sig, pub_key);
            let ret = check_verify_callback(
                &CxxInterpreter {
                    sighash: &sighash,
                    lock_time,
                    is_final,
                },
                &RustInterpreter::new(
                    interpreter::CallbackTransactionSignatureChecker {
                        sighash: &sighash,
                        lock_time: lock_time.into(),
                        is_final,
                    },
                ),
                &script,
                flags,
            );
            prop_assert_eq!(
                ret.0.map_err(normalize_err),
                ret.1.clone().map_err(normalize_err),
                "original Rust result: {:?}", ret.1);
        }
    }
}
