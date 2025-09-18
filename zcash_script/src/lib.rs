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

mod external;
pub mod interpreter;
mod num;
pub mod op;
pub mod opcode;
pub mod pattern;
pub mod pv;
pub mod script;
pub mod signature;

#[cfg(any(test, feature = "test-dependencies"))]
pub mod test_vectors;

use alloc::vec::Vec;

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
    /// The script sig.
    pub sig: script::Component<Sig>,
    /// The script pubkey.
    pub pub_key: script::Component<PubKey>,
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

/// Utilities useful for tests in other modules and crates.
#[cfg(any(test, feature = "test-dependencies"))]
pub mod testing {
    use alloc::vec::Vec;

    use hex::FromHex;

    use crate::{
        interpreter,
        pattern::{check_multisig, pay_to_script_hash, push_num, push_script},
        pv,
        script::{self, Evaluable},
        signature::HashType,
        test_vectors::TestVector,
        Opcode, Script,
    };

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
        interpreter_fn: &dyn Fn(
            &script::Raw,
            interpreter::Flags,
        )
            -> Result<bool, (Option<script::ComponentType>, script::Error)>,
        sigop_count_fn: &dyn Fn(&script::Code) -> Result<u32, script::Error>,
    ) {
        match tv.run(&|script, flags| interpreter_fn(script, flags), &|pubkey| {
            sigop_count_fn(pubkey).unwrap_or_else(|e| panic!("something bad happened: {:?}", e))
        }) {
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
    use super::{
        test_vectors::test_vectors,
        testing::{missing_sighash, run_test_vector},
    };
    use crate::interpreter::CallbackTransactionSignatureChecker;

    #[cfg(feature = "signature-validation")]
    #[test]
    fn test_test_vectors() {
        for tv in test_vectors() {
            run_test_vector(
                &tv,
                false,
                &|script, flags| {
                    script
                        .eval(
                            flags,
                            &CallbackTransactionSignatureChecker {
                                sighash: &missing_sighash,
                                lock_time: 0,
                                is_final: false,
                            },
                        )
                        .map_err(|(t, e)| (Some(t), e))
                },
                &|pubkey| Ok(pubkey.sig_op_count(false)),
            )
        }
    }
}
