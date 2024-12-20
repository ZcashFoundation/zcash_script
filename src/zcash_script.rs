use std::num::TryFromIntError;

use super::interpreter::*;
use super::script::*;
use super::script_error::*;

/// This maps to `zcash_script_error_t`, but most of those cases aren’t used any more. This only
/// replicates the still-used cases, and then an `Unknown` bucket for anything else that might
/// happen.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// Any failure that results in the script being invalid.
    Ok(ScriptError),
    /// An exception was caught.
    VerifyScript,
    /// The script size can’t fit in a `u32`, as required by the C++ code.
    InvalidScriptSize(TryFromIntError),
    /// Some other failure value recovered from C++.
    ///
    /// __NB__: Linux uses `u32` for the underlying C++ enum while Windows uses `i32`, so `i64` can
    ///         hold either.
    Unknown(i64),
}

/// The external API of zcash_script. This is defined to make it possible to compare the C++ and
/// Rust implementations.
pub trait ZcashScript {
    /// Returns `Ok(())` if the a transparent input correctly spends the matching output
    ///  under the additional constraints specified by `flags`. This function
    ///  receives only the required information to validate the spend and not
    ///  the transaction itself. In particular, the sighash for the spend
    ///  is obtained using a callback function.
    ///
    ///  - sighash: a callback function which is called to obtain the sighash.
    ///  - lock_time: the lock time of the transaction being validated.
    ///  - is_final: a boolean indicating whether the input being validated is final
    ///    (i.e. its sequence number is 0xFFFFFFFF).
    ///  - script_pub_key: the scriptPubKey of the output being spent.
    ///  - script_sig: the scriptSig of the input being validated.
    ///  - flags: the script verification flags to use.
    ///
    ///  Note that script verification failure is indicated by `Err(Error::Ok)`.
    fn verify_callback(
        &self,
        script_pub_key: &[u8],
        script_sig: &[u8],
        flags: VerificationFlags,
    ) -> Result<(), Error>;

    /// Returns the number of transparent signature operations in the input or
    /// output script pointed to by script.
    fn legacy_sigop_count_script(&self, script: &[u8]) -> Result<u32, Error>;
}

pub fn stepwise_verify<F>(
    script_pub_key: &[u8],
    script_sig: &[u8],
    flags: VerificationFlags,
    payload: &mut F::Payload,
    stepper: &F,
) -> Result<(), Error>
where
    F: StepFn,
{
    verify_script(
        &Script(script_sig),
        &Script(script_pub_key),
        flags,
        payload,
        stepper,
    )
    .map_err(Error::Ok)
}

/// A payload for comparing the results of two steppers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StepResults<T, U> {
    /// This contains the step-wise states of the steppers as long as they were identical. Its
    /// `head` contains the initial state and its `tail` has a 1:1 correspondence to the opcodes
    /// (not to the bytes).
    pub identical_states: Vec<State>,
    /// If the execution matched the entire way, then this contains `None`. If there was a
    /// divergence, then this contains `Some` with a pair of `Result`s – one representing each
    /// stepper’s outcome at the point at which they diverged.
    pub diverging_result: Option<(Result<State, ScriptError>, Result<State, ScriptError>)>,
    /// The final payload of the first stepper.
    pub payload_l: T,
    /// The final payload of the second stepper.
    pub payload_r: U,
}

impl<T, U> StepResults<T, U> {
    pub fn initial(payload_l: T, payload_r: U) -> Self {
        StepResults {
            identical_states: vec![],
            diverging_result: None,
            payload_l,
            payload_r,
        }
    }
}

/// This compares two `ZcashScript` implementations in a deep way – checking the entire `State` step
/// by step. Note that this has some tradeoffs: one is performance. Another is that it doesn’t run
/// the entire codepath of either implementation. The setup/wrapup code is specific to this
/// definition, but any differences there should be caught very easily by other testing mechanisms
/// (like `check_verify_callback`).
///
/// This returns a very debuggable result. See `StepResults` for details.
pub struct ComparisonStepEvaluator<'a, T, U> {
    pub eval_step_l: &'a dyn StepFn<Payload = T>,
    pub eval_step_r: &'a dyn StepFn<Payload = U>,
}

impl<'a, T: Clone, U: Clone> StepFn for ComparisonStepEvaluator<'a, T, U> {
    type Payload = StepResults<T, U>;
    fn call<'b>(
        &self,
        pc: &'b [u8],
        script: &Script,
        state: &mut State,
        payload: &mut StepResults<T, U>,
    ) -> Result<&'b [u8], ScriptError> {
        let mut right_state = (*state).clone();
        let left = self
            .eval_step_l
            .call(pc, script, state, &mut payload.payload_l);
        let right = self
            .eval_step_r
            .call(pc, script, &mut right_state, &mut payload.payload_r);

        match (left, right) {
            (Ok(_), Ok(_)) => {
                if *state == right_state {
                    payload.identical_states.push(state.clone());
                    left
                } else {
                    // In this case, the script hasn’t failed, but we stop running
                    // anything
                    payload.diverging_result = Some((
                        left.map(|_| state.clone()),
                        right.map(|_| right_state.clone()),
                    ));
                    Err(ScriptError::UnknownError)
                }
            }
            // at least one is `Err`
            (_, _) => {
                if left != right {
                    payload.diverging_result = Some((
                        left.map(|_| state.clone()),
                        right.map(|_| right_state.clone()),
                    ));
                }
                left.and(right)
            }
        }
    }
}

pub struct StepwiseInterpreter<F>
where
    F: StepFn,
{
    initial_payload: F::Payload,
    stepper: F,
}

impl<F: StepFn> StepwiseInterpreter<F> {
    pub fn new(initial_payload: F::Payload, stepper: F) -> Self {
        StepwiseInterpreter {
            initial_payload,
            stepper,
        }
    }
}

pub fn rust_interpreter<C: SignatureChecker + Copy>(
    flags: VerificationFlags,
    checker: C,
) -> StepwiseInterpreter<DefaultStepEvaluator<C>> {
    StepwiseInterpreter {
        initial_payload: (),
        stepper: DefaultStepEvaluator { flags, checker },
    }
}

impl<F: StepFn> ZcashScript for StepwiseInterpreter<F> {
    /// Returns the number of transparent signature operations in the
    /// transparent inputs and outputs of this transaction.
    fn legacy_sigop_count_script(&self, script: &[u8]) -> Result<u32, Error> {
        let cscript = Script(script);
        Ok(cscript.get_sig_op_count(false))
    }

    fn verify_callback(
        &self,
        script_pub_key: &[u8],
        script_sig: &[u8],
        flags: VerificationFlags,
    ) -> Result<(), Error> {
        let mut payload = self.initial_payload.clone();
        stepwise_verify(
            script_pub_key,
            script_sig,
            flags,
            &mut payload,
            &self.stepper,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::*;
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

        let checker = CallbackTransactionSignatureChecker {
            sighash: &sighash,
            lock_time: n_lock_time.into(),
            is_final,
        };
        let rust_stepper = DefaultStepEvaluator { flags, checker };
        let stepper = ComparisonStepEvaluator {
            eval_step_l: &rust_stepper,
            eval_step_r: &rust_stepper,
        };
        let mut res = StepResults::initial((), ());
        let ret = stepwise_verify(script_pub_key, script_sig, flags, &mut res, &stepper);

        if res.diverging_result != None {
            panic!("invalid result: {:?}", res);
        }
        assert_eq!(ret, Ok(()));
    }

    #[test]
    fn broken_stepper_causes_divergence() {
        let n_lock_time: u32 = 2410374;
        let is_final: bool = true;
        let script_pub_key = &SCRIPT_PUBKEY;
        let script_sig = &SCRIPT_SIG;
        let flags = VerificationFlags::P2SH | VerificationFlags::CHECKLOCKTIMEVERIFY;

        let checker = CallbackTransactionSignatureChecker {
            sighash: &sighash,
            lock_time: n_lock_time.into(),
            is_final,
        };
        let rust_stepper = DefaultStepEvaluator { flags, checker };
        let broken_stepper = BrokenStepEvaluator(rust_stepper);
        let stepper = ComparisonStepEvaluator {
            eval_step_l: &rust_stepper,
            eval_step_r: &broken_stepper,
        };
        let mut res = StepResults::initial((), ());
        let ret = stepwise_verify(script_pub_key, script_sig, flags, &mut res, &stepper);

        // The final return value is from whichever stepper failed.
        assert_eq!(
            ret,
            Err(Error::Ok(ScriptError::ReadError {
                expected_bytes: 1,
                available_bytes: 0,
            }))
        );

        // `State`s are large, so we just check that there was some progress in lock step, and a
        // divergence.
        match res {
            StepResults {
                identical_states,
                diverging_result:
                    Some((
                        Ok(state),
                        Err(ScriptError::ReadError {
                            expected_bytes: 1,
                            available_bytes: 0,
                        }),
                    )),
                payload_l: (),
                payload_r: (),
            } => {
                assert!(
                    identical_states.len() == 6
                        && state.stack().len() == 4
                        && state.altstack().is_empty()
                        && state.op_count() == 2
                        && state.vexec().is_empty()
                );
            }
            _ => {
                panic!("invalid result: {:?}", res);
            }
        }
    }

    #[test]
    fn it_fails_on_invalid_sighash() {
        let n_lock_time: u32 = 2410374;
        let is_final: bool = true;
        let script_pub_key = &SCRIPT_PUBKEY;
        let script_sig = &SCRIPT_SIG;
        let flags = VerificationFlags::P2SH | VerificationFlags::CHECKLOCKTIMEVERIFY;

        let checker = CallbackTransactionSignatureChecker {
            sighash: &invalid_sighash,
            lock_time: n_lock_time.into(),
            is_final,
        };
        let rust_stepper = DefaultStepEvaluator { flags, checker };
        let stepper = ComparisonStepEvaluator {
            eval_step_l: &rust_stepper,
            eval_step_r: &rust_stepper,
        };
        let mut res = StepResults::initial((), ());
        let ret = stepwise_verify(script_pub_key, script_sig, flags, &mut res, &stepper);

        if res.diverging_result != None {
            panic!("mismatched result: {:?}", res);
        }
        assert_eq!(ret, Err(Error::Ok(ScriptError::EvalFalse)));
    }

    #[test]
    fn it_fails_on_missing_sighash() {
        let n_lock_time: u32 = 2410374;
        let is_final: bool = true;
        let script_pub_key = &SCRIPT_PUBKEY;
        let script_sig = &SCRIPT_SIG;
        let flags = VerificationFlags::P2SH | VerificationFlags::CHECKLOCKTIMEVERIFY;

        let checker = CallbackTransactionSignatureChecker {
            sighash: &missing_sighash,
            lock_time: n_lock_time.into(),
            is_final,
        };
        let rust_stepper = DefaultStepEvaluator { flags, checker };
        let stepper = ComparisonStepEvaluator {
            eval_step_l: &rust_stepper,
            eval_step_r: &rust_stepper,
        };
        let mut res = StepResults::initial((), ());
        let ret = stepwise_verify(script_pub_key, script_sig, flags, &mut res, &stepper);

        if res.diverging_result != None {
            panic!("mismatched result: {:?}", res);
        }
        assert_eq!(ret, Err(Error::Ok(ScriptError::EvalFalse)));
    }

    proptest! {
        // The stepwise comparison tests are significantly slower than the simple comparison tests,
        // so run fewer iterations.
        #![proptest_config(ProptestConfig {
            cases: 2_000, .. ProptestConfig::default()
        })]

        #[test]
        fn test_arbitrary_scripts(
            lock_time in prop::num::u32::ANY,
            is_final in prop::bool::ANY,
            pub_key in prop::collection::vec(0..=0xffu8, 0..=OVERFLOW_SCRIPT_SIZE),
            sig in prop::collection::vec(0..=0xffu8, 1..=OVERFLOW_SCRIPT_SIZE),
            flags in prop::bits::u32::masked(VerificationFlags::all().bits()),
        ) {
            let checker = CallbackTransactionSignatureChecker {
                sighash: &missing_sighash,
                lock_time: lock_time.into(),
                is_final,
            };
            let flags = repair_flags(VerificationFlags::from_bits_truncate(flags));
            let rust_stepper = DefaultStepEvaluator { flags, checker };
            let stepper = ComparisonStepEvaluator {
            eval_step_l: &rust_stepper,
            eval_step_r: &rust_stepper,
        };
            let mut res = StepResults::initial((), ());
            let _ = stepwise_verify(&pub_key[..], &sig[..], flags, &mut res, &stepper);

            if res.diverging_result != None {
                panic!("mismatched result: {:?}", res);
            }
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
            let checker = CallbackTransactionSignatureChecker {
                sighash: &missing_sighash,
                lock_time: lock_time.into(),
                is_final,
            };
            let flags = repair_flags(VerificationFlags::from_bits_truncate(flags)) | VerificationFlags::SigPushOnly;
            let rust_stepper = DefaultStepEvaluator { flags, checker };
            let stepper = ComparisonStepEvaluator {
            eval_step_l: &rust_stepper,
            eval_step_r: &rust_stepper,
        };
            let mut res = StepResults::initial((), ());
            let _ = stepwise_verify(&pub_key[..], &sig[..], flags, &mut res, &stepper);

            if res.diverging_result != None {
                panic!("mismatched result: {:?}", res);
            }
        }
    }
}
