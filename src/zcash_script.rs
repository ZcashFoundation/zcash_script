use thiserror::Error;

use crate::{
    interpreter::{
        verify_script, DefaultStepEvaluator, SignatureChecker, State, StepFn, VerificationFlags,
    },
    script,
};

/// This extends `ScriptError` with cases that can only occur when using the C++ implementation.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum Error {
    /// An error that could occur in any implementation has occurred.
    #[error("{0}")]
    Script(script::Error),

    /// An exception was caught during C++ verification.
    #[error("caught exception during verification")]
    CaughtException,

    /// Some other failure value recovered from C++.
    ///
    /// __NB__: Linux uses `u32` for the underlying C++ enum while Windows uses `i32`, so `i64` can
    ///         hold either.
    #[error("unknown error code: {0}")]
    Unknown(i64),
}

impl Error {
    /// Convert errors that don’t exist in the C++ code into the cases that do.
    pub fn normalize(&self) -> Self {
        match self {
            Error::Script(serr) => Error::Script(serr.normalize()),
            _ => self.clone(),
        }
    }
}

impl From<script::Error> for Error {
    fn from(value: script::Error) -> Self {
        Error::Script(value)
    }
}

/// A verification error annotated with the script component it occurred in.
pub type AnnError = (Option<script::ComponentType>, Error);

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
    ///  Note that script verification failure is indicated by `Err(Error::Script)`.
    fn verify_callback(
        &self,
        script_pub_key: &[u8],
        script_sig: &[u8],
        flags: VerificationFlags,
    ) -> Result<(), AnnError>;

    /// Returns the number of transparent signature operations in the input or
    /// output script pointed to by script.
    fn legacy_sigop_count_script(&self, script: &[u8]) -> Result<u32, Error>;
}

// NB: This is extracted from [StepwiseInterpreter::verify_callback] to be used in tests. The public
//     API gives no access to the payload.
fn stepwise_verify<F>(
    script_pub_key: &[u8],
    script_sig: &[u8],
    flags: VerificationFlags,
    payload: &mut F::Payload,
    stepper: &F,
) -> Result<(), (script::ComponentType, Error)>
where
    F: StepFn,
{
    verify_script(
        &script::Code(script_sig),
        &script::Code(script_pub_key),
        flags,
        payload,
        stepper,
    )
    .map_err(|(t, e)| (t, Error::Script(e)))
}

/// A payload for comparing the results of two steppers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StepResults<T, U> {
    /// This contains the step-wise states of the steppers as long as they were identical. Its
    /// `head` contains the initial state and its `tail` has a 1:1 correspondence to the opcodes
    /// (not to the bytes).
    identical_states: Vec<State>,
    /// If the execution matched the entire way, then this contains `None`. If there was a
    /// divergence, then this contains `Some` with a pair of `Result`s – one representing each
    /// stepper’s outcome at the point at which they diverged.
    diverging_result: Option<(Result<State, script::Error>, Result<State, script::Error>)>,
    /// The final payload of the first stepper.
    payload_l: T,
    /// The final payload of the second stepper.
    payload_r: U,
}

impl<T, U> StepResults<T, U> {
    /// Creates an empty `StepResults` given an initial payload for each of the `StepFn`s that will
    /// be compared.
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
    /// One of the two `StepFn`s to be compared. The one difference is that in the case where both
    /// `StepFn`s fail, but with different errors, _this_ is the error that will be returned for the
    /// script.
    pub eval_step_l: &'a dyn StepFn<Payload = T>,
    /// One of the two `StepFn`s to be compared. The one difference is that in the case where both
    /// `StepFn`s fail, but with different errors, _this_ error will be discarded.
    pub eval_step_r: &'a dyn StepFn<Payload = U>,
}

impl<'a, T: Clone, U: Clone> StepFn for ComparisonStepEvaluator<'a, T, U> {
    type Payload = StepResults<T, U>;
    fn call<'b>(
        &self,
        pc: &'b [u8],
        script: &script::Code,
        state: &mut State,
        payload: &mut StepResults<T, U>,
    ) -> Result<&'b [u8], script::Error> {
        let mut right_state = (*state).clone();
        let left = self
            .eval_step_l
            .call(pc, script, state, &mut payload.payload_l);
        let right = self
            .eval_step_r
            .call(pc, script, &mut right_state, &mut payload.payload_r);

        match (left, right) {
            (l @ Ok(_), r @ Ok(_)) => {
                if *state == right_state {
                    payload.identical_states.push(state.clone());
                    l
                } else {
                    // In this case, the script hasn’t failed, but we stop running
                    // anything
                    payload.diverging_result =
                        Some((l.map(|_| state.clone()), r.map(|_| right_state.clone())));
                    Err(script::Error::ExternalError("mismatched step results"))
                }
            }
            // at least one is `Err`
            (l, r) => {
                if l != r {
                    payload.diverging_result = Some((
                        l.clone().map(|_| state.clone()),
                        r.clone().map(|_| right_state.clone()),
                    ));
                }
                l.and(r)
            }
        }
    }
}

/// This is used for any interpreter that is based on a `StepFn`.
///
/// The original C++ interpreter is _not_ a `StepwiseInterpreter`, but the pure Rust one is.
pub struct StepwiseInterpreter<F>
where
    F: StepFn,
{
    initial_payload: F::Payload,
    stepper: F,
}

impl<F: StepFn> StepwiseInterpreter<F> {
    /// Creates a new interpreter from a `StepFn` and an initial payload.
    pub fn new(initial_payload: F::Payload, stepper: F) -> Self {
        StepwiseInterpreter {
            initial_payload,
            stepper,
        }
    }
}

/// This is the pure Rust interpreter, which doesn’t use the FFI.
pub fn rust_interpreter<C: SignatureChecker + Copy>(
    flags: VerificationFlags,
    checker: C,
) -> StepwiseInterpreter<DefaultStepEvaluator<C>> {
    StepwiseInterpreter::new((), DefaultStepEvaluator { flags, checker })
}

impl<F: StepFn> ZcashScript for StepwiseInterpreter<F> {
    /// Returns the number of transparent signature operations in the
    /// transparent inputs and outputs of this transaction.
    fn legacy_sigop_count_script(&self, script: &[u8]) -> Result<u32, Error> {
        let cscript = script::Code(script);
        Ok(cscript.get_sig_op_count(false))
    }

    fn verify_callback(
        &self,
        script_pub_key: &[u8],
        script_sig: &[u8],
        flags: VerificationFlags,
    ) -> Result<(), AnnError> {
        let mut payload = self.initial_payload.clone();
        stepwise_verify(
            script_pub_key,
            script_sig,
            flags,
            &mut payload,
            &self.stepper,
        )
        .map_err(|(t, e)| (Some(t), e))
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::{prop, proptest, ProptestConfig};

    use super::{stepwise_verify, ComparisonStepEvaluator, Error, StepResults};
    use crate::{
        interpreter::{
            CallbackTransactionSignatureChecker, DefaultStepEvaluator, VerificationFlags,
        },
        opcode, script,
        testing::{
            invalid_sighash, missing_sighash, repair_flags, sighash, BrokenStepEvaluator,
            OVERFLOW_SCRIPT_SIZE, SCRIPT_PUBKEY, SCRIPT_SIG,
        },
    };

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

        if res.diverging_result.is_some() {
            panic!("invalid result: {res:?}");
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
            Err((
                script::ComponentType::PubKey,
                Error::from(script::Error::from(opcode::Error::ReadError {
                    expected_bytes: 1,
                    available_bytes: 0,
                }))
            ))
        );

        // `State`s are large, so we just check that there was some progress in lock step, and a
        // divergence.
        match res {
            StepResults {
                identical_states,
                diverging_result:
                    Some((
                        Ok(state),
                        Err(script::Error::Opcode(opcode::Error::ReadError {
                            expected_bytes: 1,
                            available_bytes: 0,
                        })),
                    )),
                payload_l: (),
                payload_r: (),
            } => {
                assert_eq!(identical_states.len(), 6);
                assert_eq!(state.stack().len(), 4);
                assert!(state.altstack().is_empty());
                assert_eq!(state.op_count(), 2);
                assert!(state.vexec().is_empty());
            }
            _ => {
                panic!("invalid result: {res:?}");
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

        if res.diverging_result.is_some() {
            panic!("mismatched result: {res:?}");
        }
        assert_eq!(
            ret,
            Err((
                script::ComponentType::Redeem,
                Error::from(script::Error::EvalFalse)
            ))
        );
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

        if res.diverging_result.is_some() {
            panic!("mismatched result: {res:?}");
        }
        assert_eq!(
            ret,
            Err((
                script::ComponentType::Redeem,
                Error::from(script::Error::EvalFalse)
            ))
        );
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

            if res.diverging_result.is_some() {
                panic!("mismatched result: {res:?}");
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

            if res.diverging_result.is_some() {
                panic!("mismatched result: {res:?}");
            }
        }
    }
}
