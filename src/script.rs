//! Managing sequences of opcodes.

use std::iter;

use thiserror::Error;

use crate::{
    interpreter, op,
    opcode::{
        self,
        push_value::{LargeValue::*, SmallValue::*},
        Operation::*,
        PushValue,
    },
    signature, Opcode,
};

/// Errors that can occur during script verification.
#[allow(missing_docs)]
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum Error {
    // Max sizes
    #[error(
        "Script size{} exceeded maxmimum ({} bytes)",
        .0.map_or("", |size| " ({size} bytes)"),
        Code::MAX_SIZE
    )]
    ScriptSize(Option<usize>),

    #[error("during parsing: {0}")]
    Opcode(opcode::Error),

    #[error("non-push opcode encountered in script sig when push-only required")]
    SigPushOnly,

    /// __TODO__: Remove the [`Option`] around [`opcode::PossiblyBad`] when C++ support is removed.
    #[error("during interpretation: {1}")]
    Interpreter(Option<opcode::PossiblyBad>, interpreter::Error),

    /// A error external to the script validation code. This can come from the stepper.
    ///
    /// __TODO__: Replace the `str` with a type parameter, which will be `Void` in validation code,
    /// but can be different in the steppers.
    #[error("external error: {0}")]
    ExternalError(&'static str),

    #[error("{} closed before the end of the script", match .0 { 1 => "1 conditional opcode wasn’t", n => "{n} conditional opcodes weren’t"})]
    UnclosedConditional(usize),

    #[error("clean stack requirement not met")]
    CleanStack,
}

impl Error {
    /// This case is only generated in comparisons. It merges the `interpreter::Error::OpCount` case
    /// with the `opcode::Error::DisabledOpcode` case. This is because there is an edge case when
    /// there is a disabled opcode as the `MAX_OP_COUNT + 1` operation (not opcode) in a script. In
    /// this case, the C++ implementation checks the op_count first, while the Rust implementation
    /// fails on disabled opcodes as soon as they’re read (since the script is guaranteed to fail if
    /// they occur, even in an inactive branch). To allow comparison tests to pass (especially
    /// property & fuzz tests), we need these two failure cases to be seen as identical.
    pub const AMBIGUOUS_COUNT_DISABLED: Self =
        Self::ExternalError("ambiguous OpCount or DisabledOpcode error");

    /// This case is only generated in comparisons. It merges `Self::ScriptNumError` and
    /// `Self::SigHighS`, which can only come from the Rust implementation, with
    /// `ScriptError_t_SCRIPT_ERR_UNKNOWN_ERROR`, which can only come from the C++ implementation,
    /// but in at least all of the cases that either of the Rust error cases would happen.
    pub const AMBIGUOUS_UNKNOWN_NUM_HIGHS: Self =
        Self::ExternalError("ambiguous Unknown, or ScriptNum, or HighS error");

    /// Convert errors that don’t exist in the C++ code into the cases that do.
    pub fn normalize(&self) -> Self {
        match self {
            Self::ScriptSize(Some(_)) => Self::ScriptSize(None),
            Self::Opcode(oerr) => match oerr {
                opcode::Error::Read { .. } => {
                    Self::Interpreter(None, interpreter::Error::BadOpcode)
                }
                opcode::Error::Disabled(_) => Self::AMBIGUOUS_COUNT_DISABLED,
                opcode::Error::PushSize(Some(_)) => Self::from(opcode::Error::PushSize(None)),
                _ => self.clone(),
            },
            Self::Interpreter(
                Some(opcode::PossiblyBad::Good(op::IF | op::NOTIF)),
                interpreter::Error::InvalidStackOperation(_),
            ) => Self::Interpreter(None, interpreter::Error::UnbalancedConditional),
            Self::Interpreter(
                Some(opcode::PossiblyBad::Good(op::FROMALTSTACK)),
                interpreter::Error::InvalidStackOperation(_),
            ) => Self::Interpreter(
                Some(opcode::PossiblyBad::Good(op::FROMALTSTACK)),
                interpreter::Error::InvalidStackOperation(None),
            ),
            Self::Interpreter(_, ierr) => match ierr {
                interpreter::Error::OpCount => Self::AMBIGUOUS_COUNT_DISABLED,
                interpreter::Error::SignatureEncoding(signature::Error::SigHighS) => {
                    Self::AMBIGUOUS_UNKNOWN_NUM_HIGHS
                }
                interpreter::Error::Num(_) => Self::AMBIGUOUS_UNKNOWN_NUM_HIGHS,
                interpreter::Error::Verify => self.clone(),
                _ => Self::Interpreter(None, ierr.normalize()),
            },
            Self::UnclosedConditional(_) => {
                Self::Interpreter(None, interpreter::Error::UnbalancedConditional)
            }
            _ => self.clone(),
        }
    }
}

impl From<opcode::Error> for Error {
    fn from(value: opcode::Error) -> Self {
        Error::Opcode(value)
    }
}

/// An iterator that provides `Opcode`s from a byte stream.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Parser<'a>(&'a [u8]);

impl<'a> Iterator for Parser<'a> {
    type Item = Result<opcode::PossiblyBad, opcode::Error>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.0.is_empty() {
            None
        } else {
            let (res, rem) = opcode::PossiblyBad::parse(self.0);
            self.0 = rem;
            Some(res)
        }
    }
}

/// When an entire [`Script`] is validated, this is used to tag errors with which component they
/// came from.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ComponentType {
    /// The script sig.
    Sig,
    /// The script pubkey.
    PubKey,
    /// The redeem script from a P2SH script.
    Redeem,
}

/// Serialized script, used inside transaction inputs and outputs
#[derive(Clone, Debug)]
pub struct Code<'a>(pub &'a [u8]);

impl Code<'_> {
    /// Maximum script length in bytes
    pub const MAX_SIZE: usize = 10_000;

    /// This parses an entire script. This is stricter than the incremental parsing that is done
    /// during [`interpreter::verify_script`], because it fails on statically-identifiable
    /// interpretation errors no matter where they occur (that is, even on branches that may not be
    /// evaluated on a particular run).
    ///
    /// This is useful for validating and analyzing scripts before they are put into a transaction,
    /// but not for scripts that are read from the chain, because it may fail on valid scripts.
    pub fn parse_strict<'a>(
        &'a self,
        flags: &'a interpreter::VerificationFlags,
    ) -> impl Iterator<Item = Result<Opcode, Vec<Error>>> + 'a {
        self.parse().map(|mpb| {
            mpb.map_err(|e| vec![Error::Opcode(e)]).and_then(|pb| {
                pb.analyze(flags)
                    .map_err(|ierrs| {
                        ierrs
                            .into_iter()
                            .map(|ie| Error::Interpreter(Some(pb.clone()), ie))
                            .collect()
                    })
                    .cloned()
            })
        })
    }

    /// Produce an [`Opcode`] iterator from [`Code`].
    pub fn parse(&self) -> Parser<'_> {
        Parser(self.0)
    }

    /// Convert a sequence of `Opcode`s to the bytes that would be included in a transaction.
    pub fn serialize(script: &[Opcode]) -> Vec<u8> {
        script.iter().flat_map(Vec::from).collect()
    }

    /// This should behave the same as `interpreter::eval_script`.
    pub fn eval(
        &self,
        flags: interpreter::VerificationFlags,
        checker: &dyn interpreter::SignatureChecker,
        stack: interpreter::Stack<Vec<u8>>,
    ) -> Result<interpreter::Stack<Vec<u8>>, Error> {
        // There's a limit on how large scripts can be.
        if self.0.len() <= Code::MAX_SIZE {
            let mut state = interpreter::State::initial(stack);
            self.parse()
                .try_for_each(|mpb| {
                    mpb.map_err(Error::Opcode).and_then(|opcode| {
                        interpreter::eval_possibly_bad(&opcode, self, flags, checker, &mut state)
                            .map_err(|e| Error::Interpreter(Some(opcode), e))
                    })
                })
                .and_then(|()| {
                    if !state.vexec().is_empty() {
                        Err(Error::UnclosedConditional(state.vexec().len()))
                    } else {
                        Ok(state.stack().clone())
                    }
                })
        } else {
            Err(Error::ScriptSize(Some(self.0.len())))
        }
    }

    /// Encode/decode small integers:
    pub fn decode_op_n(opcode: opcode::push_value::SmallValue) -> u32 {
        if opcode == OP_0 {
            return 0;
        }
        assert!(opcode >= OP_1 && opcode <= OP_16);
        (u8::from(opcode) - (u8::from(OP_1) - 1)).into()
    }

    /// Pre-version-0.6, Bitcoin always counted CHECKMULTISIGs
    /// as 20 sigops. With pay-to-script-hash, that changed:
    /// CHECKMULTISIGs serialized in script_sigs are
    /// counted more accurately, assuming they are of the form
    ///  ... OP_N CHECKMULTISIG ...
    pub fn get_sig_op_count(&self, accurate: bool) -> u32 {
        let parser = self.parse();
        match iter::once(Ok(None))
            .chain(parser.map(|r| r.map(Some)))
            .zip(parser)
            .try_fold(0, |n, ops| match ops {
                (Ok(last_opcode), Ok(opcode)) => Ok(n + match opcode {
                    opcode::PossiblyBad::Good(Opcode::Operation(op)) => match op {
                        OP_CHECKSIG | OP_CHECKSIGVERIFY => 1,
                        OP_CHECKMULTISIG | OP_CHECKMULTISIGVERIFY => match last_opcode {
                            Some(opcode::PossiblyBad::Good(Opcode::PushValue(
                                opcode::PushValue::SmallValue(pv),
                            ))) if accurate && pv >= OP_1 && pv <= OP_16 => Self::decode_op_n(pv),
                            _ => u32::from(interpreter::MAX_PUBKEY_COUNT),
                        },
                        _ => 0,
                    },
                    _ => 0,
                }),
                (_, _) => Err(n),
            }) {
            Err(n) => n,
            Ok(n) => n,
        }
    }

    /// Returns true iff this script is P2SH.
    pub fn is_pay_to_script_hash(&self) -> bool {
        self.parse_strict(&interpreter::VerificationFlags::all())
            .collect::<Result<Vec<_>, _>>()
            .map_or(false, |ops| match &ops[..] {
                [ Opcode::Operation(OP_HASH160),
                  Opcode::PushValue(PushValue::LargeValue(PushdataBytelength(v))),
                  Opcode::Operation(OP_EQUAL)
                ] => v.len() == 0x14,
                _ => false
            })
    }

    /// Called by `IsStandardTx` and P2SH/BIP62 VerifyScript (which makes it consensus-critical).
    pub fn is_push_only(&self) -> bool {
        self.parse().all(|op| {
            matches!(
                op,
                // NB: The C++ impl only checks the push size during interpretation, so we need to
                //     pass this check for too-big `PushValue`s.
                Err(opcode::Error::PushSize(_))
                    | Ok(opcode::PossiblyBad::Good(Opcode::PushValue(_))
                        | opcode::PossiblyBad::Bad(opcode::Bad::OP_RESERVED))
            )
        })
    }
}

/// A script represented by two byte sequences – one is the sig, the other is the pubkey.
pub struct Raw<'a> {
    /// The script signature from the spending transaction.
    pub sig: Code<'a>,
    /// The script pubkey from the funding transaction.
    pub pub_key: Code<'a>,
}

impl<'a> Raw<'a> {
    /// Create a [`Raw`] script from the slices extracted from transactions.
    pub fn from_raw_parts(sig: &'a [u8], pub_key: &'a [u8]) -> Self {
        Raw {
            sig: Code(sig),
            pub_key: Code(pub_key),
        }
    }

    /// Apply a function to both components of a script, returning the tuple of results.
    pub fn map<T>(&self, f: &dyn Fn(&Code) -> T) -> (T, T) {
        (f(&self.sig), f(&self.pub_key))
    }

    /// Validate a [`Raw`] script.
    pub fn eval(
        &self,
        flags: interpreter::VerificationFlags,
        checker: &dyn interpreter::SignatureChecker,
    ) -> Result<bool, (ComponentType, Error)> {
        if flags.contains(interpreter::VerificationFlags::SigPushOnly) && !self.sig.is_push_only() {
            Err((ComponentType::Sig, Error::SigPushOnly))
        } else {
            let data_stack = self
                .sig
                .eval(flags, checker, interpreter::Stack::new())
                .map_err(|e| (ComponentType::Sig, e))?;
            let pub_key_stack = self
                .pub_key
                .eval(flags, checker, data_stack.clone())
                .map_err(|e| (ComponentType::PubKey, e))?;
            if pub_key_stack.last().is_ok_and(interpreter::cast_to_bool) {
                if flags.contains(interpreter::VerificationFlags::P2SH)
                    && self.pub_key.is_pay_to_script_hash()
                {
                    // script_sig must be literals-only or validation fails
                    if self.sig.is_push_only() {
                        data_stack
                            .split_last()
                            .map_err(|e| Error::Interpreter(None, e))
                            .and_then(|(pub_key_2, remaining_stack)| {
                                Code(pub_key_2).eval(flags, checker, remaining_stack)
                            })
                            .map(|p2sh_stack| {
                                if p2sh_stack.last().is_ok_and(interpreter::cast_to_bool) {
                                    Some(p2sh_stack)
                                } else {
                                    None
                                }
                            })
                            .map_err(|e| (ComponentType::Redeem, e))
                    } else {
                        Err((ComponentType::Sig, Error::SigPushOnly))
                    }
                } else {
                    Ok(Some(pub_key_stack))
                }
                .and_then(|mresult_stack| {
                    match mresult_stack {
                        None => Ok(false),
                        Some(result_stack) => {
                            // The CLEANSTACK check is only performed after potential P2SH evaluation, as the
                            // non-P2SH evaluation of a P2SH script will obviously not result in a clean stack
                            // (the P2SH inputs remain).
                            if flags.contains(interpreter::VerificationFlags::CleanStack) {
                                // Disallow CLEANSTACK without P2SH, because Bitcoin did.
                                assert!(flags.contains(interpreter::VerificationFlags::P2SH));
                                if result_stack.len() == 1 {
                                    Ok(true)
                                } else {
                                    Err((ComponentType::Redeem, Error::CleanStack))
                                }
                            } else {
                                Ok(true)
                            }
                        }
                    }
                })
            } else {
                Ok(false)
            }
        }
    }
}
