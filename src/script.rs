//! Managing sequences of opcodes.

use itertools::{Either, Itertools};
use thiserror::Error;

use crate::{
    interpreter,
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

    #[error("during interpretation: {0}")]
    Interpreter(interpreter::Error),

    /// A error external to the script validation code. This can come from the stepper.
    ///
    /// __TODO__: Replace the `str` with a type parameter, which will be `Void` in validation code,
    /// but can be different in the steppers.
    #[error("external error: {0}")]
    ExternalError(&'static str),

    #[error("clean stack requirement not met")]
    CleanStack,

    #[error("script evaluation failed")]
    EvalFalse,
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
            Self::Opcode(oerr) => match oerr {
                opcode::Error::ReadError { .. } => Self::from(interpreter::Error::BadOpcode(None)),
                opcode::Error::Disabled(_) => Self::AMBIGUOUS_COUNT_DISABLED,
            },
            Self::Interpreter(ierr) => match ierr {
                interpreter::Error::OpCount => Self::AMBIGUOUS_COUNT_DISABLED,
                interpreter::Error::InvalidStackOperation(Some(_)) => {
                    Self::from(interpreter::Error::InvalidStackOperation(None))
                }
                interpreter::Error::InvalidAltstackOperation(Some(_)) => {
                    Self::from(interpreter::Error::InvalidAltstackOperation(None))
                }
                interpreter::Error::SignatureEncoding(sig_err) => match sig_err {
                    signature::Error::SigHashType(Some(_)) => Self::from(interpreter::Error::from(
                        signature::Error::SigHashType(None),
                    )),
                    signature::Error::SigDER(Some(_)) => {
                        Self::from(interpreter::Error::from(signature::Error::SigDER(None)))
                    }
                    signature::Error::SigHighS => Self::AMBIGUOUS_UNKNOWN_NUM_HIGHS,
                    _ => self.clone(),
                },
                interpreter::Error::PushSize(Some(_)) => {
                    Self::from(interpreter::Error::PushSize(None))
                }
                interpreter::Error::StackSize(Some(_)) => {
                    Self::from(interpreter::Error::StackSize(None))
                }
                interpreter::Error::SigCount(Some(_)) => {
                    Self::from(interpreter::Error::SigCount(None))
                }
                interpreter::Error::PubKeyCount(Some(_)) => {
                    Self::from(interpreter::Error::PubKeyCount(None))
                }
                interpreter::Error::BadOpcode(Some(_)) => {
                    Self::from(interpreter::Error::BadOpcode(None))
                }
                interpreter::Error::Num(_) => Self::AMBIGUOUS_UNKNOWN_NUM_HIGHS,
                _ => self.clone(),
            },
            Self::ScriptSize(Some(_)) => Self::ScriptSize(None),
            _ => self.clone(),
        }
    }
}

impl From<opcode::Error> for Error {
    fn from(value: opcode::Error) -> Self {
        Error::Opcode(value)
    }
}

impl From<interpreter::Error> for Error {
    fn from(value: interpreter::Error) -> Self {
        Error::Interpreter(value)
    }
}

/// “Strict” scripts disallow [`Bad`] opcodes, and so we collect any bad opcodes that we find, so we
/// can report all of them, rather than just the first one.
pub enum StrictError {
    /// A script validation failure.
    Script(Error),
    /// All of the [`Bad`] opcodes we found.
    BadOpcodes(Vec<opcode::Bad>),
}

impl From<Error> for StrictError {
    fn from(value: Error) -> Self {
        StrictError::Script(value)
    }
}

/// Serialized script, used inside transaction inputs and outputs
#[derive(Clone, Debug)]
pub struct Code<'a>(pub &'a [u8]);

impl Code<'_> {
    /// Maximum script length in bytes
    pub const MAX_SIZE: usize = 10_000;

    /// Fails on all [`Bad`] opcodes, not just ones on active branches.
    pub fn parse_strict(&self) -> Result<Vec<Opcode>, StrictError> {
        self.parse()
            .map_err(StrictError::Script)
            .and_then(|script| {
                let (opcodes, bad_opcodes): (Vec<_>, Vec<_>) =
                    script.into_iter().partition_map(|pb| match pb {
                        opcode::PossiblyBad::Good(opcode) => Either::Left(opcode),
                        opcode::PossiblyBad::Bad(bad) => Either::Right(bad),
                    });
                if bad_opcodes.is_empty() {
                    Ok(opcodes)
                } else {
                    Err(StrictError::BadOpcodes(bad_opcodes))
                }
            })
    }

    /// Parse an entire script component.
    pub fn parse(&self) -> Result<Vec<opcode::PossiblyBad>, Error> {
        let mut pc = self.0;
        let mut result = vec![];
        while !pc.is_empty() {
            let opcode::Parsed {
                opcode,
                remaining_code,
            } = Opcode::parse(pc)?;
            pc = remaining_code;
            result.push(opcode)
        }
        Ok(result)
    }

    /// Convert a sequence of `Opcode`s to the bytes that would be included in a transaction.
    pub fn serialize(script: &[Opcode]) -> Vec<u8> {
        script.iter().flat_map(Vec::from).collect()
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
        let mut n = 0;
        let mut pc = self.0;
        let mut last_opcode = None;
        while !pc.is_empty() {
            let opcode::Parsed {
                opcode,
                remaining_code,
            } = match Opcode::parse(pc) {
                Ok(o) => o,
                // Stop counting when we get to an invalid opcode.
                Err(_) => break,
            };
            pc = remaining_code;
            if let opcode::PossiblyBad::Good(Opcode::Operation(op)) = opcode {
                n += match op {
                    OP_CHECKSIG | OP_CHECKSIGVERIFY => 1,
                    OP_CHECKMULTISIG | OP_CHECKMULTISIGVERIFY => match last_opcode {
                        Some(opcode::PossiblyBad::Good(Opcode::PushValue(
                            opcode::PushValue::SmallValue(pv),
                        ))) => {
                            if accurate && pv >= OP_1 && pv <= OP_16 {
                                Self::decode_op_n(pv)
                            } else {
                                20
                            }
                        }
                        _ => 20,
                    },
                    _ => 0,
                };
            }
            last_opcode = Some(opcode);
        }
        n
    }

    /// Returns true iff this script is P2SH.
    pub fn is_pay_to_script_hash(&self) -> bool {
        self.parse_strict().map_or(false, |ops| match &ops[..] {
            [ Opcode::Operation(OP_HASH160),
              Opcode::PushValue(PushValue::LargeValue(PushdataBytelength(v))),
              Opcode::Operation(OP_EQUAL)
            ] => v.len() == 0x14,
            _ => false
        })
    }

    /// Called by `IsStandardTx` and P2SH/BIP62 VerifyScript (which makes it consensus-critical).
    pub fn is_push_only(&self) -> bool {
        self.parse().map_or(false, |op| {
            op.iter().all(|op| {
                matches!(
                    op,
                    opcode::PossiblyBad::Good(Opcode::PushValue(_))
                        | opcode::PossiblyBad::Bad(opcode::Bad::OP_RESERVED)
                )
            })
        })
    }
}
