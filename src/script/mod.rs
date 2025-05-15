//! Managing sequences of opcodes.

use std::num::TryFromIntError;

use serde::{Deserialize, Serialize};

use crate::{
    interpreter,
    opcode::{
        self,
        operation::Operation::*,
        push_value::{
            LargeValue::PushdataBytelength,
            SmallValue::{self, *},
        },
        Opcode, PushValue,
    },
};

pub(crate) mod num;

/// All errors that can happen with a script. This includes both errors during parsing and
/// interpretation.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// A error external to the script validation code. This can come from the stepper.
    ///
    /// __TODO__: Replace the `str` with a type parameter, which will be `Void` in validation code,
    /// but can be different in the steppers.
    ExternalError(&'static str),
    /// The serialized length of the script is > `MAX_SIZE` bytes
    ScriptSize(Option<TryFromIntError>),
    /// Inherit the errors that can occur when reading opcodes.
    Opcode(opcode::Error),
    /// A scriptSig contains non-`PushValue` opcodes.
    SigPushOnly,
    /// Inherit the errors that happen during interpretation.
    Interpreter(interpreter::Error),
    /// The stack didn’t contain exactly one value.
    CleanStack,
    /// After interpretation, the stack was empty or had a false value on top.
    EvalFalse,
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

/// Maximum script length in bytes
pub const MAX_SIZE: usize = 10_000;

/// Serialized script, used inside transaction inputs and outputs
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Script<'a>(pub &'a [u8]);

impl Script<'_> {
    /// This parses an entire script. This is stricter than the incremental parsing that is done
    /// during `verify_script`, because it fails on unknown opcodes no matter where they occur.
    /// I.e., this is useful for validating and analyzing scripts before they are put into a
    /// transaction, but not for scripts that are read from the chain, because it may fail on valid
    /// scripts.
    pub fn parse(&self) -> Result<Vec<Opcode>, Error> {
        let mut pc = self.0;
        let mut result = vec![];
        while !pc.is_empty() {
            opcode::parse(pc)
                .map_err(Error::Opcode)
                .and_then(|(op, new_pc)| {
                    pc = new_pc;
                    op.map_err(|byte| interpreter::Error::BadOpcode(Some(byte)).into())
                        .map(|op| result.push(op))
                })?;
        }
        Ok(result)
    }

    /// Convert a sequence of `Opcode`s to the bytes that would be included in a transaction.
    pub fn serialize(script: &[Opcode]) -> Vec<u8> {
        script
            .iter()
            .fold(Vec::new(), |acc, op| [acc, op.into()].concat())
    }

    /// Encode/decode small integers:
    pub fn decode_op_n(opcode: SmallValue) -> u32 {
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
            let (opcode, new_pc) = match opcode::parse(pc) {
                Ok(o) => o,
                // Stop counting when we get to an invalid opcode.
                Err(_) => break,
            };
            pc = new_pc;
            if let Ok(Opcode::Operation(op)) = opcode {
                if op == OP_CHECKSIG || op == OP_CHECKSIGVERIFY {
                    n += 1;
                } else if op == OP_CHECKMULTISIG || op == OP_CHECKMULTISIGVERIFY {
                    match last_opcode {
                        Some(Opcode::PushValue(PushValue::SmallValue(pv))) => {
                            if accurate && pv >= OP_1 && pv <= OP_16 {
                                n += Self::decode_op_n(pv);
                            } else {
                                n += 20
                            }
                        }
                        _ => n += 20,
                    }
                }
            }
            last_opcode = opcode.ok();
        }
        n
    }

    /// Returns true iff this script is P2SH.
    pub fn is_pay_to_script_hash(&self) -> bool {
        self.parse().map_or(false, |ops| match &ops[..] {
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
            op.iter().all(|op| matches!(op, Opcode::PushValue(_)))
        })
    }
}
