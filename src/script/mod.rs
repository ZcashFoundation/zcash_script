use std::num::TryFromIntError;

use serde::{Deserialize, Serialize};

use crate::{
    interpreter,
    opcode::{
        self,
        operation::Normal::*,
        push_value::{
            LargeValue::PushdataBytelength,
            SmallValue::{self, *},
        },
        Opcode, Operation, PushValue,
    },
};

pub(crate) mod num;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Error {
    UnknownError,
    ScriptSize(Option<TryFromIntError>),
    Opcode(opcode::Error),
    SigPushOnly,
    Interpreter(interpreter::Error),
    CleanStack,
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

/** Serialized script, used inside transaction inputs and outputs */
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Script<'a>(pub &'a [u8]);

impl Script<'_> {
    pub fn parse(&self) -> Result<Vec<Opcode>, opcode::Error> {
        let mut pc = self.0;
        let mut result = vec![];
        while !pc.is_empty() {
            opcode::parse(pc).map(|(op, new_pc)| {
                pc = new_pc;
                result.push(op)
            })?;
        }
        Ok(result)
    }

    pub fn serialize(script: &[Opcode]) -> Vec<u8> {
        script
            .iter()
            .fold(Vec::new(), |acc, op| [acc, op.into()].concat())
    }

    /** Encode/decode small integers: */
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
            if let Opcode::Operation(Operation::Normal(op)) = opcode {
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
            last_opcode = Some(opcode);
        }
        n
    }

    /// Returns true iff this script is P2SH.
    pub fn is_pay_to_script_hash(&self) -> bool {
        self.parse().map_or(false, |ops| match &ops[..] {
            [ Opcode::Operation(Operation::Normal(OP_HASH160)),
              Opcode::PushValue(PushValue::LargeValue(PushdataBytelength(v))),
              Opcode::Operation(Operation::Normal(OP_EQUAL))
            ] => v.len() == 0x14,
            _ => false
        })
    }

    /// Called by `IsStandardTx` and P2SH/BIP62 VerifyScript (which makes it consensus-critical).
    pub fn is_push_only(&self) -> bool {
        let mut pc = self.0;
        while !pc.is_empty() {
            if let Ok((Opcode::PushValue(_), new_pc)) = opcode::parse(pc) {
                pc = new_pc;
            } else {
                return false;
            }
        }
        true
    }
}
