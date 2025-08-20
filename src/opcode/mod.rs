use std::fmt::Display;

use serde::{Deserialize, Serialize};

use crate::{interpreter::*, script};
pub use operation::*;
pub use push_value::*;

mod operation;
pub mod push_value;

/** Script opcodes */
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Deserialize, Serialize)]
pub enum Opcode {
    /// - only type allowed in v5+ script_sigs
    /// - don’t count toward `op_count`
    PushValue(PushValue),
    /// - represented by a single byte
    /// - count toward `op_count``
    Operation(Operation),
}

impl Opcode {
    pub fn well_formed(
        &self,
        flags: VerificationFlags,
        op_count: &mut u8,
        vexec: &mut Stack<bool>,
    ) -> Result<(), script::Error> {
        match self {
            Opcode::PushValue(pv) => {
                if pv.value().map_or(0, |v| v.len()) <= push_value::MAX_SIZE {
                    pv.well_formed(flags.contains(VerificationFlags::MinimalData))
                } else {
                    Err(script::Error::PushSize(None))
                }
            }
            Opcode::Operation(op) => op.well_formed(flags, op_count, vexec),
        }
    }
}

impl Evaluable for Opcode {
    fn byte_len(&self) -> usize {
        match self {
            Opcode::PushValue(pv) => pv.byte_len(),
            Opcode::Operation(_) => 1,
        }
    }

    /// Run a single step of the interpreter.
    ///
    /// This is useful for testing & debugging, as we can set up the exact state we want in order to
    /// trigger some behavior.
    fn eval(
        &self,
        flags: VerificationFlags,
        script: &[u8],
        checker: &dyn SignatureChecker,
        state: &mut State,
    ) -> Result<(), script::Error> {
        match self {
            Opcode::PushValue(pv) => {
                if pv.value().map_or(0, |v| v.len()) <= push_value::MAX_SIZE {
                    if should_exec(&state.vexec) {
                        pv.eval(flags, script, checker, state)
                    } else {
                        Ok(())
                    }
                } else {
                    Err(script::Error::PushSize(None))
                }
            }
            Opcode::Operation(op) => op.eval(flags, script, checker, state),
        }
    }
}

impl script::Parsable for Opcode {
    fn to_bytes(&self) -> Vec<u8> {
        match self {
            Opcode::PushValue(v) => v.to_bytes(),
            Opcode::Operation(v) => v.to_bytes(),
        }
    }

    fn from_bytes(script: &[u8]) -> Result<(Self, &[u8]), script::Error> {
        PushValue::from_bytes(script)
            .map(|(pv, rem)| (Opcode::PushValue(pv), rem))
            .or_else(|err| match err {
                script::Error::SigPushOnly => {
                    Operation::from_bytes(script).map(|(op, rem)| (Opcode::Operation(op), rem))
                }
                _ => Err(err),
            })
    }
}

impl Display for Opcode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Opcode::PushValue(pv) => write!(f, "{}", pv),
            Opcode::Operation(op) => write!(f, "{}", op),
        }
    }
}
