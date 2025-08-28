//! Managing sequences of opcodes.

use itertools::{Either, Itertools};

use crate::{
    opcode::{
        self,
        push_value::{
            LargeValue::*,
            SmallValue::{self, *},
        },
        Operation::*,
        PushValue,
    },
    script_error::ScriptError,
    Opcode,
};

/// “Strict” scripts disallow [`Bad`] opcodes, and so we collect any bad opcodes that we find, so we
/// can report all of them, rather than just the first one.
pub enum StrictError {
    /// A script validation failure.
    Script(ScriptError),
    /// All of the [`Bad`] opcodes we found.
    BadOpcodes(Vec<opcode::Bad>),
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
    pub fn parse(&self) -> Result<Vec<opcode::PossiblyBad>, ScriptError> {
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
                            PushValue::SmallValue(pv),
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
