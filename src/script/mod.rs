use enum_primitive::FromPrimitive;

use crate::{
    opcode::{
        operation::Normal::*,
        push_value::{
            LargeValue::{self, *},
            SmallValue::{self, *},
        },
        Opcode, Operation, PushValue,
    },
    script_error::ScriptError,
};

pub(crate) mod num;

/// Maximum script length in bytes
pub const MAX_SIZE: usize = 10_000;

/** Serialized script, used inside transaction inputs and outputs */
#[derive(Clone, Debug)]
pub struct Script<'a>(pub &'a [u8]);

impl Script<'_> {
    pub fn parse(&self) -> Result<Vec<Opcode>, ScriptError> {
        let mut pc = self.0;
        let mut result = vec![];
        while !pc.is_empty() {
            Self::get_op(pc).map(|(op, new_pc)| {
                pc = new_pc;
                result.push(op)
            })?;
        }
        Ok(result)
    }

    fn split_value(script: &[u8], needed_bytes: usize) -> Result<(&[u8], &[u8]), ScriptError> {
        script
            .split_at_checked(needed_bytes)
            .ok_or(ScriptError::ReadError {
                expected_bytes: needed_bytes,
                available_bytes: script.len(),
            })
    }

    /// First splits `size_size` bytes to determine the size of the value to read, then splits the
    /// value.
    fn split_tagged_value(script: &[u8], size_size: usize) -> Result<(&[u8], &[u8]), ScriptError> {
        Script::split_value(script, size_size).and_then(|(bytes, script)| {
            let mut size = 0;
            for byte in bytes.iter().rev() {
                size <<= 8;
                size |= usize::from(*byte);
            }
            Script::split_value(script, size)
        })
    }

    pub fn get_lv(script: &[u8]) -> Result<Option<(LargeValue, &[u8])>, ScriptError> {
        match script.split_first() {
            None => Err(ScriptError::ReadError {
                expected_bytes: 1,
                available_bytes: 0,
            }),
            Some((leading_byte, script)) => match leading_byte {
                0x4c => Self::split_tagged_value(script, 1)
                    .map(|(v, script)| Some((OP_PUSHDATA1(v.to_vec()), script))),
                0x4d => Self::split_tagged_value(script, 2)
                    .map(|(v, script)| Some((OP_PUSHDATA2(v.to_vec()), script))),
                0x4e => Self::split_tagged_value(script, 4)
                    .map(|(v, script)| Some((OP_PUSHDATA4(v.to_vec()), script))),
                _ => {
                    if 0x01 <= *leading_byte && *leading_byte < 0x4c {
                        Self::split_value(script, (*leading_byte).into())
                            .map(|(v, script)| Some((PushdataBytelength(v.to_vec()), script)))
                    } else {
                        Ok(None)
                    }
                }
            },
        }
    }

    pub fn get_op(script: &[u8]) -> Result<(Opcode, &[u8]), ScriptError> {
        Self::get_lv(script).and_then(|r| {
            r.map_or(
                match script.split_first() {
                    None => Err(ScriptError::ReadError {
                        expected_bytes: 1,
                        available_bytes: 0,
                    }),
                    Some((leading_byte, script)) => Ok((
                        SmallValue::from_u8(*leading_byte)
                            .map_or(Opcode::Operation(Operation::from(*leading_byte)), |sv| {
                                Opcode::PushValue(PushValue::SmallValue(sv))
                            }),
                        script,
                    )),
                },
                |(v, script)| Ok((Opcode::PushValue(PushValue::LargeValue(v)), script)),
            )
        })
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
            let (opcode, new_pc) = match Self::get_op(pc) {
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
            if let Ok((Opcode::PushValue(_), new_pc)) = Self::get_op(pc) {
                pc = new_pc;
            } else {
                return false;
            }
        }
        true
    }
}
