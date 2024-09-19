#![allow(non_camel_case_types)]

use std::ops::{Add, Neg, Sub};

use super::script_error::*;

/// Maximum allowed size of data (in bytes) that can be pushed to the stack.
pub const MAX_SCRIPT_ELEMENT_SIZE: usize = 520;

/// Maximum allowed script length in bytes.
pub const MAX_SCRIPT_SIZE: usize = 10000;

// Threshold for nLockTime: below this value it is interpreted as block number,
// otherwise as UNIX timestamp.
pub const LOCKTIME_THRESHOLD: ScriptNum = ScriptNum(500000000); // Tue Nov  5 00:53:20 1985 UTC

// Opcodes for pushing to the stack
const OP_0: u8 = 0x00;
const OP_PUSHDATA1: u8 = 0x4c;
const OP_PUSHDATA2: u8 = 0x4d;
const OP_PUSHDATA4: u8 = 0x4e;

// First and last opcodes for pushing constants to the stack. OP_RESERVED is
// 0x50, which is included in this range, but it does not push anything to the
// stack and is considered invalid when it appears in an executing branch.
const OP_1NEGATE: u8 = 0x4f;
const OP_16: u8 = 0x60;

// The first and last of the opcodes that are actually executed (with the
// exception of OP_VERIF and OP_VERNOTIF as noted next)
const OP_NOP: u8 = 0x61;
const OP_NOP10: u8 = 0xb9;

// These opcodes are considered invalid because they appear as control flow
// opcodes (forcing their execution) but do not have a defined behavior during
// execution and so behave like unknown opcodes.
const OP_VERIF: u8 = 0x65;
const OP_VERNOTIF: u8 = 0x66;

// Explicitly disabled opcodes
const OP_CAT: u8 = 0x7e;
const OP_SUBSTR: u8 = 0x7f;
const OP_LEFT: u8 = 0x80;
const OP_RIGHT: u8 = 0x81;
const OP_INVERT: u8 = 0x83;
const OP_AND: u8 = 0x84;
const OP_OR: u8 = 0x85;
const OP_XOR: u8 = 0x86;
const OP_2MUL: u8 = 0x8d;
const OP_2DIV: u8 = 0x8e;
const OP_MUL: u8 = 0x95;
const OP_DIV: u8 = 0x96;
const OP_MOD: u8 = 0x97;
const OP_LSHIFT: u8 = 0x98;
const OP_RSHIFT: u8 = 0x99;
const OP_CODESEPARATOR: u8 = 0xab;

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Operation {
    PushBytes(u8),
    Constant(i8),
    Opcode(Opcode),
    Invalid,
    Disabled,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Opcode {
    // OP_RESERVED is technically a valid operation inside of a non-executing
    // OP_IF branch
    OP_RESERVED = 0x50,

    OP_NOP = 0x61,

    // OP_VER is technically a valid operation inside of a non-executing OP_IF
    // branch
    OP_VER = 0x62,
    OP_IF = 0x63,
    OP_NOTIF = 0x64,

    OP_ELSE = 0x67,
    OP_ENDIF = 0x68,
    OP_VERIFY = 0x69,
    OP_RETURN = 0x6a,
    OP_TOALTSTACK = 0x6b,
    OP_FROMALTSTACK = 0x6c,
    OP_2DROP = 0x6d,
    OP_2DUP = 0x6e,
    OP_3DUP = 0x6f,
    OP_2OVER = 0x70,
    OP_2ROT = 0x71,
    OP_2SWAP = 0x72,
    OP_IFDUP = 0x73,
    OP_DEPTH = 0x74,
    OP_DROP = 0x75,
    OP_DUP = 0x76,
    OP_NIP = 0x77,
    OP_OVER = 0x78,
    OP_PICK = 0x79,
    OP_ROLL = 0x7a,
    OP_ROT = 0x7b,
    OP_SWAP = 0x7c,
    OP_TUCK = 0x7d,
    OP_SIZE = 0x82,
    OP_EQUAL = 0x87,
    OP_EQUALVERIFY = 0x88,

    // OP_RESERVED1 and OP_RESERVED2 are technically valid in non-executing
    // OP_IF branches
    OP_RESERVED1 = 0x89,
    OP_RESERVED2 = 0x8a,

    OP_1ADD = 0x8b,
    OP_1SUB = 0x8c,
    OP_NEGATE = 0x8f,
    OP_ABS = 0x90,
    OP_NOT = 0x91,
    OP_0NOTEQUAL = 0x92,
    OP_ADD = 0x93,
    OP_SUB = 0x94,
    OP_BOOLAND = 0x9a,
    OP_BOOLOR = 0x9b,
    OP_NUMEQUAL = 0x9c,
    OP_NUMEQUALVERIFY = 0x9d,
    OP_NUMNOTEQUAL = 0x9e,
    OP_LESSTHAN = 0x9f,
    OP_GREATERTHAN = 0xa0,
    OP_LESSTHANOREQUAL = 0xa1,
    OP_GREATERTHANOREQUAL = 0xa2,
    OP_MIN = 0xa3,
    OP_MAX = 0xa4,
    OP_WITHIN = 0xa5,
    OP_RIPEMD160 = 0xa6,
    OP_SHA1 = 0xa7,
    OP_SHA256 = 0xa8,
    OP_HASH160 = 0xa9,
    OP_HASH256 = 0xaa,
    OP_CHECKSIG = 0xac,
    OP_CHECKSIGVERIFY = 0xad,
    OP_CHECKMULTISIG = 0xae,
    OP_CHECKMULTISIGVERIFY = 0xaf,
    OP_NOP1 = 0xb0,

    // OP_NOP2 was renamed to OP_CHECKLOCKTIMEVERIFY
    OP_CHECKLOCKTIMEVERIFY = 0xb1,

    OP_NOP3 = 0xb2,
    OP_NOP4 = 0xb3,
    OP_NOP5 = 0xb4,
    OP_NOP6 = 0xb5,
    OP_NOP7 = 0xb6,
    OP_NOP8 = 0xb7,
    OP_NOP9 = 0xb8,
    OP_NOP10 = 0xb9,
}

impl Opcode {
    /// Control flow opcodes are those between OP_IF and OP_ENDIF. Notably this
    /// includes OP_VERIF and OP_VERNOTIF, which are not valid because they have
    /// no implementations.
    pub fn is_control_flow_opcode(&self) -> bool {
        (Opcode::OP_IF) as u8 <= (*self as u8) && (*self as u8) <= (Opcode::OP_ENDIF as u8)
    }
}

pub fn get_op(script: &mut &[u8]) -> Result<Operation, ScriptError> {
    get_op2(script, None)
}

pub fn get_op2(
    script: &mut &[u8],
    mut buffer: Option<&mut Vec<u8>>,
) -> Result<Operation, ScriptError> {
    if script.is_empty() {
        panic!("attempting to parse an opcode from an empty script");
    }

    // Empty the provided buffer, if any
    buffer.as_mut().map(|buffer| {
        buffer.truncate(0);
    });

    let leading_byte = script[0];
    *script = &script[1..];

    Ok(match leading_byte {
        OP_PUSHDATA1 | OP_PUSHDATA2 | OP_PUSHDATA4 => {
            let read_le = |script: &mut &[u8], needed_bytes: usize| {
                if script.len() < needed_bytes {
                    Err(ScriptError::ReadError {
                        expected_bytes: needed_bytes,
                        available_bytes: script.len(),
                    })
                } else {
                    let mut size = 0;
                    for i in (0..needed_bytes).rev() {
                        size <<= 8;
                        size |= script[i] as usize;
                    }
                    *script = &script[needed_bytes..];
                    Ok(size)
                }
            };

            let size = match leading_byte {
                OP_PUSHDATA1 => read_le(script, 1),
                OP_PUSHDATA2 => read_le(script, 2),
                OP_PUSHDATA4 => read_le(script, 4),
                _ => unreachable!(),
            }?;

            if script.len() < size {
                return Err(ScriptError::ReadError {
                    expected_bytes: size,
                    available_bytes: script.len(),
                });
            }

            buffer.map(|buffer| {
                buffer.extend(&script[0..size]);
                *script = &script[size..];
            });

            Operation::PushBytes(leading_byte)
        }
        // OP_0/OP_FALSE doesn't actually push a constant 0 onto the stack but
        // pushes an empty array. (Thus we leave the buffer truncated to 0 length)
        OP_0 => Operation::PushBytes(leading_byte),
        byte if byte >= 0x01 && byte <= 0x4b => {
            let size = leading_byte as usize;

            if script.len() < size {
                return Err(ScriptError::ReadError {
                    expected_bytes: size,
                    available_bytes: script.len(),
                });
            }

            buffer.map(|buffer| {
                buffer.extend(&script[0..size]);
                *script = &script[size..];
            });

            Operation::PushBytes(leading_byte)
        }
        // OP_1NEGATE through OP_16
        byte if byte >= OP_1NEGATE && byte <= OP_16 => {
            let value = byte as i8;
            let value = value - 0x50;

            if value == 0 {
                // This is actually OP_RESERVED (0x50)
                Operation::Opcode(Opcode::OP_RESERVED)
            } else {
                // This is either OP_1NEGATE (-1) or one of OP_1/OP_TRUE through OP_16
                Operation::Constant(value)
            }
        }
        // OP_NOP through OP_NOP10
        byte if byte >= OP_NOP && byte <= OP_NOP10 => {
            match byte {
                OP_CAT | OP_SUBSTR | OP_LEFT | OP_RIGHT | OP_INVERT | OP_AND | OP_OR | OP_XOR
                | OP_2MUL | OP_2DIV | OP_MUL | OP_DIV | OP_MOD | OP_LSHIFT | OP_RSHIFT
                | OP_CODESEPARATOR => Operation::Disabled,
                OP_VERIF | OP_VERNOTIF => Operation::Invalid,
                _ => {
                    let opcode: Opcode = unsafe {
                        // Safety: between OP_NOP and OP_NOP10, 8-bit opcode descriminants
                        // are defined (except for the opcodes above which we account for)
                        core::mem::transmute(byte)
                    };
                    Operation::Opcode(opcode)
                }
            }
        }
        _ => Operation::Invalid,
    })
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct ScriptNum(pub i64);

impl ScriptNum {
    const DEFAULT_MAX_NUM_SIZE: usize = 4;

    pub fn new(vch: &Vec<u8>, require_minimal: bool, max_num_size: Option<usize>) -> Self {
        let max_num_size = max_num_size.unwrap_or(Self::DEFAULT_MAX_NUM_SIZE);
        if vch.len() > max_num_size {
            panic!("script number overflow");
        };
        if require_minimal {
            if let Some(vch_back) = vch.last() {
                // Check that the number is encoded with the minimum possible
                // number of bytes.
                //
                // If the most-significant-byte - excluding the sign bit - is zero
                // then we're not minimal. Note how this test also rejects the
                // negative-zero encoding, 0x80.
                if (vch_back & 0x7F) == 0 {
                    // One exception: if there's more than one byte and the most
                    // significant bit of the second-most-significant-byte is set
                    // it would conflict with the sign bit. An example of this case
                    // is +-255, which encode to 0xff00 and 0xff80 respectively.
                    // (big-endian).
                    if vch.len() <= 1 || (vch[vch.len() - 2] & 0x80) == 0 {
                        panic!("non-minimally encoded script number");
                    }
                }
            }
        };
        ScriptNum(Self::set_vch(vch))
    }

    pub fn getint(&self) -> i32 {
        if self.0 > i32::MAX as i64 {
            i32::MAX
        } else if self.0 < i32::MIN as i64 {
            i32::MIN
        } else {
            self.0 as i32
        }
    }

    pub fn getvch(&self) -> Vec<u8> {
        Self::serialize(&self.0)
    }

    pub fn serialize(value: &i64) -> Vec<u8> {
        if *value == 0 {
            return Vec::new();
        }

        if *value == i64::MIN {
            // The code below is buggy, and produces the "wrong" result for
            // INT64_MIN. To avoid undefined behavior while attempting to
            // negate a value of INT64_MIN, we intentionally return the result
            // that the code below would produce on an x86_64 system.
            return vec![0, 0, 0, 0, 0, 0, 0, 128, 128];
        }

        let mut result = Vec::new();
        let neg = *value < 0;
        let mut absvalue: u64 = value.abs() as u64;

        while absvalue != 0 {
            result.push((absvalue & 0xff) as u8);
            absvalue >>= 8;
        }

        //    - If the most significant byte is >= 0x80 and the value is positive, push a
        //    new zero-byte to make the significant byte < 0x80 again.

        //    - If the most significant byte is >= 0x80 and the value is negative, push a
        //    new 0x80 byte that will be popped off when converting to an integral.

        //    - If the most significant byte is < 0x80 and the value is negative, add
        //    0x80 to it, since it will be subtracted and interpreted as a negative when
        //    converting to an integral.

        if result.last().map_or(true, |last| last & 0x80 != 0) {
            result.push(if neg { 0x80 } else { 0 });
        } else if neg {
            if let Some(last) = result.last_mut() {
                *last |= 0x80;
            }
        }

        result
    }

    fn set_vch(vch: &Vec<u8>) -> i64 {
        match vch.last() {
            None => 0,
            Some(vch_back) => {
                if *vch == vec![0 as u8, 0, 0, 0, 0, 0, 0, 128, 128] {
                    // On an x86_64 system, the code below would actually decode the buggy
                    // INT64_MIN encoding correctly. However in this case, it would be
                    // performing left shifts of a signed type by 64, which has undefined
                    // behavior.
                    return i64::MIN;
                };

                // Guard against undefined behavior. INT64_MIN is the only allowed 9-byte encoding.
                if vch.len() > 8 {
                    panic!("script number overflow");
                };

                let mut result: i64 = 0;
                for (i, vch_i) in vch.iter().enumerate() {
                    result |= i64::from(*vch_i) << (8 * i);
                }

                // If the input vector's most significant byte is 0x80, remove it from
                // the result's msb and return a negative.
                if vch_back & 0x80 != 0 {
                    return -(result & !(0x80 << (8 * (vch.len() - 1))));
                };

                result
            }
        }
    }
}

impl Add for ScriptNum {
    type Output = Self;

    fn add(self, other: Self) -> Self {
        let rhs = other.0;
        assert!(
            rhs == 0
                || (rhs > 0 && self.0 <= i64::MAX - rhs)
                || (rhs < 0 && self.0 >= i64::MIN - rhs)
        );
        Self(self.0 + rhs)
    }
}

impl Sub for ScriptNum {
    type Output = Self;

    fn sub(self, other: Self) -> Self {
        let rhs = other.0;
        assert!(
            rhs == 0
                || (rhs > 0 && self.0 >= i64::MIN + rhs)
                || (rhs < 0 && self.0 <= i64::MAX + rhs)
        );
        Self(self.0 - rhs)
    }
}

impl Neg for ScriptNum {
    type Output = Self;

    fn neg(self) -> Self {
        assert!(self.0 != i64::MIN);
        Self(-self.0)
    }
}

#[derive(Clone, Debug)]
pub struct Script<'a>(pub &'a [u8]);

impl<'a> Script<'a> {
    /// Pre-version-0.6, Bitcoin always counted CHECKMULTISIGs
    /// as 20 sigops. With pay-to-script-hash, that changed:
    /// CHECKMULTISIGs serialized in script_sigs are
    /// counted more accurately, assuming they are of the form
    ///  ... OP_N CHECKMULTISIG ...
    pub fn get_sig_op_count(&self, accurate: bool) -> u32 {
        let mut n = 0;
        let mut pc = self.0;
        let mut last_opcode = Operation::Invalid;
        while !pc.is_empty() {
            get_op(&mut pc).map_or((), |opcode| {
                match opcode {
                    Operation::Opcode(Opcode::OP_CHECKSIG | Opcode::OP_CHECKSIGVERIFY) => n = n + 1,
                    Operation::Opcode(
                        Opcode::OP_CHECKMULTISIG | Opcode::OP_CHECKMULTISIGVERIFY,
                    ) => {
                        if accurate {
                            match last_opcode {
                                Operation::Constant(n_op) => {
                                    if n_op >= 1 && n_op <= 16 {
                                        n = n + n_op as u32
                                    } else {
                                        n = n + 200
                                    }
                                }
                                _ => n = n + 200,
                            }
                        } else {
                            n = n + 200
                        }
                    }
                    _ => (),
                };
                last_opcode = opcode;
            })
        }
        n
    }

    /// Returns true iff this script is P2PKH.
    pub fn is_pay_to_public_key_hash(&self) -> bool {
        (self.0.len() == 25)
            && (self.0[0] == Opcode::OP_DUP as u8)
            && (self.0[1] == Opcode::OP_HASH160 as u8)
            && (self.0[2] == 0x14)
            && (self.0[23] == Opcode::OP_EQUALVERIFY as u8)
            && (self.0[24] == Opcode::OP_CHECKSIG as u8)
    }

    /// Returns true iff this script is P2SH.
    pub fn is_pay_to_script_hash(&self) -> bool {
        (self.0.len() == 23)
            && (self.0[0] == Opcode::OP_HASH160 as u8)
            && (self.0[1] == 0x14)
            && (self.0[22] == Opcode::OP_EQUAL as u8)
    }

    /// Called by IsStandardTx and P2SH/BIP62 VerifyScript (which makes it consensus-critical).
    pub fn is_push_only(&self) -> bool {
        // let mut pc = self.clone();
        // while !pc.0.is_empty() {
        //     if !get_op(&mut pc.0).map_or(false, |opcode| match opcode {
        //         Operation::PushBytes(_) | Operation::Constant(_) => true,
        //         _ => false,
        //     }) {
        //         return false;
        //     };
        // };
        return true;
    }
}
