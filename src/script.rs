#![allow(non_camel_case_types)]

use std::{
    num::TryFromIntError,
    ops::{Add, Neg, Sub},
};

use enum_primitive::FromPrimitive;

use super::script_error::*;

pub const MAX_SCRIPT_ELEMENT_SIZE: usize = 520; // bytes

/// Maximum script length in bytes
pub const MAX_SCRIPT_SIZE: usize = 10000;

// Threshold for lock_time: below this value it is interpreted as block number,
// otherwise as UNIX timestamp.
pub const LOCKTIME_THRESHOLD: ScriptNum = ScriptNum(500000000); // Tue Nov  5 00:53:20 1985 UTC

/** Script opcodes */
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Opcode {
    PushValue(PushValue),
    Operation(Operation),
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
#[repr(u8)]
pub enum PushValue {
    // push value
    OP_0 = 0x00,
    PushdataBytelength(u8),
    OP_PUSHDATA1 = 0x4c,
    OP_PUSHDATA2 = 0x4d,
    OP_PUSHDATA4 = 0x4e,
    OP_1NEGATE = 0x4f,
    OP_RESERVED = 0x50,
    OP_1 = 0x51,
    OP_2 = 0x52,
    OP_3 = 0x53,
    OP_4 = 0x54,
    OP_5 = 0x55,
    OP_6 = 0x56,
    OP_7 = 0x57,
    OP_8 = 0x58,
    OP_9 = 0x59,
    OP_10 = 0x5a,
    OP_11 = 0x5b,
    OP_12 = 0x5c,
    OP_13 = 0x5d,
    OP_14 = 0x5e,
    OP_15 = 0x5f,
    OP_16 = 0x60,
}

use PushValue::*;

enum_from_primitive! {
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
#[repr(u8)]
pub enum Operation {
    // control
    OP_NOP = 0x61,
    OP_VER = 0x62,
    OP_IF = 0x63,
    OP_NOTIF = 0x64,
    OP_VERIF = 0x65,
    OP_VERNOTIF = 0x66,
    OP_ELSE = 0x67,
    OP_ENDIF = 0x68,
    OP_VERIFY = 0x69,
    OP_RETURN = 0x6a,

    // stack ops
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

    // splice ops
    OP_CAT = 0x7e,
    OP_SUBSTR = 0x7f,
    OP_LEFT = 0x80,
    OP_RIGHT = 0x81,
    OP_SIZE = 0x82,

    // bit logic
    OP_INVERT = 0x83,
    OP_AND = 0x84,
    OP_OR = 0x85,
    OP_XOR = 0x86,
    OP_EQUAL = 0x87,
    OP_EQUALVERIFY = 0x88,
    OP_RESERVED1 = 0x89,
    OP_RESERVED2 = 0x8a,

    // numeric
    OP_1ADD = 0x8b,
    OP_1SUB = 0x8c,
    OP_2MUL = 0x8d,
    OP_2DIV = 0x8e,
    OP_NEGATE = 0x8f,
    OP_ABS = 0x90,
    OP_NOT = 0x91,
    OP_0NOTEQUAL = 0x92,

    OP_ADD = 0x93,
    OP_SUB = 0x94,
    OP_MUL = 0x95,
    OP_DIV = 0x96,
    OP_MOD = 0x97,
    OP_LSHIFT = 0x98,
    OP_RSHIFT = 0x99,

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

    // crypto
    OP_RIPEMD160 = 0xa6,
    OP_SHA1 = 0xa7,
    OP_SHA256 = 0xa8,
    OP_HASH160 = 0xa9,
    OP_HASH256 = 0xaa,
    OP_CODESEPARATOR = 0xab,
    OP_CHECKSIG = 0xac,
    OP_CHECKSIGVERIFY = 0xad,
    OP_CHECKMULTISIG = 0xae,
    OP_CHECKMULTISIGVERIFY = 0xaf,

    // expansion
    OP_NOP1 = 0xb0,
    OP_NOP2 = 0xb1,
    OP_NOP3 = 0xb2,
    OP_NOP4 = 0xb3,
    OP_NOP5 = 0xb4,
    OP_NOP6 = 0xb5,
    OP_NOP7 = 0xb6,
    OP_NOP8 = 0xb7,
    OP_NOP9 = 0xb8,
    OP_NOP10 = 0xb9,

    OP_INVALIDOPCODE = 0xff,
}
}

use Operation::*;

pub const OP_CHECKLOCKTIMEVERIFY: Operation = OP_NOP2;

impl From<Opcode> for u8 {
    fn from(value: Opcode) -> Self {
        match value {
            Opcode::PushValue(pv) => pv.into(),
            Opcode::Operation(op) => op.into(),
        }
    }
}

impl From<u8> for Opcode {
    fn from(value: u8) -> Self {
        Operation::from_u8(value).map_or(
            PushValue::try_from(value)
                .map_or(Opcode::Operation(OP_INVALIDOPCODE), Opcode::PushValue),
            Opcode::Operation,
        )
    }
}

impl From<PushValue> for u8 {
    fn from(value: PushValue) -> Self {
        match value {
            OP_0 => 0x00,
            PushdataBytelength(byte) => byte,
            OP_PUSHDATA1 => 0x4c,
            OP_PUSHDATA2 => 0x4d,
            OP_PUSHDATA4 => 0x4e,
            OP_1NEGATE => 0x4f,
            OP_RESERVED => 0x50,
            OP_1 => 0x51,
            OP_2 => 0x52,
            OP_3 => 0x53,
            OP_4 => 0x54,
            OP_5 => 0x55,
            OP_6 => 0x56,
            OP_7 => 0x57,
            OP_8 => 0x58,
            OP_9 => 0x59,
            OP_10 => 0x5a,
            OP_11 => 0x5b,
            OP_12 => 0x5c,
            OP_13 => 0x5d,
            OP_14 => 0x5e,
            OP_15 => 0x5f,
            OP_16 => 0x60,
        }
    }
}

impl TryFrom<u8> for PushValue {
    type Error = ();
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x00 => Ok(OP_0),
            0x4c => Ok(OP_PUSHDATA1),
            0x4d => Ok(OP_PUSHDATA2),
            0x4e => Ok(OP_PUSHDATA4),
            0x4f => Ok(OP_1NEGATE),
            0x50 => Ok(OP_RESERVED),
            0x51 => Ok(OP_1),
            0x52 => Ok(OP_2),
            0x53 => Ok(OP_3),
            0x54 => Ok(OP_4),
            0x55 => Ok(OP_5),
            0x56 => Ok(OP_6),
            0x57 => Ok(OP_7),
            0x58 => Ok(OP_8),
            0x59 => Ok(OP_9),
            0x5a => Ok(OP_10),
            0x5b => Ok(OP_11),
            0x5c => Ok(OP_12),
            0x5d => Ok(OP_13),
            0x5e => Ok(OP_14),
            0x5f => Ok(OP_15),
            0x60 => Ok(OP_16),
            _ => {
                if value <= 0x60 {
                    Ok(PushdataBytelength(value))
                } else {
                    Err(())
                }
            }
        }
    }
}

impl From<Operation> for u8 {
    fn from(value: Operation) -> Self {
        // This is how you get the discriminant, but using `as` everywhere is too much code smell
        value as u8
    }
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct ScriptNum(i64);

impl ScriptNum {
    const DEFAULT_MAX_NUM_SIZE: usize = 4;

    pub fn new(
        vch: &Vec<u8>,
        require_minimal: bool,
        max_num_size: Option<usize>,
    ) -> Result<Self, ScriptNumError> {
        let max_num_size = max_num_size.unwrap_or(Self::DEFAULT_MAX_NUM_SIZE);
        if vch.len() > max_num_size {
            return Err(ScriptNumError::Overflow {
                max_num_size,
                actual: vch.len(),
            });
        }
        if require_minimal && !vch.is_empty() {
            // Check that the number is encoded with the minimum possible
            // number of bytes.
            //
            // If the most-significant-byte - excluding the sign bit - is zero
            // then we're not minimal. Note how this test also rejects the
            // negative-zero encoding, 0x80.
            if (vch.last().unwrap_or_else(|| unreachable!()) & 0x7F) == 0 {
                // One exception: if there's more than one byte and the most
                // significant bit of the second-most-significant-byte is set
                // it would conflict with the sign bit. An example of this case
                // is +-255, which encode to 0xff00 and 0xff80 respectively.
                // (big-endian).
                if vch.len() <= 1 {
                    return Err(ScriptNumError::NegativeZero);
                } else if (vch[vch.len() - 2] & 0x80) == 0 {
                    return Err(ScriptNumError::NonMinimalEncoding);
                }
            }
        }
        Self::set_vch(vch).map(ScriptNum)
    }

    pub fn getint(&self) -> i32 {
        if self.0 > i32::MAX.into() {
            i32::MAX
        } else if self.0 < i32::MIN.into() {
            i32::MIN
        } else {
            self.0.try_into().unwrap()
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
        let mut absvalue = value.abs();

        while absvalue != 0 {
            result.push(
                (absvalue & 0xff)
                    .try_into()
                    .unwrap_or_else(|_| unreachable!()),
            );
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

    fn set_vch(vch: &Vec<u8>) -> Result<i64, ScriptNumError> {
        match vch.last() {
            None => Ok(0),
            Some(vch_back) => {
                if *vch == vec![0, 0, 0, 0, 0, 0, 0, 128, 128] {
                    // On an x86_64 system, the code below would actually decode the buggy
                    // INT64_MIN encoding correctly. However in this case, it would be
                    // performing left shifts of a signed type by 64, which has undefined
                    // behavior.
                    return Ok(i64::MIN);
                };

                // Guard against undefined behavior. INT64_MIN is the only allowed 9-byte encoding.
                if vch.len() > 8 {
                    return Err(ScriptNumError::Overflow {
                        max_num_size: 8,
                        actual: vch.len(),
                    });
                };

                let mut result: i64 = 0;
                for (i, vch_i) in vch.iter().enumerate() {
                    result |= i64::from(*vch_i) << (8 * i);
                }

                // If the input vector's most significant byte is 0x80, remove it from
                // the result's msb and return a negative.
                if vch_back & 0x80 != 0 {
                    return Ok(-(result & !(0x80 << (8 * (vch.len() - 1)))));
                };

                Ok(result)
            }
        }
    }
}

impl From<i64> for ScriptNum {
    fn from(value: i64) -> Self {
        ScriptNum(value)
    }
}

impl From<i32> for ScriptNum {
    fn from(value: i32) -> Self {
        ScriptNum(value.into())
    }
}

impl From<u8> for ScriptNum {
    fn from(value: u8) -> Self {
        ScriptNum(value.into())
    }
}

/// TODO: This instance will be obsolete if we convert bool directly to a `Vec<u8>`, which is also
///       more efficient.
impl From<bool> for ScriptNum {
    fn from(value: bool) -> Self {
        ScriptNum(value.into())
    }
}

impl TryFrom<usize> for ScriptNum {
    type Error = TryFromIntError;
    fn try_from(value: usize) -> Result<Self, Self::Error> {
        value.try_into().map(ScriptNum)
    }
}

impl TryFrom<ScriptNum> for u16 {
    type Error = TryFromIntError;
    fn try_from(value: ScriptNum) -> Result<Self, Self::Error> {
        value.getint().try_into()
    }
}

impl TryFrom<ScriptNum> for u8 {
    type Error = TryFromIntError;
    fn try_from(value: ScriptNum) -> Result<Self, Self::Error> {
        value.getint().try_into()
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

/** Serialized script, used inside transaction inputs and outputs */
#[derive(Clone, Debug)]
pub struct Script<'a>(pub &'a [u8]);

impl Script<'_> {
    pub fn get_op(script: &mut &[u8]) -> Result<Opcode, ScriptError> {
        Self::get_op2(script, &mut vec![])
    }

    pub fn get_op2(script: &mut &[u8], buffer: &mut Vec<u8>) -> Result<Opcode, ScriptError> {
        if script.is_empty() {
            return Err(ScriptError::ReadError {
                expected_bytes: 1,
                available_bytes: 0,
            });
        }

        // Empty the provided buffer, if any
        buffer.truncate(0);

        let leading_byte = Opcode::from(script[0]);
        *script = &script[1..];

        Ok(match leading_byte {
            Opcode::PushValue(pv) => match pv {
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
                                size |= usize::from(script[i]);
                            }
                            *script = &script[needed_bytes..];
                            Ok(size)
                        }
                    };

                    let size = match pv {
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

                    buffer.extend(&script[0..size]);
                    *script = &script[size..];

                    leading_byte
                }
                // OP_0/OP_FALSE doesn't actually push a constant 0 onto the stack but
                // pushes an empty array. (Thus we leave the buffer truncated to 0 length)
                OP_0 => leading_byte,
                PushdataBytelength(size_byte) => {
                    let size = size_byte.into();

                    if script.len() < size {
                        return Err(ScriptError::ReadError {
                            expected_bytes: size,
                            available_bytes: script.len(),
                        });
                    }

                    buffer.extend(&script[0..size]);
                    *script = &script[size..];

                    leading_byte
                }
                _ => leading_byte,
            },
            _ => leading_byte,
        })
    }

    /** Encode/decode small integers: */
    pub fn decode_op_n(opcode: PushValue) -> u32 {
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
        let mut last_opcode = Opcode::Operation(OP_INVALIDOPCODE);
        while !pc.is_empty() {
            let opcode = match Self::get_op(&mut pc) {
                Ok(o) => o,
                Err(_) => break,
            };
            if let Opcode::Operation(op) = opcode {
                if op == OP_CHECKSIG || op == OP_CHECKSIGVERIFY {
                    n += 1;
                } else if op == OP_CHECKMULTISIG || op == OP_CHECKMULTISIGVERIFY {
                    match last_opcode {
                        Opcode::PushValue(pv) => {
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
            last_opcode = opcode;
        }
        n
    }

    /// Returns true iff this script is P2SH.
    pub fn is_pay_to_script_hash(&self) -> bool {
        self.0.len() == 23
            && self.0[0] == OP_HASH160.into()
            && self.0[1] == 0x14
            && self.0[22] == OP_EQUAL.into()
    }

    /// Called by `IsStandardTx` and P2SH/BIP62 VerifyScript (which makes it consensus-critical).
    pub fn is_push_only(&self) -> bool {
        let mut pc = self.0;
        while !pc.is_empty() {
            if let Ok(Opcode::PushValue(_)) = Self::get_op(&mut pc) {
            } else {
                return false;
            }
        }
        true
    }
}
