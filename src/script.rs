#![allow(non_camel_case_types)]

use bounded_vec::{BoundedVec, EmptyBoundedVec};
use enum_primitive::FromPrimitive;
use itertools::{Either, Itertools};

use super::script_error::{ScriptError, ScriptNumError};

pub const MAX_SCRIPT_ELEMENT_SIZE: usize = 520; // bytes

/// Maximum script length in bytes
pub const MAX_SCRIPT_SIZE: usize = 10_000;

// Threshold for lock_time: below this value it is interpreted as block number,
// otherwise as UNIX timestamp.
pub const LOCKTIME_THRESHOLD: i64 = 500_000_000; // Tue Nov  5 00:53:20 1985 UTC

/** Script opcodes */
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Opcode {
    PushValue(PushValue),
    /// - always evaluated
    /// - can be cast to its discriminant
    Control(Control),
    /// - only evaluated on active branch
    /// - can be cast to its discriminant
    Operation(Operation),
}

impl From<&Opcode> for Vec<u8> {
    fn from(value: &Opcode) -> Self {
        match value {
            Opcode::PushValue(v) => v.into(),
            Opcode::Control(v) => vec![(*v).into()],
            Opcode::Operation(v) => vec![(*v).into()],
        }
    }
}

/// Data values that aren’t represented within their opcode byte.
///
/// TODO: These should have lower bounds that can prevent non-minimal encodings, but that requires
///       at least `const_generic_exprs`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum LargeValue {
    /// NB: The lower bound here is 1 because `PushdataBytelength([;0])` has the same encoding as
    ///     [`OP_0`].
    PushdataBytelength(BoundedVec<u8, 1, 0x4b>),
    OP_PUSHDATA1(EmptyBoundedVec<u8, 0xff>),
    OP_PUSHDATA2(EmptyBoundedVec<u8, 0xffff>),
    OP_PUSHDATA4(EmptyBoundedVec<u8, 0xffffffff>),
}
use LargeValue::*;

impl From<LargeValue> for Vec<u8> {
    fn from(value: LargeValue) -> Self {
        match value {
            PushdataBytelength(bv) => {
                [serialize_num(bv.len().try_into().unwrap()), bv.to_vec()].concat()
            }
            OP_PUSHDATA1(bv) => [
                vec![0x4c],
                serialize_num(bv.as_slice().len().try_into().unwrap()),
                bv.to_vec(),
            ]
            .concat(),
            OP_PUSHDATA2(bv) => [
                vec![0x4d],
                serialize_num(bv.as_slice().len().try_into().unwrap()),
                bv.to_vec(),
            ]
            .concat(),
            OP_PUSHDATA4(bv) => [
                vec![0x4e],
                serialize_num(bv.as_slice().len().try_into().unwrap()),
                bv.to_vec(),
            ]
            .concat(),
        }
    }
}
impl LargeValue {
    const PUSHDATA1_BYTE: u8 = 0x4c;
    const PUSHDATA2_BYTE: u8 = 0x4d;
    const PUSHDATA4_BYTE: u8 = 0x4e;

    /// Returns a [`LargeValue`] as minimally-encoded as possible. That is, non-empty values that
    /// should be minimally-encoded as [`SmallValue`]s will be [`PushdataBytelength`].
    fn from_slice(v: &[u8]) -> Option<LargeValue> {
        if v.is_empty() {
            None
        } else if let Ok(bv) = BoundedVec::try_from(v.to_vec()) {
            Some(PushdataBytelength(bv))
        } else if let Ok(bv) = BoundedVec::try_from(v.to_vec()) {
            Some(OP_PUSHDATA1(bv))
        } else if let Ok(bv) = BoundedVec::try_from(v.to_vec()) {
            Some(OP_PUSHDATA2(bv))
        } else if let Ok(bv) = BoundedVec::try_from(v.to_vec()) {
            Some(OP_PUSHDATA4(bv))
        } else {
            None
        }
    }

    /// Get the [`Stack`] element represented by this [`LargeValue`].
    pub fn value(&self) -> &[u8] {
        match self {
            PushdataBytelength(v) => v.as_slice(),
            OP_PUSHDATA1(v) => v.as_slice(),
            OP_PUSHDATA2(v) => v.as_slice(),
            OP_PUSHDATA4(v) => v.as_slice(),
        }
    }

    /// Returns false if there is a smaller possible encoding of the provided value.
    pub fn is_minimal_push(&self) -> bool {
        match self {
            PushdataBytelength(data) => match data.as_slice() {
                [b] => *b != 0x81 && (*b < 1 || 16 < *b),
                _ => true,
            },
            OP_PUSHDATA1(data) => usize::from(Self::PUSHDATA1_BYTE) <= data.as_slice().len(),
            OP_PUSHDATA2(data) => 0x100 <= data.as_slice().len(),
            OP_PUSHDATA4(data) => 0x10000 <= data.as_slice().len(),
        }
    }
}

impl From<LargeValue> for u8 {
    fn from(lv: LargeValue) -> Self {
        match lv {
            PushdataBytelength(value) => value
                .as_slice()
                .len()
                .try_into()
                .expect("the upper bound of PushdataBytelength fits in u8"),
            OP_PUSHDATA1(_) => LargeValue::PUSHDATA1_BYTE,
            OP_PUSHDATA2(_) => LargeValue::PUSHDATA2_BYTE,
            OP_PUSHDATA4(_) => LargeValue::PUSHDATA4_BYTE,
        }
    }
}

enum_from_primitive! {
/// Data values represented entirely by their opcode byte.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
#[repr(u8)]
pub enum SmallValue {
    // push value
    OP_0 = 0x00,
    OP_1NEGATE = 0x4f,
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
}

use SmallValue::*;

impl SmallValue {
    /// Get the [`Stack`] element represented by this [`SmallValue`].
    pub fn value(&self) -> Vec<u8> {
        match self {
            OP_0 => vec![],
            OP_1NEGATE => vec![0x81],
            _ => vec![u8::from(*self) - (u8::from(OP_1) - 1)],
        }
    }
}

impl From<SmallValue> for u8 {
    fn from(value: SmallValue) -> Self {
        // This is how you get the discriminant, but using `as` everywhere is too much code smell
        value as u8
    }
}

/// Opcodes that represent constants to be pushed onto the stack.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum PushValue {
    /// Constants that are represented by a single byte.
    SmallValue(SmallValue),
    /// Constants that contain data in addition to the opcode byte.
    LargeValue(LargeValue),
}

impl PushValue {
    /// Produce a minimal `PushValue` for the given data.
    pub fn from_slice(v: &[u8]) -> Option<PushValue> {
        match v {
            [] => Some(PushValue::SmallValue(OP_0)),
            [0x81] => Some(PushValue::SmallValue(OP_1NEGATE)),
            [1] => Some(PushValue::SmallValue(OP_1)),
            [2] => Some(PushValue::SmallValue(OP_2)),
            [3] => Some(PushValue::SmallValue(OP_3)),
            [4] => Some(PushValue::SmallValue(OP_4)),
            [5] => Some(PushValue::SmallValue(OP_5)),
            [6] => Some(PushValue::SmallValue(OP_6)),
            [7] => Some(PushValue::SmallValue(OP_7)),
            [8] => Some(PushValue::SmallValue(OP_8)),
            [9] => Some(PushValue::SmallValue(OP_9)),
            [10] => Some(PushValue::SmallValue(OP_10)),
            [11] => Some(PushValue::SmallValue(OP_11)),
            [12] => Some(PushValue::SmallValue(OP_12)),
            [13] => Some(PushValue::SmallValue(OP_13)),
            [14] => Some(PushValue::SmallValue(OP_14)),
            [15] => Some(PushValue::SmallValue(OP_15)),
            [16] => Some(PushValue::SmallValue(OP_16)),
            _ => LargeValue::from_slice(v).map(PushValue::LargeValue),
        }
    }

    /// Get the [`Stack`] element represented by this [`PushValue`].
    pub fn value(&self) -> Vec<u8> {
        match self {
            PushValue::LargeValue(pv) => pv.value().to_vec(),
            PushValue::SmallValue(pv) => pv.value(),
        }
    }

    /// Returns false if there is a smaller possible encoding of the provided value.
    pub fn is_minimal_push(&self) -> bool {
        match self {
            PushValue::LargeValue(lv) => lv.is_minimal_push(),
            PushValue::SmallValue(_) => true,
        }
    }
}

impl From<&PushValue> for Vec<u8> {
    fn from(value: &PushValue) -> Self {
        match value {
            PushValue::SmallValue(v) => vec![(*v).into()],
            PushValue::LargeValue(v) => v.clone().into(),
        }
    }
}

enum_from_primitive! {
/// Control operations are evaluated regardless of whether the current branch is active.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
#[repr(u8)]
pub enum Control {
    OP_IF = 0x63,
    OP_NOTIF = 0x64,
    OP_ELSE = 0x67,
    OP_ENDIF = 0x68,
}
}

enum_from_primitive! {
/// Normal operations are only executed when they are on an active branch.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
#[repr(u8)]
pub enum Operation {
    // control
    OP_NOP = 0x61,
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
    OP_SIZE = 0x82,

    // bit logic
    OP_EQUAL = 0x87,
    OP_EQUALVERIFY = 0x88,

    // numeric
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

    // crypto
    OP_RIPEMD160 = 0xa6,
    OP_SHA1 = 0xa7,
    OP_SHA256 = 0xa8,
    OP_HASH160 = 0xa9,
    OP_HASH256 = 0xaa,
    OP_CHECKSIG = 0xac,
    OP_CHECKSIGVERIFY = 0xad,
    OP_CHECKMULTISIG = 0xae,
    OP_CHECKMULTISIGVERIFY = 0xaf,

    // expansion
    OP_NOP1 = 0xb0,
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
}

use Operation::*;

impl From<Opcode> for u8 {
    fn from(value: Opcode) -> Self {
        match value {
            Opcode::PushValue(pv) => pv.into(),
            Opcode::Control(ctl) => ctl.into(),
            Opcode::Operation(op) => op.into(),
        }
    }
}

impl From<PushValue> for u8 {
    fn from(value: PushValue) -> Self {
        match value {
            PushValue::SmallValue(pv) => pv.into(),
            PushValue::LargeValue(pv) => pv.into(),
        }
    }
}

impl From<Operation> for u8 {
    fn from(value: Operation) -> Self {
        // This is how you get the discriminant, but using `as` everywhere is too much code smell
        value as u8
    }
}

impl From<Control> for u8 {
    fn from(value: Control) -> Self {
        // This is how you get the discriminant, but using `as` everywhere is too much code smell
        value as u8
    }
}

const DEFAULT_MAX_NUM_SIZE: usize = 4;

pub fn parse_num(
    vch: &Vec<u8>,
    require_minimal: bool,
    max_num_size: Option<usize>,
) -> Result<i64, ScriptNumError> {
    match vch.last() {
        None => Ok(0),
        Some(vch_back) => {
            let max_num_size = max_num_size.unwrap_or(DEFAULT_MAX_NUM_SIZE);
            if vch.len() > max_num_size {
                return Err(ScriptNumError::Overflow {
                    max_num_size,
                    actual: vch.len(),
                });
            }
            if require_minimal {
                // Check that the number is encoded with the minimum possible number of bytes.
                //
                // If the most-significant-byte - excluding the sign bit - is zero then we're not
                // minimal. Note how this test also rejects the negative-zero encoding, 0x80.
                if (vch_back & 0x7F) == 0 {
                    // One exception: if there's more than one byte and the most significant bit of
                    // the second-most-significant-byte is set then it would have conflicted with
                    // the sign bit if one fewer byte were used, and so such encodings are minimal.
                    // An example of this is +-255, which have minimal encodings [0xff, 0x00] and
                    // [0xff, 0x80] respectively.
                    if vch.len() <= 1 || (vch[vch.len() - 2] & 0x80) == 0 {
                        return Err(ScriptNumError::NonMinimalEncoding);
                    }
                }
            }

            if *vch == vec![0, 0, 0, 0, 0, 0, 0, 128, 128] {
                // Match the behaviour of the C++ code, which special-cased this encoding to avoid
                // an undefined shift of a signed type by 64 bits.
                return Ok(i64::MIN);
            };

            // Ensure defined behaviour (in Rust, left shift of `i64` by 64 bits is an arithmetic
            // overflow that may panic or give an unspecified result). The above encoding of
            // `i64::MIN` is the only allowed 9-byte encoding.
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

            // If the input vector's most significant byte is 0x80, remove it from the result's msb
            // and return a negative.
            if vch_back & 0x80 != 0 {
                return Ok(-(result & !(0x80 << (8 * (vch.len() - 1)))));
            };

            Ok(result)
        }
    }
}

pub fn serialize_num(value: i64) -> Vec<u8> {
    if value == 0 {
        return Vec::new();
    }

    if value == i64::MIN {
        // The code below was based on buggy C++ code, that produced the "wrong" result for
        // INT64_MIN. In that case we intentionally return the result that the C++ code as compiled
        // for zcashd (with `-fwrapv`) originally produced on an x86_64 system.
        return vec![0, 0, 0, 0, 0, 0, 0, 128, 128];
    }

    let mut result = Vec::new();
    let neg = value < 0;
    let mut absvalue = value.abs();

    while absvalue != 0 {
        result.push(
            (absvalue & 0xff)
                .try_into()
                .unwrap_or_else(|_| unreachable!()),
        );
        absvalue >>= 8;
    }

    // - If the most significant byte is >= 0x80 and the value is positive, push a new zero-byte to
    //   make the significant byte < 0x80 again.
    // - If the most significant byte is >= 0x80 and the value is negative, push a new 0x80 byte
    //   that will be popped off when converting to an integral.
    // - If the most significant byte is < 0x80 and the value is negative, add 0x80 to it, since it
    //   will be subtracted and interpreted as a negative when converting to an integral.

    if result.last().map_or(true, |last| last & 0x80 != 0) {
        result.push(if neg { 0x80 } else { 0 });
    } else if neg {
        if let Some(last) = result.last_mut() {
            *last |= 0x80;
        }
    }

    result
}

/// Bad opcodes are a bit complicated.
///
/// - They only fail if they are evaluated, so we can’t statically fail scripts that contain them
///   (unlike [Disabled]).
/// - [Bad::OP_RESERVED] counts as a push value for the purposes of
///   [interpreter::VerificationFlags::SigPushOnly] (but push-only sigs must necessarily evaluate
///   all of their opcodes, so what we’re preserving here is that we get
///   [script::Error::SigPushOnly] in this case instead of [script::Error::BadOpcode]).
/// - [Bad::OP_VERIF] and [Bad::OP_VERNOTIF] both _always_ get evaluated, so we need to special case
///   them when checking whether to throw [script::Error::BadOpcode]
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Bad {
    OP_RESERVED,
    OP_VER,
    OP_VERIF,
    OP_VERNOTIF,
    OP_RESERVED1,
    OP_RESERVED2,
    Unknown(u8),
}

impl From<u8> for Bad {
    fn from(value: u8) -> Self {
        match value {
            0x50 => Bad::OP_RESERVED,
            0x62 => Bad::OP_VER,
            0x65 => Bad::OP_VERIF,
            0x66 => Bad::OP_VERNOTIF,
            0x89 => Bad::OP_RESERVED1,
            0x8a => Bad::OP_RESERVED2,
            _ => Bad::Unknown(value),
        }
    }
}

impl From<Bad> for u8 {
    fn from(value: Bad) -> Self {
        match value {
            Bad::OP_RESERVED => 0x50,
            Bad::OP_VER => 0x62,
            Bad::OP_VERIF => 0x65,
            Bad::OP_VERNOTIF => 0x66,
            Bad::OP_RESERVED1 => 0x89,
            Bad::OP_RESERVED2 => 0x8a,
            Bad::Unknown(byte) => byte,
        }
    }
}

enum_from_primitive! {
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
#[repr(u8)]
pub enum Disabled {
    // splice ops
    OP_CAT = 0x7e,
    OP_SUBSTR = 0x7f,
    OP_LEFT = 0x80,
    OP_RIGHT = 0x81,
    // bit logic
    OP_INVERT = 0x83,
    OP_AND = 0x84,
    OP_OR = 0x85,
    OP_XOR = 0x86,
    // numeric
    OP_2MUL = 0x8d,
    OP_2DIV = 0x8e,
    OP_MUL = 0x95,
    OP_DIV = 0x96,
    OP_MOD = 0x97,
    OP_LSHIFT = 0x98,
    OP_RSHIFT = 0x99,

    //crypto
    OP_CODESEPARATOR = 0xab,
}
}

impl From<Disabled> for u8 {
    fn from(value: Disabled) -> Self {
        // This is how you get the discriminant, but using `as` everywhere is too much code smell
        value as u8
    }
}

/// When writing scripts, we don’t want to allow bad opcodes, so `Opcode` doesn’t include them.
/// However, when validating scripts, bad opcodes only cause a failure when they’re on an active
/// branch, so this type allows us to hold onto the bad opcodes when parsing.
pub enum PossiblyBad {
    Good(Opcode),
    Bad(Bad),
}

pub struct ParsedOpcode<'a> {
    /// The [`PossiblyBad`] allows us to preserve unknown opcodes, which only trigger a failure if
    /// they’re on an active branch during interpretation.
    pub opcode: PossiblyBad,
    pub remaining_code: &'a [u8],
}

/// “Strict” scripts disallow [`Bad`] opcodes, and so we collect any bad opcodes that we find, so we
/// can report all of them, rather than just the first one.
pub enum StrictError {
    /// A script validation failure.
    Script(ScriptError),
    /// All of the [`Bad`] opcodes we found.
    BadOpcodes(Vec<Bad>),
}

/** Serialized script, used inside transaction inputs and outputs */
#[derive(Clone, Debug)]
pub struct Script<'a>(pub &'a [u8]);

impl Script<'_> {
    /// Fails on all [`Bad`] opcodes, not just ones on active branches.
    pub fn parse_strict(&self) -> Result<Vec<Opcode>, StrictError> {
        self.parse()
            .map_err(StrictError::Script)
            .and_then(|script| {
                let (opcodes, bad_opcodes): (Vec<_>, Vec<_>) =
                    script.into_iter().partition_map(|pb| match pb {
                        PossiblyBad::Good(opcode) => Either::Left(opcode),
                        PossiblyBad::Bad(bad) => Either::Right(bad),
                    });
                if bad_opcodes.is_empty() {
                    Ok(opcodes)
                } else {
                    Err(StrictError::BadOpcodes(bad_opcodes))
                }
            })
    }

    pub fn parse(&self) -> Result<Vec<PossiblyBad>, ScriptError> {
        let mut pc = self.0;
        let mut result = vec![];
        while !pc.is_empty() {
            let ParsedOpcode {
                opcode,
                remaining_code,
            } = Self::get_op(pc)?;
            pc = remaining_code;
            result.push(opcode)
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

    /// Parse a single [`LargeValue`] from a script. Returns `Ok(None)` if the first byte doesn’t
    /// correspond to a [`LargeValue`].
    fn get_lv(script: &[u8]) -> Result<Option<(LargeValue, &[u8])>, ScriptError> {
        match script.split_first() {
            None => Err(ScriptError::ReadError {
                expected_bytes: 1,
                available_bytes: 0,
            }),
            Some((leading_byte, script)) => match leading_byte {
                0x01..LargeValue::PUSHDATA1_BYTE => {
                    Self::split_value(script, (*leading_byte).into()).map(|(v, script)| {
                        v.to_vec()
                            .try_into()
                            .map(|bv| (PushdataBytelength(bv), script))
                            .ok()
                    })
                }
                &LargeValue::PUSHDATA1_BYTE => {
                    Self::split_tagged_value(script, 1).map(|(v, script)| {
                        v.to_vec()
                            .try_into()
                            .map(|bv| (OP_PUSHDATA1(bv), script))
                            .ok()
                    })
                }
                &LargeValue::PUSHDATA2_BYTE => {
                    Self::split_tagged_value(script, 2).map(|(v, script)| {
                        v.to_vec()
                            .try_into()
                            .map(|bv| (OP_PUSHDATA2(bv), script))
                            .ok()
                    })
                }
                &LargeValue::PUSHDATA4_BYTE => {
                    Self::split_tagged_value(script, 4).map(|(v, script)| {
                        v.to_vec()
                            .try_into()
                            .map(|bv| (OP_PUSHDATA4(bv), script))
                            .ok()
                    })
                }
                _ => Ok(None),
            },
        }
    }

    /// This parses a single opcode from a byte stream.
    ///
    /// NB: The nested `Result` allows us to preserve unknown opcodes, which only trigger a failure
    ///     if they’re on an active branch during interpretation.
    pub fn get_op(script: &[u8]) -> Result<ParsedOpcode, ScriptError> {
        match Self::get_lv(script)? {
            None => match script.split_first() {
                None => Err(ScriptError::ReadError {
                    expected_bytes: 1,
                    available_bytes: 0,
                }),
                Some((leading_byte, remaining_code)) => Disabled::from_u8(*leading_byte).map_or(
                    Ok(ParsedOpcode {
                        opcode: if let Some(sv) = SmallValue::from_u8(*leading_byte) {
                            PossiblyBad::Good(Opcode::PushValue(PushValue::SmallValue(sv)))
                        } else if let Some(ctl) = Control::from_u8(*leading_byte) {
                            PossiblyBad::Good(Opcode::Control(ctl))
                        } else if let Some(op) = Operation::from_u8(*leading_byte) {
                            PossiblyBad::Good(Opcode::Operation(op))
                        } else {
                            PossiblyBad::Bad(Bad::from(*leading_byte))
                        },
                        remaining_code,
                    }),
                    |disabled| Err(ScriptError::DisabledOpcode(Some(disabled))),
                ),
            },
            Some((v, remaining_code)) => Ok(ParsedOpcode {
                opcode: PossiblyBad::Good(Opcode::PushValue(PushValue::LargeValue(v))),
                remaining_code,
            }),
        }
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
            let ParsedOpcode {
                opcode,
                remaining_code,
            } = match Self::get_op(pc) {
                Ok(o) => o,
                // Stop counting when we get to an invalid opcode.
                Err(_) => break,
            };
            pc = remaining_code;
            if let PossiblyBad::Good(Opcode::Operation(op)) = opcode {
                n += match op {
                    OP_CHECKSIG | OP_CHECKSIGVERIFY => 1,
                    OP_CHECKMULTISIG | OP_CHECKMULTISIGVERIFY => match last_opcode {
                        Some(PossiblyBad::Good(Opcode::PushValue(PushValue::SmallValue(pv)))) => {
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
                    PossiblyBad::Good(Opcode::PushValue(_)) | PossiblyBad::Bad(Bad::OP_RESERVED)
                )
            })
        })
    }
}
