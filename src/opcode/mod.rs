#![allow(non_camel_case_types)]

pub mod push_value;

use super::Opcode;
use push_value::{
    LargeValue,
    SmallValue::{self, *},
};

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

impl From<&PushValue> for Vec<u8> {
    fn from(value: &PushValue) -> Self {
        match value {
            PushValue::SmallValue(v) => vec![(*v).into()],
            PushValue::LargeValue(v) => v.into(),
        }
    }
}

impl From<Control> for u8 {
    fn from(value: Control) -> Self {
        // This is how you get the discriminant, but using `as` everywhere is too much code smell
        value as u8
    }
}

impl From<Operation> for u8 {
    fn from(value: Operation) -> Self {
        // This is how you get the discriminant, but using `as` everywhere is too much code smell
        value as u8
    }
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

/// When writing scripts, we don’t want to allow bad opcodes, so `Opcode` doesn’t include them.
/// However, when validating scripts, bad opcodes only cause a failure when they’re on an active
/// branch, so this type allows us to hold onto the bad opcodes when parsing.
pub enum PossiblyBad {
    Good(Opcode),
    Bad(Bad),
}

pub struct Parsed<'a> {
    /// The [`PossiblyBad`] allows us to preserve unknown opcodes, which only trigger a failure if
    /// they’re on an active branch during interpretation.
    pub opcode: PossiblyBad,
    pub remaining_code: &'a [u8],
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
