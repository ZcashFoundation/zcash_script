#![allow(non_camel_case_types)]

pub mod push_value;

use enum_primitive::FromPrimitive;
use thiserror::Error;

use super::Opcode;
use crate::interpreter;
use push_value::{
    LargeValue,
    SmallValue::{self, *},
};

#[derive(Copy, Clone, Debug, PartialEq, Eq, Error)]
pub enum Error {
    #[error("expected {expected_bytes} bytes, but only {available_bytes} bytes available")]
    ReadError {
        expected_bytes: usize,
        available_bytes: usize,
    },

    /// __TODO__: `Option` can go away once C++ support is removed.
    #[error("disabled opcode encountered{}", .0.map_or("".to_owned(), |op| format!(": {:?}", op)))]
    Disabled(Option<Disabled>),
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

    /// Statically analyze a push value.
    pub fn analyze(&self, flags: &interpreter::VerificationFlags) -> Vec<interpreter::Error> {
        let mut errors = Vec::new();
        if flags.contains(interpreter::VerificationFlags::MinimalData) && !self.is_minimal_push() {
            errors.push(interpreter::Error::MinimalData);
        }
        let len = self.value().len();
        if push_value::LargeValue::MAX_SIZE < len {
            errors.push(interpreter::Error::PushSize(Some(len)));
        }
        errors
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

impl Operation {
    /// Statically analyze an operation.
    ///
    /// __NB__: [`Operation::OP_RETURN`] isn’t tracked by this function. That is functionally
    ///         more like a `break` then an error.
    pub fn analyze(&self, flags: &interpreter::VerificationFlags) -> Vec<interpreter::Error> {
        match self {
            Operation::OP_CHECKLOCKTIMEVERIFY
                if !flags.contains(interpreter::VerificationFlags::CHECKLOCKTIMEVERIFY)
                    && flags.contains(interpreter::VerificationFlags::DiscourageUpgradableNOPs) =>
            {
                vec![interpreter::Error::DiscourageUpgradableNOPs]
            }
            Operation::OP_NOP1
            | Operation::OP_NOP3
            | Operation::OP_NOP4
            | Operation::OP_NOP5
            | Operation::OP_NOP6
            | Operation::OP_NOP7
            | Operation::OP_NOP8
            | Operation::OP_NOP9
            | Operation::OP_NOP10
                if flags.contains(interpreter::VerificationFlags::DiscourageUpgradableNOPs) =>
            {
                vec![interpreter::Error::DiscourageUpgradableNOPs]
            }

            _ => vec![],
        }
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

/// Opcodes that fail if they’re on an active branch.
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
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum PossiblyBad {
    Good(Opcode),
    Bad(Bad),
}

impl PossiblyBad {
    /// This parses a single opcode from a byte stream.
    ///
    /// This always returns the unparsed bytes, because parsing failures don’t invalidate the
    /// remainder of the stream (if any).
    pub fn parse(script: &[u8]) -> (Result<PossiblyBad, Error>, &[u8]) {
        match push_value::LargeValue::parse(script) {
            None => match script.split_first() {
                None => (
                    Err(Error::ReadError {
                        expected_bytes: 1,
                        available_bytes: 0,
                    }),
                    &[],
                ),
                Some((leading_byte, remaining_code)) => (
                    Disabled::from_u8(*leading_byte).map_or(
                        Ok(
                            if let Some(sv) = push_value::SmallValue::from_u8(*leading_byte) {
                                PossiblyBad::Good(Opcode::PushValue(PushValue::SmallValue(sv)))
                            } else if let Some(ctl) = Control::from_u8(*leading_byte) {
                                PossiblyBad::Good(Opcode::Control(ctl))
                            } else if let Some(op) = Operation::from_u8(*leading_byte) {
                                PossiblyBad::Good(Opcode::Operation(op))
                            } else {
                                PossiblyBad::Bad(Bad::from(*leading_byte))
                            },
                        ),
                        |disabled| Err(Error::Disabled(Some(disabled))),
                    ),
                    remaining_code,
                ),
            },
            Some((res, remaining_code)) => (
                res.map(|v| PossiblyBad::Good(Opcode::PushValue(PushValue::LargeValue(v)))),
                remaining_code,
            ),
        }
    }

    /// Statically analyze a possibly-bad opcode.
    pub fn analyze(
        &self,
        flags: &interpreter::VerificationFlags,
    ) -> Result<&Opcode, Vec<interpreter::Error>> {
        match self {
            PossiblyBad::Good(op) => {
                let errors = op.analyze(flags);
                if errors.is_empty() {
                    Ok(op)
                } else {
                    Err(errors)
                }
            }
            PossiblyBad::Bad(_) => Err(vec![interpreter::Error::BadOpcode]),
        }
    }
}

impl From<Opcode> for PossiblyBad {
    fn from(value: Opcode) -> Self {
        PossiblyBad::Good(value)
    }
}

impl From<Bad> for PossiblyBad {
    fn from(value: Bad) -> Self {
        PossiblyBad::Bad(value)
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
