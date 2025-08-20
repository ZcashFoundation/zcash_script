#![allow(non_camel_case_types)]

use std::fmt::Display;

use enum_primitive::FromPrimitive;
use serde::{Deserialize, Serialize};

use crate::{interpreter::*, opcode::check_signature_encoding, script, scriptnum::*};

pub const MAX_SIZE: usize = 520; // bytes

fn read_le<const N: usize>(script: &[u8]) -> Result<(usize, &[u8]), script::Error> {
    match script.split_first_chunk::<N>() {
        None => Err(script::Error::ReadError {
            expected_bytes: N,
            available_bytes: script.len(),
        }),
        Some((first, rest)) => {
            let mut size = 0;
            for i in first.iter().rev() {
                size <<= 8;
                size |= usize::from(*i);
            }
            Ok((size, rest))
        }
    }
}

fn read_push_value(script: &[u8], needed_bytes: usize) -> Result<(&[u8], &[u8]), script::Error> {
    match script.split_at_checked(needed_bytes) {
        None => Err(script::Error::ReadError {
            expected_bytes: needed_bytes,
            available_bytes: script.len(),
        }),
        Some((first, rest)) => Ok((first, rest)),
    }
}

fn read_push_data<const N: usize>(script: &[u8]) -> Result<(&[u8], &[u8]), script::Error> {
    read_le::<N>(script).and_then(|(size, rest)| read_push_value(rest, size))
}

impl script::Parsable for PushValue {
    fn to_bytes(&self) -> Vec<u8> {
        self.into()
    }

    fn from_bytes(script: &[u8]) -> Result<(Self, &[u8]), script::Error> {
        let make_lv = PushValue::LargeValue;

        match script.split_first() {
            None => panic!("attempting to parse an opcode from an empty script"),
            Some((&leading_byte, script)) => match leading_byte {
                0x4c => read_push_data::<1>(script)
                    .map(|(v, rest)| (make_lv(OP_PUSHDATA1(v.to_vec())), rest)),
                0x4d => read_push_data::<2>(script)
                    .map(|(v, rest)| (make_lv(OP_PUSHDATA2(v.to_vec())), rest)),
                0x4e => read_push_data::<4>(script)
                    .map(|(v, rest)| (make_lv(OP_PUSHDATA4(v.to_vec())), rest)),
                _ => {
                    if 0x01 <= leading_byte && leading_byte < 0x4c {
                        read_push_value(script, leading_byte.into())
                            .map(|(v, rest)| (make_lv(PushdataBytelength(v.to_vec())), rest))
                    } else {
                        SmallValue::from_u8(leading_byte)
                            .ok_or(script::Error::SigPushOnly)
                            .map(|sv| (PushValue::SmallValue(sv), script))
                    }
                }
            },
        }
    }
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Deserialize, Serialize)]
pub enum LargeValue {
    // push value
    PushdataBytelength(Vec<u8>),
    OP_PUSHDATA1(Vec<u8>),
    OP_PUSHDATA2(Vec<u8>),
    OP_PUSHDATA4(Vec<u8>),
}

use LargeValue::*;

impl From<&LargeValue> for Vec<u8> {
    fn from(value: &LargeValue) -> Self {
        let bytes = value.value();
        match value {
            PushdataBytelength(_) => {
                [ScriptNum(bytes.len().try_into().unwrap()).getvch(), bytes].concat()
            }
            OP_PUSHDATA1(_) => [
                vec![0x4c],
                ScriptNum(bytes.len().try_into().unwrap()).getvch(),
                bytes,
            ]
            .concat(),
            OP_PUSHDATA2(_) => [
                vec![0x4d],
                ScriptNum(bytes.len().try_into().unwrap()).getvch(),
                bytes,
            ]
            .concat(),
            OP_PUSHDATA4(_) => [
                vec![0x4e],
                ScriptNum(bytes.len().try_into().unwrap()).getvch(),
                bytes,
            ]
            .concat(),
        }
    }
}

impl LargeValue {
    pub fn byte_len(&self) -> usize {
        1 + match self {
            PushdataBytelength(data) => data.len(),
            OP_PUSHDATA1(data) => 1 + data.len(),
            OP_PUSHDATA2(data) => 2 + data.len(),
            OP_PUSHDATA4(data) => 4 + data.len(),
        }
    }

    pub fn value(&self) -> ValType {
        match self {
            PushdataBytelength(v) | OP_PUSHDATA1(v) | OP_PUSHDATA2(v) | OP_PUSHDATA4(v) => {
                v.clone()
            }
        }
    }

    pub fn is_minimal_push(&self) -> bool {
        match self {
            PushdataBytelength(data) => match data[..] {
                [byte] => byte != 0x81 && (byte < 1 || 16 < byte),
                _ => true,
            },
            OP_PUSHDATA1(data) => 0x4c <= data.len(),
            OP_PUSHDATA2(data) => 0x100 <= data.len(),
            OP_PUSHDATA4(data) => 0x10000 <= data.len(),
        }
    }
}

enum_from_primitive! {
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Deserialize, Serialize)]
#[repr(u8)]
pub enum SmallValue {
    // push value
    OP_0 = 0x00,
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
}

use SmallValue::*;

impl SmallValue {
    pub fn value(&self) -> Option<ValType> {
        match self {
            OP_0 => Some(vec![]),
            OP_1NEGATE => Some(vec![0x81]),
            OP_RESERVED => None,
            _ => Some(vec![u8::from(self.clone()) - (u8::from(OP_1) - 1)]),
        }
    }
}

impl From<SmallValue> for u8 {
    fn from(value: SmallValue) -> Self {
        // This is how you get the discriminant, but using `as` everywhere is too much code smell
        value as u8
    }
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Deserialize, Serialize)]
pub enum PushValue {
    /// - can be cast to its discriminant
    SmallValue(SmallValue),
    /// - variable-length representation
    LargeValue(LargeValue),
}

impl PushValue {
    pub fn value(&self) -> Option<ValType> {
        match self {
            PushValue::LargeValue(pv) => Some(pv.value()),
            PushValue::SmallValue(pv) => pv.value(),
        }
    }

    pub fn is_minimal_push(&self) -> bool {
        match self {
            PushValue::LargeValue(lv) => lv.is_minimal_push(),
            PushValue::SmallValue(_) => true,
        }
    }

    pub fn well_formed(&self, require_minimal: bool) -> Result<(), script::Error> {
        if require_minimal && !self.is_minimal_push() {
            Err(script::Error::MinimalData)
        } else {
            self.value()
                .map_or(Err(script::Error::BadOpcode(None)), |_| Ok(()))
        }
    }

    pub fn eval_(
        &self,
        require_minimal: bool,
        stack: &mut Stack<ValType>,
    ) -> Result<(), script::Error> {
        if require_minimal && !self.is_minimal_push() {
            Err(script::Error::MinimalData)
        } else {
            self.value()
                .map_or(Err(script::Error::BadOpcode(None)), |v| Ok(stack.push(v)))
        }
    }
}

impl Evaluable for PushValue {
    fn byte_len(&self) -> usize {
        match self {
            PushValue::LargeValue(pv) => pv.byte_len(),
            PushValue::SmallValue(_) => 1,
        }
    }

    fn eval(
        &self,
        flags: VerificationFlags,
        _script: &[u8],
        _checker: &dyn SignatureChecker,
        state: &mut State,
    ) -> Result<(), script::Error> {
        self.eval_(
            flags.contains(VerificationFlags::MinimalData),
            &mut state.stack,
        )
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

impl Display for PushValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.value() {
            Some(mut value) => {
                let mut hash_type = "".to_string();
                if let Ok(Some(signature)) =
                    check_signature_encoding(&value, VerificationFlags::StrictEnc)
                {
                    value = signature.sig.serialize_der().to_vec();
                    hash_type = format!("[{}]", signature.sighash);
                }
                write!(f, "{}{}", hex::encode(value), hash_type)
            }
            // This is the only instance where None is returned.
            None => write!(f, "OP_RESERVED"),
        }
    }
}
