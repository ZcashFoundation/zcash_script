#![allow(non_camel_case_types)]

use alloc::vec::Vec;

use serde::{de, Deserialize, Serialize, Serializer};
use serde_repr::{Deserialize_repr, Serialize_repr};

use crate::{opcode::PushValue, script::num};

/// Values that require data beyond the single opcode byte.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
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
        let byte_len = num::serialize(
            bytes
                .len()
                .try_into()
                .expect("no ‘LargeValue’ allows more than ‘i64::MAX’ bytes"),
        );
        match value {
            PushdataBytelength(_) => [byte_len, bytes].concat(),
            OP_PUSHDATA1(_) => [vec![0x4c], byte_len, bytes].concat(),
            OP_PUSHDATA2(_) => [vec![0x4d], byte_len, bytes].concat(),
            OP_PUSHDATA4(_) => [vec![0x4e], byte_len, bytes].concat(),
        }
    }
}

impl LargeValue {
    pub const MAX_SIZE: usize = 520; // bytes

    pub fn value(&self) -> Vec<u8> {
        match self {
            PushdataBytelength(v) | OP_PUSHDATA1(v) | OP_PUSHDATA2(v) | OP_PUSHDATA4(v) => {
                v.clone()
            }
        }
    }

    pub fn is_minimal_push(&self) -> bool {
        match self {
            PushdataBytelength(data) => match data.len() {
                1 => data[0] != 0x81 && (data[0] < 1 || 16 < data[0]),
                _ => true,
            },
            OP_PUSHDATA1(data) => 0x4c <= data.len(),
            OP_PUSHDATA2(data) => 0x100 <= data.len(),
            OP_PUSHDATA4(data) => 0x10000 <= data.len(),
        }
    }
}

impl Serialize for LargeValue {
    /// Wraps in a `PushValue`, then serializes that, since they have the same representation.
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        PushValue::LargeValue(self.clone()).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for LargeValue {
    /// Deserializes to a `PushValue`, then extracts the `LargeValue`.
    fn deserialize<D>(deserializer: D) -> Result<LargeValue, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        PushValue::deserialize(deserializer).and_then(|pv| match pv {
            PushValue::LargeValue(lv) => Ok(lv),
            _ => Err(de::Error::custom("invalid LargeValue")),
        })
    }
}

enum_from_primitive! {
/// Values represented entirely by their opcode byte.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Serialize_repr, Deserialize_repr)]
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
    pub fn value(&self) -> Option<Vec<u8>> {
        match self {
            OP_0 => Some(vec![]),
            OP_1NEGATE => Some(vec![0x81]),
            OP_RESERVED => None,
            _ => Some(vec![u8::from(*self) - (u8::from(OP_1) - 1)]),
        }
    }
}

impl From<SmallValue> for u8 {
    fn from(value: SmallValue) -> Self {
        // This is how you get the discriminant, but using `as` everywhere is too much code smell
        value as u8
    }
}
