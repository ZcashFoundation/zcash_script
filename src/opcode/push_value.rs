#![allow(non_camel_case_types)]

use bounded_vec::{BoundedVec, EmptyBoundedVec};

use crate::{num, script_error::ScriptError};

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

impl LargeValue {
    const PUSHDATA1_BYTE: u8 = 0x4c;
    const PUSHDATA2_BYTE: u8 = 0x4d;
    const PUSHDATA4_BYTE: u8 = 0x4e;

    pub const MAX_SIZE: usize = 520; // bytes

    /// Returns a [`LargeValue`] as minimally-encoded as possible. That is, non-empty values that
    /// should be minimally-encoded as [`SmallValue`]s will be [`PushdataBytelength`].
    pub fn from_slice(v: &[u8]) -> Option<LargeValue> {
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
        Self::split_value(script, size_size).and_then(|(bytes, script)| {
            let mut size = 0;
            for byte in bytes.iter().rev() {
                size <<= 8;
                size |= usize::from(*byte);
            }
            Self::split_value(script, size)
        })
    }

    /// Parse a single [`LargeValue`] from a script. Returns `Ok(None)` if the first byte doesn’t
    /// correspond to a [`LargeValue`].
    pub fn parse(script: &[u8]) -> Result<Option<(LargeValue, &[u8])>, ScriptError> {
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

impl From<&LargeValue> for Vec<u8> {
    fn from(value: &LargeValue) -> Self {
        let to_vec = |prefix: Option<u8>, contents: &[u8]| {
            prefix
                .into_iter()
                .chain(num::serialize(
                    contents.len().try_into().expect("upper bound fits in i64"),
                ))
                .chain(contents.iter().copied())
                .collect()
        };

        match value {
            PushdataBytelength(bv) => to_vec(None, bv.as_slice()),
            OP_PUSHDATA1(bv) => to_vec(Some(LargeValue::PUSHDATA1_BYTE), bv.as_slice()),
            OP_PUSHDATA2(bv) => to_vec(Some(LargeValue::PUSHDATA2_BYTE), bv.as_slice()),
            OP_PUSHDATA4(bv) => to_vec(Some(LargeValue::PUSHDATA4_BYTE), bv.as_slice()),
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
