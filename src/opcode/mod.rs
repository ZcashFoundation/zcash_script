pub mod operation;
pub mod push_value;

use core::fmt;

use enum_primitive::FromPrimitive;
use serde::{de, Deserialize, Serialize, Serializer};

use operation::{Control, Normal};
use push_value::{LargeValue, SmallValue};

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ReadError {
    pub expected_bytes: usize,
    pub available_bytes: usize,
}

/** Script opcodes */
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Opcode {
    PushValue(PushValue),
    Operation(Operation),
}

impl From<&Opcode> for Vec<u8> {
    fn from(value: &Opcode) -> Self {
        match value {
            Opcode::PushValue(v) => v.into(),
            Opcode::Operation(v) => vec![(*v).into()],
        }
    }
}

fn split_value(script: &[u8], needed_bytes: usize) -> Result<(&[u8], &[u8]), ReadError> {
    script.split_at_checked(needed_bytes).ok_or(ReadError {
        expected_bytes: needed_bytes,
        available_bytes: script.len(),
    })
}

/// First splits `size_size` bytes to determine the size of the value to read, then splits the
/// value.
fn split_tagged_value(script: &[u8], size_size: usize) -> Result<(&[u8], &[u8]), ReadError> {
    split_value(script, size_size).and_then(|(bytes, script)| {
        let mut size = 0;
        for byte in bytes.iter().rev() {
            size <<= 8;
            size |= usize::from(*byte);
        }
        split_value(script, size)
    })
}

fn get_lv(script: &[u8]) -> Result<Option<(LargeValue, &[u8])>, ReadError> {
    use LargeValue::*;

    match script.split_first() {
        None => Err(ReadError {
            expected_bytes: 1,
            available_bytes: 0,
        }),
        Some((leading_byte, script)) => match leading_byte {
            0x4c => split_tagged_value(script, 1)
                .map(|(v, script)| Some((OP_PUSHDATA1(v.to_vec()), script))),
            0x4d => split_tagged_value(script, 2)
                .map(|(v, script)| Some((OP_PUSHDATA2(v.to_vec()), script))),
            0x4e => split_tagged_value(script, 4)
                .map(|(v, script)| Some((OP_PUSHDATA4(v.to_vec()), script))),
            _ => {
                if 0x01 <= *leading_byte && *leading_byte < 0x4c {
                    split_value(script, (*leading_byte).into())
                        .map(|(v, script)| Some((PushdataBytelength(v.to_vec()), script)))
                } else {
                    Ok(None)
                }
            }
        },
    }
}

pub fn parse(script: &[u8]) -> Result<(Opcode, &[u8]), ReadError> {
    get_lv(script).and_then(|r| {
        r.map_or(
            match script.split_first() {
                None => Err(ReadError {
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

impl Serialize for Opcode {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bytes = Vec::<u8>::from(self);
        match bytes[..] {
            [opcode] => serializer.serialize_u8(opcode),
            _ => serializer.serialize_bytes(&bytes),
        }
    }
}

struct OpcodeVisitor;

impl<'de> de::Visitor<'de> for OpcodeVisitor {
    type Value = Opcode;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a slice of bytes")
    }

    fn visit_bytes<E>(self, value: &[u8]) -> Result<Opcode, E>
    where
        E: de::Error,
    {
        parse(value)
            .map_err(|_| E::custom("not enough bytes"))
            .and_then(|(opcode, remainder)| {
                if remainder.is_empty() {
                    Ok(opcode)
                } else {
                    Err(E::custom("leftover bytes"))
                }
            })
    }

    fn visit_u8<E>(self, value: u8) -> Result<Opcode, E>
    where
        E: de::Error,
    {
        Self::visit_bytes(OpcodeVisitor, &[value])
    }
}

impl<'de> Deserialize<'de> for Opcode {
    fn deserialize<D>(deserializer: D) -> Result<Opcode, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        deserializer.deserialize_bytes(OpcodeVisitor)
    }
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum PushValue {
    SmallValue(SmallValue),
    LargeValue(LargeValue),
}

impl PushValue {
    pub fn value(&self) -> Option<Vec<u8>> {
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
}

impl Serialize for PushValue {
    /// Wraps in an `Opcode`, then serializes that, since they have the same representation.
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        Opcode::PushValue(self.clone()).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for PushValue {
    /// Deserializes to an `Opcode` then extracts the `PushValue`.
    fn deserialize<D>(deserializer: D) -> Result<PushValue, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        Opcode::deserialize(deserializer).and_then(|op| match op {
            Opcode::PushValue(pv) => Ok(pv),
            Opcode::Operation(_) => Err(de::Error::custom("invalid PushValue")),
        })
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

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Operation {
    /// - always evaluated
    /// - can be cast to its discriminant
    Control(Control),
    /// - only evaluated on active branch
    /// - can be cast to its discriminant
    Normal(Normal),
    /// `Unknown` is a bit odd. It is executed in the same cases as `Normal`, but making it part of
    /// `Normal` complicated the byte mapping implementation. It also takes any byte, but if you
    /// create one with a byte that represents some other opcode, the interpretation will behave
    /// differently than if you serialize and re-parse it.
    Unknown(u8),
}

impl From<u8> for Operation {
    fn from(value: u8) -> Self {
        Control::from_u8(value).map_or(
            Normal::from_u8(value).map_or(Operation::Unknown(value), Operation::Normal),
            Operation::Control,
        )
    }
}

impl Serialize for Operation {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u8((*self).into())
    }
}

struct OperationVisitor;

impl<'de> de::Visitor<'de> for OperationVisitor {
    type Value = Operation;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a byte")
    }

    fn visit_u8<E>(self, value: u8) -> Result<Operation, E>
    where
        E: de::Error,
    {
        Ok(value.into())
    }
}

impl<'de> Deserialize<'de> for Operation {
    fn deserialize<D>(deserializer: D) -> Result<Operation, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        deserializer.deserialize_u8(OperationVisitor)
    }
}

impl From<Operation> for u8 {
    fn from(value: Operation) -> Self {
        match value {
            Operation::Control(op) => op.into(),
            Operation::Normal(op) => op.into(),
            Operation::Unknown(byte) => byte,
        }
    }
}
