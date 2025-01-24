pub mod operation;
pub mod push_value;

use enum_primitive::FromPrimitive;

use operation::{Control, Normal};
use push_value::{LargeValue, SmallValue};

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

impl From<&PushValue> for Vec<u8> {
    fn from(value: &PushValue) -> Self {
        match value {
            PushValue::SmallValue(v) => vec![(*v).into()],
            PushValue::LargeValue(v) => v.into(),
        }
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

impl From<u8> for Operation {
    fn from(value: u8) -> Self {
        Control::from_u8(value).map_or(
            Normal::from_u8(value).map_or(Operation::Unknown(value), Operation::Normal),
            Operation::Control,
        )
    }
}
