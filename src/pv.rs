//! Convenience definitions for all push values.

use crate::opcode::{
    push_value::{LargeValue::*, SmallValue::*},
    PushValue::{self, LargeValue, SmallValue},
};

pub const _0: PushValue = SmallValue(OP_0);
pub const _1NEGATE: PushValue = SmallValue(OP_1NEGATE);
pub const _1: PushValue = SmallValue(OP_1);
pub const _2: PushValue = SmallValue(OP_2);
pub const _3: PushValue = SmallValue(OP_3);
pub const _4: PushValue = SmallValue(OP_4);
pub const _5: PushValue = SmallValue(OP_5);
pub const _6: PushValue = SmallValue(OP_6);
pub const _7: PushValue = SmallValue(OP_7);
pub const _8: PushValue = SmallValue(OP_8);
pub const _9: PushValue = SmallValue(OP_9);
pub const _10: PushValue = SmallValue(OP_10);
pub const _11: PushValue = SmallValue(OP_11);
pub const _12: PushValue = SmallValue(OP_12);
pub const _13: PushValue = SmallValue(OP_13);
pub const _14: PushValue = SmallValue(OP_14);
pub const _15: PushValue = SmallValue(OP_15);
pub const _16: PushValue = SmallValue(OP_16);

pub fn pushdata_bytelength(value: Vec<u8>) -> PushValue {
    LargeValue(PushdataBytelength(value))
}

pub fn pushdata1(value: Vec<u8>) -> PushValue {
    LargeValue(OP_PUSHDATA1(value))
}

pub fn pushdata2(value: Vec<u8>) -> PushValue {
    LargeValue(OP_PUSHDATA2(value))
}

pub fn pushdata4(value: Vec<u8>) -> PushValue {
    LargeValue(OP_PUSHDATA4(value))
}

pub mod bad {
    use crate::opcode::{
        push_value::SmallValue::*,
        PushValue::{self, SmallValue},
    };

    pub const RESERVED: PushValue = SmallValue(OP_RESERVED);
}
