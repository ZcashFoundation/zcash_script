//! Convenience definitions for all opcodes.

use crate::{
    opcode::{
        operation::{Control::*, Normal::*},
        Opcode::{self, Operation, PushValue},
        Operation::{Control, Normal},
    },
    pv,
};

pub const _0: Opcode = PushValue(pv::_0);
pub const _1NEGATE: Opcode = PushValue(pv::_1NEGATE);
pub const _1: Opcode = PushValue(pv::_1);
pub const _2: Opcode = PushValue(pv::_2);
pub const _3: Opcode = PushValue(pv::_3);
pub const _4: Opcode = PushValue(pv::_4);
pub const _5: Opcode = PushValue(pv::_5);
pub const _6: Opcode = PushValue(pv::_6);
pub const _7: Opcode = PushValue(pv::_7);
pub const _8: Opcode = PushValue(pv::_8);
pub const _9: Opcode = PushValue(pv::_9);
pub const _10: Opcode = PushValue(pv::_10);
pub const _11: Opcode = PushValue(pv::_11);
pub const _12: Opcode = PushValue(pv::_12);
pub const _13: Opcode = PushValue(pv::_13);
pub const _14: Opcode = PushValue(pv::_14);
pub const _15: Opcode = PushValue(pv::_15);
pub const _16: Opcode = PushValue(pv::_16);

pub fn pushdata_bytelength(value: Vec<u8>) -> Opcode {
    PushValue(pv::pushdata_bytelength(value))
}

pub fn pushdata1(value: Vec<u8>) -> Opcode {
    PushValue(pv::pushdata1(value))
}

pub fn pushdata2(value: Vec<u8>) -> Opcode {
    PushValue(pv::pushdata2(value))
}

pub fn pushdata4(value: Vec<u8>) -> Opcode {
    PushValue(pv::pushdata4(value))
}

pub const NOP: Opcode = Operation(Normal(OP_NOP));
pub const IF: Opcode = Operation(Control(OP_IF));
pub const NOTIF: Opcode = Operation(Control(OP_NOTIF));
pub const ELSE: Opcode = Operation(Control(OP_ELSE));
pub const ENDIF: Opcode = Operation(Control(OP_ENDIF));
pub const VERIFY: Opcode = Operation(Normal(OP_VERIFY));
pub const RETURN: Opcode = Operation(Normal(OP_RETURN));
pub const TOALTSTACK: Opcode = Operation(Normal(OP_TOALTSTACK));
pub const FROMALTSTACK: Opcode = Operation(Normal(OP_FROMALTSTACK));
pub const _2DROP: Opcode = Operation(Normal(OP_2DROP));
pub const _2DUP: Opcode = Operation(Normal(OP_2DUP));
pub const _3DUP: Opcode = Operation(Normal(OP_3DUP));
pub const _2OVER: Opcode = Operation(Normal(OP_2OVER));
pub const _2ROT: Opcode = Operation(Normal(OP_2ROT));
pub const _2SWAP: Opcode = Operation(Normal(OP_2SWAP));
pub const IFDUP: Opcode = Operation(Normal(OP_IFDUP));
pub const DEPTH: Opcode = Operation(Normal(OP_DEPTH));
pub const DROP: Opcode = Operation(Normal(OP_DROP));
pub const DUP: Opcode = Operation(Normal(OP_DUP));
pub const NIP: Opcode = Operation(Normal(OP_NIP));
pub const OVER: Opcode = Operation(Normal(OP_NIP));
pub const PICK: Opcode = Operation(Normal(OP_PICK));
pub const ROLL: Opcode = Operation(Normal(OP_ROLL));
pub const ROT: Opcode = Operation(Normal(OP_ROT));
pub const SWAP: Opcode = Operation(Normal(OP_SWAP));
pub const TUCK: Opcode = Operation(Normal(OP_TUCK));
pub const SIZE: Opcode = Operation(Normal(OP_SIZE));
pub const EQUAL: Opcode = Operation(Normal(OP_EQUAL));
pub const EQUALVERIFY: Opcode = Operation(Normal(OP_EQUALVERIFY));
pub const _1ADD: Opcode = Operation(Normal(OP_1ADD));
pub const _1SUB: Opcode = Operation(Normal(OP_1SUB));
pub const NEGATE: Opcode = Operation(Normal(OP_NEGATE));
pub const ABS: Opcode = Operation(Normal(OP_ABS));
pub const NOT: Opcode = Operation(Normal(OP_NOT));
pub const _0NOTEQUAL: Opcode = Operation(Normal(OP_0NOTEQUAL));
pub const ADD: Opcode = Operation(Normal(OP_ADD));
pub const SUB: Opcode = Operation(Normal(OP_SUB));
pub const BOOLAND: Opcode = Operation(Normal(OP_BOOLAND));
pub const BOOLOR: Opcode = Operation(Normal(OP_BOOLOR));
pub const NUMEQUAL: Opcode = Operation(Normal(OP_NUMEQUAL));
pub const LESSTHAN: Opcode = Operation(Normal(OP_LESSTHAN));
pub const GREATERTHAN: Opcode = Operation(Normal(OP_GREATERTHAN));
pub const LESSTHANOREQUAL: Opcode = Operation(Normal(OP_LESSTHANOREQUAL));
pub const GREATERTHANOREQUAL: Opcode = Operation(Normal(OP_GREATERTHANOREQUAL));
pub const MIN: Opcode = Operation(Normal(OP_MIN));
pub const MAX: Opcode = Operation(Normal(OP_MAX));
pub const WITHIN: Opcode = Operation(Normal(OP_WITHIN));
pub const RIPEMD160: Opcode = Operation(Normal(OP_RIPEMD160));
pub const SHA1: Opcode = Operation(Normal(OP_SHA1));
pub const SHA256: Opcode = Operation(Normal(OP_SHA256));
pub const HASH160: Opcode = Operation(Normal(OP_HASH160));
pub const HASH256: Opcode = Operation(Normal(OP_HASH256));
pub const CHECKSIG: Opcode = Operation(Normal(OP_CHECKSIG));
pub const CHECKSIGVERIFY: Opcode = Operation(Normal(OP_CHECKSIGVERIFY));
pub const CHECKMULTISIG: Opcode = Operation(Normal(OP_CHECKMULTISIG));
pub const CHECKMULTISIGVERIFY: Opcode = Operation(Normal(OP_CHECKMULTISIGVERIFY));
pub const NOP1: Opcode = Operation(Normal(OP_NOP1));
pub const CHECKLOCKTIMEVERIFY: Opcode = Operation(Normal(OP_CHECKLOCKTIMEVERIFY));
pub const NOP3: Opcode = Operation(Normal(OP_NOP3));
pub const NOP4: Opcode = Operation(Normal(OP_NOP4));
pub const NOP5: Opcode = Operation(Normal(OP_NOP5));
pub const NOP6: Opcode = Operation(Normal(OP_NOP6));
pub const NOP7: Opcode = Operation(Normal(OP_NOP7));
pub const NOP8: Opcode = Operation(Normal(OP_NOP8));
pub const NOP9: Opcode = Operation(Normal(OP_NOP9));
pub const NOP10: Opcode = Operation(Normal(OP_NOP10));

pub mod bad {
    use crate::{
        opcode::{
            operation::{Control::*, Normal::*},
            Opcode::{self, Operation, PushValue},
            Operation::{Control, Normal},
        },
        pv,
    };

    pub const RESERVED: Opcode = PushValue(pv::bad::RESERVED);
    pub const VERIF: Opcode = Operation(Control(OP_VERIF));
    pub const VERNOTIF: Opcode = Operation(Control(OP_VERNOTIF));
    pub const VER: Opcode = Operation(Normal(OP_VER));
    pub const RESERVED1: Opcode = Operation(Normal(OP_RESERVED1));
    pub const RESERVED2: Opcode = Operation(Normal(OP_RESERVED2));
}
