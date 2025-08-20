#![allow(non_camel_case_types)]

use std::{collections::VecDeque, fmt::Display};

use enum_primitive::FromPrimitive;
use ripemd::Ripemd160;
use secp256k1::ecdsa;
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::{Digest, Sha256};

use crate::{external::pubkey::PubKey, interpreter::*, script, scriptnum::*};

fn is_compressed_or_uncompressed_pub_key(vch_pub_key: &[u8]) -> bool {
    match vch_pub_key[0] {
        0x02 | 0x03 => vch_pub_key.len() == PubKey::COMPRESSED_SIZE,
        0x04 => vch_pub_key.len() == PubKey::SIZE,
        _ => false, // not a public key
    }
}

fn decode_signature(
    vch_sig_in: &[u8],
    is_strict: bool,
) -> Result<Option<Signature>, script::Error> {
    match vch_sig_in.split_last() {
        // Empty signature. Not strictly DER encoded, but allowed to provide a compact way to
        // provide an invalid signature for use with CHECK(MULTI)SIG
        None => Ok(None),
        Some((hash_type, vch_sig)) => Ok(Some(Signature {
            sig: ecdsa::Signature::from_der(vch_sig).map_err(script::Error::SigDER)?,
            sighash: HashType::from_bits((*hash_type).into(), is_strict)
                .map_err(script::Error::SigHashType)?,
        })),
    }
}

pub(crate) fn check_signature_encoding(
    vch_sig: &[u8],
    flags: VerificationFlags,
) -> Result<Option<Signature>, script::Error> {
    decode_signature(vch_sig, flags.contains(VerificationFlags::StrictEnc)).and_then(
        |sig| match sig {
            None => Ok(None),
            Some(sig0) => {
                if flags.contains(VerificationFlags::LowS) && !PubKey::check_low_s(&sig0.sig) {
                    Err(script::Error::SigHighS)
                } else {
                    Ok(Some(sig0))
                }
            }
        },
    )
}

fn check_pub_key_encoding(vch_sig: &[u8], flags: VerificationFlags) -> Result<(), script::Error> {
    if flags.contains(VerificationFlags::StrictEnc)
        && !is_compressed_or_uncompressed_pub_key(vch_sig)
    {
        return Err(script::Error::PubKeyType);
    };
    Ok(())
}

fn is_sig_valid(
    vch_sig: &[u8],
    vch_pub_key: &[u8],
    flags: VerificationFlags,
    script: &[u8],
    checker: &dyn SignatureChecker,
) -> Result<bool, script::Error> {
    let sig = check_signature_encoding(vch_sig, flags)?;
    check_pub_key_encoding(vch_pub_key, flags).map(|()| {
        sig.map(|sig0| checker.check_sig(&sig0, &vch_pub_key, script))
            .unwrap_or(false)
    })
}

const BN_ZERO: ScriptNum = ScriptNum(0);
const BN_ONE: ScriptNum = ScriptNum(1);
const VCH_FALSE: Vec<u8> = Vec::new();
const VCH_TRUE: [u8; 1] = [1];

fn cast_from_bool(b: bool) -> Vec<u8> {
    if b {
        VCH_TRUE.to_vec()
    } else {
        VCH_FALSE
    }
}

fn unop<T: Clone>(
    stack: &mut Stack<T>,
    op: impl Fn(T) -> Result<T, script::Error>,
) -> Result<(), script::Error> {
    let item = stack.pop()?;
    op(item).map(|res| stack.push(res))
}

fn binop<T: Clone>(
    stack: &mut Stack<T>,
    op: impl Fn(T, T) -> Result<T, script::Error>,
) -> Result<(), script::Error> {
    let x2 = stack.pop()?;
    let x1 = stack.pop()?;
    op(x1, x2).map(|res| stack.push(res))
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Deserialize, Serialize)]
pub enum Operation {
    /// - always evaluated
    /// - can be cast to its discriminant
    Control(Control),
    /// - only evaluated on active branch
    /// - can be cast to its discriminant
    Normal(Normal),
    /// - only evaluated on active branch
    Unknown(u8),
}

impl Operation {
    pub fn well_formed(
        &self,
        flags: VerificationFlags,
        op_count: &mut u8,
        vexec: &mut Stack<bool>,
    ) -> Result<(), script::Error> {
        // Note how OP_RESERVED does not count towards the opcode limit.
        *op_count += 1;
        if *op_count <= 201 {
            match self {
                Operation::Control(control) => control.well_formed(vexec),
                Operation::Normal(normal) => normal.well_formed(flags),
                Operation::Unknown(byte) => Err(script::Error::BadOpcode(Some(*byte))),
            }
        } else {
            Err(script::Error::OpCount)
        }
    }

    pub fn eval(
        &self,
        flags: VerificationFlags,
        script: &[u8],
        checker: &dyn SignatureChecker,
        state: &mut State,
    ) -> Result<(), script::Error> {
        let stack = &mut state.stack;
        let op_count = &mut state.op_count;
        let vexec = &mut state.vexec;
        let altstack = &mut state.altstack;

        // Note how OP_RESERVED does not count towards the opcode limit.
        *op_count += 1;
        if *op_count <= 201 {
            match self {
                Operation::Control(control) => control.eval(stack, vexec),
                Operation::Normal(normal) => {
                    if should_exec(vexec) {
                        normal.eval(flags, script, checker, stack, altstack, op_count)
                    } else {
                        Ok(())
                    }
                }
                Operation::Unknown(byte) => {
                    if should_exec(vexec) {
                        Err(script::Error::BadOpcode(Some(*byte)))
                    } else {
                        Ok(())
                    }
                }
            }
        } else {
            Err(script::Error::OpCount)
        }
    }
}

impl script::Parsable for Operation {
    fn to_bytes(&self) -> Vec<u8> {
        vec![(*self).into()]
    }

    fn from_bytes(script: &[u8]) -> Result<(Self, &[u8]), script::Error> {
        script
            .split_first()
            .map(|(&leading_byte, script)| (Operation::from(leading_byte), script))
            .ok_or(script::Error::ReadError {
                expected_bytes: 1,
                available_bytes: 0,
            })
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

impl From<Operation> for u8 {
    fn from(value: Operation) -> Self {
        match value {
            Operation::Control(v) => v.into(),
            Operation::Normal(v) => v.into(),
            Operation::Unknown(byte) => byte,
        }
    }
}

impl Display for Operation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Operation::Control(control) => write!(f, "{}", control),
            Operation::Normal(normal) => write!(f, "{}", normal),
            Operation::Unknown(byte) => write!(f, "{:02x}", byte),
        }
    }
}

// Are we in an executing branch of the script?
pub fn should_exec(vexec: &Stack<bool>) -> bool {
    vexec.iter().all(|value| *value)
}

enum_from_primitive! {
/// Control operations are evaluated regardless of whether the current branch is active.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Deserialize, Serialize)]
#[repr(u8)]
pub enum Control {
    OP_IF = 0x63,
    OP_NOTIF = 0x64,
    OP_VERIF = 0x65,
    OP_VERNOTIF = 0x66,
    OP_ELSE = 0x67,
    OP_ENDIF = 0x68,

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

use Control::*;

impl Control {
    /// Processes the script generically – i.e., any errors that occur would occur regardless of the
    /// initial stack it’s provided.
    pub fn well_formed(&self, vexec: &mut Stack<bool>) -> Result<(), script::Error> {
        match self {
            OP_IF | OP_NOTIF => Ok(vexec.push(true)),

            OP_ELSE => vexec
                .rget(0)
                .map_err(|_| script::Error::UnbalancedConditional)
                .map(|_| ()),

            OP_ENDIF => vexec
                .pop()
                .map_err(|_| script::Error::UnbalancedConditional)
                .map(|_| ()),

            OP_VERIF | OP_VERNOTIF => Err(script::Error::BadOpcode(Some((*self).into()))),

            // Disabled operations fail whenever they appear in a script, regardless of whether
            // they are on an active branch.
            OP_CAT | OP_SUBSTR | OP_LEFT | OP_RIGHT | OP_INVERT | OP_AND | OP_OR | OP_XOR
            | OP_2MUL | OP_2DIV | OP_MUL | OP_DIV | OP_MOD | OP_LSHIFT | OP_RSHIFT
            | OP_CODESEPARATOR => Err(script::Error::DisabledOpcode((*self).into())),
        }
    }

    /// <expression> if [statements] [else [statements]] endif
    pub fn eval(
        &self,
        stack: &mut Stack<Vec<u8>>,
        vexec: &mut Stack<bool>,
    ) -> Result<(), script::Error> {
        match self {
            OP_IF | OP_NOTIF => Ok(vexec.push(if should_exec(vexec) {
                let vch = stack
                    .pop()
                    .map_err(|_| script::Error::UnbalancedConditional)?;
                let value = cast_to_bool(&vch);
                if *self == OP_NOTIF {
                    !value
                } else {
                    value
                }
            } else {
                false
            })),

            OP_ELSE => vexec
                .pop()
                .map_err(|_| script::Error::UnbalancedConditional)
                .map(|last| vexec.push(!last)),

            OP_ENDIF => vexec
                .pop()
                .map_err(|_| script::Error::UnbalancedConditional)
                .map(|_| ()),

            OP_VERIF | OP_VERNOTIF => Err(script::Error::BadOpcode(Some((*self).into()))),

            // Disabled operations fail whenever they appear in a script, regardless of whether
            // they are on an active branch.
            OP_CAT | OP_SUBSTR | OP_LEFT | OP_RIGHT | OP_INVERT | OP_AND | OP_OR | OP_XOR
            | OP_2MUL | OP_2DIV | OP_MUL | OP_DIV | OP_MOD | OP_LSHIFT | OP_RSHIFT
            | OP_CODESEPARATOR => Err(script::Error::DisabledOpcode((*self).into())),
        }
    }
}

impl From<Control> for u8 {
    fn from(value: Control) -> Self {
        // This is how you get the discriminant, but using `as` everywhere is too much code smell
        value as u8
    }
}

impl Display for Control {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OP_IF => write!(f, "OP_IF"),
            OP_NOTIF => write!(f, "OP_NOTIF"),
            OP_VERIF => write!(f, "OP_VERIF"),
            OP_VERNOTIF => write!(f, "OP_VERNOTIF"),
            OP_ELSE => write!(f, "OP_ELSE"),
            OP_ENDIF => write!(f, "OP_ENDIF"),
            OP_CAT => write!(f, "OP_CAT"),
            OP_SUBSTR => write!(f, "OP_SUBSTR"),
            OP_LEFT => write!(f, "OP_LEFT"),
            OP_RIGHT => write!(f, "OP_RIGHT"),
            OP_INVERT => write!(f, "OP_INVERT"),
            OP_AND => write!(f, "OP_AND"),
            OP_OR => write!(f, "OP_OR"),
            OP_XOR => write!(f, "OP_XOR"),
            OP_2MUL => write!(f, "OP_2MUL"),
            OP_2DIV => write!(f, "OP_2DIV"),
            OP_MUL => write!(f, "OP_MUL"),
            OP_DIV => write!(f, "OP_DIV"),
            OP_MOD => write!(f, "OP_MOD"),
            OP_LSHIFT => write!(f, "OP_LSHIFT"),
            OP_RSHIFT => write!(f, "OP_RSHIFT"),
            OP_CODESEPARATOR => write!(f, "OP_CODESEPARATOR"),
        }
    }
}

enum_from_primitive! {
/// Normal operations are only executed when they are on an active branch.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Deserialize, Serialize)]
#[repr(u8)]
pub enum Normal {
    // control
    OP_NOP = 0x61,
    OP_VER = 0x62,
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
    OP_RESERVED1 = 0x89,
    OP_RESERVED2 = 0x8a,

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

use Normal::*;

impl Normal {
    pub fn well_formed(&self, flags: VerificationFlags) -> Result<(), script::Error> {
        match self {
            OP_CHECKLOCKTIMEVERIFY => {
                if !flags.contains(VerificationFlags::CHECKLOCKTIMEVERIFY)
                    && flags.contains(VerificationFlags::DiscourageUpgradableNOPs)
                {
                    Err(script::Error::DiscourageUpgradableNOPs)
                } else {
                    Ok(())
                }
            }
            OP_NOP1 | OP_NOP3 | OP_NOP4 | OP_NOP5 | OP_NOP6 | OP_NOP7 | OP_NOP8 | OP_NOP9
            | OP_NOP10 => {
                if flags.contains(VerificationFlags::DiscourageUpgradableNOPs) {
                    Err(script::Error::DiscourageUpgradableNOPs)
                } else {
                    Ok(())
                }
            }
            OP_RETURN => Err(script::Error::OpReturn),
            OP_VER | OP_RESERVED1 | OP_RESERVED2 => {
                Err(script::Error::BadOpcode(Some((*self).into())))
            }
            _ => Ok(()),
        }
    }

    pub fn eval(
        &self,
        flags: VerificationFlags,
        script: &[u8],
        checker: &dyn SignatureChecker,
        stack: &mut Stack<Vec<u8>>,
        altstack: &mut Stack<Vec<u8>>,
        op_count: &mut u8,
    ) -> Result<(), script::Error> {
        let require_minimal = flags.contains(VerificationFlags::MinimalData);

        let unop_num = |stackin: &mut Stack<Vec<u8>>,
                        op: &dyn Fn(ScriptNum) -> ScriptNum|
         -> Result<(), script::Error> {
            unop(stackin, |vch| {
                ScriptNum::new(&vch, require_minimal, None)
                    .map_err(script::Error::ScriptNumError)
                    .map(|bn| op(bn).getvch())
            })
        };

        let binop_num = |stack: &mut Stack<Vec<u8>>,
                         op: &dyn Fn(ScriptNum, ScriptNum) -> Vec<u8>|
         -> Result<(), script::Error> {
            binop(stack, |x1, x2| {
                let bn2 = ScriptNum::new(&x2, require_minimal, None)
                    .map_err(script::Error::ScriptNumError)?;
                let bn1 = ScriptNum::new(&x1, require_minimal, None)
                    .map_err(script::Error::ScriptNumError)?;
                Ok(op(bn1, bn2))
            })
        };

        let magma = |stack: &mut Stack<Vec<u8>>,
                     op: &dyn Fn(ScriptNum, ScriptNum) -> ScriptNum|
         -> Result<(), script::Error> {
            binop_num(stack, &|bn1, bn2| op(bn1, bn2).getvch())
        };

        let binrel = |stack: &mut Stack<Vec<u8>>,
                      op: &dyn Fn(ScriptNum, ScriptNum) -> bool|
         -> Result<(), script::Error> {
            binop_num(stack, &|bn1, bn2| cast_from_bool(op(bn1, bn2)))
        };

        match self {
            //
            // Control
            //
            OP_NOP => Ok(()),

            OP_CHECKLOCKTIMEVERIFY => {
                // This was originally OP_NOP2 but has been repurposed
                // for OP_CHECKLOCKTIMEVERIFY. So, we should act based
                // on whether or not CLTV has been activated in a soft
                // fork.
                if !flags.contains(VerificationFlags::CHECKLOCKTIMEVERIFY) {
                    if flags.contains(VerificationFlags::DiscourageUpgradableNOPs) {
                        Err(script::Error::DiscourageUpgradableNOPs)
                    } else {
                        Ok(())
                    }
                } else {
                    // Note that elsewhere numeric opcodes are limited to
                    // operands in the range -2**31+1 to 2**31-1, however it is
                    // legal for opcodes to produce results exceeding that
                    // range. This limitation is implemented by `ScriptNum`'s
                    // default 4-byte limit.
                    //
                    // If we kept to that limit we'd have a year 2038 problem,
                    // even though the `lock_time` field in transactions
                    // themselves is u32 which only becomes meaningless
                    // after the year 2106.
                    //
                    // Thus as a special case we tell `ScriptNum` to accept up
                    // to 5-byte bignums, which are good until 2**39-1, well
                    // beyond the 2**32-1 limit of the `lock_time` field itself.
                    let lock_time = ScriptNum::new(stack.rget(0)?, require_minimal, Some(5))
                        .map_err(script::Error::ScriptNumError)?;

                    // In the rare event that the argument may be < 0 due to
                    // some arithmetic being done first, you can always use
                    // 0 MAX CHECKLOCKTIMEVERIFY.
                    if lock_time < ScriptNum(0) {
                        return Err(script::Error::NegativeLockTime);
                    }

                    // Actually compare the specified lock time with the transaction.
                    if checker.check_lock_time(&lock_time) {
                        Ok(())
                    } else {
                        Err(script::Error::UnsatisfiedLockTime)
                    }
                }
            }

            OP_NOP1 | OP_NOP3 | OP_NOP4 | OP_NOP5 | OP_NOP6 | OP_NOP7 | OP_NOP8 | OP_NOP9
            | OP_NOP10 => {
                // Do nothing, though if the caller wants to prevent people from using
                // these NOPs (as part of a standard tx rule, for example) they can
                // enable `DiscourageUpgradableNOPs` to turn these opcodes into errors.
                if flags.contains(VerificationFlags::DiscourageUpgradableNOPs) {
                    Err(script::Error::DiscourageUpgradableNOPs)
                } else {
                    Ok(())
                }
            }

            // (true -- ) or
            // (false -- false) and return
            OP_VERIFY => stack.pop().and_then(|vch| {
                if cast_to_bool(&vch) {
                    Ok(())
                } else {
                    Err(script::Error::Verify)
                }
            }),

            OP_RETURN => Err(script::Error::OpReturn),

            //
            // Stack ops
            //
            OP_TOALTSTACK => stack.pop().map(|vch| altstack.push(vch)),

            OP_FROMALTSTACK => altstack
                .pop()
                .map_err(|_| script::Error::InvalidAltstackOperation)
                .map(|vch| stack.push(vch)),

            // (x1 x2 --)
            OP_2DROP => stack.pop().and_then(|_| stack.pop()).map(|_| ()),

            // (x1 x2 -- x1 x2 x1 x2)
            OP_2DUP => stack.push_dup(1).and_then(|_| stack.push_dup(1)),

            // (x1 x2 x3 -- x1 x2 x3 x1 x2 x3)
            OP_3DUP => stack
                .push_dup(2)
                .and_then(|_| stack.push_dup(2))
                .and_then(|_| stack.push_dup(2)),

            // (x1 x2 x3 x4 -- x1 x2 x3 x4 x1 x2)
            OP_2OVER => stack.push_dup(3).and_then(|_| stack.push_dup(3)),

            // (x1 x2 x3 x4 x5 x6 -- x3 x4 x5 x6 x1 x2)
            OP_2ROT => stack.rget(4).cloned().and_then(|vch2| {
                stack
                    .rget(5)
                    .cloned()
                    .and_then(|vch1| stack.erase(6, Some(4)).map(|()| stack.push(vch1)))
                    .map(|()| stack.push(vch2))
            }),

            // (x1 x2 x3 x4 -- x3 x4 x1 x2)
            OP_2SWAP => stack.swap(3, 1).and_then(|()| stack.swap(2, 0)),

            // (x - 0 | x x)
            OP_IFDUP => {
                let vch = stack.rget(0)?;
                Ok(if cast_to_bool(vch) {
                    stack.push(vch.clone())
                })
            }

            // -- stacksize
            OP_DEPTH => i64::try_from(stack.len())
                .map_err(|err| script::Error::StackSize(Some(err)))
                .map(|bn| stack.push(ScriptNum(bn).getvch())),

            // (x -- )
            OP_DROP => stack.pop().map(|_| ()),

            // (x -- x x)
            OP_DUP => stack.push_dup(0),

            // (x1 x2 -- x2)
            OP_NIP => stack.erase(2, None),

            // (x1 x2 -- x1 x2 x1)
            OP_OVER => stack.push_dup(1),

            // (xn ... x2 x1 x0 n - xn ... x2 x1 x0 xn)
            // (xn ... x2 x1 x0 n - ... x2 x1 x0 xn)
            OP_PICK | OP_ROLL => stack
                .pop()
                .and_then(|vch| {
                    ScriptNum::new(&vch, require_minimal, None)
                        .map_err(script::Error::ScriptNumError)
                })
                .and_then(|num| {
                    usize::try_from(num.getint()).map_err(|_| script::Error::InvalidStackOperation)
                })
                .and_then(|n| {
                    stack.rget(n).cloned().and_then(|vch| {
                        if *self == OP_ROLL {
                            stack.erase(n, None)?;
                        }
                        Ok(stack.push(vch))
                    })
                }),

            // (x1 x2 x3 -- x2 x3 x1)
            //  x2 x1 x3  after first swap
            //  x2 x3 x1  after second swap
            OP_ROT => stack.swap(2, 1).and_then(|()| stack.swap(1, 0)),

            // (x1 x2 -- x2 x1)
            OP_SWAP => stack.swap(1, 0),

            // (x1 x2 -- x2 x1 x2)
            OP_TUCK => stack.rget(0).cloned().and_then(|vch| stack.insert(2, vch)),

            // (in -- in size)
            OP_SIZE => stack
                .rget(0)?
                .len()
                .try_into()
                .map_err(|err| script::Error::PushSize(Some(err)))
                .map(|n| stack.push(ScriptNum(n).getvch())),

            //
            // Bitwise logic
            //

            // (x1 x2 - bool)
            OP_EQUAL => binop(stack, &|x1, x2| Ok(cast_from_bool(x1 == x2))),
            // (x1 x2 - bool)
            OP_EQUALVERIFY => stack.pop().and_then(|vch2| {
                stack.pop().and_then(|vch1| {
                    if vch1 == vch2 {
                        Ok(())
                    } else {
                        Err(script::Error::EqualVerify)
                    }
                })
            }),

            //
            // Numeric
            //
            OP_1ADD => unop_num(stack, &|x| x + BN_ONE),
            OP_1SUB => unop_num(stack, &|x| x - BN_ONE),
            OP_NEGATE => unop_num(stack, &|x| -x),
            OP_ABS => unop_num(stack, &|x| if x < BN_ZERO { -x } else { x }),
            OP_NOT => unop_num(stack, &|x| ScriptNum((x == BN_ZERO).into())),
            OP_0NOTEQUAL => unop_num(stack, &|x| ScriptNum((x != BN_ZERO).into())),

            // (x1 x2 -- out)
            OP_ADD => magma(stack, &|x1, x2| x1 + x2),
            OP_SUB => magma(stack, &|x1, x2| x1 - x2),
            OP_BOOLAND => binrel(stack, &|x1, x2| x1 != BN_ZERO && x2 != BN_ZERO),
            OP_BOOLOR => binrel(stack, &|x1, x2| x1 != BN_ZERO || x2 != BN_ZERO),
            OP_NUMEQUAL => binrel(stack, &|x1, x2| x1 == x2),
            OP_NUMEQUALVERIFY => {
                let x2 = stack.pop()?;
                let x1 = stack.pop()?;
                ScriptNum::new(&x1, require_minimal, None)
                    .map_err(script::Error::ScriptNumError)
                    .and_then(|bn1| {
                        ScriptNum::new(&x2, require_minimal, None)
                            .map_err(script::Error::ScriptNumError)
                            .and_then(|bn2| {
                                if bn1 == bn2 {
                                    Ok(())
                                } else {
                                    Err(script::Error::NumEqualVerify)
                                }
                            })
                    })
            }
            OP_NUMNOTEQUAL => binrel(stack, &|x1, x2| x1 != x2),
            OP_LESSTHAN => binrel(stack, &|x1, x2| x1 < x2),
            OP_GREATERTHAN => binrel(stack, &|x1, x2| x1 > x2),
            OP_LESSTHANOREQUAL => binrel(stack, &|x1, x2| x1 <= x2),
            OP_GREATERTHANOREQUAL => binrel(stack, &|x1, x2| x1 >= x2),
            OP_MIN => magma(stack, &|x1, x2| {
                if x1 < x2 {
                    x1
                } else {
                    x2
                }
            }),
            OP_MAX => magma(stack, &|x1, x2| {
                if x1 > x2 {
                    x1
                } else {
                    x2
                }
            }),

            // (x min max -- out)
            OP_WITHIN => stack.pop().and_then(|x3| {
                stack.pop().and_then(|x2| {
                    stack.pop().and_then(|x1| {
                        ScriptNum::new(&x1, require_minimal, None)
                            .and_then(|bn1| {
                                ScriptNum::new(&x2, require_minimal, None).and_then(|bn2| {
                                    ScriptNum::new(&x3, require_minimal, None).map(|bn3| {
                                        stack.push(cast_from_bool(bn2 <= bn1 && bn1 < bn3))
                                    })
                                })
                            })
                            .map_err(script::Error::ScriptNumError)
                    })
                })
            }),

            //
            // Crypto
            //
            OP_RIPEMD160 => unop(stack, &|hash| Ok(Ripemd160::digest(hash).to_vec())),
            OP_SHA1 => unop(stack, &|hash| {
                let mut hasher = Sha1::new();
                hasher.update(hash);
                Ok(hasher.finalize().to_vec())
            }),
            OP_SHA256 => unop(stack, &|hash| Ok(Sha256::digest(hash).to_vec())),
            OP_HASH160 => unop(stack, &|hash| {
                Ok(Ripemd160::digest(Sha256::digest(hash)).to_vec())
            }),
            OP_HASH256 => unop(stack, &|hash| {
                Ok(Sha256::digest(Sha256::digest(hash)).to_vec())
            }),

            // (sig pubkey -- bool)
            OP_CHECKSIG | OP_CHECKSIGVERIFY => {
                let vch_pub_key = &stack.pop()?;
                let vch_sig = &stack.pop()?;
                let success = is_sig_valid(&vch_sig, &vch_pub_key, flags, script, checker)?;
                if *self == OP_CHECKSIGVERIFY {
                    if success {
                        Ok(())
                    } else {
                        Err(script::Error::CheckSigVerify)
                    }
                } else {
                    Ok(stack.push(cast_from_bool(success)))
                }
            }

            // ([sig ...] num_of_signatures [pubkey ...] num_of_pubkeys -- bool)
            OP_CHECKMULTISIG | OP_CHECKMULTISIGVERIFY => {
                let keys_count = stack
                    .pop()
                    .and_then(|vch| {
                        ScriptNum::new(&vch, require_minimal, None)
                            .map_err(script::Error::ScriptNumError)
                    })
                    .and_then(|bn| {
                        u8::try_from(bn.getint())
                            .map_err(|err| script::Error::PubKeyCount(Some(err)))
                    })?;
                if keys_count > 20 {
                    return Err(script::Error::PubKeyCount(None));
                };
                *op_count += keys_count;
                if *op_count > 201 {
                    return Err(script::Error::OpCount);
                };

                let mut keys = VecDeque::with_capacity(keys_count.into());
                for _ in 0..keys_count {
                    stack.pop().map(|key| keys.push_back(key))?;
                }

                let sigs_count = stack
                    .pop()
                    .and_then(|vch| {
                        ScriptNum::new(&vch, require_minimal, None)
                            .map_err(script::Error::ScriptNumError)
                    })
                    .and_then(|bn| {
                        usize::try_from(bn.getint())
                            .map_err(|err| script::Error::SigCount(Some(err)))
                    })?;
                if sigs_count > keys_count.into() {
                    Err(script::Error::SigCount(None))
                } else {
                    // Note how this makes the exact order of pubkey/signature evaluation
                    // distinguishable by CHECKMULTISIG NOT if the STRICTENC flag is set. See the
                    // script_(in)valid tests for details.
                    let success = (0..sigs_count).rfold(Ok(true), |acc, i| {
                        acc.and_then(|prev| {
                            stack.pop().and_then(|sig| {
                                if prev {
                                    while let Some(key) = keys.pop_front() {
                                        if is_sig_valid(&sig, &key, flags, script, checker)? {
                                            return Ok(true);
                                        } else if keys.len() < i {
                                            // If there are more signatures left than keys left, then
                                            // too many signatures have failed. Exit early, without
                                            // checking any further signatures.
                                            return Ok(false);
                                        }
                                    }
                                    Ok(false)
                                } else {
                                    Ok(false)
                                }
                            })
                        })
                    })?;

                    // A bug causes CHECKMULTISIG to consume one extra argument whose contents were not
                    // checked in any way.
                    //
                    // Unfortunately this is a potential source of mutability, so optionally verify it
                    // is exactly equal to zero prior to removing it from the stack.
                    if !stack.pop()?.is_empty() && flags.contains(VerificationFlags::NullDummy) {
                        Err(script::Error::SigNullDummy)
                    } else if *self == OP_CHECKMULTISIGVERIFY {
                        if success {
                            Ok(())
                        } else {
                            Err(script::Error::CheckMultisigVerify)
                        }
                    } else {
                        Ok(stack.push(cast_from_bool(success)))
                    }
                }
            }
            OP_VER | OP_RESERVED1 | OP_RESERVED2 => {
                Err(script::Error::BadOpcode(Some((*self).into())))
            }
        }
    }
}

impl From<Normal> for u8 {
    fn from(value: Normal) -> Self {
        // This is how you get the discriminant, but using `as` everywhere is too much code smell
        value as u8
    }
}

impl Display for Normal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OP_NOP => write!(f, "OP_NOP"),
            OP_VER => write!(f, "OP_VER"),
            OP_VERIFY => write!(f, "OP_VERIFY"),
            OP_RETURN => write!(f, "OP_RETURN"),
            OP_TOALTSTACK => write!(f, "OP_TOALTSTACK"),
            OP_FROMALTSTACK => write!(f, "OP_FROMALTSTACK"),
            OP_2DROP => write!(f, "OP_2DROP"),
            OP_2DUP => write!(f, "OP_2DUP"),
            OP_3DUP => write!(f, "OP_3DUP"),
            OP_2OVER => write!(f, "OP_2OVER"),
            OP_2ROT => write!(f, "OP_2ROT"),
            OP_2SWAP => write!(f, "OP_2SWAP"),
            OP_IFDUP => write!(f, "OP_IFDUP"),
            OP_DEPTH => write!(f, "OP_DEPTH"),
            OP_DROP => write!(f, "OP_DROP"),
            OP_DUP => write!(f, "OP_DUP"),
            OP_NIP => write!(f, "OP_NIP"),
            OP_OVER => write!(f, "OP_OVER"),
            OP_PICK => write!(f, "OP_PICK"),
            OP_ROLL => write!(f, "OP_ROLL"),
            OP_ROT => write!(f, "OP_ROT"),
            OP_SWAP => write!(f, "OP_SWAP"),
            OP_TUCK => write!(f, "OP_TUCK"),
            OP_SIZE => write!(f, "OP_SIZE"),
            OP_EQUAL => write!(f, "OP_EQUAL"),
            OP_EQUALVERIFY => write!(f, "OP_EQUALVERIFY"),
            OP_RESERVED1 => write!(f, "OP_RESERVED1"),
            OP_RESERVED2 => write!(f, "OP_RESERVED2"),
            OP_1ADD => write!(f, "OP_1ADD"),
            OP_1SUB => write!(f, "OP_1SUB"),
            OP_NEGATE => write!(f, "OP_NEGATE"),
            OP_ABS => write!(f, "OP_ABS"),
            OP_NOT => write!(f, "OP_NOT"),
            OP_0NOTEQUAL => write!(f, "OP_0NOTEQUAL"),
            OP_ADD => write!(f, "OP_ADD"),
            OP_SUB => write!(f, "OP_SUB"),
            OP_BOOLAND => write!(f, "OP_BOOLAND"),
            OP_BOOLOR => write!(f, "OP_BOOLOR"),
            OP_NUMEQUAL => write!(f, "OP_NUMEQUAL"),
            OP_NUMEQUALVERIFY => write!(f, "OP_NUMEQUALVERIFY"),
            OP_NUMNOTEQUAL => write!(f, "OP_NUMNOTEQUAL"),
            OP_LESSTHAN => write!(f, "OP_LESSTHAN"),
            OP_GREATERTHAN => write!(f, "OP_GREATERTHAN"),
            OP_LESSTHANOREQUAL => write!(f, "OP_LESSTHANOREQUAL"),
            OP_GREATERTHANOREQUAL => write!(f, "OP_GREATERTHANOREQUAL"),
            OP_MIN => write!(f, "OP_MIN"),
            OP_MAX => write!(f, "OP_MAX"),
            OP_WITHIN => write!(f, "OP_WITHIN"),
            OP_RIPEMD160 => write!(f, "OP_RIPEMD160"),
            OP_SHA1 => write!(f, "OP_SHA1"),
            OP_SHA256 => write!(f, "OP_SHA256"),
            OP_HASH160 => write!(f, "OP_HASH160"),
            OP_HASH256 => write!(f, "OP_HASH256"),
            OP_CHECKSIG => write!(f, "OP_CHECKSIG"),
            OP_CHECKSIGVERIFY => write!(f, "OP_CHECKSIGVERIFY"),
            OP_CHECKMULTISIG => write!(f, "OP_CHECKMULTISIG"),
            OP_CHECKMULTISIGVERIFY => write!(f, "OP_CHECKMULTISIGVERIFY"),
            OP_NOP1 => write!(f, "OP_NOP1"),
            // exception for retrocompatibility
            OP_CHECKLOCKTIMEVERIFY => write!(f, "OP_NOP2"),
            OP_NOP3 => write!(f, "OP_NOP3"),
            OP_NOP4 => write!(f, "OP_NOP4"),
            OP_NOP5 => write!(f, "OP_NOP5"),
            OP_NOP6 => write!(f, "OP_NOP6"),
            OP_NOP7 => write!(f, "OP_NOP7"),
            OP_NOP8 => write!(f, "OP_NOP8"),
            OP_NOP9 => write!(f, "OP_NOP9"),
            OP_NOP10 => write!(f, "OP_NOP10"),
        }
    }
}
