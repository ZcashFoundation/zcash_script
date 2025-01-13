//! Much of this comes from
//! https://gist.github.com/str4d/9d80f1b60e6787310897044502cb025b

use crate::script::{Control::*, LargeValue::*, Normal::*, SmallValue::*, *};

pub const EMPTY_STACK_CHECK: [Opcode; 3] = [
    Opcode::Operation(Operation::Normal(OP_DEPTH)),
    Opcode::PushValue(PushValue::SmallValue(OP_0)),
    Opcode::Operation(Operation::Normal(OP_EQUAL)),
];

pub fn ignored_value(v: &[u8]) -> [Opcode; 2] {
    [
        Opcode::PushValue(push_vec(v)),
        Opcode::Operation(Operation::Normal(OP_DROP)),
    ]
}

// pub const combined_multisig: Vec<Opcode> = t_of_n_multisigverify + t_of_n_multisig;

// abstractions

pub fn branch(thn: &[Opcode], els: &[Opcode]) -> Vec<Opcode> {
    [
        &[Opcode::Operation(Operation::Control(OP_IF))],
        thn,
        &[Opcode::Operation(Operation::Control(OP_ELSE))],
        els,
        &[Opcode::Operation(Operation::Control(OP_ENDIF))],
    ]
    .concat()
}

///
/// Example: `if_else(size_check(20), [], [OP_RETURN])`
pub fn if_else(cond: &[Opcode], thn: &[Opcode], els: &[Opcode]) -> Vec<Opcode> {
    let mut vec = cond.to_vec();
    vec.extend(branch(thn, els));
    vec
}

pub fn check_multisig(sig_count: u8, pks: &[&[u8]], verify: bool) -> Vec<Opcode> {
    [
        &[Opcode::PushValue(push_num(sig_count.into()))],
        &pks.iter()
            .map(|pk| Opcode::PushValue(push_vec(pk)))
            .collect::<Vec<Opcode>>()[..],
        &[
            Opcode::PushValue(push_num(
                pks.len()
                    .try_into()
                    .expect("Should not be more than 20 pubkeys"),
            )),
            Opcode::Operation(Operation::Normal(if verify {
                OP_CHECKMULTISIGVERIFY
            } else {
                OP_CHECKMULTISIG
            })),
        ],
    ]
    .concat()
}

pub fn equals(expected: PushValue, verify: bool) -> [Opcode; 2] {
    [
        Opcode::PushValue(expected),
        Opcode::Operation(Operation::Normal(if verify {
            OP_EQUALVERIFY
        } else {
            OP_EQUAL
        })),
    ]
}

pub fn size_check(expected: u32, verify: bool) -> Vec<Opcode> {
    [
        &[Opcode::Operation(Operation::Normal(OP_SIZE))],
        &equals(push_num(expected.into()), verify)[..],
    ]
    .concat()
}

pub fn check_lock_time_verify(lt: &[u8]) -> [Opcode; 2] {
    [
        Opcode::PushValue(push_vec(lt)),
        Opcode::Operation(Operation::Normal(OP_CHECKLOCKTIMEVERIFY)),
    ]
}

pub fn htlc(pos_check: &[Opcode], lt: &[u8], hash: &[u8; 20]) -> Vec<Opcode> {
    let mut cltv = check_lock_time_verify(lt).to_vec();
    cltv.push(Opcode::Operation(Operation::Normal(OP_DROP)));
    [
        &branch(pos_check, &cltv),
        &[
            Opcode::Operation(Operation::Normal(OP_DUP)),
            Opcode::Operation(Operation::Normal(OP_HASH160)),
        ][..],
        &equals(push_vec(hash), true),
        &[Opcode::Operation(Operation::Normal(OP_CHECKSIG))],
    ]
    .concat()
}

/// Produce a minimal `PushValue` that encodes the provided number.
pub fn push_num(n: i64) -> PushValue {
    push_vec(&serialize_num(n))
}

/// Produce a minimal `PushValue` that encodes the provided script. This is particularly useful with
/// P2SH.
pub fn push_script(script: &[Opcode]) -> PushValue {
    push_vec(&Script::serialize(script))
}

/// Produce a minimal `PushValue` for the given data.
pub fn push_vec(v: &[u8]) -> PushValue {
    match v {
        [] => PushValue::SmallValue(OP_0),
        [byte] => match byte {
            0x81 => PushValue::SmallValue(OP_1NEGATE),
            1 => PushValue::SmallValue(OP_1),
            2 => PushValue::SmallValue(OP_2),
            3 => PushValue::SmallValue(OP_3),
            4 => PushValue::SmallValue(OP_4),
            5 => PushValue::SmallValue(OP_5),
            6 => PushValue::SmallValue(OP_6),
            7 => PushValue::SmallValue(OP_7),
            8 => PushValue::SmallValue(OP_8),
            9 => PushValue::SmallValue(OP_9),
            10 => PushValue::SmallValue(OP_10),
            11 => PushValue::SmallValue(OP_11),
            12 => PushValue::SmallValue(OP_12),
            13 => PushValue::SmallValue(OP_13),
            14 => PushValue::SmallValue(OP_14),
            15 => PushValue::SmallValue(OP_15),
            16 => PushValue::SmallValue(OP_16),
            _ => PushValue::LargeValue(PushdataBytelength(v.to_vec())),
        },
        _ => {
            let len = v.len();
            let vec = v.to_vec();
            PushValue::LargeValue(if len < 0x4f {
                PushdataBytelength(vec)
            } else if len <= u8::MAX.into() {
                OP_PUSHDATA1(vec)
            } else if len <= u16::MAX.into() {
                OP_PUSHDATA2(vec)
            } else {
                OP_PUSHDATA4(vec)
            })
        }
    }
}

pub fn pay_to_pubkey(pubkey: &[u8]) -> [Opcode; 2] {
    [
        Opcode::PushValue(push_vec(pubkey)),
        Opcode::Operation(Operation::Normal(OP_CHECKSIG)),
    ]
}

pub fn pay_to_pubkey_hash(hash: &[u8; 20]) -> Vec<Opcode> {
    [
        &[
            Opcode::Operation(Operation::Normal(OP_DUP)),
            Opcode::Operation(Operation::Normal(OP_HASH160)),
        ],
        &equals(push_vec(hash), true)[..],
        &[Opcode::Operation(Operation::Normal(OP_CHECKSIG))],
    ]
    .concat()
}

pub fn pay_to_script_hash(hash: &[u8; 20]) -> Vec<Opcode> {
    [
        &[Opcode::Operation(Operation::Normal(OP_HASH160))],
        &equals(push_vec(hash), false)[..],
    ]
    .concat()
}

/// One party has SHA-256 hashlock, other party can spend unconditionally
pub fn sha256_htlc(sha: &[u8; 32], lt: &[u8], hash: &[u8; 20]) -> Vec<Opcode> {
    htlc(&sha256_hashlock(sha, true), lt, hash)
}

pub fn sha256_hashlock(sha: &[u8; 32], verify: bool) -> Vec<Opcode> {
    [
        &[Opcode::Operation(Operation::Normal(OP_SHA256))],
        &equals(push_vec(sha), verify)[..],
    ]
    .concat()
}

/// Two-sided Hash160 HTLC with size checks
pub fn hash160_htlc(hash1: &[u8; 20], lt: &[u8], hash2: &[u8; 20]) -> Vec<Opcode> {
    htlc(
        &[
            &[Opcode::Operation(Operation::Normal(OP_HASH160))],
            &equals(push_vec(hash1), true)[..],
        ]
        .concat()[..],
        lt,
        hash2,
    )
}
