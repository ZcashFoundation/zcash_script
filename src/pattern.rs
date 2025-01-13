//! Reusable bits of scripts, to avoid writing hex strings.
//!
//! Much of this comes from https://gist.github.com/str4d/9d80f1b60e6787310897044502cb025b – the
//! corresponding definitions here have a “label” tag in the documentation that indicates the result
//! of `label_script` that they map to.
//!
//! Zcash Script doesn’t have a real type system, but many of these are annotated with some
//! indication of the type. Being scripts with holes, the types are more complicated than those
//! listed with the opcodes in interpreter.rs. Here’s the decoder ring:

//! * `Bool`, `PubKey`, `Signature`, and other capitalized WordsSmashedTogether – a individual stack
//!   value, with a particular shape
//! * `[]` – a comma-separated sequence of stack values
//! * `+` – a concatenation of stack sequences (useful with type variables that represent sequences)
//! * `*` – repetition `n*Signature` is a sequence of `n` Signature`s
//! * `->` – input on the left, output on the right
//! * `∪` – a union of stack sequences (in negative position, this is “existential”, and “universal”
//!   in positive position)
//! * `💥` – terminates evaluation, if followed by `?`, it _may_ terminate evaluation
//! * vars – identifiers in the Rust function signature, indicates where those values are used. In
//!   the case of identifiers that represent `[Opcode]`, an occurrence in negative position
//!   represents the input type of that script, and an occurence in positive position represents the
//!   output type of that script. Identifiers that don’t show up in the rust function signature
//!   represent type variables – they are the same type in each occurrence.
//! * `_` – any type, each occurrence can represent a different type

use ripemd::Ripemd160;
use sha2::{Digest, Sha256};

use crate::{
    op, pv,
    script::{
        self,
        Opcode::{self, PushValue},
        Script,
    },
};

/// Pushes a value onto the stack that indicates whether the stack was previously empty.
///
/// type: `[] -> [Bool]`
pub const EMPTY_STACK_CHECK: [Opcode; 3] = [op::DEPTH, op::_0, op::EQUAL];

/// Pushes a value onto the stack, then immediately drops it.
///
/// type: `[] -> []`
pub fn ignored_value(v: script::PushValue) -> [Opcode; 2] {
    [PushValue(v), op::DROP]
}

// abstractions

/// Holds the two branches of a conditional, without the condition.
///
/// type: `(thn ∪ els) + [Bool] -> (thn ∪ els)`
pub fn branch(thn: &[Opcode], els: &[Opcode]) -> Vec<Opcode> {
    [&[op::IF], thn, &[op::ELSE], els, &[op::ENDIF]].concat()
}

/// Like `branch`, but also holds the conditional.
///
/// Example: `if_else(size_check(20), [], [op::RETURN])`
///
/// type: `((thn ∪ els) - y) + x -> (y - (thn ∪ els)) + (thn ∪ els)`
///     where cond: `x -> y + [Bool]`
pub fn if_else(cond: &[Opcode], thn: &[Opcode], els: &[Opcode]) -> Vec<Opcode> {
    let mut vec = cond.to_vec();
    vec.extend(branch(thn, els));
    vec
}

/// Performs a `sig_count`-of-`pks.len()` multisig.
///
/// if `verify`
///   type: `sig_count*Signature -> 💥?`
///   type: `sig_count*Signature -> [Bool]`
pub fn check_multisig(sig_count: u8, pks: &[&[u8]], verify: bool) -> Vec<Opcode> {
    [
        &[PushValue(push_num(sig_count.into()))],
        &pks.iter()
            .map(|pk| PushValue(pv::push_value(pk).expect("each pubkey is no more than 65 bytes")))
            .collect::<Vec<Opcode>>()[..],
        &[
            PushValue(push_num(
                pks.len()
                    .try_into()
                    .expect("Should not be more than 20 pubkeys"),
            )),
            if verify {
                op::CHECKMULTISIGVERIFY
            } else {
                op::CHECKMULTISIG
            },
        ],
    ]
    .concat()
}

/// Checks equality against some constant value.
///
/// if `verify`
///   type: `[_] -> 💥?`
///   type: `[_] -> [Bool]`
pub fn equals(expected: script::PushValue, verify: bool) -> [Opcode; 2] {
    [
        PushValue(expected),
        if verify { op::EQUALVERIFY } else { op::EQUAL },
    ]
}

/// Checks a signature against the provided pubkey.
///
/// if `verify`
///   type: `[Signature] -> 💥?`
///   type: `[Signature] -> [Bool]`
pub fn check_sig(pubkey: &[u8], verify: bool) -> [Opcode; 2] {
    [
        PushValue(pv::push_value(pubkey).expect("each pubkey is no more than 65 bytes")),
        if verify {
            op::CHECKSIGVERIFY
        } else {
            op::CHECKSIG
        },
    ]
}

/// Checks that the top of the stack has exactly the expected size.
///
/// if `verify`
///   type: `[a] -> [a] + 💥?`
///   type: `[a] -> [a, Bool]`
pub fn size_check(expected: u32, verify: bool) -> Vec<Opcode> {
    [&[op::SIZE], &equals(push_num(expected.into()), verify)[..]].concat()
}

/// “CLTV”
///
/// type: `[] -> [lt] + 💥?`
pub fn check_lock_time_verify(lt: u32) -> [Opcode; 3] {
    [
        PushValue(push_num(lt.into())),
        op::CHECKLOCKTIMEVERIFY,
        op::DROP,
    ]
}

/// Produce a minimal `PushValue` that encodes the provided number.
pub fn push_num(n: i64) -> script::PushValue {
    pv::push_value(&script::serialize_num(n)).expect("all i64 can be encoded as `PushValue`")
}

/// Produce a minimal `PushValue` that encodes the provided script. This is particularly useful with
/// P2SH.
pub fn push_script(script: &[Opcode]) -> Option<script::PushValue> {
    pv::push_value(&Script::serialize(script))
}

/// Creates a `PushValue` from a 20-byte value (basically, RipeMD160 and other hashes).
///
/// __TODO__: Once const_generic_exprs lands, this should become `push_array<N>(a: &[u8; N])` with
///           `N` bounded by `MAX_SCRIPT_ELEMENT_SIZE`.
pub fn push_160b_hash(hash: &[u8; 20]) -> script::PushValue {
    pv::push_value(hash).expect("20 is a valid data size")
}

/// Creates a `PushValue` from a 32-byte value (basically, SHA-256 and other hashes).
///
/// __TODO__: Once const_generic_exprs lands, this should become `push_array<N>(a: &[u8; N])` with
///           `N` bounded by `MAX_SCRIPT_ELEMENT_SIZE`.
pub fn push_256b_hash(hash: &[u8; 32]) -> script::PushValue {
    pv::push_value(hash).expect("32 is a valid data size")
}

/// P2PK
///
/// label: Pay-to-(compressed-)pubkey inside P2SH
///
/// type: `[Signature] -> [Bool]`
pub fn pay_to_pubkey(pubkey: &[u8]) -> [Opcode; 2] {
    check_sig(pubkey, false)
}

/// P2PKH
///
/// type: `[Signature, PubKey] -> [Bool] ∪  💥`
pub fn pay_to_pubkey_hash(pk: &[u8]) -> Vec<Opcode> {
    [
        &[op::DUP, op::HASH160],
        &equals(
            push_160b_hash(&Ripemd160::digest(Sha256::digest(pk)).into()),
            true,
        )[..],
        &[op::CHECKSIG],
    ]
    .concat()
}

/// P2SH
///
/// type: `[_] -> [Bool]`
pub fn pay_to_script_hash(redeem_script: &[Opcode]) -> Vec<Opcode> {
    [
        &[op::HASH160],
        &equals(
            push_160b_hash(
                &Ripemd160::digest(Sha256::digest(Script::serialize(redeem_script))).into(),
            ),
            false,
        )[..],
    ]
    .concat()
}

/// multisig with ignored value and empty stack check
///
/// label: 2-of-3 multisig with compressed pubkeys, a 4-byte ignored data value, and an empty stack
///   check
///
/// type: `n*Signature -> [Bool] ∪  💥`
pub fn check_multisig_empty(n: u8, x: &[&[u8]], ignored: script::PushValue) -> Vec<Opcode> {
    [
        &check_multisig(n, x, true),
        &ignored_value(ignored)[..],
        &EMPTY_STACK_CHECK,
    ]
    .concat()
}

/// Combined multisig
///
/// 1-of-3 and 2-of-2 combined multisig with compressed pubkeys
///
/// type: m*Signature + n*Signature -> [Bool] ∪  💥
pub fn combined_multisig(m: u8, x: &[&[u8]], n: u8, y: &[&[u8]]) -> Vec<Opcode> {
    [
        &check_multisig(m, x, true)[..],
        &check_multisig(n, y, false)[..],
    ]
    .concat()
}

/// P2PKH with an ignored value
///
/// label:
/// - P2PKH inside P2SH with a 32-byte ignored data value
/// - P2PKH inside P2SH with a zero-value placeholder ignored data value
///
/// type: [Signature, PubKey] -> [Bool] ∪  💥
pub fn p2pkh_ignored(ignored: script::PushValue, pk: &[u8]) -> Vec<Opcode> {
    [&ignored_value(ignored)[..], &pay_to_pubkey_hash(pk)].concat()
}

/// P2PK with ignored value and empty stack check
///
/// label: Pay-to-(compressed-)pubkey inside P2SH with an empty stack check
///
/// type: `Signature -> [Bool] ∪  💥`
pub fn p2pk_empty(recipient_pk: &[u8], ignored: script::PushValue) -> Vec<Opcode> {
    [
        &check_sig(recipient_pk, true)[..],
        &ignored_value(ignored)[..],
        &EMPTY_STACK_CHECK,
    ]
    .concat()
}

/// Hash160 HTLC
pub fn hash160_htlc(
    lt: u32,
    sender_pk: &[u8],
    recipient_hash: &[u8; 20],
    recipient_pk: &[u8],
) -> Vec<Opcode> {
    branch(
        &[
            &check_lock_time_verify(lt)[..],
            &check_sig(sender_pk, false)[..],
        ]
        .concat(),
        &[
            &[op::HASH160],
            &equals(push_160b_hash(recipient_hash), true)[..],
            &check_sig(recipient_pk, false)[..],
        ]
        .concat(),
    )
}

/// Hash160 HTLC with size check
pub fn hash160_htlc_size_check(
    lt: u32,
    sender_pk: &[u8],
    recipient_hash: &[u8; 20],
    recipient_pk: &[u8],
) -> Vec<Opcode> {
    branch(
        &[
            &check_lock_time_verify(lt)[..],
            &check_sig(sender_pk, false)[..],
        ]
        .concat(),
        &[
            &size_check(20, true)[..],
            &[op::HASH160],
            &equals(push_160b_hash(recipient_hash), true)[..],
            &check_sig(recipient_pk, false)[..],
        ]
        .concat(),
    )
}

/// Hash160 HTLC
pub fn hash160_htlc_neg(
    lt: u32,
    sender_pk: &[u8],
    recipient_hash: &[u8; 20],
    recipient_pk: &[u8],
) -> Vec<Opcode> {
    branch(
        &[
            &[op::HASH160],
            &equals(push_160b_hash(recipient_hash), true)[..],
            &pay_to_pubkey_hash(recipient_pk)[..],
        ]
        .concat(),
        &[
            &check_lock_time_verify(lt)[..],
            &pay_to_pubkey_hash(sender_pk)[..],
        ]
        .concat(),
    )
}

/// SHA-256 HTLC
pub fn sha256_htlc(
    lt: u32,
    sender_pk: &[u8],
    recipient_sha: &[u8; 32],
    recipient_pk: &[u8],
) -> Vec<Opcode> {
    branch(
        &[
            &check_lock_time_verify(lt)[..],
            &check_sig(sender_pk, false)[..],
        ]
        .concat(),
        &[
            &[op::SHA256],
            &equals(push_256b_hash(recipient_sha), true)[..],
            &check_sig(recipient_pk, false)[..],
        ]
        .concat(),
    )
}

/// SHA-256 HTLC
///
/// label:
/// - SHA-256 HTLC (2-byte CLTV)
/// - SHA-256 HTLC (3-byte CLTV)
pub fn sha256_htlc_neg(
    lt: u32,
    sender_pk: &[u8],
    recipient_sha: &[u8; 32],
    recipient_pk: &[u8],
) -> Vec<Opcode> {
    branch(
        &[
            &[op::SHA256],
            &equals(push_256b_hash(recipient_sha), true)[..],
            &pay_to_pubkey_hash(recipient_pk)[..],
        ]
        .concat(),
        &[
            &check_lock_time_verify(lt)[..],
            &pay_to_pubkey_hash(sender_pk)[..],
        ]
        .concat(),
    )
}

/// SHA-256 HTLC with size check
pub fn sha256_htlc_size_check(
    lt: u32,
    sender_pk: &[u8],
    recipient_sha: &[u8; 32],
    recipient_pk: &[u8],
) -> Vec<Opcode> {
    branch(
        &[
            &size_check(20, true)[..],
            &[op::SHA256],
            &equals(push_256b_hash(recipient_sha), true)[..],
            &pay_to_pubkey_hash(recipient_pk)[..],
        ]
        .concat(),
        &[
            &check_lock_time_verify(lt)[..],
            &pay_to_pubkey_hash(sender_pk)[..],
        ]
        .concat(),
    )
}

/// One party has SHA-256 hashlock, other party can spend unconditionally
pub fn sha256_htlc_with_unconditional(
    sender_hash: &[u8; 20],
    recipient_sha: &[u8; 32],
    recipient_pk: &[u8],
) -> Vec<Opcode> {
    branch(
        &[
            &[op::SHA256],
            &equals(push_256b_hash(recipient_sha), true)[..],
            &pay_to_pubkey_hash(recipient_pk)[..],
        ]
        .concat(),
        &[
            &[op::_1, op::DROP, op::HASH160],
            &equals(push_160b_hash(sender_hash), true)[..],
            &[op::CHECKSIG],
        ]
        .concat(),
    )
}

/// Two-sided Hash160 HTLC with size checks
pub fn dual_hash160_htlc_size_check(
    lt: u32,
    sender_hash: &[u8; 20],
    sender_pk: &[u8],
    recipient_hash: &[u8; 20],
    recipient_pk: &[u8],
) -> Vec<Opcode> {
    let verify = |hash, pk| {
        [
            &[op::SIZE],
            &equals(push_num(20), true)[..],
            &[op::HASH160],
            &equals(push_160b_hash(hash), true)[..],
            &check_sig(pk, false)[..],
        ]
        .concat()
    };
    branch(
        &[
            &check_lock_time_verify(lt)[..],
            &verify(sender_hash, sender_pk)[..],
        ]
        .concat(),
        &verify(recipient_hash, recipient_pk),
    )
}
