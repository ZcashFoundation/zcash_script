use std::{
    cmp::{max, min},
    num::TryFromIntError,
    slice::Iter,
};

use ripemd::Ripemd160;
use secp256k1::{self, ecdsa};
use sha1::Sha1;
use sha2::{Digest, Sha256};

use crate::{
    external::pubkey::PubKey,
    opcode::{
        self,
        operation::{
            Control::{self, *},
            Operation::{self, *},
        },
        push_value::LargeValue,
        Opcode, PushValue,
    },
    script::{self, num, Script},
};

/// Things that can go wrong when constructing a `HashType` from bit flags.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum InvalidHashType {
    /// Either or both of the two least-significant bits must be set.
    UnknownSignedOutputs,
    /// With v5 transactions, bits other than those specified for `HashType` must be 0. The `i32`
    /// includes only the bits that are undefined by `HashType`.
    ExtraBitsSet(i32),
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Error {
    OpReturn,

    // Max sizes
    PushSize(Option<TryFromIntError>),
    OpCount,
    StackSize(Option<TryFromIntError>),
    SigCount(Option<TryFromIntError>),
    PubKeyCount(Option<TryFromIntError>),

    // Failed verify operations
    Verify,
    EqualVerify,
    CheckMultisigVerify,
    CheckSigVerify,
    NumEqualVerify,

    // Logical/Format/Canonical errors
    BadOpcode(Option<u8>),
    InvalidStackOperation,
    InvalidAltstackOperation,
    UnbalancedConditional,

    // OP_CHECKLOCKTIMEVERIFY
    NegativeLockTime,
    UnsatisfiedLockTime,

    // BIP62
    SigHashType(Option<InvalidHashType>),
    SigDER(Option<secp256k1::Error>),
    MinimalData,
    SigHighS,
    SigNullDummy,
    PubKeyType,

    // softfork safeness
    DiscourageUpgradableNOPs,

    // extensions (these don’t exist in C++, and thus map to `UnknownError`)
    /// Corresponds to the `scriptnum_error` exception in C++.
    Num(num::Error),
}

impl From<num::Error> for Error {
    fn from(value: num::Error) -> Self {
        Error::Num(value)
    }
}

// Threshold for lock_time: below this value it is interpreted as block number,
// otherwise as UNIX timestamp.
pub const LOCKTIME_THRESHOLD: i64 = 500_000_000; // Tue Nov  5 00:53:20 1985 UTC

const MAX_MULTISIG_KEYS: u8 = 20;

const MAX_OP_COUNT: u8 = 201;

/// The ways in which a transparent input may commit to the transparent outputs of its
/// transaction.
///
/// Note that:
/// - Transparent inputs always commit to all shielded outputs.
/// - Shielded inputs always commit to all outputs.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SignedOutputs {
    /// The input signature commits to all transparent outputs in the transaction.
    All,
    /// The transparent input's signature commits to the transparent output at the same
    /// index as the transparent input.
    ///
    /// If the specified transparent output along with any shielded outputs only consume
    /// part of this input, anyone is permitted to modify the transaction to claim the
    /// remainder.
    Single,
    /// The transparent input's signature does not commit to any transparent outputs.
    ///
    /// If the shielded outputs only consume part (or none) of this input, anyone is
    /// permitted to modify the transaction to claim the remainder.
    None,
}

/// The different SigHash types, as defined in <https://zips.z.cash/zip-0143>
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct HashType {
    pub signed_outputs: SignedOutputs,
    /// Allows anyone to add transparent inputs to this transaction.
    pub anyone_can_pay: bool,
}

impl HashType {
    /// Construct a `HashType` from bit flags.
    ///
    /// ## Consensus rules
    ///
    /// [§4.10](https://zips.z.cash/protocol/protocol.pdf#sighash):
    /// - Any `HashType` in a v5 transaction must have no undefined bits set.
    pub fn from_bits(bits: i32, is_strict: bool) -> Result<Self, InvalidHashType> {
        let unknown_bits = (bits | 0x83) ^ 0x83;
        if is_strict && unknown_bits != 0 {
            Err(InvalidHashType::ExtraBitsSet(unknown_bits))
        } else {
            let msigned_outputs = match (bits & 2 != 0, bits & 1 != 0) {
                (false, false) => Err(InvalidHashType::UnknownSignedOutputs),
                (false, true) => Ok(SignedOutputs::All),
                (true, false) => Ok(SignedOutputs::None),
                (true, true) => Ok(SignedOutputs::Single),
            };
            msigned_outputs.map(|signed_outputs| HashType {
                signed_outputs,
                anyone_can_pay: bits & 0x80 != 0,
            })
        }
    }
}

bitflags::bitflags! {
    #[derive(Copy, Clone, Debug, PartialEq, Eq)]
    /// Script verification flags
    pub struct VerificationFlags: u32 {
        /// Evaluate P2SH subscripts (softfork safe,
        /// [BIP16](https://github.com/bitcoin/bips/blob/master/bip-0016.mediawiki).
        const P2SH = 1 << 0;

        /// Passing a non-strict-DER signature or one with undefined hashtype to a checksig operation causes script failure.
        /// Evaluating a pubkey that is not (0x04 + 64 bytes) or (0x02 or 0x03 + 32 bytes) by checksig causes script failure.
        /// (softfork safe, but not used or intended as a consensus rule).
        const StrictEnc = 1 << 1;

        /// Passing a non-strict-DER signature or one with S > order/2 to a checksig operation causes script failure
        /// (softfork safe, [BIP62](https://github.com/bitcoin/bips/blob/master/bip-0062.mediawiki) rule 5).
        const LowS = 1 << 3;

        /// verify dummy stack item consumed by CHECKMULTISIG is of zero-length (softfork safe, [BIP62](https://github.com/bitcoin/bips/blob/master/bip-0062.mediawiki) rule 7).
        const NullDummy = 1 << 4;

        /// Using a non-push operator in the scriptSig causes script failure (softfork safe, [BIP62](https://github.com/bitcoin/bips/blob/master/bip-0062.mediawiki) rule 2).
        const SigPushOnly = 1 << 5;

        /// Require minimal encodings for all push operations (OP_0... OP_16, OP_1NEGATE where possible, direct
        /// pushes up to 75 bytes, OP_PUSHDATA1 up to 255 bytes, OP_PUSHDATA2 for anything larger). Evaluating
        /// any other push causes the script to fail ([BIP62](https://github.com/bitcoin/bips/blob/master/bip-0062.mediawiki) rule 3).
        /// In addition, whenever a stack element is interpreted as a number, it must be of minimal length ([BIP62](https://github.com/bitcoin/bips/blob/master/bip-0062.mediawiki) rule 4).
        /// (softfork safe)
        const MinimalData = 1 << 6;

        /// Discourage use of NOPs reserved for upgrades (NOP1-10)
        ///
        /// Provided so that nodes can avoid accepting or mining transactions
        /// containing executed NOP's whose meaning may change after a soft-fork,
        /// thus rendering the script invalid; with this flag set executing
        /// discouraged NOPs fails the script. This verification flag will never be
        /// a mandatory flag applied to scripts in a block. NOPs that are not
        /// executed, e.g.  within an unexecuted IF ENDIF block, are *not* rejected.
        const DiscourageUpgradableNOPs = 1 << 7;

        /// Require that only a single stack element remains after evaluation. This changes the success criterion from
        /// "At least one stack element must remain, and when interpreted as a boolean, it must be true" to
        /// "Exactly one stack element must remain, and when interpreted as a boolean, it must be true".
        /// (softfork safe, [BIP62](https://github.com/bitcoin/bips/blob/master/bip-0062.mediawiki) rule 6)
        /// Note: CLEANSTACK should never be used without P2SH.
        const CleanStack = 1 << 8;

        /// Verify CHECKLOCKTIMEVERIFY
        ///
        /// See [BIP65](https://github.com/bitcoin/bips/blob/master/bip-0065.mediawiki) for details.
        const CHECKLOCKTIMEVERIFY = 1 << 9;
    }
}

pub trait SignatureChecker {
    fn check_sig(&self, script_sig: &Signature, vch_pub_key: &[u8], script_code: &Script) -> bool;

    fn check_lock_time(&self, lock_time: i64) -> bool;
}

pub struct BaseSignatureChecker();

impl SignatureChecker for BaseSignatureChecker {
    fn check_sig(
        &self,
        _script_sig: &Signature,
        _vch_pub_key: &[u8],
        _script_code: &Script,
    ) -> bool {
        false
    }

    fn check_lock_time(&self, _lock_time: i64) -> bool {
        false
    }
}

#[derive(Copy, Clone)]
pub struct CallbackTransactionSignatureChecker<'a> {
    pub sighash: SighashCalculator<'a>,
    /// This is stored as an `i64` instead of the `u32` used by transactions to avoid partial
    /// conversions when reading from the stack.
    pub lock_time: i64,
    pub is_final: bool,
}

type ValType = Vec<u8>;

fn cast_to_bool(vch: &ValType) -> bool {
    for i in 0..vch.len() {
        if vch[i] != 0 {
            // Can be negative zero
            if i == vch.len() - 1 && vch[i] == 0x80 {
                return false;
            }
            return true;
        }
    }
    false
}

/**
 * Script is a stack machine (like Forth) that evaluates a predicate
 * returning a bool indicating valid or not.  There are no loops.
 */
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Stack<T>(Vec<T>);

/// Wraps a Vec (or whatever underlying implementation we choose in a way that matches the C++ impl
/// and provides us some decent chaining)
impl<T: Clone> Stack<T> {
    pub fn new() -> Self {
        Stack(vec![])
    }

    fn rindex(&self, i: usize) -> Result<usize, Error> {
        let len = self.0.len();
        if i < len {
            Ok(len - i - 1)
        } else {
            Err(Error::InvalidStackOperation)
        }
    }

    pub fn rget(&self, i: usize) -> Result<&T, Error> {
        let idx = self.rindex(i)?;
        self.0.get(idx).ok_or(Error::InvalidStackOperation)
    }

    pub fn rswap(&mut self, a: usize, b: usize) -> Result<(), Error> {
        let ra = self.rindex(a)?;
        let rb = self.rindex(b)?;
        self.0.swap(ra, rb);
        Ok(())
    }

    pub fn pop(&mut self) -> Result<T, Error> {
        self.0.pop().ok_or(Error::InvalidStackOperation)
    }

    pub fn push(&mut self, value: T) {
        self.0.push(value)
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn iter(&self) -> Iter<'_, T> {
        self.0.iter()
    }

    pub fn last_mut(&mut self) -> Result<&mut T, Error> {
        self.0.last_mut().ok_or(Error::InvalidStackOperation)
    }

    pub fn last(&self) -> Result<&T, Error> {
        self.0.last().ok_or(Error::InvalidStackOperation)
    }

    pub fn split_last(&self) -> Result<(&T, Stack<T>), Error> {
        self.0
            .split_last()
            .ok_or(Error::InvalidStackOperation)
            .map(|(last, rem)| (last, Stack(rem.to_vec())))
    }

    pub fn rerase(&mut self, start: usize, end: Option<usize>) -> Result<(), Error> {
        let rstart = self.rindex(start)?;
        for _ in 0..end.map_or(1, |e| start - e) {
            self.0.remove(rstart);
        }
        Ok(())
    }

    pub fn rinsert(&mut self, i: usize, element: T) -> Result<(), Error> {
        let ri = self.rindex(i)?;
        self.0.insert(ri, element);
        Ok(())
    }
}

fn is_compressed_or_uncompressed_pub_key(vch_pub_key: &[u8]) -> bool {
    match vch_pub_key.first() {
        Some(0x02 | 0x03) => vch_pub_key.len() == PubKey::COMPRESSED_SIZE,
        Some(0x04) => vch_pub_key.len() == PubKey::SIZE,
        _ => false, // not a public key
    }
}

#[derive(Clone)]
pub struct Signature {
    sig: ecdsa::Signature,
    sighash: HashType,
}

fn decode_signature(vch_sig_in: &[u8], is_strict: bool) -> Result<Option<Signature>, Error> {
    match vch_sig_in.split_last() {
        // Empty signature. Not strictly DER encoded, but allowed to provide a compact way to
        // provide an invalid signature for use with CHECK(MULTI)SIG
        None => Ok(None),
        Some((hash_type, vch_sig)) => Ok(Some(Signature {
            sig: ecdsa::Signature::from_der(vch_sig).map_err(|e| Error::SigDER(Some(e)))?,
            sighash: HashType::from_bits((*hash_type).into(), is_strict)
                .map_err(|e| Error::SigHashType(Some(e)))?,
        })),
    }
}

fn check_signature_encoding(
    vch_sig: &[u8],
    flags: VerificationFlags,
) -> Result<Option<Signature>, Error> {
    decode_signature(vch_sig, flags.contains(VerificationFlags::StrictEnc)).and_then(
        |sig| match sig {
            None => Ok(None),
            Some(sig0) => {
                if flags.contains(VerificationFlags::LowS) && !PubKey::check_low_s(&sig0.sig) {
                    Err(Error::SigHighS)
                } else {
                    Ok(Some(sig0))
                }
            }
        },
    )
}

fn check_pub_key_encoding(vch_sig: &[u8], flags: VerificationFlags) -> Result<(), Error> {
    if flags.contains(VerificationFlags::StrictEnc)
        && !is_compressed_or_uncompressed_pub_key(vch_sig)
    {
        return Err(Error::PubKeyType);
    };
    Ok(())
}

fn is_sig_valid(
    vch_sig: &[u8],
    vch_pub_key: &[u8],
    flags: VerificationFlags,
    script: &Script<'_>,
    checker: &dyn SignatureChecker,
) -> Result<bool, Error> {
    let sig = check_signature_encoding(vch_sig, flags)?;
    check_pub_key_encoding(vch_pub_key, flags).map(|()| {
        sig.map(|sig0| checker.check_sig(&sig0, vch_pub_key, script))
            .unwrap_or(false)
    })
}

fn unop<T: Clone>(stack: &mut Stack<T>, op: impl Fn(T) -> Result<T, Error>) -> Result<(), Error> {
    let item = stack.pop()?;
    op(item).map(|res| stack.push(res))
}

fn binfn<T: Clone, R>(
    stack: &mut Stack<T>,
    op: impl Fn(T, T) -> Result<R, Error>,
) -> Result<R, Error> {
    let x2 = stack.pop()?;
    let x1 = stack.pop()?;
    op(x1, x2)
}

fn binbasic_num<R>(
    stack: &mut Stack<Vec<u8>>,
    require_minimal: bool,
    op: impl Fn(i64, i64) -> Result<R, Error>,
) -> Result<R, Error> {
    binfn(stack, |x1, x2| {
        let bn2 = num::parse(&x2, require_minimal, None).map_err(Error::Num)?;
        let bn1 = num::parse(&x1, require_minimal, None).map_err(Error::Num)?;
        op(bn1, bn2)
    })
}
fn binop<T: Clone>(
    stack: &mut Stack<T>,
    op: impl Fn(T, T) -> Result<T, Error>,
) -> Result<(), Error> {
    binfn(stack, op).map(|res| stack.push(res))
}

fn cast_from_bool(b: bool) -> ValType {
    static VCH_FALSE: [u8; 0] = [];
    static VCH_TRUE: [u8; 1] = [1];
    if b {
        VCH_TRUE.to_vec()
    } else {
        VCH_FALSE.to_vec()
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct State {
    stack: Stack<Vec<u8>>,
    altstack: Stack<Vec<u8>>,
    // We keep track of how many operations have executed so far to prevent expensive-to-verify
    // scripts
    op_count: u8,
    // This keeps track of the conditional flags at each nesting level during execution. If we're in
    // a branch of execution where *any* of these conditionals are false, we ignore opcodes unless
    // those opcodes direct control flow (OP_IF, OP_ELSE, etc.).
    vexec: Stack<bool>,
}

impl State {
    /// Creates a new empty state.
    pub fn new() -> Self {
        Self::initial(Stack::new())
    }

    /// Creates a state with an initial stack, but other components empty.
    pub fn initial(stack: Stack<Vec<u8>>) -> Self {
        Self::from_parts(stack, Stack::new(), 0, Stack::new())
    }

    pub fn increment_op_count(&mut self) -> Result<(), Error> {
        self.op_count += 1;
        if self.op_count <= MAX_OP_COUNT {
            Ok(())
        } else {
            Err(Error::OpCount)
        }
    }

    /// Create an arbitrary state.
    pub fn from_parts(
        stack: Stack<Vec<u8>>,
        altstack: Stack<Vec<u8>>,
        op_count: u8,
        vexec: Stack<bool>,
    ) -> Self {
        State {
            stack,
            altstack,
            op_count,
            vexec,
        }
    }

    pub fn stack(&self) -> &Stack<Vec<u8>> {
        &self.stack
    }

    pub fn altstack(&self) -> &Stack<Vec<u8>> {
        &self.altstack
    }

    pub fn op_count(&self) -> u8 {
        self.op_count
    }

    pub fn vexec(&self) -> &Stack<bool> {
        &self.vexec
    }
}

/// Run a single step of the interpreter.
///
/// This is useful for testing & debugging, as we can set up the exact state we want in order to
/// trigger some behavior.
pub fn eval_step<'a>(
    pc: &'a [u8],
    script: &Script,
    flags: VerificationFlags,
    checker: impl SignatureChecker,
    state: &mut State,
) -> Result<&'a [u8], script::Error> {
    //
    // Read instruction
    //
    opcode::parse(pc)
        .map_err(script::Error::from)
        .and_then(|(opcode, new_pc)| match opcode {
            Err(byte) => {
                state.increment_op_count()?;
                if should_exec(&state.vexec) {
                    Err(Error::BadOpcode(Some(byte)).into())
                } else {
                    Ok(new_pc)
                }
            }
            Ok(opcode) => eval_opcode(flags, opcode, script, &checker, state)
                .map_err(script::Error::from)
                .map(|()| new_pc),
        })
}

fn eval_opcode(
    flags: VerificationFlags,
    opcode: Opcode,
    script: &Script,
    checker: &dyn SignatureChecker,
    state: &mut State,
) -> Result<(), Error> {
    (match opcode {
        Opcode::PushValue(pv) => {
            if pv.value().map_or(0, |v| v.len()) <= LargeValue::MAX_SIZE {
                if should_exec(&state.vexec) {
                    eval_push_value(
                        &pv,
                        flags.contains(VerificationFlags::MinimalData),
                        &mut state.stack,
                    )
                } else {
                    Ok(())
                }
            } else {
                Err(Error::PushSize(None))
            }
        }
        Opcode::Operation(normal) => {
            // Note how OP_RESERVED does not count towards the opcode limit.
            state.increment_op_count()?;
            if should_exec(&state.vexec) {
                eval_operation(
                    normal,
                    flags,
                    script,
                    checker,
                    &mut state.stack,
                    &mut state.altstack,
                    &mut state.op_count,
                )
            } else {
                Ok(())
            }
        }
        Opcode::Control(un) => {
            // Note how OP_RESERVED does not count towards the opcode limit.
            state.increment_op_count()?;
            eval_control(un, &mut state.stack, &mut state.vexec)
        }
    })
    .and_then(|()| {
        // Size limits
        if state.stack.len() + state.altstack.len() > 1000 {
            Err(Error::StackSize(None))
        } else {
            Ok(())
        }
    })
}

fn eval_push_value(
    pv: &PushValue,
    require_minimal: bool,
    stack: &mut Stack<Vec<u8>>,
) -> Result<(), Error> {
    if require_minimal && !pv.is_minimal_push() {
        Err(Error::MinimalData)
    } else {
        pv.value().map_or(Err(Error::BadOpcode(None)), |v| {
            stack.push(v);
            Ok(())
        })
    }
}

// Are we in an executing branch of the script?
fn should_exec(vexec: &Stack<bool>) -> bool {
    vexec.iter().all(|value| *value)
}

/// <expression> if [statements] [else [statements]] endif
fn eval_control(
    op: Control,
    stack: &mut Stack<Vec<u8>>,
    vexec: &mut Stack<bool>,
) -> Result<(), Error> {
    match op {
        OP_IF | OP_NOTIF => {
            // <expression> if [statements] [else [statements]] endif
            let mut value = false;
            if should_exec(vexec) {
                if stack.is_empty() {
                    return Err(Error::UnbalancedConditional);
                }
                let vch: &ValType = stack.rget(0)?;
                value = cast_to_bool(vch);
                if op == OP_NOTIF {
                    value = !value
                };
                stack.pop()?;
            }
            vexec.push(value);
        }

        OP_ELSE => {
            if vexec.is_empty() {
                return Err(Error::UnbalancedConditional);
            }
            vexec.last_mut().map(|last| *last = !*last)?;
        }

        OP_ENDIF => {
            if vexec.is_empty() {
                return Err(Error::UnbalancedConditional);
            }
            vexec.pop()?;
        }

        OP_VERIF | OP_VERNOTIF => return Err(Error::BadOpcode(Some(op.into()))),
    }
    Ok(())
}

fn eval_operation(
    op: Operation,
    flags: VerificationFlags,
    script: &Script,
    checker: &dyn SignatureChecker,
    stack: &mut Stack<Vec<u8>>,
    altstack: &mut Stack<Vec<u8>>,
    op_count: &mut u8,
) -> Result<(), Error> {
    let require_minimal = flags.contains(VerificationFlags::MinimalData);

    let unfn_num =
        |stackin: &mut Stack<Vec<u8>>, op: &dyn Fn(i64) -> Vec<u8>| -> Result<(), Error> {
            unop(stackin, |vch| {
                num::parse(&vch, require_minimal, None)
                    .map_err(Error::Num)
                    .map(op)
            })
        };

    let unop_num = |stack: &mut Stack<Vec<u8>>, op: &dyn Fn(i64) -> i64| -> Result<(), Error> {
        unfn_num(stack, &|bn| num::serialize(op(bn)))
    };

    let binfn_num = |stack: &mut Stack<Vec<u8>>,
                     op: &dyn Fn(i64, i64) -> Vec<u8>|
     -> Result<(), Error> {
        binbasic_num(stack, require_minimal, |bn1, bn2| Ok(op(bn1, bn2))).map(|res| stack.push(res))
    };

    let binop_num =
        |stack: &mut Stack<Vec<u8>>, op: &dyn Fn(i64, i64) -> i64| -> Result<(), Error> {
            binfn_num(stack, &|bn1, bn2| num::serialize(op(bn1, bn2)))
        };

    let binrel = |stack: &mut Stack<Vec<u8>>, op: &dyn Fn(i64, i64) -> bool| -> Result<(), Error> {
        binfn_num(stack, &|bn1, bn2| cast_from_bool(op(bn1, bn2)))
    };

    let unrel = |stack: &mut Stack<Vec<u8>>, op: &dyn Fn(i64) -> bool| -> Result<(), Error> {
        unfn_num(stack, &|bn| cast_from_bool(op(bn)))
    };

    match op {
        //
        // Control
        //
        OP_NOP => (),

        OP_CHECKLOCKTIMEVERIFY => {
            // https://zips.z.cash/protocol/protocol.pdf#bips :
            //
            //   The following BIPs apply starting from the Zcash genesis block,
            //   i.e. any activation rules or exceptions for particular blocks in
            //   the Bitcoin block chain are to be ignored: [BIP-16], [BIP-30],
            //   [BIP-65], [BIP-66].
            //
            // So BIP 65, which defines CHECKLOCKTIMEVERIFY, is in practice always
            // enabled, and this `if` branch is dead code. In zcashd see
            // https://github.com/zcash/zcash/blob/a3435336b0c561799ac6805a27993eca3f9656df/src/main.cpp#L3151
            if !flags.contains(VerificationFlags::CHECKLOCKTIMEVERIFY) {
                if flags.contains(VerificationFlags::DiscourageUpgradableNOPs) {
                    return Err(Error::DiscourageUpgradableNOPs);
                }
            } else {
                if stack.is_empty() {
                    return Err(Error::InvalidStackOperation);
                }

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
                let lock_time = num::parse(stack.rget(0)?, require_minimal, Some(5))?;

                // In the rare event that the argument may be < 0 due to
                // some arithmetic being done first, you can always use
                // 0 MAX CHECKLOCKTIMEVERIFY.
                if lock_time < 0 {
                    return Err(Error::NegativeLockTime);
                }

                // Actually compare the specified lock time with the transaction.
                if !checker.check_lock_time(lock_time) {
                    return Err(Error::UnsatisfiedLockTime);
                }
            }
        }

        OP_NOP1 | OP_NOP3 | OP_NOP4 | OP_NOP5 | OP_NOP6 | OP_NOP7 | OP_NOP8 | OP_NOP9
        | OP_NOP10 => {
            // Do nothing, though if the caller wants to prevent people from using
            // these NOPs (as part of a standard tx rule, for example) they can
            // enable `DiscourageUpgradableNOPs` to turn these opcodes into errors.
            if flags.contains(VerificationFlags::DiscourageUpgradableNOPs) {
                return Err(Error::DiscourageUpgradableNOPs);
            }
        }

        OP_VERIFY => {
            // (true -- ) or
            // (false -- false) and return
            if stack.is_empty() {
                return Err(Error::InvalidStackOperation);
            }
            let value = cast_to_bool(stack.rget(0)?);
            if value {
                stack.pop()?;
            } else {
                return Err(Error::Verify);
            }
        }

        OP_RETURN => return Err(Error::OpReturn),

        //
        // Stack ops
        //
        OP_TOALTSTACK => {
            if stack.is_empty() {
                return Err(Error::InvalidStackOperation);
            }
            altstack.push(stack.rget(0)?.clone());
            stack.pop()?;
        }

        OP_FROMALTSTACK => {
            if altstack.is_empty() {
                return Err(Error::InvalidAltstackOperation);
            }
            stack.push(altstack.rget(0)?.clone());
            altstack.pop()?;
        }

        OP_2DROP => {
            if stack.len() < 2 {
                return Err(Error::InvalidStackOperation);
            }

            stack.pop()?;
            stack.pop()?;
        }

        OP_2DUP => {
            // (x1 x2 -- x1 x2 x1 x2)
            if stack.len() < 2 {
                return Err(Error::InvalidStackOperation);
            }
            let vch1 = stack.rget(1)?.clone();
            let vch2 = stack.rget(0)?.clone();
            stack.push(vch1);
            stack.push(vch2);
        }

        OP_3DUP => {
            // (x1 x2 x3 -- x1 x2 x3 x1 x2 x3)
            if stack.len() < 3 {
                return Err(Error::InvalidStackOperation);
            }
            let vch1 = stack.rget(2)?.clone();
            let vch2 = stack.rget(1)?.clone();
            let vch3 = stack.rget(0)?.clone();
            stack.push(vch1);
            stack.push(vch2);
            stack.push(vch3);
        }

        OP_2OVER => {
            // (x1 x2 x3 x4 -- x1 x2 x3 x4 x1 x2)
            if stack.len() < 4 {
                return Err(Error::InvalidStackOperation);
            }
            let vch1 = stack.rget(3)?.clone();
            let vch2 = stack.rget(2)?.clone();
            stack.push(vch1);
            stack.push(vch2);
        }

        OP_2ROT => {
            // (x1 x2 x3 x4 x5 x6 -- x3 x4 x5 x6 x1 x2)
            if stack.len() < 6 {
                return Err(Error::InvalidStackOperation);
            }
            let vch1 = stack.rget(5)?.clone();
            let vch2 = stack.rget(4)?.clone();
            stack.rerase(5, Some(3))?;
            stack.push(vch1);
            stack.push(vch2);
        }

        OP_2SWAP => {
            // (x1 x2 x3 x4 -- x3 x4 x1 x2)
            if stack.len() < 4 {
                return Err(Error::InvalidStackOperation);
            }
            stack.rswap(3, 1)?;
            stack.rswap(2, 0)?;
        }

        OP_IFDUP => {
            // (x - 0 | x x)
            if stack.is_empty() {
                return Err(Error::InvalidStackOperation);
            }
            let vch = stack.rget(0)?;
            if cast_to_bool(vch) {
                stack.push(vch.to_vec())
            }
        }

        OP_DEPTH => {
            // -- stacksize
            let bn = i64::try_from(stack.len()).map_err(|err| Error::StackSize(Some(err)))?;
            stack.push(num::serialize(bn))
        }

        OP_DROP => {
            // (x -- )
            if stack.is_empty() {
                return Err(Error::InvalidStackOperation);
            }
            stack.pop()?;
        }

        OP_DUP => {
            // (x -- x x)
            if stack.is_empty() {
                return Err(Error::InvalidStackOperation);
            }

            let vch = stack.rget(0)?;
            stack.push(vch.clone());
        }

        OP_NIP => {
            // (x1 x2 -- x2)
            if stack.len() < 2 {
                return Err(Error::InvalidStackOperation);
            }
            stack.rerase(1, None)?;
        }

        OP_OVER => {
            // (x1 x2 -- x1 x2 x1)
            if stack.len() < 2 {
                return Err(Error::InvalidStackOperation);
            }
            let vch = stack.rget(1)?;
            stack.push(vch.clone());
        }

        OP_PICK | OP_ROLL => {
            // (xn ... x2 x1 x0 n - xn ... x2 x1 x0 xn)
            // (xn ... x2 x1 x0 n - ... x2 x1 x0 xn)
            if stack.len() < 2 {
                return Err(Error::InvalidStackOperation);
            }
            let n = u16::try_from(num::parse(stack.rget(0)?, require_minimal, None)?)
                .map_err(|_| Error::InvalidStackOperation)?;
            stack.pop()?;
            if usize::from(n) >= stack.len() {
                return Err(Error::InvalidStackOperation);
            }
            let vch: ValType = stack.rget(n.into())?.clone();
            if op == OP_ROLL {
                stack.rerase(n.into(), None)?;
            }
            stack.push(vch)
        }

        OP_ROT => {
            // (x1 x2 x3 -- x2 x3 x1)
            //  x2 x1 x3  after first swap
            //  x2 x3 x1  after second swap
            if stack.len() < 3 {
                return Err(Error::InvalidStackOperation);
            }
            stack.rswap(2, 1)?;
            stack.rswap(1, 0)?;
        }

        OP_SWAP => {
            // (x1 x2 -- x2 x1)
            if stack.len() < 2 {
                return Err(Error::InvalidStackOperation);
            }
            stack.rswap(1, 0)?;
        }

        OP_TUCK => {
            // (x1 x2 -- x2 x1 x2)
            if stack.len() < 2 {
                return Err(Error::InvalidStackOperation);
            }
            let vch = stack.rget(0)?.clone();
            stack.rinsert(1, vch)?
        }

        OP_SIZE => {
            // (in -- in size)
            if stack.is_empty() {
                return Err(Error::InvalidStackOperation);
            }
            let bn = i64::try_from(stack.rget(0)?.len())
                .expect("stack element size <= MAX_SCRIPT_ELEMENT_SIZE");
            stack.push(num::serialize(bn))
        }

        //
        // Bitwise logic
        //
        // (x1 x2 - bool)
        OP_EQUAL => binop(stack, |x1, x2| Ok(cast_from_bool(x1 == x2)))?,
        OP_EQUALVERIFY => binfn(stack, |x1, x2| {
            if x1 == x2 {
                Ok(())
            } else {
                Err(Error::EqualVerify)
            }
        })?,

        //
        // Numeric
        //

        // (in -- out)
        OP_1ADD => unop_num(stack, &|x| x + 1)?,
        OP_1SUB => unop_num(stack, &|x| x - 1)?,
        OP_NEGATE => unop_num(stack, &|x| -x)?,
        OP_ABS => unop_num(stack, &|x| x.abs())?,
        OP_NOT => unrel(stack, &|x| x == 0)?,
        OP_0NOTEQUAL => unrel(stack, &|x| x != 0)?,

        // (x1 x2 -- out)
        OP_ADD => binop_num(stack, &|x1, x2| x1 + x2)?,
        OP_SUB => binop_num(stack, &|x1, x2| x1 - x2)?,
        OP_BOOLAND => binrel(stack, &|x1, x2| x1 != 0 && x2 != 0)?,
        OP_BOOLOR => binrel(stack, &|x1, x2| x1 != 0 || x2 != 0)?,
        OP_NUMEQUAL => binrel(stack, &|x1, x2| x1 == x2)?,
        OP_NUMEQUALVERIFY => binbasic_num(stack, require_minimal, |x1, x2| {
            if x1 == x2 {
                Ok(())
            } else {
                Err(Error::NumEqualVerify)
            }
        })?,
        OP_NUMNOTEQUAL => binrel(stack, &|x1, x2| x1 != x2)?,
        OP_LESSTHAN => binrel(stack, &|x1, x2| x1 < x2)?,
        OP_GREATERTHAN => binrel(stack, &|x1, x2| x1 > x2)?,
        OP_LESSTHANOREQUAL => binrel(stack, &|x1, x2| x1 <= x2)?,
        OP_GREATERTHANOREQUAL => binrel(stack, &|x1, x2| x1 >= x2)?,
        OP_MIN => binop_num(stack, &min)?,
        OP_MAX => binop_num(stack, &max)?,

        OP_WITHIN => {
            // (x min max -- out)
            if stack.len() < 3 {
                return Err(Error::InvalidStackOperation);
            }
            let bn1 = num::parse(stack.rget(2)?, require_minimal, None)?;
            let bn2 = num::parse(stack.rget(1)?, require_minimal, None)?;
            let bn3 = num::parse(stack.rget(0)?, require_minimal, None)?;
            let value = bn2 <= bn1 && bn1 < bn3;
            stack.pop()?;
            stack.pop()?;
            stack.pop()?;
            stack.push(cast_from_bool(value))
        }

        //
        // Crypto
        //
        OP_RIPEMD160 | OP_SHA1 | OP_SHA256 | OP_HASH160 | OP_HASH256 => {
            // (in -- hash)
            if stack.is_empty() {
                return Err(Error::InvalidStackOperation);
            }
            let vch = stack.rget(0)?;
            let mut vch_hash = vec![];
            if op == OP_RIPEMD160 {
                vch_hash = Ripemd160::digest(vch).to_vec();
            } else if op == OP_SHA1 {
                let mut hasher = Sha1::new();
                hasher.update(vch);
                vch_hash = hasher.finalize().to_vec();
            } else if op == OP_SHA256 {
                vch_hash = Sha256::digest(vch).to_vec();
            } else if op == OP_HASH160 {
                vch_hash = Ripemd160::digest(Sha256::digest(vch)).to_vec();
            } else if op == OP_HASH256 {
                vch_hash = Sha256::digest(Sha256::digest(vch)).to_vec();
            }
            stack.pop()?;
            stack.push(vch_hash)
        }

        OP_CHECKSIG | OP_CHECKSIGVERIFY => {
            // (sig pubkey -- bool)
            if stack.len() < 2 {
                return Err(Error::InvalidStackOperation);
            }

            let vch_sig = stack.rget(1)?.clone();
            let vch_pub_key = stack.rget(0)?.clone();

            let success = is_sig_valid(&vch_sig, &vch_pub_key, flags, script, checker)?;

            stack.pop()?;
            stack.pop()?;
            stack.push(cast_from_bool(success));
            if op == OP_CHECKSIGVERIFY {
                if success {
                    stack.pop()?;
                } else {
                    return Err(Error::CheckSigVerify);
                }
            }
        }

        OP_CHECKMULTISIG | OP_CHECKMULTISIGVERIFY => {
            // ([sig ...] num_of_signatures [pubkey ...] num_of_pubkeys -- bool)

            // NB: This is guaranteed u8-safe, because we are limited to 20 keys and
            //     20 signatures, plus a couple other fields. u8 also gives us total
            //     conversions to the other types we deal with here (`isize` and `i64`).
            let mut i: u8 = 0;
            if stack.len() < i.into() {
                return Err(Error::InvalidStackOperation);
            };

            let mut keys_count =
                u8::try_from(num::parse(stack.rget(i.into())?, require_minimal, None)?)
                    .map_err(|err| Error::PubKeyCount(Some(err)))?;
            if keys_count > MAX_MULTISIG_KEYS {
                return Err(Error::PubKeyCount(None));
            };
            assert!(*op_count <= MAX_OP_COUNT);
            *op_count += keys_count;
            if *op_count > MAX_OP_COUNT {
                return Err(Error::OpCount);
            };
            i += 1;
            let mut ikey = i;
            i += keys_count;
            if stack.len() <= i.into() {
                return Err(Error::InvalidStackOperation);
            }

            let mut sigs_count =
                u8::try_from(num::parse(stack.rget(i.into())?, require_minimal, None)?)
                    .map_err(|err| Error::SigCount(Some(err)))?;
            if sigs_count > keys_count {
                return Err(Error::SigCount(None));
            };
            assert!(i <= MAX_MULTISIG_KEYS + 1);
            i += 1;
            let mut isig = i;
            i += sigs_count;
            if stack.len() <= i.into() {
                return Err(Error::InvalidStackOperation);
            };

            let mut success = true;
            while success && sigs_count > 0 {
                let vch_sig: &ValType = stack.rget(isig.into())?;
                let vch_pub_key: &ValType = stack.rget(ikey.into())?;

                // Note how this makes the exact order of pubkey/signature evaluation
                // distinguishable by CHECKMULTISIG NOT if the STRICTENC flag is set.
                // See the script_(in)valid tests for details.
                let ok: bool = is_sig_valid(vch_sig, vch_pub_key, flags, script, checker)?;

                if ok {
                    isig += 1;
                    sigs_count -= 1;
                }
                ikey += 1;
                keys_count -= 1;

                // If there are more signatures left than keys left,
                // then too many signatures have failed. Exit early,
                // without checking any further signatures.
                if sigs_count > keys_count {
                    success = false;
                };
            }

            // Clean up stack of actual arguments
            for _ in 0..i {
                stack.pop()?;
            }

            // A bug causes CHECKMULTISIG to consume one extra argument
            // whose contents were not checked in any way.
            //
            // Unfortunately this is a potential source of mutability,
            // so optionally verify it is exactly equal to zero prior
            // to removing it from the stack.
            if stack.is_empty() {
                return Err(Error::InvalidStackOperation);
            }
            if flags.contains(VerificationFlags::NullDummy) && !stack.rget(0)?.is_empty() {
                return Err(Error::SigNullDummy);
            }
            stack.pop()?;

            stack.push(cast_from_bool(success));

            if op == OP_CHECKMULTISIGVERIFY {
                if success {
                    stack.pop()?;
                } else {
                    return Err(Error::CheckMultisigVerify);
                }
            }
        }

        _ => {
            return Err(Error::BadOpcode(Some(op.into())));
        }
    }
    Ok(())
}

pub trait StepFn {
    type Payload: Clone;
    fn call<'a>(
        &self,
        pc: &'a [u8],
        script: &Script,
        state: &mut State,
        payload: &mut Self::Payload,
    ) -> Result<&'a [u8], script::Error>;
}

/// Produces the default stepper, which carries no payload and runs the script as before.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct DefaultStepEvaluator<C> {
    pub flags: VerificationFlags,
    pub checker: C,
}

impl<C: SignatureChecker + Copy> StepFn for DefaultStepEvaluator<C> {
    type Payload = ();
    fn call<'a>(
        &self,
        pc: &'a [u8],
        script: &Script,
        state: &mut State,
        _payload: &mut (),
    ) -> Result<&'a [u8], script::Error> {
        eval_step(pc, script, self.flags, self.checker, state)
    }
}

pub fn eval_script<F>(
    stack: Stack<Vec<u8>>,
    script: &Script,
    payload: &mut F::Payload,
    eval_step: &F,
) -> Result<Stack<Vec<u8>>, script::Error>
where
    F: StepFn,
{
    // There's a limit on how large scripts can be.
    if script.0.len() > script::MAX_SIZE {
        return Err(script::Error::ScriptSize(None));
    }

    let mut pc = script.0;

    let mut state = State::initial(stack);

    // Main execution loop
    while !pc.is_empty() {
        pc = eval_step.call(pc, script, &mut state, payload)?;
    }

    if !state.vexec.is_empty() {
        return Err(Error::UnbalancedConditional.into());
    }

    Ok(state.stack)
}

/// All signature hashes are 32 bytes, since they are either:
/// - a SHA-256 output (for v1 or v2 transactions).
/// - a BLAKE2b-256 output (for v3 and above transactions).
pub const SIGHASH_SIZE: usize = 32;

/// A function which is called to obtain the sighash.
///    - script_code: the scriptCode being validated. Note that this not always
///      matches script_sig, i.e. for P2SH.
///    - hash_type: the hash type being used.
///
/// The `extern "C"` function that calls this doesn’t give much opportunity for rich failure
/// reporting, but returning `None` indicates _some_ failure to produce the desired hash.
pub type SighashCalculator<'a> = &'a dyn Fn(&[u8], HashType) -> Option<[u8; SIGHASH_SIZE]>;

impl SignatureChecker for CallbackTransactionSignatureChecker<'_> {
    fn check_sig(&self, sig: &Signature, vch_pub_key: &[u8], script_code: &Script) -> bool {
        let pubkey = PubKey(vch_pub_key);

        pubkey.is_valid()
            && (self.sighash)(script_code.0, sig.sighash)
                .map(|sighash| pubkey.verify(&sighash, &sig.sig))
                .unwrap_or(false)
    }

    fn check_lock_time(&self, lock_time: i64) -> bool {
        // There are two kinds of nLockTime: lock-by-blockheight
        // and lock-by-blocktime, distinguished by whether
        // nLockTime < LOCKTIME_THRESHOLD.
        //
        // We want to compare apples to apples, so fail the script
        // unless the type of nLockTime being tested is the same as
        // the nLockTime in the transaction.
        if self.lock_time < LOCKTIME_THRESHOLD && lock_time >= LOCKTIME_THRESHOLD
            || self.lock_time >= LOCKTIME_THRESHOLD && lock_time < LOCKTIME_THRESHOLD
            // Now that we know we're comparing apples-to-apples, the
            // comparison is a simple numeric one.
            || lock_time > self.lock_time
        {
            false
            // Finally the nLockTime feature can be disabled and thus
            // CHECKLOCKTIMEVERIFY bypassed if every txin has been
            // finalized by setting nSequence to maxint. The
            // transaction would be allowed into the blockchain, making
            // the opcode ineffective.
            //
            // Testing if this vin is not final is sufficient to
            // prevent this condition. Alternatively we could test all
            // inputs, but testing just this input minimizes the data
            // required to prove correct CHECKLOCKTIMEVERIFY execution.
        } else {
            !self.is_final
        }
    }
}

pub fn verify_script<F>(
    script_sig: &Script,
    script_pub_key: &Script,
    flags: VerificationFlags,
    payload: &mut F::Payload,
    stepper: &F,
) -> Result<(), script::Error>
where
    F: StepFn,
{
    if flags.contains(VerificationFlags::SigPushOnly) && !script_sig.is_push_only() {
        Err(script::Error::SigPushOnly)
    } else {
        let data_stack = eval_script(Stack::new(), script_sig, payload, stepper)?;
        let pub_key_stack = eval_script(data_stack.clone(), script_pub_key, payload, stepper)?;
        if pub_key_stack.last().map_or(false, cast_to_bool) {
            // Additional validation for spend-to-script-hash transactions:
            let result_stack = if flags.contains(VerificationFlags::P2SH)
                && script_pub_key.is_pay_to_script_hash()
            {
                // script_sig must be literals-only or validation fails
                if script_sig.is_push_only() {
                    data_stack
                        // stack cannot be empty here, because if it was the P2SH HASH <> EQUAL
                        // scriptPubKey would be evaluated with an empty stack and the `eval_script`
                        // above would return false.
                        .split_last()
                        .map_err(script::Error::from)
                        .and_then(|(pub_key_2, remaining_stack)| {
                            eval_script(remaining_stack, &Script(pub_key_2), payload, stepper)
                        })
                        .and_then(|p2sh_stack| {
                            if p2sh_stack.last().map_or(false, cast_to_bool) {
                                Ok(p2sh_stack)
                            } else {
                                Err(script::Error::EvalFalse)
                            }
                        })
                } else {
                    Err(script::Error::SigPushOnly)
                }?
            } else {
                pub_key_stack
            };

            // The CLEANSTACK check is only performed after potential P2SH evaluation,
            // as the non-P2SH evaluation of a P2SH script will obviously not result in
            // a clean stack (the P2SH inputs remain).
            if flags.contains(VerificationFlags::CleanStack) {
                // Disallow CLEANSTACK without P2SH, because Bitcoin did.
                assert!(flags.contains(VerificationFlags::P2SH));
                if result_stack.len() == 1 {
                    Ok(())
                } else {
                    Err(script::Error::CleanStack)
                }
            } else {
                Ok(())
            }
        } else {
            Err(script::Error::EvalFalse)
        }
    }
}
