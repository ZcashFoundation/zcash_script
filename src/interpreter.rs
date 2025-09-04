//! Execution of opcodes

use std::{
    cmp::{max, min},
    num::TryFromIntError,
    slice::Iter,
};

use ripemd::Ripemd160;
use sha1::Sha1;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    external::pubkey::PubKey,
    interpreter, num,
    opcode::{self, Control::*, Operation::*},
    script, signature, Opcode,
};

/// Any error that can happen during interpretation of a single opcode.
#[allow(missing_docs)]
#[derive(Clone, PartialEq, Eq, Debug, Error)]
pub enum Error {
    #[error("OP_RETURN encountered")]
    OpReturn,

    /// __NB__: This doesn’t take an “actual count” argument, because `OpCount` depends on
    ///         conditional execution and thus can only be checked incrementally. However, we could
    ///         statically check a “minimum operation count” for a script, which could then include
    ///         the minimum in the error.
    #[error("operation count exceeded maxmimum of {}", interpreter::MAX_OP_COUNT)]
    OpCount,

    #[error(
        "stack depth exceeded maxmimum of {} entries",
        interpreter::MAX_STACK_DEPTH
    )]
    StackSize(Option<TryFromIntError>),

    #[error(
        "signature count wasn’t in the range 1..={}{}",
        interpreter::MAX_PUBKEY_COUNT,
        .0.map_or("", |e| ": {e}")
    )]
    SigCount(Option<TryFromIntError>),

    #[error(
        "public key count wasn’t in the range 1..={}{}",
        interpreter::MAX_PUBKEY_COUNT,
        .0.map_or("", |e| ": {e}")
    )]
    PubKeyCount(Option<TryFromIntError>),

    // Failed verify operations
    #[error("verify operation failed")]
    Verify,

    // Logical/Format/Canonical errors
    #[error("bad opcode encountered")]
    BadOpcode,

    #[error("{}", .0.map_or("invalid stack operation encountered", |(elem, max)| "tried to retrieve element {elem} from a stack with {max} elements"))]
    InvalidStackOperation(Option<(usize, usize)>),

    #[error("unbalanced conditional encountered")]
    UnbalancedConditional,

    // OP_CHECKLOCKTIMEVERIFY
    #[error("negative lock time encountered")]
    NegativeLockTime,

    #[error("unsatisfied locktime condition")]
    UnsatisfiedLockTime,

    #[error("signature encoding error: {0}")]
    SignatureEncoding(signature::Error),

    #[error("non-minimal data encountered when minimal data required")]
    MinimalData,

    #[error("signature null dummy error")]
    SigNullDummy,

    #[error("public key type error")]
    PubKeyType,

    // softfork safeness
    #[error("discouraged upgradable NOP encountered")]
    DiscourageUpgradableNOPs,

    // extensions (these don’t exist in C++, and thus map to `UnknownError`)
    /// Corresponds to the `scriptnum_error` exception in C++.
    #[error("script number error: {0}")]
    Num(num::Error),
}

impl Error {
    /// Convert errors that don’t exist in the C++ code into the cases that do.
    pub fn normalize(&self) -> Self {
        match self {
            Self::InvalidStackOperation(Some(_)) => Self::InvalidStackOperation(None),
            Self::SignatureEncoding(sig_err) => match sig_err {
                signature::Error::SigHashType(Some(_)) => {
                    Self::from(signature::Error::SigHashType(None))
                }
                signature::Error::SigDER(Some(_)) => Self::from(signature::Error::SigDER(None)),
                _ => self.clone(),
            },
            Self::StackSize(Some(_)) => Self::StackSize(None),
            Self::SigCount(Some(_)) => Self::SigCount(None),
            Self::PubKeyCount(Some(_)) => Self::PubKeyCount(None),
            _ => self.clone(),
        }
    }
}

impl From<num::Error> for Error {
    fn from(value: num::Error) -> Self {
        Error::Num(value)
    }
}

impl From<signature::Error> for Error {
    fn from(value: signature::Error) -> Self {
        Error::SignatureEncoding(value)
    }
}

/// Threshold for lock_time: below this value it is interpreted as block number,
/// otherwise as UNIX timestamp.
const LOCKTIME_THRESHOLD: i64 = 500_000_000; // Tue Nov  5 00:53:20 1985 UTC

/// The maximum number of operations allowed in a script component.
pub const MAX_OP_COUNT: u8 = 201;

/// The maximum number of pubkeys (and signatures, by implication) allowed in CHECKMULTISIG.
pub const MAX_PUBKEY_COUNT: u8 = 20;

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

/// This verifies that a signature is correct for the given pubkey and script code.
pub trait SignatureChecker {
    /// Check that the signature is valid.
    fn check_sig(
        &self,
        _script_sig: &signature::Decoded,
        _vch_pub_key: &[u8],
        _script_code: &script::Code,
    ) -> bool {
        false
    }

    /// Return true if the lock time argument is more recent than the time the script was evaluated.
    fn check_lock_time(&self, _lock_time: i64) -> bool {
        false
    }
}

/// A signature checker that always fails. This is helpful in testing cases that don’t involve
/// `CHECK*SIG`. The name comes from the C++ impl, where there is no separation between this and the
/// trait.
pub struct BaseSignatureChecker();

impl SignatureChecker for BaseSignatureChecker {}

/// A signature checker that uses a callback to get necessary information about the transaction
/// involved.
#[derive(Copy, Clone)]
pub struct CallbackTransactionSignatureChecker<'a> {
    /// The callback to be used to calculate the sighash.
    pub sighash: SighashCalculator<'a>,
    /// This is stored as an `i64` instead of the `u32` used by transactions to avoid partial
    /// conversions when reading from the stack.
    pub lock_time: i64,
    /// Whether this is the final UTXO in the transaction.
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

/// Script is a stack machine (like Forth) that evaluates a predicate returning a bool indicating
/// valid or not.  There are no loops.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Stack<T>(Vec<T>);

// NB: This isn’t in `impl Stack`, because that requires us to specify type parameters, even though
//     this value doesn’t care about them.
/// The maximum number of elements allowed in the _combined_ stack and altstack.
pub const MAX_STACK_DEPTH: usize = 1000;

/// Wraps a Vec (or whatever underlying implementation we choose in a way that matches the C++ impl
/// and provides us some decent chaining)
impl<T> Stack<T> {
    /// Creates an empty stack.
    pub fn new() -> Self {
        Stack(vec![])
    }

    fn check_len(&self, min: usize) -> Result<(), Error> {
        let len = self.0.len();
        if min <= len {
            Ok(())
        } else {
            Err(Error::InvalidStackOperation(Some((min - 1, len))))
        }
    }

    fn rindex(&self, i: usize) -> Result<usize, Error> {
        let len = self.0.len();
        if i < len {
            Ok(len - i - 1)
        } else {
            Err(Error::InvalidStackOperation(Some((i, len))))
        }
    }

    /// Gets an element from the stack without removing it., counting from the right. I.e.,
    /// `rget(0)` returns the top element.
    fn rget(&self, i: usize) -> Result<&T, Error> {
        let idx = self.rindex(i)?;
        self.0.get(idx).ok_or(Error::InvalidStackOperation(None))
    }

    /// Swaps the elements at two indices in the stack, counting from the right.
    fn rswap(&mut self, a: usize, b: usize) -> Result<(), Error> {
        let ra = self.rindex(a)?;
        let rb = self.rindex(b)?;
        self.0.swap(ra, rb);
        Ok(())
    }

    /// Removes and returns the top element from the stack.
    fn pop(&mut self) -> Result<T, Error> {
        self.0
            .pop()
            .ok_or(Error::InvalidStackOperation(Some((0, self.0.len()))))
    }

    /// Adds a new element to the top of the stack.
    fn push(&mut self, value: T) {
        self.0.push(value)
    }

    /// Returns true if there are no elements in the stack.
    pub(crate) fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Returns the number of elements in the stack.
    pub(crate) fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns an iterator over the stack.
    fn iter(&self) -> Iter<'_, T> {
        self.0.iter()
    }

    /// Returns a mutable reference to the last element of the stack.
    fn last_mut(&mut self) -> Result<&mut T, Error> {
        let len = self.0.len();
        self.0
            .last_mut()
            .ok_or(Error::InvalidStackOperation(Some((0, len))))
    }

    /// Returns a reference to the last element of the stack.
    fn last(&self) -> Result<&T, Error> {
        self.0
            .last()
            .ok_or(Error::InvalidStackOperation(Some((0, self.0.len()))))
    }

    /// Removes an element from the stack, counting from the right.
    fn rremove(&mut self, start: usize) -> Result<T, Error> {
        self.rindex(start).map(|rstart| self.0.remove(rstart))
    }

    /// Inserts an element at the given index, counting from the right.
    fn rinsert(&mut self, i: usize, element: T) -> Result<(), Error> {
        let ri = self.rindex(i)?;
        self.0.insert(ri, element);
        Ok(())
    }
}

impl<T: Clone> Stack<T> {
    /// Returns the last element of the stack as well as the remainder of the stack.
    fn split_last(&self) -> Result<(&T, Stack<T>), Error> {
        self.0
            .split_last()
            .ok_or(Error::InvalidStackOperation(Some((0, self.0.len()))))
            .map(|(last, rem)| (last, Stack(rem.to_vec())))
    }
}

fn is_compressed_or_uncompressed_pub_key(vch_pub_key: &[u8]) -> bool {
    match vch_pub_key.first() {
        Some(0x02 | 0x03) => vch_pub_key.len() == PubKey::COMPRESSED_SIZE,
        Some(0x04) => vch_pub_key.len() == PubKey::SIZE,
        _ => false, // not a public key
    }
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
    script: &script::Code,
    checker: &dyn SignatureChecker,
) -> Result<bool, Error> {
    // Note how this makes the exact order of pubkey/signature evaluation distinguishable by
    // CHECKMULTISIG NOT if the STRICTENC flag is set. See the script_(in)valid tests for details.
    match signature::Decoded::from_bytes(
        vch_sig,
        flags.contains(VerificationFlags::LowS),
        flags.contains(VerificationFlags::StrictEnc),
    ) {
        signature::Validity::InvalidAbort(e) => Err(Error::from(e)),
        signature::Validity::InvalidContinue => {
            // We still need to check the pubkey here, because it can cause an abort.
            check_pub_key_encoding(vch_pub_key, flags)?;
            Ok(false)
        }
        signature::Validity::Valid(sig) => {
            check_pub_key_encoding(vch_pub_key, flags)?;
            Ok(checker.check_sig(&sig, vch_pub_key, script))
        }
    }
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

/// This holds the various components that need to be carried between individual opcode evaluations.
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

    /// Bumps the current `op_count` by one and errors if it exceeds `MAX_OP_COUNT`.
    fn increment_op_count(&mut self) -> Result<(), Error> {
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

    /// Extract the primary stack from the state.
    pub fn stack(&self) -> &Stack<Vec<u8>> {
        &self.stack
    }

    /// Extract the altstack from the state.
    pub fn altstack(&self) -> &Stack<Vec<u8>> {
        &self.altstack
    }

    /// Extract the op_count from the state (in most cases, you can use `increment_op_count`
    /// instead).
    pub fn op_count(&self) -> u8 {
        self.op_count
    }

    /// Extract the current conditional state from the overall state.
    pub fn vexec(&self) -> &Stack<bool> {
        &self.vexec
    }
}

/// Run a single step of the interpreter.
///
/// This is useful for testing & debugging, as we can set up the exact state we want in order to
/// trigger some behavior.
fn eval_step<'a>(
    pc: &'a [u8],
    script: &script::Code,
    flags: VerificationFlags,
    checker: &dyn SignatureChecker,
    state: &mut State,
) -> Result<&'a [u8], script::Error> {
    //
    // Read instruction
    //
    let (res, remaining_code) = opcode::PossiblyBad::parse(pc);
    res.map_err(script::Error::Opcode).and_then(|opcode| {
        eval_possibly_bad(&opcode, script, flags, checker, state)
            .map_err(|ierr| script::Error::Interpreter(Some(opcode), ierr))
            .map(|()| remaining_code)
    })
}

/// Bad opcodes are a bit complicated.
///
/// - They only fail if they are evaluated, so we can’t statically fail scripts that contain them
///   (unlike [Disabled]).
/// - [Bad::OP_RESERVED] counts as a push value for the purposes of
///   [interpreter::VerificationFlags::SigPushOnly] (but push-only sigs must necessarily evaluate
///   all of their opcodes, so what we’re preserving here is that we get
///   [script::Error::SigPushOnly] in this case instead of [script::Error::BadOpcode]).
/// - [Bad::OP_VERIF] and [Bad::OP_VERNOTIF] both _always_ get evaluated, so we need to special case
///   them when checking whether to throw [script::Error::BadOpcode]
fn eval_bad(bad: &opcode::Bad, state: &mut State) -> Result<(), Error> {
    // Note how OP_RESERVED does not count towards the opcode limit.
    if &opcode::Bad::OP_RESERVED != bad {
        state.increment_op_count()?;
    }
    if matches!(bad, opcode::Bad::OP_VERIF | opcode::Bad::OP_VERNOTIF) || should_exec(&state.vexec)
    {
        Err(Error::BadOpcode)
    } else {
        Ok(())
    }
}

/// Eval a single [`Opcode`] … which may be [`opcode::Bad`].
pub fn eval_possibly_bad(
    opcode: &opcode::PossiblyBad,
    script: &script::Code,
    flags: VerificationFlags,
    checker: &dyn SignatureChecker,
    state: &mut State,
) -> Result<(), Error> {
    match opcode {
        opcode::PossiblyBad::Bad(bad) => eval_bad(bad, state),
        opcode::PossiblyBad::Good(opcode) => eval_opcode(flags, opcode, script, checker, state),
    }
}

fn eval_opcode(
    flags: VerificationFlags,
    opcode: &Opcode,
    script: &script::Code,
    checker: &dyn SignatureChecker,
    state: &mut State,
) -> Result<(), Error> {
    match opcode {
        Opcode::PushValue(pv) => {
            if should_exec(&state.vexec) {
                eval_push_value(
                    pv,
                    flags.contains(VerificationFlags::MinimalData),
                    &mut state.stack,
                )
            } else {
                Ok(())
            }
        }
        Opcode::Control(control) => {
            state.increment_op_count()?;
            eval_control(control, &mut state.stack, &mut state.vexec)
        }
        Opcode::Operation(normal) => {
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
    }
    .and_then(|()| {
        // Size limits
        if state.stack.len() + state.altstack.len() > MAX_STACK_DEPTH {
            Err(Error::StackSize(None))
        } else {
            Ok(())
        }
    })
}

fn eval_push_value(
    pv: &opcode::PushValue,
    require_minimal: bool,
    stack: &mut Stack<Vec<u8>>,
) -> Result<(), Error> {
    if require_minimal && !pv.is_minimal_push() {
        Err(Error::MinimalData)
    } else {
        stack.push(pv.value());
        Ok(())
    }
}

// Are we in an executing branch of the script?
fn should_exec(vexec: &Stack<bool>) -> bool {
    vexec.iter().all(|value| *value)
}

/// <expression> if [statements] [else [statements]] endif
fn eval_control(
    op: &opcode::Control,
    stack: &mut Stack<Vec<u8>>,
    vexec: &mut Stack<bool>,
) -> Result<(), Error> {
    match op {
        // <expression> if [statements] [else [statements]] endif
        OP_IF | OP_NOTIF => vexec.push(
            should_exec(vexec) && {
                let value = cast_to_bool(&stack.pop()?);
                if op == &OP_NOTIF {
                    !value
                } else {
                    value
                }
            },
        ),

        OP_ELSE => vexec
            .last_mut()
            .map_err(|_| Error::UnbalancedConditional)
            .map(|last| *last = !*last)?,

        OP_ENDIF => {
            vexec.pop().map_err(|_| Error::UnbalancedConditional)?;
        }
    }
    Ok(())
}

fn eval_operation(
    op: &opcode::Operation,
    flags: VerificationFlags,
    script: &script::Code,
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
            if cast_to_bool(stack.rget(0)?) {
                stack.pop()?;
            } else {
                return Err(Error::Verify);
            }
        }

        OP_RETURN => return Err(Error::OpReturn),

        //
        // Stack ops
        //
        OP_TOALTSTACK => altstack.push(stack.pop()?),

        OP_FROMALTSTACK => stack.push(altstack.pop()?),

        OP_2DROP => {
            // (x1 x2 -- )
            //
            // NB: This needs to be done in this order (rather than `pop(); pop()`) to maintain
            //     state compatibilty with C++. If there is exactly one element on the stack,
            //     removing the top element first would leave us with a different state when the
            //     error occurs.
            stack.rremove(1).and_then(|_| stack.pop())?;
        }

        OP_2DUP => {
            // (x1 x2 -- x1 x2 x1 x2)
            stack.push(stack.rget(1)?.clone());
            stack.push(stack.rget(1)?.clone());
        }

        OP_3DUP => {
            // (x1 x2 x3 -- x1 x2 x3 x1 x2 x3)
            stack.push(stack.rget(2)?.clone());
            stack.push(stack.rget(2)?.clone());
            stack.push(stack.rget(2)?.clone());
        }

        OP_2OVER => {
            // (x1 x2 x3 x4 -- x1 x2 x3 x4 x1 x2)
            stack.push(stack.rget(3)?.clone());
            stack.push(stack.rget(3)?.clone());
        }

        OP_2ROT => {
            // (x1 x2 x3 x4 x5 x6 -- x3 x4 x5 x6 x1 x2)
            let vch1 = stack.rremove(5)?.clone();
            let vch2 = stack.rremove(4)?.clone();
            stack.push(vch1);
            stack.push(vch2);
        }

        OP_2SWAP => {
            // (x1 x2 x3 x4 -- x3 x4 x1 x2)
            stack.rswap(3, 1)?;
            stack.rswap(2, 0)?;
        }

        OP_IFDUP => {
            // (x - 0 | x x)
            let vch = stack.rget(0)?;
            if cast_to_bool(vch) {
                stack.push(vch.clone())
            }
        }

        // -- stacksize
        OP_DEPTH => stack.push(num::serialize(
            i64::try_from(stack.len()).map_err(|err| Error::StackSize(Some(err)))?,
        )),

        OP_DROP => {
            // (x -- )
            stack.pop()?;
        }

        // (x -- x x)
        OP_DUP => stack.push(stack.rget(0)?.clone()),

        // (x1 x2 -- x2)
        OP_NIP => stack.rremove(1).map(|_| ())?,

        // (x1 x2 -- x1 x2 x1)
        OP_OVER => stack.push(stack.rget(1)?.clone()),

        OP_PICK | OP_ROLL => {
            // (xn ... x2 x1 x0 n - xn ... x2 x1 x0 xn)
            // (xn ... x2 x1 x0 n - ... x2 x1 x0 xn)
            stack.check_len(2)?;
            let n = usize::try_from(num::parse(stack.rget(0)?, require_minimal, None)?)
                .map_err(|_| Error::InvalidStackOperation(None))?;
            stack.pop()?;
            stack.check_len(n + 1)?;
            let vch: ValType = stack.rget(n)?.clone();
            if op == &OP_ROLL {
                stack.rremove(n)?;
            }
            stack.push(vch)
        }

        OP_ROT => {
            // (x1 x2 x3 -- x2 x3 x1)
            //  x2 x1 x3  after first swap
            //  x2 x3 x1  after second swap
            stack.rswap(2, 1)?;
            stack.rswap(1, 0)?;
        }

        // (x1 x2 -- x2 x1)
        OP_SWAP => stack.rswap(1, 0)?,

        // (x1 x2 -- x2 x1 x2)
        OP_TUCK => stack.rinsert(1, stack.rget(0)?.clone())?,

        // (in -- in size)
        OP_SIZE => stack.push(num::serialize(
            i64::try_from(stack.rget(0)?.len()).expect("stack element size <= PushValue::MAX_SIZE"),
        )),

        //
        // Bitwise logic
        //
        // (x1 x2 - bool)
        OP_EQUAL => binop(stack, |x1, x2| Ok(cast_from_bool(x1 == x2)))?,
        OP_EQUALVERIFY => binfn(
            stack,
            |x1, x2| {
                if x1 == x2 {
                    Ok(())
                } else {
                    Err(Error::Verify)
                }
            },
        )?,

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
                Err(Error::Verify)
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
            let bn1 = num::parse(stack.rget(2)?, require_minimal, None)?;
            let bn2 = num::parse(stack.rget(1)?, require_minimal, None)?;
            let bn3 = num::parse(stack.rget(0)?, require_minimal, None)?;
            stack.pop()?;
            stack.pop()?;
            stack.pop()?;
            stack.push(cast_from_bool(bn2 <= bn1 && bn1 < bn3))
        }

        //
        // Crypto
        //
        OP_RIPEMD160 | OP_SHA1 | OP_SHA256 | OP_HASH160 | OP_HASH256 => {
            // (in -- hash)
            let vch = stack.pop()?;
            let mut vch_hash = vec![];
            if op == &OP_RIPEMD160 {
                vch_hash = Ripemd160::digest(vch).to_vec();
            } else if op == &OP_SHA1 {
                let mut hasher = Sha1::new();
                hasher.update(vch);
                vch_hash = hasher.finalize().to_vec();
            } else if op == &OP_SHA256 {
                vch_hash = Sha256::digest(vch).to_vec();
            } else if op == &OP_HASH160 {
                vch_hash = Ripemd160::digest(Sha256::digest(vch)).to_vec();
            } else if op == &OP_HASH256 {
                vch_hash = Sha256::digest(Sha256::digest(vch)).to_vec();
            }
            stack.push(vch_hash)
        }

        OP_CHECKSIG | OP_CHECKSIGVERIFY => {
            // (sig pubkey -- bool)
            let vch_sig = stack.rget(1)?.clone();
            let vch_pub_key = stack.rget(0)?.clone();

            let success = is_sig_valid(&vch_sig, &vch_pub_key, flags, script, checker)?;

            stack.pop()?;
            stack.pop()?;
            stack.push(cast_from_bool(success));
            if op == &OP_CHECKSIGVERIFY {
                if success {
                    stack.pop()?;
                } else {
                    return Err(Error::Verify);
                }
            }
        }

        OP_CHECKMULTISIG | OP_CHECKMULTISIGVERIFY => {
            // ([sig ...] num_of_signatures [pubkey ...] num_of_pubkeys -- bool)

            // NB: This is guaranteed u8-safe, because we are limited to 20 keys and
            //     20 signatures, plus a couple other fields. u8 also gives us total
            //     conversions to the other types we deal with here (`isize` and `i64`).
            let mut i: u8 = 0;

            let mut keys_count =
                u8::try_from(num::parse(stack.rget(i.into())?, require_minimal, None)?)
                    .map_err(|err| Error::PubKeyCount(Some(err)))?;
            if keys_count > MAX_PUBKEY_COUNT {
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
            assert!(i <= 1 + MAX_PUBKEY_COUNT);

            let mut sigs_count =
                u8::try_from(num::parse(stack.rget(i.into())?, require_minimal, None)?)
                    .map_err(|err| Error::SigCount(Some(err)))?;
            if sigs_count > keys_count {
                return Err(Error::SigCount(None));
            };
            i += 1;
            let mut isig = i;
            i += sigs_count;
            stack.check_len(usize::from(i) + 1)?;

            let mut success = true;
            while success && sigs_count > 0 {
                let vch_sig: &ValType = stack.rget(isig.into())?;
                let vch_pub_key: &ValType = stack.rget(ikey.into())?;

                // Check signature
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
            if flags.contains(VerificationFlags::NullDummy) && !stack.rget(0)?.is_empty() {
                return Err(Error::SigNullDummy);
            }
            stack.pop()?;

            stack.push(cast_from_bool(success));

            if op == &OP_CHECKMULTISIGVERIFY {
                if success {
                    stack.pop()?;
                } else {
                    return Err(Error::Verify);
                }
            }
        }
    }
    Ok(())
}

/// A wrapper around a function that executes a single opcode from a script.
pub trait StepFn {
    /// Any additional data that is needed by the `StepFn`. In most cases, it can be `()`.
    type Payload: Clone;
    /// Call the underlying function to evaluate a single opcode.
    fn call<'a>(
        &self,
        pc: &'a [u8],
        script: &script::Code,
        state: &mut State,
        payload: &mut Self::Payload,
    ) -> Result<&'a [u8], script::Error>;
}

/// Produces the default stepper, which carries no payload and runs the script as before.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct DefaultStepEvaluator<C> {
    /// The flags which can modify interpretation rules.
    pub(crate) flags: VerificationFlags,
    /// The `SignatureChecker` used in `CHECK*SIG`.
    pub(crate) checker: C,
}

impl<C: SignatureChecker + Copy> StepFn for DefaultStepEvaluator<C> {
    type Payload = ();
    fn call<'a>(
        &self,
        pc: &'a [u8],
        script: &script::Code,
        state: &mut State,
        _payload: &mut (),
    ) -> Result<&'a [u8], script::Error> {
        eval_step(pc, script, self.flags, &self.checker, state)
    }
}

/// Execution of a script component (e.g., script sig, script pubkey, or redeem script).
fn eval_script<F>(
    stack: Stack<Vec<u8>>,
    script: &script::Code,
    payload: &mut F::Payload,
    eval_step: &F,
) -> Result<Stack<Vec<u8>>, script::Error>
where
    F: StepFn,
{
    // There's a limit on how large scripts can be.
    if script.0.len() > script::Code::MAX_SIZE {
        return Err(script::Error::ScriptSize(Some(script.0.len())));
    }

    let mut pc = script.0;

    let mut state = State::initial(stack);

    // Main execution loop
    while !pc.is_empty() {
        pc = eval_step.call(pc, script, &mut state, payload)?;
    }

    if !state.vexec.is_empty() {
        return Err(script::Error::UnclosedConditional(state.vexec.len()));
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
pub type SighashCalculator<'a> =
    &'a dyn Fn(&[u8], &signature::HashType) -> Option<[u8; SIGHASH_SIZE]>;

impl SignatureChecker for CallbackTransactionSignatureChecker<'_> {
    fn check_sig(
        &self,
        sig: &signature::Decoded,
        vch_pub_key: &[u8],
        script_code: &script::Code,
    ) -> bool {
        let pubkey = PubKey(vch_pub_key);

        pubkey.is_valid()
            && (self.sighash)(script_code.0, sig.sighash_type())
                .map(|sighash| pubkey.verify(&sighash, sig.sig()))
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

fn eval_sig<F>(
    script_sig: &script::Code,
    flags: VerificationFlags,
    payload: &mut F::Payload,
    stepper: &F,
) -> Result<Stack<Vec<u8>>, script::Error>
where
    F: StepFn,
{
    if flags.contains(VerificationFlags::SigPushOnly) && !script_sig.is_push_only() {
        Err(script::Error::SigPushOnly)
    } else {
        eval_script(Stack::new(), script_sig, payload, stepper)
    }
}

/// Additional validation for spend-to-script-hash transactions:
fn eval_p2sh<F>(
    data_stack: Stack<Vec<u8>>,
    payload: &mut F::Payload,
    stepper: &F,
) -> Result<Option<Stack<Vec<u8>>>, script::Error>
where
    F: StepFn,
{
    let (pub_key_2, remaining_stack) = data_stack.split_last().expect(
        "stack cannot be empty here, because if it were, the P2SH HASH <> EQUAL scriptPubKey would \
         be evaluated with an empty stack and the `eval_script` in the caller would return false.",
    );
    eval_script(remaining_stack, &script::Code(pub_key_2), payload, stepper).map(|p2sh_stack| {
        if p2sh_stack.last().is_ok_and(cast_to_bool) {
            Some(p2sh_stack)
        } else {
            None
        }
    })
}

/// Full execution of a script.
pub fn verify_script<F>(
    script_sig: &script::Code,
    script_pub_key: &script::Code,
    flags: VerificationFlags,
    payload: &mut F::Payload,
    stepper: &F,
) -> Result<bool, (script::ComponentType, script::Error)>
where
    F: StepFn,
{
    let data_stack = eval_sig(script_sig, flags, payload, stepper)
        .map_err(|e| (script::ComponentType::Sig, e))?;
    let pub_key_stack = eval_script(data_stack.clone(), script_pub_key, payload, stepper)
        .map_err(|e| (script::ComponentType::PubKey, e))?;
    if pub_key_stack.last().is_ok_and(cast_to_bool) {
        if flags.contains(VerificationFlags::P2SH) && script_pub_key.is_pay_to_script_hash() {
            // script_sig must be literals-only or validation fails
            if script_sig.is_push_only() {
                eval_p2sh(data_stack, payload, stepper)
                    .map_err(|e| (script::ComponentType::Redeem, e))
            } else {
                Err((script::ComponentType::Sig, script::Error::SigPushOnly))
            }
        } else {
            Ok(Some(pub_key_stack))
        }
        .and_then(|mresult_stack| {
            match mresult_stack {
                None => Ok(false),
                Some(result_stack) => {
                    // The CLEANSTACK check is only performed after potential P2SH evaluation, as the
                    // non-P2SH evaluation of a P2SH script will obviously not result in a clean stack
                    // (the P2SH inputs remain).
                    if flags.contains(VerificationFlags::CleanStack) {
                        // Disallow CLEANSTACK without P2SH, because Bitcoin did.
                        assert!(flags.contains(VerificationFlags::P2SH));
                        if result_stack.len() == 1 {
                            Ok(true)
                        } else {
                            Err((script::ComponentType::Redeem, script::Error::CleanStack))
                        }
                    } else {
                        Ok(true)
                    }
                }
            }
        })
    } else {
        Ok(false)
    }
}
