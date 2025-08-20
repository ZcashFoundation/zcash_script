use std::{fmt::Display, hash::Hash, slice::Iter};

use secp256k1::ecdsa;

use crate::{
    script::{self, error::InvalidHashType},
    scriptnum::*,
};

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

impl Display for HashType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let signed_outputs = match self.signed_outputs {
            SignedOutputs::All => "ALL",
            SignedOutputs::Single => "SINGLE",
            SignedOutputs::None => "NONE",
        };
        let anyone_can_pay = if self.anyone_can_pay {
            "|ANYONECANPAY"
        } else {
            ""
        };
        write!(f, "{}{}", signed_outputs, anyone_can_pay)
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
        /// pushes up to 75 bytes, OP_PUSHDATA up to 255 bytes, OP_PUSHDATA2 for anything larger). Evaluating
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
    fn check_sig(&self, script_sig: &Signature, vch_pub_key: &[u8], script_code: &[u8]) -> bool;
    fn check_lock_time(&self, lock_time: &ScriptNum) -> bool;
}

pub struct BaseSignatureChecker();

impl SignatureChecker for BaseSignatureChecker {
    fn check_sig(&self, _script_sig: &Signature, _vch_pub_key: &[u8], _script_code: &[u8]) -> bool {
        false
    }

    fn check_lock_time(&self, _lock_time: &ScriptNum) -> bool {
        false
    }
}

pub fn cast_to_bool(vch: &ValType) -> bool {
    let vch_ = vch.clone().to_vec();
    for (i, vchi) in vch_.to_vec().iter().enumerate() {
        if *vchi != 0 {
            // Can be negative zero
            if i == vch_.len() - 1 && *vchi == 0x80 {
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
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Stack<T>(Vec<T>);

fn catch_underflow<U>(opt: Option<U>) -> Result<U, script::Error> {
    opt.ok_or(script::Error::InvalidStackOperation)
}

/// Wraps a Vec (or whatever underlying implementation we choose in a way that matches the C++ impl
/// and provides us some decent chaining)
impl<T: Clone> Stack<T> {
    pub fn new() -> Self {
        Stack(vec![])
    }

    fn rindex(&self, i: usize) -> Result<usize, script::Error> {
        let len = self.0.len();
        if i < len {
            Ok(len - i - 1)
        } else {
            Err(script::Error::InvalidStackOperation)
        }
    }

    pub fn rget(&self, i: usize) -> Result<&T, script::Error> {
        self.rindex(i)
            .and_then(|idx| catch_underflow(self.0.get(idx)))
    }

    pub fn push_dup(&mut self, i: usize) -> Result<(), script::Error> {
        self.rget(i).cloned().map(|elem| self.push(elem))
    }

    pub fn swap(&mut self, a: usize, b: usize) -> Result<(), script::Error> {
        if self.len() <= a || self.len() <= b {
            Err(script::Error::InvalidStackOperation)
        } else {
            Ok(self.0.swap(a, b))
        }
    }

    pub fn pop(&mut self) -> Result<T, script::Error> {
        catch_underflow(self.0.pop())
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

    pub fn last(&self) -> Result<&T, script::Error> {
        catch_underflow(self.0.last())
    }

    pub fn split_last(&self) -> Result<(&T, Stack<T>), script::Error> {
        catch_underflow(self.0.split_last()).map(|(last, rem)| (last, Stack(rem.to_vec())))
    }

    pub fn erase(&mut self, start: usize, end: Option<usize>) -> Result<(), script::Error> {
        self.rindex(start).map(|idx| {
            for _ in 0..end.map_or(1, |e| start - e) {
                self.0.remove(idx);
            }
        })
    }

    pub fn insert(&mut self, i: usize, element: T) -> Result<(), script::Error> {
        self.rindex(i).map(|idx| self.0.insert(idx, element))
    }
}

pub type ValType = Vec<u8>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct State {
    pub stack: Stack<ValType>,
    pub altstack: Stack<ValType>,
    // We keep track of how many operations have executed so far to prevent expensive-to-verify
    // scripts
    pub op_count: u8,
    // This keeps track of the conditional flags at each nesting level during execution. If we're in
    // a branch of execution where *any* of these conditionals are false, we ignore opcodes unless
    // those opcodes direct control flow (OP_IF, OP_ELSE, etc.).
    pub vexec: Stack<bool>,
}

impl State {
    pub fn initial(stack: Stack<ValType>) -> Self {
        State {
            stack,
            altstack: Stack::new(),
            op_count: 0,
            vexec: Stack::new(),
        }
    }
}

#[derive(Clone)]
pub struct Signature {
    pub sig: ecdsa::Signature,
    pub sighash: HashType,
}

pub trait Evaluable {
    fn byte_len(&self) -> usize;

    fn eval(
        &self,
        flags: VerificationFlags,
        script: &[u8],
        checker: &dyn SignatureChecker,
        state: &mut State,
    ) -> Result<(), script::Error>;
}

/// Produces a step evaluator that does nothing but standard evaluation.
pub fn basic_evaluator<'a>(
    flags: VerificationFlags,
    checker: &'a impl SignatureChecker,
) -> impl Fn(&dyn Evaluable, &[u8], &mut State, &mut ()) -> Result<(), script::Error> + 'a {
    move |pc, script: &[u8], state, _payload| {
        pc.eval(flags, script, checker, state).and_then(|()| {
            // Size limits
            if state.stack.len() + state.altstack.len() > 1000 {
                Err(script::Error::StackSize(None))
            } else {
                Ok(())
            }
        })
    }
}
