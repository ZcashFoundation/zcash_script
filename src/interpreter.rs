use std::slice::Iter;

use ripemd::Ripemd160;
use sha1::Sha1;
use sha2::{Digest, Sha256};

use super::external::pubkey::PubKey;
use super::script::{Operation::*, PushValue::*, *};
use super::script_error::*;

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

/// Things that can go wrong when constructing a `HashType` from bit flags.
pub enum InvalidHashType {
    /// Either or both of the two least-significant bits must be set.
    UnknownSignedOutputs,
    /// With v5 transactions, bits other than those specified for `HashType` must be 0. The `i32`
    /// includes only the bits that are undefined by `HashType`.
    ExtraBitsSet(i32),
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
    fn check_sig(&self, _script_sig: &[u8], _vch_pub_key: &[u8], _script_code: &Script) -> bool {
        false
    }

    fn check_lock_time(&self, _lock_time: &ScriptNum) -> bool {
        false
    }
}

pub struct BaseSignatureChecker();

impl SignatureChecker for BaseSignatureChecker {}

#[derive(Copy, Clone)]
pub struct CallbackTransactionSignatureChecker<'a> {
    pub sighash: SighashCalculator<'a>,
    pub lock_time: &'a ScriptNum,
    pub is_final: bool,
}

type ValType = Vec<u8>;

fn set_success<T>(res: T) -> Result<T, ScriptError> {
    Ok(res)
}

fn set_error<T>(serror: ScriptError) -> Result<T, ScriptError> {
    Err(serror)
}

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
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Stack<T>(Vec<T>);

/// Wraps a Vec (or whatever underlying implementation we choose in a way that matches the C++ impl
/// and provides us some decent chaining)
impl<T: Clone> Stack<T> {
    fn reverse_index(&self, i: isize) -> Result<usize, ScriptError> {
        usize::try_from(-i)
            .map(|a| self.0.len() - a)
            .map_err(|_| ScriptError::InvalidStackOperation)
    }

    pub fn top(&self, i: isize) -> Result<&T, ScriptError> {
        let idx = self.reverse_index(i)?;
        self.0.get(idx).ok_or(ScriptError::InvalidStackOperation)
    }

    pub fn swap(&mut self, a: isize, b: isize) -> Result<(), ScriptError> {
        let au = self.reverse_index(a)?;
        let bu = self.reverse_index(b)?;
        self.0.swap(au, bu);
        Ok(())
    }

    pub fn pop(&mut self) -> Result<T, ScriptError> {
        self.0.pop().ok_or(ScriptError::InvalidStackOperation)
    }

    pub fn push_back(&mut self, value: T) {
        self.0.push(value)
    }

    pub fn empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn size(&self) -> usize {
        self.0.len()
    }

    pub fn iter(&self) -> Iter<'_, T> {
        self.0.iter()
    }

    pub fn back(&mut self) -> Result<&mut T, ScriptError> {
        self.0.last_mut().ok_or(ScriptError::InvalidStackOperation)
    }

    pub fn last(&self) -> Result<&T, ScriptError> {
        self.0.last().ok_or(ScriptError::InvalidStackOperation)
    }

    pub fn split_last(&self) -> Result<(&T, Stack<T>), ScriptError> {
        self.0
            .split_last()
            .ok_or(ScriptError::InvalidStackOperation)
            .map(|(last, rem)| (last, Stack(rem.to_vec())))
    }

    pub fn erase(&mut self, start: usize, end: Option<usize>) {
        for _ in 0..end.map_or(1, |e| e - start) {
            self.0.remove(start);
        }
    }

    pub fn insert(&mut self, i: usize, element: T) {
        self.0.insert(i, element)
    }

    pub fn end(&self) -> usize {
        self.0.len()
    }
}

fn is_compressed_or_uncompressed_pub_key(vch_pub_key: &ValType) -> bool {
    if vch_pub_key.len() < PubKey::COMPRESSED_PUBLIC_KEY_SIZE {
        //  Non-canonical public key: too short
        return false;
    }
    if vch_pub_key[0] == 0x04 {
        if vch_pub_key.len() != PubKey::PUBLIC_KEY_SIZE {
            //  Non-canonical public key: invalid length for uncompressed key
            return false;
        }
    } else if vch_pub_key[0] == 0x02 || vch_pub_key[0] == 0x03 {
        if vch_pub_key.len() != PubKey::COMPRESSED_PUBLIC_KEY_SIZE {
            //  Non-canonical public key: invalid length for compressed key
            return false;
        }
    } else {
        //  Non-canonical public key: neither compressed nor uncompressed
        return false;
    }
    true
}

/**
 * A canonical signature consists of: <30> <total len> <02> <len R> <R> <02> <len S> <S> <hashtype>
 * Where R and S are not negative (their first byte has its highest bit not set), and not
 * excessively padded (do not start with a 0 byte, unless an otherwise negative number follows,
 * in which case a single 0 byte is necessary and even required).
 *
 * See https://bitcointalk.org/index.php?topic=8392.msg127623#msg127623
 *
 * This function is consensus-critical since BIP66.
 */
fn is_valid_signature_encoding(sig: &[u8]) -> bool {
    // Format: 0x30 [total-length] 0x02 [R-length] [R] 0x02 [S-length] [S] [sighash]
    // * total-length: 1-byte length descriptor of everything that follows,
    //   excluding the sighash byte.
    // * R-length: 1-byte length descriptor of the R value that follows.
    // * R: arbitrary-length big-endian encoded R value. It must use the shortest
    //   possible encoding for a positive integer (which means no null bytes at
    //   the start, except a single one when the next byte has its highest bit set).
    // * S-length: 1-byte length descriptor of the S value that follows.
    // * S: arbitrary-length big-endian encoded S value. The same rules apply.
    // * sighash: 1-byte value indicating what data is hashed (not part of the DER
    //   signature)

    // Minimum and maximum size constraints.
    if sig.len() < 9 {
        return false;
    };
    if sig.len() > 73 {
        return false;
    };

    // A signature is of type 0x30 (compound).
    if sig[0] != 0x30 {
        return false;
    };

    // Make sure the length covers the entire signature.
    if usize::from(sig[1]) != sig.len() - 3 {
        return false;
    };

    // Extract the length of the R element.
    let len_r = usize::from(sig[3]);

    // Make sure the length of the S element is still inside the signature.
    if 5 + len_r >= sig.len() {
        return false;
    };

    // Extract the length of the S element.
    let len_s = usize::from(sig[5 + len_r]);

    // Verify that the length of the signature matches the sum of the length
    // of the elements.
    if len_r + len_s + 7 != sig.len() {
        return false;
    };

    // Check whether the R element is an integer.
    if sig[2] != 0x02 {
        return false;
    };

    // Zero-length integers are not allowed for R.
    if len_r == 0 {
        return false;
    };

    // Negative numbers are not allowed for R.
    if sig[4] & 0x80 != 0 {
        return false;
    };

    // Null bytes at the start of R are not allowed, unless R would
    // otherwise be interpreted as a negative number.
    if len_r > 1 && sig[4] == 0x00 && sig[5] & 0x80 == 0 {
        return false;
    };

    // Check whether the S element is an integer.
    if sig[len_r + 4] != 0x02 {
        return false;
    };

    // Zero-length integers are not allowed for S.
    if len_s == 0 {
        return false;
    };

    // Negative numbers are not allowed for S.
    if sig[len_r + 6] & 0x80 != 0 {
        return false;
    };

    // Null bytes at the start of S are not allowed, unless S would otherwise be
    // interpreted as a negative number.
    if len_s > 1 && sig[len_r + 6] == 0x00 && sig[len_r + 7] & 0x80 == 0 {
        return false;
    };

    true
}

fn is_low_der_signature(vch_sig: &ValType) -> Result<bool, ScriptError> {
    if !is_valid_signature_encoding(vch_sig) {
        return set_error(ScriptError::SigDER);
    };
    // https://bitcoin.stackexchange.com/a/12556:
    //     Also note that inside transaction signatures, an extra hashtype byte
    //     follows the actual signature data.
    let (_, vch_sig_copy) = vch_sig
        .split_last()
        .expect("`is_valid_signature_encoding` checks that the length is at least 9");
    // If the S value is above the order of the curve divided by two, its
    // complement modulo the order could have been used instead, which is
    // one byte shorter when encoded correctly.
    // FIXME: This can return `false` without setting an error, which is not the expectation of the
    //        caller.
    Ok(PubKey::check_low_s(vch_sig_copy))
}

fn is_defined_hashtype_signature(vch_sig: &ValType) -> bool {
    if vch_sig.is_empty() {
        return false;
    };

    HashType::from_bits(i32::from(vch_sig[vch_sig.len() - 1]), true).is_ok()
}

fn check_signature_encoding(
    vch_sig: &Vec<u8>,
    flags: VerificationFlags,
) -> Result<(), ScriptError> {
    // Empty signature. Not strictly DER encoded, but allowed to provide a
    // compact way to provide an invalid signature for use with CHECK(MULTI)SIG
    if vch_sig.is_empty() {
        return Ok(());
    };
    if !is_valid_signature_encoding(vch_sig) {
        return set_error(ScriptError::SigDER);
    } else if flags.contains(VerificationFlags::LowS) && !is_low_der_signature(vch_sig)? {
        return set_error(ScriptError::SigHighS);
    } else if flags.contains(VerificationFlags::StrictEnc)
        && !is_defined_hashtype_signature(vch_sig)
    {
        return set_error(ScriptError::SigHashType);
    };
    Ok(())
}

fn check_pub_key_encoding(vch_sig: &ValType, flags: VerificationFlags) -> Result<(), ScriptError> {
    if flags.contains(VerificationFlags::StrictEnc)
        && !is_compressed_or_uncompressed_pub_key(vch_sig)
    {
        return Err(ScriptError::PubKeyType);
    };
    set_success(())
}

fn check_minimal_push(data: &[u8], opcode: PushValue) -> bool {
    if data.is_empty() {
        // Could have used OP_0.
        return opcode == OP_0;
    } else if data.len() == 1 && data[0] >= 1 && data[0] <= 16 {
        // Could have used OP_1 .. OP_16.
        return u8::from(opcode) == u8::from(OP_1) + (data[0] - 1);
    } else if data.len() == 1 && data[0] == 0x81 {
        // Could have used OP_1NEGATE.
        return opcode == OP_1NEGATE;
    } else if data.len() <= 75 {
        // Could have used a direct push (opcode indicating number of bytes pushed + those bytes).
        return usize::from(u8::from(opcode)) == data.len();
    } else if data.len() <= 255 {
        // Could have used OP_PUSHDATA.
        return opcode == OP_PUSHDATA1;
    } else if data.len() <= 65535 {
        // Could have used OP_PUSHDATA2.
        return opcode == OP_PUSHDATA2;
    }
    true
}

const VCH_FALSE: ValType = Vec::new();
const VCH_TRUE: [u8; 1] = [1];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct State {
    pub stack: Stack<Vec<u8>>,
    pub altstack: Stack<Vec<u8>>,
    // We keep track of how many operations have executed so far to prevent expensive-to-verify
    // scripts
    pub op_count: u8,
    // This keeps track of the conditional flags at each nesting level during execution. If we're in
    // a branch of execution where *any* of these conditionals are false, we ignore opcodes unless
    // those opcodes direct control flow (OP_IF, OP_ELSE, etc.).
    pub vexec: Stack<bool>,
}

impl State {
    pub fn initial(stack: Stack<Vec<u8>>) -> Self {
        State {
            stack,
            altstack: Stack(vec![]),
            op_count: 0,
            vexec: Stack(vec![]),
        }
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
) -> Result<&'a [u8], ScriptError> {
    let stack = &mut state.stack;
    let op_count = &mut state.op_count;
    let require_minimal = flags.contains(VerificationFlags::MinimalData);
    let vexec = &mut state.vexec;
    let altstack = &mut state.altstack;

    // Are we in an executing branch of the script?
    let exec = vexec.iter().all(|value| *value);

    //
    // Read instruction
    //
    let (opcode, vch_push_value, new_pc) = Script::get_op2(pc)?;
    if vch_push_value.len() > MAX_SCRIPT_ELEMENT_SIZE {
        return set_error(ScriptError::PushSize);
    }

    match opcode {
        Opcode::PushValue(pv) => {
            if exec {
                match pv {
                    //
                    // Push value
                    //
                    OP_1NEGATE | OP_1 | OP_2 | OP_3 | OP_4 | OP_5 | OP_6 | OP_7 | OP_8 | OP_9
                    | OP_10 | OP_11 | OP_12 | OP_13 | OP_14 | OP_15 | OP_16 => {
                        // ( -- value)
                        let bn = ScriptNum::from(u8::from(pv)) - u8::from(OP_RESERVED).into();
                        stack.push_back(bn.getvch());
                        // The result of these opcodes should always be the minimal way to push the data
                        // they push, so no need for a CheckMinimalPush here.
                    }
                    _ => {
                        if pv <= OP_PUSHDATA4 {
                            if require_minimal && !check_minimal_push(vch_push_value, pv) {
                                return set_error(ScriptError::MinimalData);
                            }
                            stack.push_back(vch_push_value.to_vec());
                        } else {
                            return set_error(ScriptError::BadOpcode);
                        }
                    }
                }
            }
        }
        Opcode::Operation(op) => {
            // Note how OP_RESERVED does not count towards the opcode limit.
            *op_count += 1;
            if *op_count > 201 {
                return set_error(ScriptError::OpCount);
            }

            if op == OP_CAT
                || op == OP_SUBSTR
                || op == OP_LEFT
                || op == OP_RIGHT
                || op == OP_INVERT
                || op == OP_AND
                || op == OP_OR
                || op == OP_XOR
                || op == OP_2MUL
                || op == OP_2DIV
                || op == OP_MUL
                || op == OP_DIV
                || op == OP_MOD
                || op == OP_LSHIFT
                || op == OP_RSHIFT
                || op == OP_CODESEPARATOR
            {
                return set_error(ScriptError::DisabledOpcode); // Disabled opcodes.
            }

            if exec || (OP_IF <= op && op <= OP_ENDIF) {
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
                                return set_error(ScriptError::DiscourageUpgradableNOPs);
                            }
                        } else {
                            if stack.size() < 1 {
                                return set_error(ScriptError::InvalidStackOperation);
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
                            let lock_time =
                                ScriptNum::new(stack.top(-1)?, require_minimal, Some(5))?;

                            // In the rare event that the argument may be < 0 due to
                            // some arithmetic being done first, you can always use
                            // 0 MAX CHECKLOCKTIMEVERIFY.
                            if lock_time < ScriptNum::ZERO {
                                return set_error(ScriptError::NegativeLockTime);
                            }

                            // Actually compare the specified lock time with the transaction.
                            if !checker.check_lock_time(&lock_time) {
                                return set_error(ScriptError::UnsatisfiedLockTime);
                            }
                        }
                    }

                    OP_NOP1 | OP_NOP3 | OP_NOP4 | OP_NOP5 | OP_NOP6 | OP_NOP7 | OP_NOP8
                    | OP_NOP9 | OP_NOP10 => {
                        // Do nothing, though if the caller wants to prevent people from using
                        // these NOPs (as part of a standard tx rule, for example) they can
                        // enable `DiscourageUpgradableNOPs` to turn these opcodes into errors.
                        if flags.contains(VerificationFlags::DiscourageUpgradableNOPs) {
                            return set_error(ScriptError::DiscourageUpgradableNOPs);
                        }
                    }

                    OP_IF | OP_NOTIF => {
                        // <expression> if [statements] [else [statements]] endif
                        let mut value = false;
                        if exec {
                            if stack.size() < 1 {
                                return set_error(ScriptError::UnbalancedConditional);
                            }
                            let vch: &ValType = stack.top(-1)?;
                            value = cast_to_bool(vch);
                            if op == OP_NOTIF {
                                value = !value
                            };
                            stack.pop()?;
                        }
                        vexec.push_back(value);
                    }

                    OP_ELSE => {
                        if vexec.empty() {
                            return set_error(ScriptError::UnbalancedConditional);
                        }
                        vexec.back().map(|last| *last = !*last)?;
                    }

                    OP_ENDIF => {
                        if vexec.empty() {
                            return set_error(ScriptError::UnbalancedConditional);
                        }
                        vexec.pop()?;
                    }

                    OP_VERIFY => {
                        // (true -- ) or
                        // (false -- false) and return
                        if stack.size() < 1 {
                            return set_error(ScriptError::InvalidStackOperation);
                        }
                        let value = cast_to_bool(stack.top(-1)?);
                        if value {
                            stack.pop()?;
                        } else {
                            return set_error(ScriptError::Verify);
                        }
                    }

                    OP_RETURN => return set_error(ScriptError::OpReturn),

                    //
                    // Stack ops
                    //
                    OP_TOALTSTACK => {
                        if stack.empty() {
                            return set_error(ScriptError::InvalidStackOperation);
                        }
                        altstack.push_back(stack.top(-1)?.clone());
                        stack.pop()?;
                    }

                    OP_FROMALTSTACK => {
                        if altstack.empty() {
                            return set_error(ScriptError::InvalidAltstackOperation);
                        }
                        stack.push_back(altstack.top(-1)?.clone());
                        altstack.pop()?;
                    }

                    OP_2DROP => {
                        if stack.size() < 2 {
                            return set_error(ScriptError::InvalidStackOperation);
                        }

                        stack.pop()?;
                        stack.pop()?;
                    }

                    OP_2DUP => {
                        // (x1 x2 -- x1 x2 x1 x2)
                        if stack.size() < 2 {
                            return set_error(ScriptError::InvalidStackOperation);
                        }
                        let vch1 = stack.top(-2)?.clone();
                        let vch2 = stack.top(-1)?.clone();
                        stack.push_back(vch1);
                        stack.push_back(vch2);
                    }

                    OP_3DUP => {
                        // (x1 x2 x3 -- x1 x2 x3 x1 x2 x3)
                        if stack.size() < 3 {
                            return set_error(ScriptError::InvalidStackOperation);
                        }
                        let vch1 = stack.top(-3)?.clone();
                        let vch2 = stack.top(-2)?.clone();
                        let vch3 = stack.top(-1)?.clone();
                        stack.push_back(vch1);
                        stack.push_back(vch2);
                        stack.push_back(vch3);
                    }

                    OP_2OVER => {
                        // (x1 x2 x3 x4 -- x1 x2 x3 x4 x1 x2)
                        if stack.size() < 4 {
                            return set_error(ScriptError::InvalidStackOperation);
                        }
                        let vch1 = stack.top(-4)?.clone();
                        let vch2 = stack.top(-3)?.clone();
                        stack.push_back(vch1);
                        stack.push_back(vch2);
                    }

                    OP_2ROT => {
                        // (x1 x2 x3 x4 x5 x6 -- x3 x4 x5 x6 x1 x2)
                        if stack.size() < 6 {
                            return set_error(ScriptError::InvalidStackOperation);
                        }
                        let vch1 = stack.top(-6)?.clone();
                        let vch2 = stack.top(-5)?.clone();
                        stack.erase(stack.end() - 6, Some(stack.end() - 4));
                        stack.push_back(vch1);
                        stack.push_back(vch2);
                    }

                    OP_2SWAP => {
                        // (x1 x2 x3 x4 -- x3 x4 x1 x2)
                        if stack.size() < 4 {
                            return set_error(ScriptError::InvalidStackOperation);
                        }
                        stack.swap(-4, -2)?;
                        stack.swap(-3, -1)?;
                    }

                    OP_IFDUP => {
                        // (x - 0 | x x)
                        if stack.size() < 1 {
                            return set_error(ScriptError::InvalidStackOperation);
                        }
                        let vch = stack.top(-1)?;
                        if cast_to_bool(vch) {
                            stack.push_back(vch.to_vec())
                        }
                    }

                    OP_DEPTH => {
                        // -- stacksize
                        let bn = ScriptNum::try_from(stack.size())
                            .map_err(|_| ScriptError::StackSize)?;
                        stack.push_back(bn.getvch())
                    }

                    OP_DROP => {
                        // (x -- )
                        if stack.size() < 1 {
                            return set_error(ScriptError::InvalidStackOperation);
                        }
                        stack.pop()?;
                    }

                    OP_DUP => {
                        // (x -- x x)
                        if stack.size() < 1 {
                            return set_error(ScriptError::InvalidStackOperation);
                        }

                        let vch = stack.top(-1)?;
                        stack.push_back(vch.clone());
                    }

                    OP_NIP => {
                        // (x1 x2 -- x2)
                        if stack.size() < 2 {
                            return set_error(ScriptError::InvalidStackOperation);
                        }
                        stack.erase(stack.end() - 2, None);
                    }

                    OP_OVER => {
                        // (x1 x2 -- x1 x2 x1)
                        if stack.size() < 2 {
                            return set_error(ScriptError::InvalidStackOperation);
                        }
                        let vch = stack.top(-2)?;
                        stack.push_back(vch.clone());
                    }

                    OP_PICK | OP_ROLL => {
                        // (xn ... x2 x1 x0 n - xn ... x2 x1 x0 xn)
                        // (xn ... x2 x1 x0 n - ... x2 x1 x0 xn)
                        if stack.size() < 2 {
                            return set_error(ScriptError::InvalidStackOperation);
                        }
                        let n =
                            u16::try_from(ScriptNum::new(stack.top(-1)?, require_minimal, None)?)
                                .map_err(|_| ScriptError::InvalidStackOperation)?;
                        stack.pop()?;
                        if usize::from(n) >= stack.size() {
                            return set_error(ScriptError::InvalidStackOperation);
                        }
                        let vch: ValType = stack
                            .top(
                                -isize::try_from(n)
                                    .map_err(|_| ScriptError::InvalidStackOperation)?
                                    - 1,
                            )?
                            .clone();
                        if op == OP_ROLL {
                            stack.erase(stack.end() - usize::from(n) - 1, None);
                        }
                        stack.push_back(vch)
                    }

                    OP_ROT => {
                        // (x1 x2 x3 -- x2 x3 x1)
                        //  x2 x1 x3  after first swap
                        //  x2 x3 x1  after second swap
                        if stack.size() < 3 {
                            return set_error(ScriptError::InvalidStackOperation);
                        }
                        stack.swap(-3, -2)?;
                        stack.swap(-2, -1)?;
                    }

                    OP_SWAP => {
                        // (x1 x2 -- x2 x1)
                        if stack.size() < 2 {
                            return set_error(ScriptError::InvalidStackOperation);
                        }
                        stack.swap(-2, -1)?;
                    }

                    OP_TUCK => {
                        // (x1 x2 -- x2 x1 x2)
                        if stack.size() < 2 {
                            return set_error(ScriptError::InvalidStackOperation);
                        }
                        let vch = stack.top(-1)?.clone();
                        stack.insert(stack.end() - 2, vch)
                    }

                    OP_SIZE => {
                        // (in -- in size)
                        if stack.size() < 1 {
                            return set_error(ScriptError::InvalidStackOperation);
                        }
                        let bn = ScriptNum::try_from(stack.top(-1)?.len())
                            .expect("stack element size fits in ScriptNum");
                        stack.push_back(bn.getvch())
                    }

                    //
                    // Bitwise logic
                    //
                    OP_EQUAL | OP_EQUALVERIFY => {
                        // (x1 x2 - bool)
                        if stack.size() < 2 {
                            return set_error(ScriptError::InvalidStackOperation);
                        }
                        let vch1 = stack.top(-2)?.clone();
                        let vch2 = stack.top(-1)?.clone();
                        let equal = vch1 == vch2;
                        stack.pop()?;
                        stack.pop()?;
                        stack.push_back(if equal { VCH_TRUE.to_vec() } else { VCH_FALSE });
                        if op == OP_EQUALVERIFY {
                            if equal {
                                stack.pop()?;
                            } else {
                                return set_error(ScriptError::EqualVerify);
                            }
                        }
                    }

                    //
                    // Numeric
                    //
                    OP_1ADD | OP_1SUB | OP_NEGATE | OP_ABS | OP_NOT | OP_0NOTEQUAL => {
                        // (in -- out)
                        if stack.size() < 1 {
                            return set_error(ScriptError::InvalidStackOperation);
                        }
                        let mut bn = ScriptNum::new(stack.top(-1)?, require_minimal, None)?;
                        match op {
                            OP_1ADD => bn = bn + ScriptNum::ONE,
                            OP_1SUB => bn = bn - ScriptNum::ONE,
                            OP_NEGATE => bn = -bn,
                            OP_ABS => {
                                if bn < ScriptNum::ZERO {
                                    bn = -bn
                                }
                            }
                            OP_NOT => bn = ScriptNum::from(bn == ScriptNum::ZERO),
                            OP_0NOTEQUAL => bn = ScriptNum::from(bn != ScriptNum::ZERO),
                            _ => panic!("invalid opcode"),
                        }
                        stack.pop()?;
                        stack.push_back(bn.getvch())
                    }

                    OP_ADD
                    | OP_SUB
                    | OP_BOOLAND
                    | OP_BOOLOR
                    | OP_NUMEQUAL
                    | OP_NUMEQUALVERIFY
                    | OP_NUMNOTEQUAL
                    | OP_LESSTHAN
                    | OP_GREATERTHAN
                    | OP_LESSTHANOREQUAL
                    | OP_GREATERTHANOREQUAL
                    | OP_MIN
                    | OP_MAX => {
                        // (x1 x2 -- out)
                        if stack.size() < 2 {
                            return set_error(ScriptError::InvalidStackOperation);
                        }
                        let bn1 = ScriptNum::new(stack.top(-2)?, require_minimal, None)?;
                        let bn2 = ScriptNum::new(stack.top(-1)?, require_minimal, None)?;
                        let bn = match op {
                            OP_ADD => bn1 + bn2,

                            OP_SUB => bn1 - bn2,

                            OP_BOOLAND => {
                                ScriptNum::from(bn1 != ScriptNum::ZERO && bn2 != ScriptNum::ZERO)
                            }
                            OP_BOOLOR => {
                                ScriptNum::from(bn1 != ScriptNum::ZERO || bn2 != ScriptNum::ZERO)
                            }
                            OP_NUMEQUAL => ScriptNum::from(bn1 == bn2),
                            OP_NUMEQUALVERIFY => ScriptNum::from(bn1 == bn2),
                            OP_NUMNOTEQUAL => ScriptNum::from(bn1 != bn2),
                            OP_LESSTHAN => ScriptNum::from(bn1 < bn2),
                            OP_GREATERTHAN => ScriptNum::from(bn1 > bn2),
                            OP_LESSTHANOREQUAL => ScriptNum::from(bn1 <= bn2),
                            OP_GREATERTHANOREQUAL => ScriptNum::from(bn1 >= bn2),
                            OP_MIN => {
                                if bn1 < bn2 {
                                    bn1
                                } else {
                                    bn2
                                }
                            }
                            OP_MAX => {
                                if bn1 > bn2 {
                                    bn1
                                } else {
                                    bn2
                                }
                            }
                            _ => panic!("invalid opcode"),
                        };
                        stack.pop()?;
                        stack.pop()?;
                        stack.push_back(bn.getvch());

                        if op == OP_NUMEQUALVERIFY {
                            if cast_to_bool(stack.top(-1)?) {
                                stack.pop()?;
                            } else {
                                return set_error(ScriptError::NumEqualVerify);
                            }
                        }
                    }

                    OP_WITHIN => {
                        // (x min max -- out)
                        if stack.size() < 3 {
                            return set_error(ScriptError::InvalidStackOperation);
                        }
                        let bn1 = ScriptNum::new(stack.top(-3)?, require_minimal, None)?;
                        let bn2 = ScriptNum::new(stack.top(-2)?, require_minimal, None)?;
                        let bn3 = ScriptNum::new(stack.top(-1)?, require_minimal, None)?;
                        let value = bn2 <= bn1 && bn1 < bn3;
                        stack.pop()?;
                        stack.pop()?;
                        stack.pop()?;
                        stack.push_back(if value { VCH_TRUE.to_vec() } else { VCH_FALSE })
                    }

                    //
                    // Crypto
                    //
                    OP_RIPEMD160 | OP_SHA1 | OP_SHA256 | OP_HASH160 | OP_HASH256 => {
                        // (in -- hash)
                        if stack.size() < 1 {
                            return set_error(ScriptError::InvalidStackOperation);
                        }
                        let vch = stack.top(-1)?;
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
                        stack.push_back(vch_hash)
                    }

                    OP_CHECKSIG | OP_CHECKSIGVERIFY => {
                        // (sig pubkey -- bool)
                        if stack.size() < 2 {
                            return set_error(ScriptError::InvalidStackOperation);
                        }

                        let vch_sig = stack.top(-2)?.clone();
                        let vch_pub_key = stack.top(-1)?.clone();

                        check_signature_encoding(&vch_sig, flags)?;
                        check_pub_key_encoding(&vch_pub_key, flags)?;
                        let success = checker.check_sig(&vch_sig, &vch_pub_key, script);

                        stack.pop()?;
                        stack.pop()?;
                        stack.push_back(if success {
                            VCH_TRUE.to_vec()
                        } else {
                            VCH_FALSE
                        });
                        if op == OP_CHECKSIGVERIFY {
                            if success {
                                stack.pop()?;
                            } else {
                                return set_error(ScriptError::CheckSigVerify);
                            }
                        }
                    }

                    OP_CHECKMULTISIG | OP_CHECKMULTISIGVERIFY => {
                        // ([sig ...] num_of_signatures [pubkey ...] num_of_pubkeys -- bool)

                        // NB: This is guaranteed u8-safe, because we are limited to 20 keys and
                        //     20 signatures, plus a couple other fields. u8 also gives us total
                        //     conversions to the other types we deal with here (`isize` and `i64`).
                        let mut i: u8 = 1;
                        if stack.size() < i.into() {
                            return set_error(ScriptError::InvalidStackOperation);
                        };

                        let mut keys_count = u8::try_from(ScriptNum::new(
                            stack.top(-isize::from(i))?,
                            require_minimal,
                            None,
                        )?)
                        .map_err(|_| ScriptError::PubKeyCount)?;
                        if keys_count > 20 {
                            return set_error(ScriptError::PubKeyCount);
                        };
                        assert!(*op_count <= 201);
                        *op_count += keys_count;
                        if *op_count > 201 {
                            return set_error(ScriptError::OpCount);
                        };
                        i += 1;
                        let mut ikey = i;
                        i += keys_count;
                        if stack.size() < i.into() {
                            return set_error(ScriptError::InvalidStackOperation);
                        }

                        let mut sigs_count = u8::try_from(ScriptNum::new(
                            stack.top(-isize::from(i))?,
                            require_minimal,
                            None,
                        )?)
                        .map_err(|_| ScriptError::SigCount)?;
                        if sigs_count > keys_count {
                            return set_error(ScriptError::SigCount);
                        };
                        assert!(i <= 22);
                        i += 1;
                        let mut isig = i;
                        i += sigs_count;
                        if stack.size() < i.into() {
                            return set_error(ScriptError::InvalidStackOperation);
                        };

                        let mut success = true;
                        while success && sigs_count > 0 {
                            let vch_sig: &ValType = stack.top(-isize::from(isig))?;
                            let vch_pub_key: &ValType = stack.top(-isize::from(ikey))?;

                            // Note how this makes the exact order of pubkey/signature evaluation
                            // distinguishable by CHECKMULTISIG NOT if the STRICTENC flag is set.
                            // See the script_(in)valid tests for details.
                            check_signature_encoding(vch_sig, flags)?;
                            check_pub_key_encoding(vch_pub_key, flags)?;

                            // Check signature
                            let ok: bool = checker.check_sig(vch_sig, vch_pub_key, script);

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
                        for _ in 1..i {
                            stack.pop()?;
                        }

                        // A bug causes CHECKMULTISIG to consume one extra argument
                        // whose contents were not checked in any way.
                        //
                        // Unfortunately this is a potential source of mutability,
                        // so optionally verify it is exactly equal to zero prior
                        // to removing it from the stack.
                        if stack.size() < 1 {
                            return set_error(ScriptError::InvalidStackOperation);
                        }
                        if flags.contains(VerificationFlags::NullDummy)
                            && !stack.top(-1)?.is_empty()
                        {
                            return set_error(ScriptError::SigNullDummy);
                        }
                        stack.pop()?;

                        stack.push_back(if success {
                            VCH_TRUE.to_vec()
                        } else {
                            VCH_FALSE
                        });

                        if op == OP_CHECKMULTISIGVERIFY {
                            if success {
                                stack.pop()?;
                            } else {
                                return set_error(ScriptError::CheckMultisigVerify);
                            }
                        }
                    }

                    _ => {
                        return set_error(ScriptError::BadOpcode);
                    }
                }
            }
        }
    }

    // Size limits
    if stack.size() + altstack.size() > 1000 {
        return set_error(ScriptError::StackSize);
    }

    set_success(new_pc)
}

pub trait StepFn {
    type Payload: Clone;
    fn call<'a>(
        &self,
        pc: &'a [u8],
        script: &Script,
        state: &mut State,
        payload: &mut Self::Payload,
    ) -> Result<&'a [u8], ScriptError>;
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
    ) -> Result<&'a [u8], ScriptError> {
        eval_step(pc, script, self.flags, self.checker, state)
    }
}

pub fn eval_script<F>(
    stack: Stack<Vec<u8>>,
    script: &Script,
    payload: &mut F::Payload,
    eval_step: &F,
) -> Result<Stack<Vec<u8>>, ScriptError>
where
    F: StepFn,
{
    // There's a limit on how large scripts can be.
    if script.0.len() > MAX_SCRIPT_SIZE {
        return set_error(ScriptError::ScriptSize);
    }

    let mut pc = script.0;

    let mut state = State::initial(stack);

    // Main execution loop
    while !pc.is_empty() {
        pc = eval_step.call(pc, script, &mut state, payload)?;
    }

    if !state.vexec.empty() {
        return set_error(ScriptError::UnbalancedConditional);
    }

    set_success(state.stack)
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

impl CallbackTransactionSignatureChecker<'_> {
    pub fn verify_signature(vch_sig: &[u8], pubkey: &PubKey, sighash: &[u8; SIGHASH_SIZE]) -> bool {
        pubkey.verify(sighash, vch_sig)
    }
}

impl SignatureChecker for CallbackTransactionSignatureChecker<'_> {
    fn check_sig(&self, vch_sig_in: &[u8], vch_pub_key: &[u8], script_code: &Script) -> bool {
        let pubkey = PubKey(vch_pub_key);
        if !pubkey.is_valid() {
            return false;
        };

        // Hash type is one byte tacked on to the end of the signature
        match vch_sig_in.split_last() {
            None => false,
            Some((hash_type, vch_sig)) => HashType::from_bits((*hash_type).into(), false)
                .ok()
                .and_then(|hash_type| (self.sighash)(script_code.0, hash_type))
                .map(|sighash| Self::verify_signature(vch_sig, &pubkey, &sighash))
                .unwrap_or(false),
        }
    }

    fn check_lock_time(&self, lock_time: &ScriptNum) -> bool {
        // There are two kinds of nLockTime: lock-by-blockheight
        // and lock-by-blocktime, distinguished by whether
        // nLockTime < LOCKTIME_THRESHOLD.
        //
        // We want to compare apples to apples, so fail the script
        // unless the type of nLockTime being tested is the same as
        // the nLockTime in the transaction.
        if *self.lock_time < LOCKTIME_THRESHOLD && *lock_time >= LOCKTIME_THRESHOLD
            || *self.lock_time >= LOCKTIME_THRESHOLD && *lock_time < LOCKTIME_THRESHOLD
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
) -> Result<(), ScriptError>
where
    F: StepFn,
{
    if flags.contains(VerificationFlags::SigPushOnly) && !script_sig.is_push_only() {
        return set_error(ScriptError::SigPushOnly);
    }

    let data_stack = eval_script(Stack(Vec::new()), script_sig, payload, stepper)?;
    let pub_key_stack = eval_script(data_stack.clone(), script_pub_key, payload, stepper)?;
    if pub_key_stack.empty() {
        return set_error(ScriptError::EvalFalse);
    }
    if !cast_to_bool(pub_key_stack.last()?) {
        return set_error(ScriptError::EvalFalse);
    }

    // Additional validation for spend-to-script-hash transactions:
    let result_stack = if flags.contains(VerificationFlags::P2SH)
        && script_pub_key.is_pay_to_script_hash()
    {
        // script_sig must be literals-only or validation fails
        if !script_sig.is_push_only() {
            return set_error(ScriptError::SigPushOnly);
        };

        // stack cannot be empty here, because if it was the
        // P2SH  HASH <> EQUAL  scriptPubKey would be evaluated with
        // an empty stack and the `eval_script` above would return false.
        assert!(!data_stack.empty());

        data_stack
            .split_last()
            .map_err(|_| ScriptError::InvalidStackOperation)
            .and_then(|(pub_key_serialized, remaining_stack)| {
                let pub_key_2 = Script(pub_key_serialized);

                eval_script(remaining_stack, &pub_key_2, payload, stepper).and_then(|p2sh_stack| {
                    if p2sh_stack.empty() {
                        return set_error(ScriptError::EvalFalse);
                    }
                    if !cast_to_bool(p2sh_stack.last()?) {
                        return set_error(ScriptError::EvalFalse);
                    }
                    Ok(p2sh_stack)
                })
            })?
    } else {
        pub_key_stack
    };

    // The CLEANSTACK check is only performed after potential P2SH evaluation,
    // as the non-P2SH evaluation of a P2SH script will obviously not result in
    // a clean stack (the P2SH inputs remain).
    if flags.contains(VerificationFlags::CleanStack) {
        // Disallow CLEANSTACK without P2SH, because Bitcoin did.
        assert!(flags.contains(VerificationFlags::P2SH));
        if result_stack.size() != 1 {
            return set_error(ScriptError::CleanStack);
        }
    };

    set_success(())
}
