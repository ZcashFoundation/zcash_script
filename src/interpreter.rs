use std::slice::Iter;

use ripemd::Ripemd160;
use sha1::Sha1;
use sha2::{Digest, Sha256};

use super::external::pubkey::PubKey;
use super::external::uint256::UInt256;
use super::script::*;
use super::script_error::*;

bitflags::bitflags! {
    /// The different SigHash types, as defined in <https://zips.z.cash/zip-0143>
    ///
    /// TODO: This is currently defined as `i32` to match the `c_int` constants in this package, but
    ///       should use librustzcash’s `u8` constants once we’ve removed the C++.
    #[derive(Copy, Clone, Debug, PartialEq, Eq)]
    pub struct HashType: i32 {
        /// Sign all the outputs
        const All = 1;
        /// Sign none of the outputs - anyone can spend
        const None = 2;
        /// Sign one of the outputs - anyone can spend the rest
        const Single = 3;
        /// Anyone can add inputs to this transaction
        const AnyoneCanPay = 0x80;
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

/// All signature hashes are 32 bits, since they are necessarily produced by SHA256.
pub const SIGHASH_SIZE: usize = 32;

/// A function which is called to obtain the sighash.
///    - script_code: the scriptCode being validated. Note that this not always
///      matches script_sig, i.e. for P2SH.
///    - hash_type: the hash type being used.
///
/// The `extern "C"` function that calls this doesn’t give much opportunity for rich failure
/// reporting, but returning `None` indicates _some_ failure to produce the desired hash.
///
/// TODO: Can we get the “32” from somewhere rather than hardcoding it?
pub type SighashCalculator<'a> = &'a dyn Fn(&[u8], HashType) -> Option<[u8; SIGHASH_SIZE]>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Stack<T>(Vec<T>);

/// Wraps a Vec (or whatever underlying implementation we choose in a way that matches the C++ impl
/// and provides us some decent chaining)
impl<T> Stack<T> {
    fn from_top(&self, i: isize) -> Result<usize, ScriptError> {
        usize::try_from(-i)
            .map(|a| self.0.len() - a)
            .map_err(|_| ScriptError::InvalidStackOperation)
    }

    pub fn top(&self, i: isize) -> Result<&T, ScriptError> {
        let idx = self.from_top(i)?;
        self.0.get(idx).ok_or(ScriptError::InvalidStackOperation)
    }

    pub fn swap(&mut self, a: isize, b: isize) -> Result<(), ScriptError> {
        let au = self.from_top(a)?;
        let bu = self.from_top(b)?;
        Ok(self.0.swap(au, bu))
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

    pub fn back(&mut self) -> Option<&mut T> {
        self.0.last_mut()
    }

    pub fn erase(&mut self, start: usize, end: Option<usize>) -> () {
        for _ in 0..end.map_or(0, |e| e - start) {
            self.0.remove(start);
        }
    }

    pub fn end(&self) -> usize {
        self.0.len()
     }
}

pub trait BaseSignatureChecker {
    fn check_sig(&self, script_sig: &Vec<u8>, vch_pub_key: &Vec<u8>, script_code: &Script) -> bool {
        false
    }

    fn check_lock_time(&self, lock_time: &ScriptNum) -> bool {
        false
    }
}

type ValType = Vec<u8>;

pub struct CallbackTransactionSignatureChecker<'a> {
    pub sighash: SighashCalculator<'a>,
    pub lock_time: &'a ScriptNum,
    pub is_final: bool,
}

impl CallbackTransactionSignatureChecker<'_> {
    pub fn verify_signature(vch_sig: &Vec<u8>, pubkey: &PubKey, sighash: &UInt256) -> bool {
        pubkey.verify(sighash, vch_sig)
    }
}

impl BaseSignatureChecker for CallbackTransactionSignatureChecker<'_> {
    fn check_sig(&self, vch_sig_in: &Vec<u8>, vch_pub_key: &Vec<u8>, script_code: &Script) -> bool {
        let pubkey = PubKey(vch_pub_key.as_slice());
        if !pubkey.is_valid() {
            return false;
        };

        // Hash type is one byte tacked on to the end of the signature
        let mut vch_sig = (*vch_sig_in).clone();
        vch_sig
            .pop()
            .and_then(|hash_type| {
                (self.sighash)(script_code.0, HashType::from_bits_retain(hash_type.into()))
            })
            .map(|sighash| Self::verify_signature(&vch_sig, &pubkey, &sighash))
            .unwrap_or(false)
    }

    fn check_lock_time(&self, lock_time: &ScriptNum) -> bool {
        // There are two times of nLockTime: lock-by-blockheight
        // and lock-by-blocktime, distinguished by whether
        // nLockTime < LOCKTIME_THRESHOLD.
        //
        // We want to compare apples to apples, so fail the script
        // unless the type of nLockTime being tested is the same as
        // the nLockTime in the transaction.
        if !((*self.lock_time < LOCKTIME_THRESHOLD && *lock_time < LOCKTIME_THRESHOLD)
            || (*self.lock_time >= LOCKTIME_THRESHOLD && *lock_time >= LOCKTIME_THRESHOLD))
        {
            false
            // Now that we know we're comparing apples-to-apples, the
            // comparison is a simple numeric one.
        } else if lock_time > self.lock_time {
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
        } else if self.is_final {
            false
        } else {
            true
        }
    }

    // FIXME: Replace the above logic with this, which makes more sense (but preserve a lot of the
    //        comments).
    // !self.is_final
    //     && (self.n_lock_time < LOCKTIME_THRESHOLD && n_lock_time < LOCKTIME_THRESHOLD) ||
    //         (self.n_lock_time >= LOCKTIME_THRESHOLD && n_lock_time >= LOCKTIME_THRESHOLD))
    //     && n_lock_time <= self.n_lock_time
}

fn cast_to_bool(vch: &ValType) -> bool {
    for (i, vchi) in vch.iter().enumerate() {
        if *vchi != 0 {
            // Can be negative zero
            if i == vch.len() - 1 && *vchi == 0x80 {
                return false;
            };
            return true;
        }
    }
    false
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
 * A canonical signature exists of: <30> <total len> <02> <len R> <R> <02> <len S> <S> <hashtype>
 * Where R and S are not negative (their first byte has its highest bit not set), and not
 * excessively padded (do not start with a 0 byte, unless an otherwise negative number follows,
 * in which case a single 0 byte is necessary and even required).
 *
 * See https://bitcointalk.org/index.php?topic=8392.msg127623#msg127623
 *
 * This function is consensus-critical since BIP66.
 */
fn is_valid_signature_encoding(sig: &Vec<u8>) -> bool {
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
    if sig[1] as usize != sig.len() - 3 {
        return false;
    };

    // Extract the length of the R element.
    let len_r: usize = sig[3] as usize;

    // Make sure the length of the S element is still inside the signature.
    if 5 + len_r >= sig.len() {
        return false;
    };

    // Extract the length of the S element.
    let len_s: usize = sig[5 + len_r] as usize;

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
        return Err(ScriptError::SigDER);
    };
    // https://bitcoin.stackexchange.com/a/12556:
    //     Also note that inside transaction signatures, an extra hashtype byte
    //     follows the actual signature data.
    let vch_sig_copy = vch_sig.clone();
    // If the S value is above the order of the curve divided by two, its
    // complement modulo the order could have been used instead, which is
    // one byte shorter when encoded correctly.
    // FIXME: This can return `false` without setting an error, which is not the expectation of the
    //        caller.
    Ok(PubKey::check_low_s(&vch_sig_copy))
}

fn is_defined_hashtype_signature(vch_sig: &ValType) -> bool {
    if vch_sig.len() == 0 {
        return false;
    };
    let hash_type = i32::from(vch_sig[vch_sig.len() - 1]) & !HashType::AnyoneCanPay.bits();
    if hash_type < HashType::All.bits() || hash_type > HashType::Single.bits() {
        return false;
    };

    true
}

fn check_signature_encoding(
    vch_sig: &Vec<u8>,
    flags: VerificationFlags,
) -> Result<bool, ScriptError> {
    // Empty signature. Not strictly DER encoded, but allowed to provide a
    // compact way to provide an invalid signature for use with CHECK(MULTI)SIG
    if vch_sig.len() == 0 {
        return Ok(true);
    };
    if !is_valid_signature_encoding(vch_sig) {
        return Err(ScriptError::SigDER);
    } else if flags.contains(VerificationFlags::LowS) && !is_low_der_signature(vch_sig)? {
        // serror is set
        return Ok(false);
    } else if flags.contains(VerificationFlags::StrictEnc)
        && !is_defined_hashtype_signature(vch_sig)
    {
        return Err(ScriptError::SigHashtype);
    };
    Ok(true)
}

fn check_pub_key_encoding(vch_sig: &ValType, flags: VerificationFlags) -> Result<(), ScriptError> {
    if flags.contains(VerificationFlags::StrictEnc)
        && !is_compressed_or_uncompressed_pub_key(vch_sig)
    {
        return Err(ScriptError::PubKeyType);
    };
    Ok(())
}

fn check_minimal_push(data: &[u8], raw_opcode: u8) -> bool {
    todo!()
}

pub fn eval_script(
    stack: &mut Stack<Vec<u8>>,
    script: &Script,
    flags: VerificationFlags,
    checker: &dyn BaseSignatureChecker,
) -> Result<bool, ScriptError> {
    let bn_zero = ScriptNum(0);
    let bn_one = ScriptNum(1);
    let vch_false: ValType = vec![];
    let vch_zero: ValType = vec![];
    let vch_true: ValType = vec![1];

    // There's a limit on how large scripts can be.
    if script.0.len() > MAX_SCRIPT_SIZE {
        return Err(ScriptError::ScriptSize);
    }

    let mut pc = script.0;
    let mut vch_push_value = vec![];

    // We keep track of how many operations have executed so far to prevent
    // expensive-to-verify scripts
    let mut op_count = 0;
    let require_minimal = flags.contains(VerificationFlags::MinimalData);

    // This keeps track of the conditional flags at each nesting level
    // during execution. If we're in a branch of execution where *any*
    // of these conditionals are false, we ignore opcodes unless those
    // opcodes direct control flow (OP_IF, OP_ELSE, etc.).
    let mut vexec: Stack<bool> = Stack(vec![]);

    let mut altstack: Stack<Vec<u8>> = Stack(vec![]);

    // Main execution loop
    while !pc.is_empty() {
        // Are we in an executing branch of the script?
        let exec = vexec.iter().all(|value| *value);

        // Consume an opcode
        let operation = get_op2(&mut pc, Some(&mut vch_push_value))?;

        match operation {
            Operation::PushBytes(raw_opcode) => {
                // There's a limit to the size of the values we'll put on
                // the stack.
                if vch_push_value.len() > MAX_SCRIPT_ELEMENT_SIZE {
                    return Err(ScriptError::PushSize);
                }

                if exec {
                    // Data is being pushed to the stack here; we may need to check
                    // that the minimal script size was used to do so if our caller
                    // requires it.
                    if flags.contains(VerificationFlags::MinimalData)
                        && !check_minimal_push(&vch_push_value, raw_opcode)
                    {
                        return Err(ScriptError::MinimalData);
                    }

                    stack.push_back(vch_push_value.clone());
                }
            }
            Operation::Constant(value) => stack.push_back(vec![value as u8]),

            // Invalid and disabled opcodes do technically contribute to
            // op_count, but they always result in a failed script execution
            // anyway.
            Operation::Invalid => return Err(ScriptError::BadOpcode),
            Operation::Disabled => return Err(ScriptError::DisabledOpcode),

            Operation::Opcode(opcode) => {
                // There's a limit on how many operations can execute in a
                // script. We consider opcodes beyond OP_16 to be "actual"
                // opcodes as ones below that just involve data pushes. All
                // opcodes defined by the Opcode enum qualify except for
                // OP_RESERVED, which is not beyond OP_16.
                //
                // Note: operations even if they are not executed but are
                // still present in the script count toward this count.
                if opcode != Opcode::OP_RESERVED {
                    op_count += 1;
                    if op_count > 201 {
                        return Err(ScriptError::OpCount);
                    }
                }

                if exec || opcode.is_control_flow_opcode() {
                    match opcode {
                        Opcode::OP_RESERVED
                        | Opcode::OP_VER
                        | Opcode::OP_RESERVED1
                        | Opcode::OP_RESERVED2 => {
                            // These are considered "invalid" opcodes but
                            // only inside of *executing* OP_IF branches of
                            // the script.
                            return Err(ScriptError::BadOpcode);
                        }
                        Opcode::OP_NOP => {
                            // Do nothing.
                        }
                        Opcode::OP_NOP1
                        | Opcode::OP_NOP3
                        | Opcode::OP_NOP4
                        | Opcode::OP_NOP5
                        | Opcode::OP_NOP6
                        | Opcode::OP_NOP7
                        | Opcode::OP_NOP8
                        | Opcode::OP_NOP9
                        | Opcode::OP_NOP10 => {
                            // Do nothing, though if the caller wants to
                            // prevent people from using these NOPs (as part
                            // of a standard tx rule, for example) they can
                            // enable `DiscourageUpgradableNOPs` to turn
                            // these opcodes into errors.
                            if flags.contains(VerificationFlags::DiscourageUpgradableNOPs) {
                                return Err(ScriptError::DiscourageUpgradableNOPs);
                            }
                        }
                        Opcode::OP_CHECKLOCKTIMEVERIFY => {
                            // This was originally OP_NOP2 but has been repurposed
                            // for OP_CHECKLOCKTIMEVERIFY. So, we should act based
                            // on whether or not CLTV has been activated in a soft
                            // fork.
                            if !flags.contains(VerificationFlags::CHECKLOCKTIMEVERIFY) {
                                if flags.contains(VerificationFlags::DiscourageUpgradableNOPs) {
                                    return Err(ScriptError::DiscourageUpgradableNOPs);
                                }
                            } else {
                                if stack.size() < 1 {
                                    return Err(ScriptError::InvalidStackOperation);
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
                                    ScriptNum::new(stack.top(-1)?, require_minimal, Some(5));

                                // In the rare event that the argument may be < 0 due to
                                // some arithmetic being done first, you can always use
                                // 0 MAX CHECKLOCKTIMEVERIFY.
                                if lock_time < ScriptNum(0) {
                                    return Err(ScriptError::NegativeLockTime);
                                }

                                // Actually compare the specified lock time with the transaction.
                                if !checker.check_lock_time(&lock_time) {
                                    return Err(ScriptError::UnsatisfiedLockTime);
                                }
                            }
                        }
                        Opcode::OP_IF | Opcode::OP_NOTIF => {
                            // <expression> if [statements] [else [statements]] endif
                            let mut value = false;
                            if exec {
                                if stack.size() < 1 {
                                    return Err(ScriptError::UnbalancedConditional);
                                }
                                let vch: &ValType = stack.top(-1)?;
                                value = cast_to_bool(vch);
                                if opcode == Opcode::OP_NOTIF {
                                    value = !value
                                };
                                stack.pop()?;
                            }
                            vexec.push_back(value);
                        }
                        Opcode::OP_ELSE => {
                            if vexec.empty() {
                                return Err(ScriptError::UnbalancedConditional);
                            }

                            vexec.back().map(|last| *last = !*last);
                        }
                        Opcode::OP_ENDIF => {
                            if vexec.empty() {
                                return Err(ScriptError::UnbalancedConditional);
                            }

                            vexec.pop()?;
                        }
                        Opcode::OP_VERIFY => {
                            // (true -- ) or
                            // (false -- false) and return
                            if stack.size() < 1 {
                                return Err(ScriptError::InvalidStackOperation);
                            }
                            let value = cast_to_bool(stack.top(-1)?);
                            if value {
                                stack.pop()?;
                            } else {
                                return Err(ScriptError::VERIFY);
                            }
                        }
                        Opcode::OP_RETURN => return Err(ScriptError::OpReturn),
                        Opcode::OP_TOALTSTACK => {
                            if stack.empty() {
                                return Err(ScriptError::InvalidStackOperation);
                            }

                            altstack.push_back(stack.pop()?);
                        }
                        Opcode::OP_FROMALTSTACK => {
                            if altstack.empty() {
                                return Err(ScriptError::InvalidStackOperation);
                            }

                            stack.push_back(altstack.pop()?);
                        }
                        Opcode::OP_2DROP => {
                            if stack.size() < 2 {
                                return Err(ScriptError::InvalidStackOperation);
                            }

                            stack.pop()?;
                            stack.pop()?;
                        }
                        Opcode::OP_2DUP => {
                            if stack.size() < 2 {
                                return Err(ScriptError::InvalidStackOperation);
                            }

                            let b = stack.pop()?;
                            let a = stack.pop()?;
                            stack.push_back(a.clone());
                            stack.push_back(b.clone());
                            stack.push_back(a);
                            stack.push_back(b);
                        }
                        Opcode::OP_3DUP => {
                            if stack.size() < 3 {
                                return Err(ScriptError::InvalidStackOperation);
                            }

                            let c = stack.pop()?;
                            let b = stack.pop()?;
                            let a = stack.pop()?;
                            stack.push_back(a.clone());
                            stack.push_back(b.clone());
                            stack.push_back(c.clone());
                            stack.push_back(a);
                            stack.push_back(b);
                            stack.push_back(c);
                        }
                        Opcode::OP_2OVER => {
                            if stack.size() < 4 {
                                return Err(ScriptError::InvalidStackOperation);
                            }

                            let d = stack.pop()?;
                            let c = stack.pop()?;
                            let b = stack.pop()?;
                            let a = stack.pop()?;
                            stack.push_back(a.clone());
                            stack.push_back(b.clone());
                            stack.push_back(c);
                            stack.push_back(d);
                            stack.push_back(a);
                            stack.push_back(b);
                        }
                        Opcode::OP_2ROT => {
                            if stack.size() < 6 {
                                return Err(ScriptError::InvalidStackOperation);
                            }

                            let f = stack.pop()?;
                            let e = stack.pop()?;
                            let d = stack.pop()?;
                            let c = stack.pop()?;
                            let b = stack.pop()?;
                            let a = stack.pop()?;
                            stack.push_back(c);
                            stack.push_back(d);
                            stack.push_back(e);
                            stack.push_back(f);
                            stack.push_back(a);
                            stack.push_back(b);
                        }
                        Opcode::OP_2SWAP => {
                            if stack.size() < 4 {
                                return Err(ScriptError::InvalidStackOperation);
                            }

                            let d = stack.pop()?;
                            let c = stack.pop()?;
                            let b = stack.pop()?;
                            let a = stack.pop()?;
                            stack.push_back(c);
                            stack.push_back(d);
                            stack.push_back(a);
                            stack.push_back(b);
                        }
                        Opcode::OP_IFDUP => {
                            // (x - 0 | x x)
                            if stack.size() < 1 {
                                return Err(ScriptError::InvalidStackOperation);
                            }
                            let vch = stack.top(-1)?;
                            if cast_to_bool(vch) {
                                stack.push_back(vch.to_vec())
                            }
                        }
                        Opcode::OP_DEPTH => {
                            // -- stacksize
                            let bn = ScriptNum(i64::try_from(stack.size()).unwrap());
                            stack.push_back(bn.getvch())
                        }
                        Opcode::OP_DROP => {
                            if stack.empty() {
                                return Err(ScriptError::InvalidStackOperation);
                            }

                            stack.pop()?;
                        }
                        Opcode::OP_DUP => {
                            if stack.empty() {
                                return Err(ScriptError::InvalidStackOperation);
                            }

                            let a = stack.pop()?;
                            stack.push_back(a.clone());
                            stack.push_back(a);
                        }
                        Opcode::OP_NIP => {
                            if stack.size() < 2 {
                                return Err(ScriptError::InvalidStackOperation);
                            }

                            let b = stack.pop()?;
                            stack.pop()?;
                            stack.push_back(b);
                        }
                        Opcode::OP_OVER => {
                            if stack.size() < 2 {
                                return Err(ScriptError::InvalidStackOperation);
                            }

                            let b = stack.pop()?;
                            let a = stack.pop()?;
                            stack.push_back(a.clone());
                            stack.push_back(b);
                            stack.push_back(a);
                        }
                        Opcode::OP_PICK | Opcode::OP_ROLL => {
                            // (xn ... x2 x1 x0 n - xn ... x2 x1 x0 xn)
                            // (xn ... x2 x1 x0 n - ... x2 x1 x0 xn)
                            if stack.size() < 2 {
                                return Err(ScriptError::InvalidStackOperation);
                            }
                            let n = ScriptNum::new(stack.top(-1)?, require_minimal, None).getint();
                            stack.pop()?;
                            if n < 0 || n >= i32::try_from(stack.size()).unwrap() {
                                return Err(ScriptError::InvalidStackOperation);
                            }
                            let vch: ValType = stack.top(isize::try_from(-n).unwrap() - 1)?.clone();
                            if opcode == Opcode::OP_ROLL {
                                stack.erase(
                                    usize::try_from(
                                        i64::try_from(stack.end()).unwrap() - i64::from(n) - 1,
                                    )
                                    .unwrap(),
                                    None,
                                );
                            }
                            stack.push_back(vch)
                        }
                        Opcode::OP_ROT => {
                            // (x1 x2 x3 -- x2 x3 x1)
                            //  x2 x1 x3  after first swap
                            //  x2 x3 x1  after second swap
                            if stack.size() < 3 {
                                return Err(ScriptError::InvalidStackOperation);
                            }
                            stack.swap(-3, -2)?;
                            stack.swap(-2, -1)?;
                        }
                        Opcode::OP_SWAP => {
                            if stack.size() < 2 {
                                return Err(ScriptError::InvalidStackOperation);
                            }

                            let b = stack.pop()?;
                            let a = stack.pop()?;
                            stack.push_back(b);
                            stack.push_back(a);
                        }
                        Opcode::OP_TUCK => {
                            if stack.size() < 2 {
                                return Err(ScriptError::InvalidStackOperation);
                            }

                            let b = stack.pop()?;
                            let a = stack.pop()?;
                            stack.push_back(b.clone());
                            stack.push_back(a);
                            stack.push_back(b);
                        }
                        Opcode::OP_SIZE => {
                            // (in -- in size)
                            if stack.size() < 1 {
                                return Err(ScriptError::InvalidStackOperation);
                            }
                            let bn = ScriptNum(i64::try_from(stack.top(-1)?.len()).unwrap());
                            stack.push_back(bn.getvch())
                        }
                        Opcode::OP_EQUAL | Opcode::OP_EQUALVERIFY => {
                            if stack.size() < 2 {
                                return Err(ScriptError::InvalidStackOperation);
                            }

                            if let Ok(vch2) = stack.pop() {
                                if let Ok(vch1) = stack.pop() {
                                    let equal: bool = vch1 == vch2;
                                    // OP_NOTEQUAL is disabled because it would be too easy to say
                                    // something like n != 1 and have some wiseguy pass in 1 with extra
                                    // zero bytes after it (numerically, 0x01 == 0x0001 == 0x000001)
                                    //if (opcode == OP_NOTEQUAL)
                                    //    fEqual = !fEqual;
                                    stack.push_back(if equal {
                                        vch_true.clone()
                                    } else {
                                        vch_false.clone()
                                    });
                                    if opcode == Opcode::OP_EQUALVERIFY {
                                        if equal {
                                            stack.pop()?;
                                        } else {
                                            return Err(ScriptError::EQUALVERIFY);
                                        }
                                    }
                                }
                            }
                        }
                        Opcode::OP_1ADD
                        | Opcode::OP_1SUB
                        | Opcode::OP_NEGATE
                        | Opcode::OP_ABS
                        | Opcode::OP_NOT
                        | Opcode::OP_0NOTEQUAL => {
                            // (in -- out)
                            if stack.size() < 1 {
                                return Err(ScriptError::InvalidStackOperation);
                            }
                            let mut bn = ScriptNum::new(stack.top(-1)?, require_minimal, None);
                            match opcode {
                                Opcode::OP_1ADD => bn = bn + bn_one,
                                Opcode::OP_1SUB => bn = bn - bn_one,
                                Opcode::OP_NEGATE => bn = -bn,
                                Opcode::OP_ABS => {
                                    if bn < bn_zero {
                                        bn = -bn
                                    }
                                }
                                Opcode::OP_NOT => bn = ScriptNum((bn == bn_zero).into()),
                                Opcode::OP_0NOTEQUAL => bn = ScriptNum((bn != bn_zero).into()),
                                _ => panic!("invalid opcode"),
                            }
                            stack.pop()?;
                            stack.push_back(bn.getvch())
                        }
                        Opcode::OP_ADD
                        | Opcode::OP_SUB
                        | Opcode::OP_BOOLAND
                        | Opcode::OP_BOOLOR
                        | Opcode::OP_NUMEQUAL
                        | Opcode::OP_NUMEQUALVERIFY
                        | Opcode::OP_NUMNOTEQUAL
                        | Opcode::OP_LESSTHAN
                        | Opcode::OP_GREATERTHAN
                        | Opcode::OP_LESSTHANOREQUAL
                        | Opcode::OP_GREATERTHANOREQUAL
                        | Opcode::OP_MIN
                        | Opcode::OP_MAX => {
                            // (x1 x2 -- out)
                            if stack.size() < 2 {
                                return Err(ScriptError::InvalidStackOperation);
                            }
                            let bn1 = ScriptNum::new(stack.top(-2)?, require_minimal, None);
                            let bn2 = ScriptNum::new(stack.top(-1)?, require_minimal, None);
                            let bn;
                            match opcode {
                                Opcode::OP_ADD => bn = bn1 + bn2,

                                Opcode::OP_SUB => bn = bn1 - bn2,

                                Opcode::OP_BOOLAND => {
                                    bn = ScriptNum((bn1 != bn_zero && bn2 != bn_zero).into())
                                }
                                Opcode::OP_BOOLOR => {
                                    bn = ScriptNum((bn1 != bn_zero || bn2 != bn_zero).into())
                                }
                                Opcode::OP_NUMEQUAL => bn = ScriptNum((bn1 == bn2).into()),
                                Opcode::OP_NUMEQUALVERIFY => bn = ScriptNum((bn1 == bn2).into()),
                                Opcode::OP_NUMNOTEQUAL => bn = ScriptNum((bn1 != bn2).into()),
                                Opcode::OP_LESSTHAN => bn = ScriptNum((bn1 < bn2).into()),
                                Opcode::OP_GREATERTHAN => bn = ScriptNum((bn1 > bn2).into()),
                                Opcode::OP_LESSTHANOREQUAL => bn = ScriptNum((bn1 <= bn2).into()),
                                Opcode::OP_GREATERTHANOREQUAL => bn = ScriptNum((bn1 >= bn2).into()),
                                Opcode::OP_MIN => bn = if bn1 < bn2 { bn1 } else { bn2 },
                                Opcode::OP_MAX => bn = if bn1 > bn2 { bn1 } else { bn2 },
                                _ => panic!("invalid opcode"),
                            };
                            stack.pop()?;
                            stack.pop()?;
                            stack.push_back(bn.getvch());

                            if opcode == Opcode::OP_NUMEQUALVERIFY {
                                if cast_to_bool(stack.top(-1)?) {
                                    stack.pop()?;
                                } else {
                                    return Err(ScriptError::NUMEQUALVERIFY);
                                }
                            }
                        }
                        Opcode::OP_WITHIN => {
                            // (x min max -- out)
                            if stack.size() < 3 {
                                return Err(ScriptError::InvalidStackOperation);
                            }
                            let bn1 = ScriptNum::new(stack.top(-3)?, require_minimal, None);
                            let bn2 = ScriptNum::new(stack.top(-2)?, require_minimal, None);
                            let bn3 = ScriptNum::new(stack.top(-1)?, require_minimal, None);
                            let value = bn2 <= bn1 && bn1 < bn3;
                            stack.pop()?;
                            stack.pop()?;
                            stack.pop()?;
                            stack.push_back(if value {
                                vch_true.clone()
                            } else {
                                vch_false.clone()
                            })
                        }
                        Opcode::OP_RIPEMD160
                        | Opcode::OP_SHA1
                        | Opcode::OP_SHA256
                        | Opcode::OP_HASH160
                        | Opcode::OP_HASH256 => {
                            if let Ok(vch) = stack.pop() {
                                stack.push_back(match opcode {
                                    Opcode::OP_RIPEMD160 => Ripemd160::digest(vch).to_vec(),
                                    Opcode::OP_SHA1 => {
                                        let mut hasher = Sha1::new();
                                        hasher.update(vch);
                                        hasher.finalize().to_vec()
                                    }
                                    Opcode::OP_SHA256 => Sha256::digest(vch).to_vec(),
                                    Opcode::OP_HASH160 => {
                                        Ripemd160::digest(Sha256::digest(vch)).to_vec()
                                    }

                                    Opcode::OP_HASH256 => {
                                        Sha256::digest(Sha256::digest(vch)).to_vec()
                                    }
                                    _ => panic!("Didn’t match a hashing opcode!"),
                                });
                            } else {
                                return Err(ScriptError::InvalidStackOperation);
                            }
                        }
                        Opcode::OP_CHECKSIG | Opcode::OP_CHECKSIGVERIFY => {
                            // (sig pubkey -- bool)
                            if stack.size() < 2 {
                                return Err(ScriptError::InvalidStackOperation);
                            }

                            let vch_sig = stack.top(-2)?.clone();
                            let vch_pub_key = stack.top(-1)?.clone();

                            if !check_signature_encoding(&vch_sig, flags)? {
                                //serror is set
                                return Ok(false);
                            }
                            check_pub_key_encoding(&vch_pub_key, flags)?;
                            let success = checker.check_sig(&vch_sig, &vch_pub_key, script);

                            stack.pop()?;
                            stack.pop()?;
                            stack.push_back(if success {
                                vch_true.clone()
                            } else {
                                vch_false.clone()
                            });
                            if opcode == Opcode::OP_CHECKSIGVERIFY {
                                if success {
                                    stack.pop()?;
                                } else {
                                    return Err(ScriptError::CHECKSIGVERIFY);
                                }
                            }
                        }
                        Opcode::OP_CHECKMULTISIG | Opcode::OP_CHECKMULTISIGVERIFY => {
                            // ([sig ...] num_of_signatures [pubkey ...] num_of_pubkeys -- bool)

                            let mut i: i32 = 1;
                            if (stack.size() as i32) < i {
                                return Err(ScriptError::InvalidStackOperation);
                            };

                            let mut keys_count: i32 =
                                ScriptNum::new(stack.top(-i as isize)?, require_minimal, None)
                                    .getint();
                            if keys_count < 0 || keys_count > 20 {
                                return Err(ScriptError::PubKeyCount);
                            };
                            op_count += keys_count;
                            if op_count > 201 {
                                return Err(ScriptError::OpCount);
                            };
                            i += 1;
                            let mut ikey = i;
                            i += keys_count;
                            if (stack.size() as i32) < i {
                                return Err(ScriptError::InvalidStackOperation);
                            }

                            let mut sigs_count: i32 =
                                ScriptNum::new(stack.top(-i as isize)?, require_minimal, None)
                                    .getint();
                            if sigs_count < 0 || sigs_count > keys_count {
                                return Err(ScriptError::SigCount);
                            };
                            i += 1;
                            let mut isig = i;
                            i += sigs_count;
                            if (stack.size() as i32) < i {
                                return Err(ScriptError::InvalidStackOperation);
                            };

                            let mut success = true;
                            while success && sigs_count > 0 {
                                let vch_sig: &ValType = stack.top(-isig as isize)?;
                                let vch_pub_key: &ValType = stack.top(-ikey as isize)?;

                                // Note how this makes the exact order of pubkey/signature evaluation
                                // distinguishable by CHECKMULTISIG NOT if the STRICTENC flag is set.
                                // See the script_(in)valid tests for details.
                                if !check_signature_encoding(vch_sig, flags)? {
                                    // serror is set
                                    return Ok(false);
                                };
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
                            while {
                                let res = i > 1;
                                i -= 1;
                                res
                            } {
                                stack.pop()?;
                            }

                            // A bug causes CHECKMULTISIG to consume one extra argument
                            // whose contents were not checked in any way.
                            //
                            // Unfortunately this is a potential source of mutability,
                            // so optionally verify it is exactly equal to zero prior
                            // to removing it from the stack.
                            if stack.size() < 1 {
                                return Err(ScriptError::InvalidStackOperation);
                            };
                            if flags.contains(VerificationFlags::NullDummy)
                                && stack.top(-1)?.len() != 0
                            {
                                return Err(ScriptError::SigNullDummy);
                            };
                            stack.pop()?;

                            stack.push_back(if success {
                                vch_true.clone()
                            } else {
                                vch_false.clone()
                            });

                            if opcode == Opcode::OP_CHECKMULTISIGVERIFY {
                                if success {
                                    stack.pop()?;
                                } else {
                                    return Err(ScriptError::CHECKMULTISIGVERIFY);
                                }
                            }
                        }
                    }
                }
            }
        }

        // There's a limit to how many items can be added to the stack and
        // alt stack. This limit is enforced upon finishing the execution of
        // an opcode.
        if stack.size() + altstack.size() > 1000 {
            return Err(ScriptError::StackSize);
        }
    }

    if !vexec.empty() {
        return Err(ScriptError::UnbalancedConditional);
    };

    Ok(true)
}

pub fn verify_script(
    script_sig: &Script,
    script_pub_key: &Script,
    flags: VerificationFlags,
    checker: &dyn BaseSignatureChecker,
) -> Result<(), ScriptError> {
    if flags.contains(VerificationFlags::SigPushOnly) && !script_sig.is_push_only() {
        return Err(ScriptError::SigPushOnly);
    };

    let mut stack = Stack(Vec::new());
    let mut stack_copy = Stack(Vec::new());
    if !eval_script(&mut stack, script_sig, flags, checker)? {
        // FIXME: `eval_script` returned `false`, but didn’t error.
        return Err(ScriptError::UnknownError);
    };
    if flags.contains(VerificationFlags::P2SH) {
        stack_copy = stack.clone()
    };
    if !eval_script(&mut stack, script_pub_key, flags, checker)? {
        // FIXME: `eval_script` returned `false`, but didn’t error.
        return Err(ScriptError::UnknownError);
    };
    if stack.back().map_or(true, |b| cast_to_bool(&b) == false) {
        return Err(ScriptError::EvalFalse);
    };

    // Additional validation for spend-to-script-hash transactions:
    if flags.contains(VerificationFlags::P2SH) && script_pub_key.is_pay_to_script_hash() {
        // script_sig must be literals-only or validation fails
        if !script_sig.is_push_only() {
            return Err(ScriptError::SigPushOnly);
        };

        // Restore stack.
        stack = stack_copy;

        if let Ok(pub_key_serialized) = stack.pop() {
            let pub_key_2 = Script(&pub_key_serialized.as_slice());

            if !eval_script(&mut stack, &pub_key_2, flags, checker)? {
                // FIXME: `eval_script` returned `false`, but didn’t error.
                return Err(ScriptError::UnknownError);
            };
            if stack.back().map_or(true, |b| cast_to_bool(&b) == false) {
                return Err(ScriptError::EvalFalse);
            }
        } else {
            // stack cannot be empty here, because if it was the
            // P2SH  HASH <> EQUAL  scriptPubKey would be evaluated with
            // an empty stack and the EvalScript above would return false.
            //
            // NB: This is different behavior from the C++ implementation, which
            //     panics here.
            return Err(ScriptError::StackSize);
        }
    };

    // The CLEANSTACK check is only performed after potential P2SH evaluation,
    // as the non-P2SH evaluation of a P2SH script will obviously not result in
    // a clean stack (the P2SH inputs remain).
    if flags.contains(VerificationFlags::CleanStack) {
        // Disallow CLEANSTACK without P2SH, as otherwise a switch CLEANSTACK->P2SH+CLEANSTACK
        // would be possible, which is not a softfork (and P2SH should be one).
        assert!(flags.contains(VerificationFlags::P2SH));
        if stack.size() != 1 {
            return Err(ScriptError::CleanStack);
        }
    };

    Ok(())
}
