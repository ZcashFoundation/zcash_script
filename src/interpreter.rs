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

fn check_minimal_push(data: &[u8], raw_opcode: u8) -> bool {
    todo!()
}

pub fn evaluate(
    stack: &mut Vec<Vec<u8>>,
    script: &Script,
    options: &VerificationFlags,
) -> Result<(), ScriptError> {
    // There's a limit on how large scripts can be.
    if script.0.len() > MAX_SCRIPT_SIZE {
        return Err(ScriptError::ScriptSize);
    }

    let mut script = (*script).clone();
    let mut push_data = vec![];

    // We keep track of how many operations have executed so far to prevent
    // expensive-to-verify scripts
    let mut op_count = 0;

    // This keeps track of the conditional flags at each nesting level
    // during execution. If we're in a branch of execution where *any*
    // of these conditionals are false, we ignore opcodes unless those
    // opcodes direct control flow (OP_IF, OP_ELSE, etc.).
    let mut exec: Vec<bool> = vec![];

    let mut alt_stack: Vec<Vec<u8>> = vec![];

    // Main execution loop
    while !script.0.is_empty() {
        // Are we in an executing branch of the script?
        let executing = exec.iter().all(|value| *value);

        // Consume an opcode
        let operation = parse_opcode(&mut script.0, Some(&mut push_data))?;

        match operation {
            Operation::PushBytes(raw_opcode) => {
                // There's a limit to the size of the values we'll put on
                // the stack.
                if push_data.len() > MAX_SCRIPT_ELEMENT_SIZE {
                    return Err(ScriptError::PushSize);
                }

                if executing {
                    // Data is being pushed to the stack here; we may need to check
                    // that the minimal script size was used to do so if our caller
                    // requires it.
                    if options.contains(VerificationFlags::MinimalData)
                        && !check_minimal_push(&push_data, raw_opcode)
                    {
                        return Err(ScriptError::MinimalData);
                    }

                    stack.push(push_data.clone());
                }
            }
            Operation::Constant(value) => {
                todo!()
            }

            // Invalid and disabled opcodes do technically contribute to
            // op_count, but they always result in a failed script execution
            // anyway.
            Operation::Invalid => return Err(ScriptError::InvalidOpcode),
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

                if executing || opcode.is_control_flow_opcode() {
                    match opcode {
                        Opcode::OP_RESERVED
                        | Opcode::OP_VER
                        | Opcode::OP_RESERVED1
                        | Opcode::OP_RESERVED2 => {
                            // These are considered "invalid" opcodes but
                            // only inside of *executing* OP_IF branches of
                            // the script.
                            return Err(ScriptError::InvalidOpcode);
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
                            // enable `discourage_upgradable_nops` to turn
                            // these opcodes into errors.
                            if options.contains(VerificationFlags::DiscourageUpgradableNOPs) {
                                return Err(ScriptError::UpgradableNops);
                            }
                        }
                        Opcode::OP_CHECKLOCKTIMEVERIFY => {
                            // This was originally OP_NOP2 but has been repurposed
                            // for OP_CHECKLOCKTIMEVERIFY. So, we should act based
                            // on whether or not CLTV has been activated in a soft
                            // fork.
                            if !options.contains(VerificationFlags::CHECKLOCKTIMEVERIFY) {
                                if options.contains(VerificationFlags::DiscourageUpgradableNOPs) {
                                    return Err(ScriptError::UpgradableNops);
                                }
                            } else {
                                todo!()
                            }
                        }
                        Opcode::OP_IF | Opcode::OP_NOTIF => {
                            let mut value = false;
                            if executing {
                                if stack.is_empty() {
                                    return Err(ScriptError::UnbalancedConditional);
                                }
                                todo!()
                            }
                            exec.push(value);
                        }
                        Opcode::OP_ELSE => {
                            if exec.is_empty() {
                                return Err(ScriptError::UnbalancedConditional);
                            }

                            exec.last_mut().map(|last| *last = !*last);
                        }
                        Opcode::OP_ENDIF => {
                            if exec.is_empty() {
                                return Err(ScriptError::UnbalancedConditional);
                            }

                            exec.pop();
                        }
                        Opcode::OP_VERIFY => {
                            if stack.is_empty() {
                                return Err(ScriptError::InvalidStackOperation);
                            }

                            let value = stack.pop().unwrap();

                            todo!()
                        }
                        Opcode::OP_RETURN => return Err(ScriptError::OpReturn),
                        Opcode::OP_TOALTSTACK => {
                            if stack.is_empty() {
                                return Err(ScriptError::InvalidStackOperation);
                            }

                            alt_stack.push(stack.pop().unwrap());
                        }
                        Opcode::OP_FROMALTSTACK => {
                            if alt_stack.is_empty() {
                                return Err(ScriptError::InvalidStackOperation);
                            }

                            stack.push(alt_stack.pop().unwrap());
                        }
                        Opcode::OP_2DROP => {
                            if stack.len() < 2 {
                                return Err(ScriptError::InvalidStackOperation);
                            }

                            stack.pop();
                            stack.pop();
                        }
                        Opcode::OP_2DUP => {
                            if stack.len() < 2 {
                                return Err(ScriptError::InvalidStackOperation);
                            }

                            let b = stack.pop().unwrap();
                            let a = stack.pop().unwrap();
                            stack.push(a.clone());
                            stack.push(b.clone());
                            stack.push(a);
                            stack.push(b);
                        }
                        Opcode::OP_3DUP => {
                            if stack.len() < 3 {
                                return Err(ScriptError::InvalidStackOperation);
                            }

                            let c = stack.pop().unwrap();
                            let b = stack.pop().unwrap();
                            let a = stack.pop().unwrap();
                            stack.push(a.clone());
                            stack.push(b.clone());
                            stack.push(c.clone());
                            stack.push(a);
                            stack.push(b);
                            stack.push(c);
                        }
                        Opcode::OP_2OVER => {
                            if stack.len() < 4 {
                                return Err(ScriptError::InvalidStackOperation);
                            }

                            let d = stack.pop().unwrap();
                            let c = stack.pop().unwrap();
                            let b = stack.pop().unwrap();
                            let a = stack.pop().unwrap();
                            stack.push(a.clone());
                            stack.push(b.clone());
                            stack.push(c);
                            stack.push(d);
                            stack.push(a);
                            stack.push(b);
                        }
                        Opcode::OP_2ROT => {
                            if stack.len() < 6 {
                                return Err(ScriptError::InvalidStackOperation);
                            }

                            let f = stack.pop().unwrap();
                            let e = stack.pop().unwrap();
                            let d = stack.pop().unwrap();
                            let c = stack.pop().unwrap();
                            let b = stack.pop().unwrap();
                            let a = stack.pop().unwrap();
                            stack.push(c);
                            stack.push(d);
                            stack.push(e);
                            stack.push(f);
                            stack.push(a);
                            stack.push(b);
                        }
                        Opcode::OP_2SWAP => {
                            if stack.len() < 4 {
                                return Err(ScriptError::InvalidStackOperation);
                            }

                            let d = stack.pop().unwrap();
                            let c = stack.pop().unwrap();
                            let b = stack.pop().unwrap();
                            let a = stack.pop().unwrap();
                            stack.push(c);
                            stack.push(d);
                            stack.push(a);
                            stack.push(b);
                        }
                        Opcode::OP_IFDUP => {
                            if stack.is_empty() {
                                return Err(ScriptError::InvalidStackOperation);
                            }

                            todo!()
                        }
                        Opcode::OP_DEPTH => {
                            todo!()
                        }
                        Opcode::OP_DROP => {
                            if stack.is_empty() {
                                return Err(ScriptError::InvalidStackOperation);
                            }

                            stack.pop();
                        }
                        Opcode::OP_DUP => {
                            if stack.is_empty() {
                                return Err(ScriptError::InvalidStackOperation);
                            }

                            let a = stack.pop().unwrap();
                            stack.push(a.clone());
                            stack.push(a);
                        }
                        Opcode::OP_NIP => {
                            if stack.len() < 2 {
                                return Err(ScriptError::InvalidStackOperation);
                            }

                            let b = stack.pop().unwrap();
                            stack.pop();
                            stack.push(b);
                        }
                        Opcode::OP_OVER => {
                            if stack.len() < 2 {
                                return Err(ScriptError::InvalidStackOperation);
                            }

                            let b = stack.pop().unwrap();
                            let a = stack.pop().unwrap();
                            stack.push(a.clone());
                            stack.push(b);
                            stack.push(a);
                        }
                        Opcode::OP_PICK | Opcode::OP_ROLL => {
                            todo!()
                        }
                        Opcode::OP_ROT => {
                            todo!()
                        }
                        Opcode::OP_SWAP => {
                            if stack.len() < 2 {
                                return Err(ScriptError::InvalidStackOperation);
                            }

                            let b = stack.pop().unwrap();
                            let a = stack.pop().unwrap();
                            stack.push(b);
                            stack.push(a);
                        }
                        Opcode::OP_TUCK => {
                            if stack.len() < 2 {
                                return Err(ScriptError::InvalidStackOperation);
                            }

                            let b = stack.pop().unwrap();
                            let a = stack.pop().unwrap();
                            stack.push(b.clone());
                            stack.push(a);
                            stack.push(b);
                        }
                        Opcode::OP_SIZE => {
                            todo!()
                        }
                        Opcode::OP_EQUAL | Opcode::OP_EQUALVERIFY => {
                            if stack.len() < 2 {
                                return Err(ScriptError::InvalidStackOperation);
                            }

                            todo!()
                        }
                        Opcode::OP_1ADD
                        | Opcode::OP_1SUB
                        | Opcode::OP_NEGATE
                        | Opcode::OP_ABS
                        | Opcode::OP_NOT
                        | Opcode::OP_0NOTEQUAL => {
                            todo!()
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
                            todo!()
                        }
                        Opcode::OP_WITHIN => {
                            todo!()
                        }
                        Opcode::OP_RIPEMD160
                        | Opcode::OP_SHA1
                        | Opcode::OP_SHA256
                        | Opcode::OP_HASH160
                        | Opcode::OP_HASH256 => {
                            todo!()
                        }
                        Opcode::OP_CHECKSIG | Opcode::OP_CHECKSIGVERIFY => {
                            todo!()
                        }
                        Opcode::OP_CHECKMULTISIG | Opcode::OP_CHECKMULTISIGVERIFY => {
                            todo!()
                        }
                    }
                }
            }
        }

        // There's a limit to how many items can be added to the stack and
        // alt stack. This limit is enforced upon finishing the execution of
        // an opcode.
        if stack.len() + alt_stack.len() > 1000 {
            return Err(ScriptError::StackSize);
        }
    }

    if exec.is_empty() {
        Ok(())
    } else {
        Err(ScriptError::UnbalancedConditional)
    }
}
