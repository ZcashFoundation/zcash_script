//! Much of the code is common between the script components, so this provides operations on
//! iterators that can be shared.

use alloc::vec::Vec;

use crate::{
    interpreter, opcode,
    script::{self, Evaluable},
};

/// Evaluate an entire script.
pub fn eval_script<T: script::Evaluable, U: script::Evaluable>(
    sig: &T,
    pub_key: &U,
    flags: interpreter::Flags,
    checker: &dyn interpreter::SignatureChecker,
) -> Result<bool, (script::ComponentType, script::Error)> {
    if flags.contains(interpreter::Flags::SigPushOnly) && !sig.is_push_only() {
        Err((script::ComponentType::Sig, script::Error::SigPushOnly))
    } else {
        let data_stack = sig
            .eval(flags, checker, interpreter::Stack::new())
            .map_err(|e| (script::ComponentType::Sig, e))?;
        let pub_key_stack = pub_key
            .eval(flags, checker, data_stack.clone())
            .map_err(|e| (script::ComponentType::PubKey, e))?;
        if pub_key_stack
            .last()
            .is_ok_and(|v| interpreter::cast_to_bool(v))
        {
            if flags.contains(interpreter::Flags::P2SH) && pub_key.is_pay_to_script_hash() {
                // script_sig must be literals-only or validation fails
                if sig.is_push_only() {
                    data_stack
                        .split_last()
                        .map_err(|_| script::Error::MissingRedeemScript)
                        .and_then(|(pub_key_2, remaining_stack)| {
                            script::Code(pub_key_2.clone()).eval(flags, checker, remaining_stack)
                        })
                        .map(|p2sh_stack| {
                            if p2sh_stack
                                .last()
                                .is_ok_and(|v| interpreter::cast_to_bool(v))
                            {
                                Some(p2sh_stack)
                            } else {
                                None
                            }
                        })
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
                        if flags.contains(interpreter::Flags::CleanStack) {
                            // Disallow CLEANSTACK without P2SH, because Bitcoin did.
                            assert!(flags.contains(interpreter::Flags::P2SH));
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
}

pub fn eval<T: Into<opcode::PossiblyBad> + opcode::Evaluable + Clone>(
    mut iter: impl Iterator<Item = Result<T, script::Error>>,
    flags: interpreter::Flags,
    script_code: &script::Code,
    stack: interpreter::Stack<Vec<u8>>,
    checker: &dyn interpreter::SignatureChecker,
) -> Result<interpreter::Stack<Vec<u8>>, script::Error> {
    iter.try_fold(interpreter::State::initial(stack), |state, elem| {
        elem.and_then(|op| {
            op.eval(flags, script_code, checker, state)
                .map_err(|e| script::Error::Interpreter(Some(op.clone().into()), e))
        })
    })
    .and_then(|final_state| match final_state.vexec.len() {
        0 => Ok(final_state.stack),
        n => Err(script::Error::UnclosedConditional(n)),
    })
}

/// Pre-version-0.6, Bitcoin always counted CHECKMULTISIGs as 20 sigops. With pay-to-script-hash,
/// that changed: CHECKMULTISIGs serialized in script_sigs are counted more accurately, assuming
/// they are of the form ... OP_N CHECKMULTISIG ...
///
/// This mirrors zcashd's `CScript::GetSigOpCount`, which walks the script with `GetOp` and stops
/// only when `GetOp` fails (a push that runs past the end of the script). Bytes this crate
/// classifies as `Disabled` (OP_CAT, ..., and OP_CODESEPARATOR), and complete pushes of more than
/// 520 bytes, are read by zcashd's `GetOp` like any other instruction: they perform no signature
/// operation, so they add 0 and counting continues. They are rejected only when a script is
/// *evaluated*, never while counting, and output scripts are counted without being evaluated.
/// Treating one as a hard stop here would under-count sigops relative to zcashd and open a
/// consensus split, so we skip past it.
pub fn sig_op_count<T: Into<opcode::PossiblyBad> + opcode::Evaluable>(
    iter: impl Iterator<Item = Result<T, opcode::Error>>,
    accurate: bool,
) -> u32 {
    let mut n: u32 = 0;
    let mut last_opcode: Option<opcode::PossiblyBad> = None;
    for item in iter {
        match item {
            Ok(op) => {
                n += op.sig_op_count(last_opcode.take());
                last_opcode = accurate.then(|| op.into());
            }
            // A disabled opcode or a complete push of more than 520 bytes is valid to zcashd's
            // `GetOp`: 0 sigops, keep going, and reset `last_opcode` so a following CHECKMULTISIG
            // is charged the full 20 (zcashd's `lastOpcode` is then never OP_1..=OP_16).
            Err(opcode::Error::Disabled(_) | opcode::Error::PushSize(_)) => last_opcode = None,
            // A truncated push: zcashd's `GetOp` returns false, which stops the count.
            Err(opcode::Error::Read { .. }) => break,
        }
    }
    n
}

#[cfg(test)]
mod tests;
