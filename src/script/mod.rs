use std::fmt::Display;

use serde::{Deserialize, Serialize};

pub mod error;
mod parser;

use crate::{
    interpreter::*,
    op,
    opcode::{
        LargeValue::*,
        Normal::*,
        Opcode, Operation, PushValue,
        SmallValue::{self, *},
    },
    scriptnum::*,
    util::and_maybe::AndMaybe,
};
pub use error::Error;
pub use parser::Parsable;

/// Maximum script length in bytes
pub const MAX_SIZE: usize = 10_000;

// Threshold for lock_time: below this value it is interpreted as block number,
// otherwise as UNIX timestamp.
pub const LOCKTIME_THRESHOLD: ScriptNum = ScriptNum(500_000_000); // Tue Nov  5 00:53:20 1985 UTC

/// This can be specialized in one of two ways:
/// - with `T` ~ [`PushValue`], this creates a [`Sig`] for a new output; and
/// - with `T` ~ [`Opcode`], this reads a [`Sig`] from an input on the chain.
///
/// This is because script_sigs are now required to be push-only, but if we’re spending a pre-v5
/// output, it’s possible that it contains some operations.
///
/// If we didn’t need to allow non-push-only script_sigs, then this could simply be an ailas for
/// [`Vec<PushValue>`], but as it’s not, we need to support the older style as well.
///
/// FIXME: Delete this if there are none already on the chain, since a new one can never be
///        created.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct Sig<T>(Vec<T>);

/// Returns a pre-v5 script_sig, and also a v5+ script_sig, if possible.
///
/// If you only need one or the other, it’s better to use [`Sig::<T>::from_bytes`], but if you want
/// to take different paths depending on whether or not this is a v5+ Sig, this is the way to go.
pub fn sigs_from_bytes(bytes: &[u8]) -> Result<AndMaybe<Sig<Opcode>, Sig<PushValue>>, Error> {
    vec::from_bytes(bytes).map(|(result, _)| {
        AndMaybe::sequence(
            &result
                .iter()
                .map(|op| match op {
                    Opcode::PushValue(pv) => AndMaybe::Indeed(op.clone(), pv.clone()),
                    Opcode::Operation(_) => AndMaybe::Only(op.clone()),
                })
                .collect::<Vec<AndMaybe<Opcode, PushValue>>>(),
        )
        .bimap(
            |ts| Sig(ts.iter().cloned().cloned().collect()),
            |us| Sig(us.iter().cloned().cloned().collect()),
        )
    })
}

impl<T> Display for Sig<T>
where
    T: Display,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            self.0
                .iter()
                .map(|op| op.to_string())
                .collect::<Vec<_>>()
                .join(" ")
        )
    }
}

/// A few `pub` types with similar (if not identical) implementations are backed by [`Vec`]s, so we
/// put the common implementations in this module. This is better than, say, `impl<T: Evaluable>
/// Evaluable for Vec<T>`, because it keeps these functions private.
mod vec {
    use super::{error::Error, parser::Parsable, MAX_SIZE};
    use crate::interpreter::*;

    /// This populates the provided `Vec`.
    fn deserialize<T: Parsable>(init: &mut Vec<T>, bytes: &[u8]) -> Result<(), Error> {
        if bytes.is_empty() {
            Ok(())
        } else {
            T::from_bytes(bytes).and_then(|(op, rest)| {
                init.push(op);
                deserialize(init, rest)
            })
        }
    }

    pub fn from_bytes<T: Parsable>(bytes: &[u8]) -> Result<(Vec<T>, &[u8]), Error> {
        if bytes.len() > MAX_SIZE {
            Err(Error::ScriptSize)
        } else {
            let mut result = Vec::with_capacity(bytes.len());
            deserialize(&mut result, bytes).map(|()| {
                result.shrink_to_fit();
                (result, &[][..])
            })
        }
    }

    pub fn byte_len<T: Evaluable>(vec: &Vec<T>) -> usize {
        vec.iter().map(T::byte_len).sum()
    }

    pub fn eval<T: Evaluable, P>(
        vec: &Vec<T>,
        stack: Stack<ValType>,
        script_code: &[u8],
        payload: &mut P,
        eval_step: &impl Fn(&dyn Evaluable, &[u8], &mut State, &mut P) -> Result<(), Error>,
    ) -> Result<Stack<ValType>, Error> {
        // There's a limit on how large scripts can be.
        if byte_len(vec) > MAX_SIZE {
            return Err(Error::ScriptSize);
        }

        // Main execution loop
        //
        // TODO: With a streaming lexer, this could be
        //
        // lex(script).fold(eval_step, State::initial(stack))
        let mut state = State::initial(stack);
        vec.iter().fold(Ok(&mut state), |state, opcode| {
            state.and_then(|state| eval_step(opcode, script_code, state, payload).map(|()| state))
        })?;

        if !state.vexec.is_empty() {
            return Err(Error::UnbalancedConditional);
        }

        Ok(state.stack)
    }
}

impl<T: Evaluable> Sig<T> {
    pub fn byte_len(&self) -> usize {
        vec::byte_len(&self.0)
    }

    pub fn eval<P>(
        &self,
        stack: Stack<ValType>,
        script_code: &[u8],
        payload: &mut P,
        eval_step: &impl Fn(&dyn Evaluable, &[u8], &mut State, &mut P) -> Result<(), Error>,
    ) -> Result<Stack<ValType>, Error> {
        vec::eval(&self.0, stack, script_code, payload, eval_step)
    }
}

impl Sig<Opcode> {
    pub fn well_formed(&self, flags: VerificationFlags) -> Result<(), Error> {
        if self.byte_len() > MAX_SIZE {
            return Err(Error::ScriptSize);
        }

        let mut state = State::initial(Stack::new());
        self.0.iter().fold(Ok(()), |prev, opcode| {
            prev.and_then(|()| opcode.well_formed(flags, &mut state.op_count, &mut state.vexec))
        })?;

        if !state.vexec.is_empty() {
            return Err(Error::UnbalancedConditional);
        }

        Ok(())
    }
}

impl Sig<PushValue> {
    /// Create a new v5-compatible script_sig.
    ///
    /// If you need a pre-v5 script_sig, it can only be instantiated using
    /// [`Parsable::from_bytes`], as we should no longer have _new_ pre-v5 script_sigs, but are
    /// only reading them off earlier parts of the chain.
    pub fn new(script_sig: Vec<PushValue>) -> Self {
        Sig(script_sig)
    }

    pub fn well_formed(&self, flags: VerificationFlags) -> Result<(), Error> {
        // There's a limit on how large scripts can be.
        if self.byte_len() > MAX_SIZE {
            return Err(Error::ScriptSize);
        }

        self.0.iter().fold(Ok(()), |prev, pv| {
            prev.and_then(|()| pv.well_formed(flags.contains(VerificationFlags::MinimalData)))
        })
    }
}

impl<T: Parsable> Parsable for Sig<T> {
    fn to_bytes(&self) -> Vec<u8> {
        self.0
            .iter()
            .fold(Vec::new(), |acc, op| [acc, op.to_bytes()].concat())
    }

    fn from_bytes(bytes: &[u8]) -> Result<(Self, &[u8]), Error> {
        vec::from_bytes(bytes).map(|(r, t)| (Sig(r), t))
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
pub struct PubKey(pub Vec<Opcode>);

impl PubKey {
    pub fn byte_len(&self) -> usize {
        vec::byte_len(&self.0)
    }

    /** Encode/decode small integers: */
    fn decode_op_n(opcode: SmallValue) -> u32 {
        if opcode == OP_0 {
            return 0;
        }
        assert!(OP_1 <= opcode && opcode <= OP_16);
        (u8::from(opcode) - (u8::from(OP_1) - 1)).into()
    }

    /// Pre-version-0.6, Bitcoin always counted CHECKMULTISIGs
    /// as 20 sigops. With pay-to-script-hash, that changed:
    /// CHECKMULTISIGs serialized in script_sigs are
    /// counted more accurately, assuming they are of the form
    ///  ... OP_N CHECKMULTISIG ...
    pub fn get_sig_op_count(&self, accurate: bool) -> u32 {
        self.0
            .iter()
            .fold((0, None), |(n, last_opcode), opcode| {
                (
                    if let Opcode::Operation(Operation::Normal(op)) = opcode {
                        if *op == OP_CHECKSIG || *op == OP_CHECKSIGVERIFY {
                            n + 1
                        } else if *op == OP_CHECKMULTISIG || *op == OP_CHECKMULTISIGVERIFY {
                            match last_opcode {
                                Some(&Opcode::PushValue(PushValue::SmallValue(pv))) => {
                                    if accurate && OP_1 <= pv && pv <= OP_16 {
                                        n + Self::decode_op_n(pv)
                                    } else {
                                        n + 20
                                    }
                                }
                                _ => n + 20,
                            }
                        } else {
                            n
                        }
                    } else {
                        n
                    },
                    Some(opcode),
                )
            })
            .0
    }

    /// Returns true iff this script is P2SH.
    pub fn is_pay_to_script_hash(&self) -> bool {
        match &(self.0)[..] {
            [op::HASH160, Opcode::PushValue(PushValue::LargeValue(PushdataBytelength(v))), op::EQUAL] => {
                v.len() == 0x14
            }
            _ => false,
        }
    }

    /// Do some basic static analysis to ensure the script makes sense. E.g., it ensures
    /// - that the script isn’t too long
    /// - that conditionals are balanced
    /// - that pushes are minimal (if the flags require it)
    /// - that no push is too large
    /// - that there are no bad or disabled opcodes in the script
    /// - etc.
    ///
    /// **TODO**: This checks all branches, because it can’t know whether any particular branch will
    ///           be executed on a given run. Unfortunately, this means it can return a failure even
    ///           if an invalid branch is unreachable. It would be better to distinguish failures
    ///           that might not happen from those that will.
    ///
    /// **TODO**: Ideally, this could have the same skeleton as `eval`, with just different
    ///           behaviors passed in. The behavior here would basically be a NOP, but it _could_ be
    ///           richer. E.g., it could track what is needed in the stack – not just how many
    ///           elements, but what each element is an argument to (e.g., hashes, numbers, or a
    ///           redeem script); it could do partial evaluation; etc.
    pub fn well_formed(&self, flags: VerificationFlags) -> Result<(), Error> {
        if self.byte_len() > MAX_SIZE {
            return Err(Error::ScriptSize);
        }

        let mut state = State::initial(Stack::new());
        self.0.iter().fold(Ok(()), |prev, opcode| {
            prev.and_then(|()| opcode.well_formed(flags, &mut state.op_count, &mut state.vexec))
        })?;

        if !state.vexec.is_empty() {
            return Err(Error::UnbalancedConditional);
        }

        Ok(())
    }

    pub fn eval<P>(
        &self,
        stack: Stack<ValType>,
        script_code: &[u8],
        payload: &mut P,
        eval_step: &impl Fn(&dyn Evaluable, &[u8], &mut State, &mut P) -> Result<(), Error>,
    ) -> Result<Stack<ValType>, Error> {
        vec::eval(&self.0, stack, script_code, payload, eval_step)
    }
}

impl Parsable for PubKey {
    fn to_bytes(&self) -> Vec<u8> {
        self.0
            .iter()
            .fold(Vec::new(), |acc, op| [acc, op.to_bytes()].concat())
    }

    fn from_bytes(bytes: &[u8]) -> Result<(Self, &[u8]), Error> {
        vec::from_bytes(bytes).map(|(r, t)| (PubKey(r), t))
    }
}

impl Display for PubKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            self.0
                .iter()
                .map(|op| op.to_string())
                .collect::<Vec<_>>()
                .join(" ")
        )
    }
}

/// A Zcash script consists of both the script_sig and the script_pubkey.
///
/// See the documentation on [`Sig`] for explanation of `T`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Script<T> {
    pub sig: Sig<T>,
    pub pub_key: PubKey,
}

impl<T: Evaluable> Script<T> {
    pub fn byte_len(&self) -> usize {
        self.sig.byte_len() + self.pub_key.byte_len()
    }

    /// The primary script evaluator.
    ///
    /// **NB**: This takes an extra `p2sh` function argument. The behavior of P2SH scripts depends
    ///         on the specific `T`, so those specializations provide that argument and are the
    ///         functions that should be called.
    fn eval_<P>(
        &self,
        flags: VerificationFlags,
        script_code: &[u8],
        payload: &mut P,
        stepper: &impl Fn(&dyn Evaluable, &[u8], &mut State, &mut P) -> Result<(), Error>,
        p2sh: impl Fn(&Stack<ValType>, &mut P) -> Result<Stack<ValType>, Error>,
    ) -> Result<(), Error> {
        let data_stack = self.sig.eval(Stack::new(), &[], payload, stepper)?;
        let pub_key_stack =
            self.pub_key
                .eval(data_stack.clone(), &script_code, payload, stepper)?;
        if pub_key_stack.last().map_or(false, cast_to_bool) {
            // Additional validation for spend-to-script-hash transactions:
            let result_stack = if flags.contains(VerificationFlags::P2SH)
                && self.pub_key.is_pay_to_script_hash()
            {
                p2sh(&data_stack, payload)?
            } else {
                pub_key_stack
            };

            // The CLEANSTACK check is only performed after potential P2SH evaluation,
            // as the non-P2SH evaluation of a P2SH script will obviously not result in
            // a clean stack (the P2SH inputs remain).
            if flags.contains(VerificationFlags::CleanStack) {
                // Disallow CLEANSTACK without P2SH, as otherwise a switch
                // CLEANSTACK->P2SH+CLEANSTACK would be possible, which is not a softfork (and P2SH
                // should be one).
                assert!(flags.contains(VerificationFlags::P2SH));
                if result_stack.len() != 1 {
                    return Err(Error::CleanStack);
                }
            }

            Ok(())
        } else {
            Err(Error::EvalFalse)
        }
    }
}

impl Script<Opcode> {
    pub fn well_formed_(&self, flags: VerificationFlags) -> Result<(), Error> {
        self.sig.well_formed(flags)?;
        self.pub_key.well_formed(flags)?;
        if flags.contains(VerificationFlags::P2SH) && self.pub_key.is_pay_to_script_hash() {
            Err(Error::SigPushOnly)?
        }

        if flags.contains(VerificationFlags::CleanStack) {
            assert!(flags.contains(VerificationFlags::P2SH));
        }

        Ok(())
    }

    pub fn eval<P>(
        &self,
        flags: VerificationFlags,
        script_code: &[u8],
        payload: &mut P,
        stepper: &impl Fn(&dyn Evaluable, &[u8], &mut State, &mut P) -> Result<(), Error>,
    ) -> Result<(), Error> {
        self.eval_(flags, script_code, payload, stepper, |_, _| {
            Err(Error::SigPushOnly)
        })
    }
}

impl Script<PushValue> {
    pub fn well_formed(&self, flags: VerificationFlags) -> Result<(), Error> {
        self.sig.well_formed(flags)?;
        self.pub_key.well_formed(flags)?;
        if flags.contains(VerificationFlags::CleanStack) {
            assert!(flags.contains(VerificationFlags::P2SH));
        }

        Ok(())
    }

    pub fn eval<P>(
        &self,
        flags: VerificationFlags,
        script_code: &[u8],
        payload: &mut P,
        stepper: &impl Fn(&dyn Evaluable, &[u8], &mut State, &mut P) -> Result<(), Error>,
    ) -> Result<(), Error> {
        self.eval_(
            flags,
            script_code,
            payload,
            stepper,
            |data_stack, payload| {
                data_stack
                    // stack cannot be empty here, because if it was the P2SH HASH <> EQUAL
                    // scriptPubKey would be evaluated with an empty stack and the
                    // `pub_key.eval` above would return false.
                    .split_last()
                    .and_then(|(pub_key_2, remaining_stack)| {
                        PubKey::from_bytes(pub_key_2).and_then(|(pk2, _)| {
                            pk2.eval(remaining_stack, pub_key_2, payload, stepper)
                        })
                    })
                    .and_then(|p2sh_stack| {
                        if p2sh_stack.last().map_or(false, cast_to_bool) {
                            Ok(p2sh_stack)
                        } else {
                            Err(Error::EvalFalse)
                        }
                    })
            },
        )
    }
}
