use thiserror::Error;

use crate::{
    interpreter::{self, SignatureChecker},
    script,
};

/// This extends `ScriptError` with cases that can only occur when using the C++ implementation.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum Error {
    /// An error that could occur in any implementation has occurred.
    #[error("{0}")]
    Script(script::Error),

    /// An exception was caught during C++ verification.
    #[error("caught exception during verification")]
    CaughtException,

    /// Some other failure value recovered from C++.
    ///
    /// __NB__: Linux uses `u32` for the underlying C++ enum while Windows uses `i32`, so `i64` can
    ///         hold either.
    #[error("unknown error code: {0}")]
    Unknown(i64),
}

impl Error {
    /// Convert errors that don’t exist in the C++ code into the cases that do.
    pub fn normalize(&self) -> Self {
        match self {
            Error::Script(serr) => Error::Script(serr.normalize()),
            _ => self.clone(),
        }
    }
}

impl From<script::Error> for Error {
    fn from(value: script::Error) -> Self {
        Error::Script(value)
    }
}

/// A verification error annotated with the script component it occurred in.
pub type AnnError = (Option<script::ComponentType>, Error);

/// The external API of zcash_script. This is defined to make it possible to compare the C++ and
/// Rust implementations.
pub trait ZcashScript {
    /// Returns `Ok(true)` if the a transparent input correctly spends the matching output under the
    /// additional constraints specified by `flags`. This function receives only the required
    /// information to validate the spend and not the transaction itself. In particular, the sighash
    /// for the spend is obtained using a callback function.
    ///
    ///  - sighash: a callback function which is called to obtain the sighash.
    ///  - lock_time: the lock time of the transaction being validated.
    ///  - is_final: a boolean indicating whether the input being validated is final
    ///    (i.e. its sequence number is 0xFFFFFFFF).
    ///  - script_pub_key: the scriptPubKey of the output being spent.
    ///  - script_sig: the scriptSig of the input being validated.
    ///  - flags: the script verification flags to use.
    ///
    ///  Note that script verification failure is indicated by `Err(Error::Script)`.
    fn verify_callback(
        &self,
        script: &script::Raw,
        flags: interpreter::Flags,
    ) -> Result<bool, AnnError>;

    /// Returns the number of transparent signature operations in the input or
    /// output script pointed to by script.
    fn legacy_sigop_count_script(&self, script: &script::Code) -> Result<u32, Error>;
}

/// This is the pure Rust interpreter, which doesn’t use the FFI.
pub struct RustInterpreter<C> {
    checker: C,
}

impl<C> RustInterpreter<C> {
    /// Create a Rust interpreter, using some signature checker.
    pub fn new(checker: C) -> Self {
        RustInterpreter { checker }
    }
}

impl<C: SignatureChecker + Copy> ZcashScript for RustInterpreter<C> {
    /// Returns the number of transparent signature operations in the
    /// transparent inputs and outputs of this transaction.
    fn legacy_sigop_count_script(&self, script: &script::Code) -> Result<u32, Error> {
        Ok(script.get_sig_op_count(false))
    }

    fn verify_callback(
        &self,
        script: &script::Raw,
        flags: interpreter::Flags,
    ) -> Result<bool, AnnError> {
        script
            .eval(flags, &self.checker)
            .map_err(|(t, e)| (Some(t), Error::Script(e)))
    }
}
