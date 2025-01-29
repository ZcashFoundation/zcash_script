use std::num::TryFromIntError;

use super::interpreter::*;
use super::script::*;
use super::script_error::*;

/// This maps to `zcash_script_error_t`, but most of those cases aren’t used any more. This only
/// replicates the still-used cases, and then an `Unknown` bucket for anything else that might
/// happen.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// Any failure that results in the script being invalid.
    ///
    /// __NB__: This is in `Option` because this type is used by both the C++ and Rust
    ///         implementations, but the C++ impl doesn’t yet expose the original error.
    Ok(Option<ScriptError>),
    /// An exception was caught.
    VerifyScript,
    /// The script size can’t fit in a `u32`, as required by the C++ code.
    InvalidScriptSize(TryFromIntError),
    /// Some other failure value recovered from C++.
    ///
    /// __NB__: Linux uses `u32` for the underlying C++ enum while Windows uses `i32`, so `i64` can
    ///         hold either.
    Unknown(i64),
}

/// The external API of zcash_script. This is defined to make it possible to compare the C++ and
/// Rust implementations.
pub trait ZcashScript {
    /// Returns `Ok(())` if the a transparent input correctly spends the matching output
    ///  under the additional constraints specified by `flags`. This function
    ///  receives only the required information to validate the spend and not
    ///  the transaction itself. In particular, the sighash for the spend
    ///  is obtained using a callback function.
    ///
    ///  - sighash: a callback function which is called to obtain the sighash.
    ///  - lock_time: the lock time of the transaction being validated.
    ///  - is_final: a boolean indicating whether the input being validated is final
    ///    (i.e. its sequence number is 0xFFFFFFFF).
    ///  - script_pub_key: the scriptPubKey of the output being spent.
    ///  - script_sig: the scriptSig of the input being validated.
    ///  - flags: the script verification flags to use.
    ///
    ///  Note that script verification failure is indicated by `Err(Error::Ok)`.
    fn verify_callback(
        sighash_callback: SighashCalculator,
        lock_time: u32,
        is_final: bool,
        script_pub_key: &[u8],
        script_sig: &[u8],
        flags: VerificationFlags,
    ) -> Result<(), Error>;

    /// Returns the number of transparent signature operations in the input or
    /// output script pointed to by script.
    fn legacy_sigop_count_script(script: &[u8]) -> Result<u32, Error>;
}

/// A tag to indicate that the Rust implementation of zcash_script should be used.
pub enum RustInterpreter {}

impl ZcashScript for RustInterpreter {
    /// Returns the number of transparent signature operations in the
    /// transparent inputs and outputs of this transaction.
    fn legacy_sigop_count_script(script: &[u8]) -> Result<u32, Error> {
        let cscript = Script(script);
        Ok(cscript.get_sig_op_count(false))
    }

    fn verify_callback(
        sighash: SighashCalculator,
        lock_time: u32,
        is_final: bool,
        script_pub_key: &[u8],
        script_sig: &[u8],
        flags: VerificationFlags,
    ) -> Result<(), Error> {
        let lock_time_num = lock_time.into();
        verify_script(
            &Script(script_sig),
            &Script(script_pub_key),
            flags,
            &CallbackTransactionSignatureChecker {
                sighash,
                lock_time: &lock_time_num,
                is_final,
            },
        )
        .map_err(|e| Error::Ok(Some(e)))
    }
}
