use super::interpreter::*;

/// This maps to `zcash_script_error_t`, but most of those cases aren’t used any more. This only
/// replicates the still-used cases, and then an `Unknown` bucket for anything else that might
/// happen.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum Error {
    /// Any failure that results in the script being invalid.
    Ok = 0,
    /// An exception was caught.
    VerifyScript = 7,
    /// Some other failure value recovered from C++.
    Unknown(u32),
}

/// A function which is called to obtain the sighash.
///    - script_code: the scriptCode being validated. Note that this not always
///      matches script_sig, i.e. for P2SH.
///    - hash_type: the hash type being used.
///
/// The underlying C++ callback doesn’t give much opportunity for rich failure reporting, but
/// returning `None` indicates _some_ failure to produce the desired hash.
///
/// TODO: Can we get the “32” from somewhere rather than hardcoding it?
pub type SighashCallback<'a> = &'a dyn Fn(&[u8], HashType) -> Option<[u8; 32]>;

/// The external API of zcash_script. This is defined to make it possible to compare the C++ and
/// Rust implementations.
pub trait ZcashScript {
    /// Returns `Ok(())` if the a transparent input correctly spends the matching output
    ///  under the additional constraints specified by `flags`. This function
    ///  receives only the required information to validate the spend and not
    ///  the transaction itself. In particular, the sighash for the spend
    ///  is obtained using a callback function.
    ///
    ///  - sighash_callback: a callback function which is called to obtain the sighash.
    ///  - n_lock_time: the lock time of the transaction being validated.
    ///  - is_final: a boolean indicating whether the input being validated is final
    ///    (i.e. its sequence number is 0xFFFFFFFF).
    ///  - script_pub_key: the scriptPubKey of the output being spent.
    ///  - script_sig: the scriptSig of the input being validated.
    ///  - flags: the script verification flags to use.
    ///  - err: if not NULL, err will contain an error/success code for the operation.
    ///
    ///  Note that script verification failure is indicated by `Err(Error::Ok)`.
    fn verify_callback(
        sighash_callback: SighashCallback,
        n_lock_time: i64,
        is_final: bool,
        script_pub_key: &[u8],
        script_sig: &[u8],
        flags: VerificationFlags,
    ) -> Result<(), Error>;

    /// Returns the number of transparent signature operations in the input or
    /// output script pointed to by script.
    fn legacy_sigop_count_script(script: &[u8]) -> u32;
}
