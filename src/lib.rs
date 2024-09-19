//! Zcash transparent script implementations.

#![doc(html_logo_url = "https://www.zfnd.org/images/zebra-icon.png")]
#![doc(html_root_url = "https://docs.rs/zcash_script/0.3.0")]
#![allow(unsafe_code)]

mod cxx;
pub use cxx::*;

mod interpreter;
pub use interpreter::{HashType, VerificationFlags};
mod zcash_script;
pub use zcash_script::*;

use std::os::raw::{c_int, c_uint, c_void};

/// A tag to indicate that the C++ implementation of zcash_script should be used.
pub enum Cxx {}

impl From<zcash_script_error_t> for Error {
    #[allow(non_upper_case_globals)]
    fn from(err_code: zcash_script_error_t) -> Error {
        match err_code {
            zcash_script_error_t_zcash_script_ERR_OK => Error::Ok,
            zcash_script_error_t_zcash_script_ERR_VERIFY_SCRIPT => Error::VerifyScript,
            unknown => Error::Unknown(unknown.into()),
        }
    }
}

/// The sighash callback to use with zcash_script.
extern "C" fn sighash_callback(
    sighash_out: *mut u8,
    sighash_out_len: c_uint,
    ctx: *const c_void,
    script_code: *const u8,
    script_code_len: c_uint,
    hash_type: c_int,
) {
    let checked_script_code_len = usize::try_from(script_code_len)
        .expect("This was converted from a `usize` in the first place");
    // SAFETY: `script_code` is created from a Rust slice in `verify_callback`, passed through the
    // C++ code, eventually to `CallbackTransactionSignatureChecker::CheckSig`, which calls this
    // function.
    let script_code_vec =
        unsafe { std::slice::from_raw_parts(script_code, checked_script_code_len) };
    let ctx = ctx as *const SighashCalculator;
    // SAFETY: `ctx` is a valid `SighashCalculator` passed to `verify_callback` which forwards it to
    // the `CallbackTransactionSignatureChecker`.
    if let Some(sighash) = unsafe { *ctx }(script_code_vec, HashType::from_bits_retain(hash_type)) {
        assert_eq!(sighash_out_len, sighash.len().try_into().unwrap());
        // SAFETY: `sighash_out` is a valid buffer created in
        // `CallbackTransactionSignatureChecker::CheckSig`.
        unsafe { std::ptr::copy_nonoverlapping(sighash.as_ptr(), sighash_out, sighash.len()) };
    }
}

/// This steals a bit of the wrapper code from zebra_script, to provide the API that they want.
impl ZcashScript for Cxx {
    fn verify_callback(
        sighash: SighashCalculator,
        lock_time: i64,
        is_final: bool,
        script_pub_key: &[u8],
        signature_script: &[u8],
        flags: VerificationFlags,
    ) -> Result<(), Error> {
        let mut err = 0;

        // SAFETY: The `script` fields are created from a valid Rust `slice`.
        let ret = unsafe {
            zcash_script_verify_callback(
                (&sighash as *const SighashCalculator) as *const c_void,
                Some(sighash_callback),
                lock_time,
                if is_final { 1 } else { 0 },
                script_pub_key.as_ptr(),
                script_pub_key
                    .len()
                    .try_into()
                    .map_err(Error::InvalidScriptSize)?,
                signature_script.as_ptr(),
                signature_script
                    .len()
                    .try_into()
                    .map_err(Error::InvalidScriptSize)?,
                flags.bits(),
                &mut err,
            )
        };

        if ret == 1 {
            Ok(())
        } else {
            Err(Error::from(err))
        }
    }

    /// Returns the number of transparent signature operations in the
    /// transparent inputs and outputs of this transaction.
    fn legacy_sigop_count_script(script: &[u8]) -> Result<u32, Error> {
        script
            .len()
            .try_into()
            .map_err(Error::InvalidScriptSize)
            .map(|script_len| unsafe {
                zcash_script_legacy_sigop_count_script(script.as_ptr(), script_len)
            })
    }
}

#[cfg(feature = "rust-interpreter")]
pub mod rust_interpreter;

#[cfg(test)]
mod tests {
    pub use super::*;
    use hex::FromHex;

    lazy_static::lazy_static! {
        pub static ref SCRIPT_PUBKEY: Vec<u8> = <Vec<u8>>::from_hex("a914c117756dcbe144a12a7c33a77cfa81aa5aeeb38187").unwrap();
        pub static ref SCRIPT_SIG: Vec<u8> = <Vec<u8>>::from_hex("00483045022100d2ab3e6258fe244fa442cfb38f6cef9ac9a18c54e70b2f508e83fa87e20d040502200eead947521de943831d07a350e45af8e36c2166984a8636f0a8811ff03ed09401473044022013e15d865010c257eef133064ef69a780b4bc7ebe6eda367504e806614f940c3022062fdbc8c2d049f91db2042d6c9771de6f1ef0b3b1fea76c1ab5542e44ed29ed8014c69522103b2cc71d23eb30020a4893982a1e2d352da0d20ee657fa02901c432758909ed8f21029d1e9a9354c0d2aee9ffd0f0cea6c39bbf98c4066cf143115ba2279d0ba7dabe2103e32096b63fd57f3308149d238dcbb24d8d28aad95c0e4e74e3e5e6a11b61bcc453ae").expect("Block bytes are in valid hex representation");
    }

    fn sighash(_script_code: &[u8], _hash_type: HashType) -> Option<[u8; 32]> {
        hex::decode("e8c7bdac77f6bb1f3aba2eaa1fada551a9c8b3b5ecd1ef86e6e58a5f1aab952c")
            .unwrap()
            .as_slice()
            .first_chunk::<32>()
            .map(|hash| *hash)
    }

    fn invalid_sighash(_script_code: &[u8], _hash_type: HashType) -> Option<[u8; 32]> {
        hex::decode("08c7bdac77f6bb1f3aba2eaa1fada551a9c8b3b5ecd1ef86e6e58a5f1aab952c")
            .unwrap()
            .as_slice()
            .first_chunk::<32>()
            .map(|hash| *hash)
    }

    fn missing_sighash(_script_code: &[u8], _hash_type: HashType) -> Option<[u8; 32]> {
        None
    }

    #[test]
    fn it_works() {
        let n_lock_time: i64 = 2410374;
        let is_final: bool = true;
        let script_pub_key = &SCRIPT_PUBKEY;
        let script_sig = &SCRIPT_SIG;
        let flags = VerificationFlags::P2SH | VerificationFlags::CHECKLOCKTIMEVERIFY;

        let ret = Cxx::verify_callback(
            &sighash,
            n_lock_time,
            is_final,
            script_pub_key,
            script_sig,
            flags,
        );

        assert!(ret.is_ok());
    }

    #[test]
    fn it_fails_on_invalid_sighash() {
        let n_lock_time: i64 = 2410374;
        let is_final: bool = true;
        let script_pub_key = &SCRIPT_PUBKEY;
        let script_sig = &SCRIPT_SIG;
        let flags = VerificationFlags::P2SH | VerificationFlags::CHECKLOCKTIMEVERIFY;

        let ret = Cxx::verify_callback(
            &invalid_sighash,
            n_lock_time,
            is_final,
            script_pub_key,
            script_sig,
            flags,
        );

        assert_eq!(ret, Err(Error::Ok));
    }

    #[test]
    fn it_fails_on_missing_sighash() {
        let n_lock_time: i64 = 2410374;
        let is_final: bool = true;
        let script_pub_key = &SCRIPT_PUBKEY;
        let script_sig = &SCRIPT_SIG;
        let flags = VerificationFlags::P2SH | VerificationFlags::CHECKLOCKTIMEVERIFY;

        let ret = Cxx::verify_callback(
            &missing_sighash,
            n_lock_time,
            is_final,
            script_pub_key,
            script_sig,
            flags,
        );

        assert_eq!(ret, Err(Error::Ok));
    }
}
