//! Rust bindings for Zcash transparent scripts.

#![allow(missing_docs)]
#![allow(clippy::needless_lifetimes)]
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(unsafe_code)]
#![allow(unused_imports)]
#![allow(clippy::unwrap_or_default)]

// Use the generated C++ bindings
include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
#[cfg(test)]
mod tests {
    use alloc::vec::Vec;
    use core::{
        ffi::{c_int, c_uint, c_void},
        ptr,
    };

    use hex::FromHex;

    lazy_static::lazy_static! {
        pub static ref SCRIPT_PUBKEY: Vec<u8> = <Vec<u8>>::from_hex("a914c117756dcbe144a12a7c33a77cfa81aa5aeeb38187").unwrap();
        pub static ref SCRIPT_SIG: Vec<u8> = <Vec<u8>>::from_hex("00483045022100d2ab3e6258fe244fa442cfb38f6cef9ac9a18c54e70b2f508e83fa87e20d040502200eead947521de943831d07a350e45af8e36c2166984a8636f0a8811ff03ed09401473044022013e15d865010c257eef133064ef69a780b4bc7ebe6eda367504e806614f940c3022062fdbc8c2d049f91db2042d6c9771de6f1ef0b3b1fea76c1ab5542e44ed29ed8014c69522103b2cc71d23eb30020a4893982a1e2d352da0d20ee657fa02901c432758909ed8f21029d1e9a9354c0d2aee9ffd0f0cea6c39bbf98c4066cf143115ba2279d0ba7dabe2103e32096b63fd57f3308149d238dcbb24d8d28aad95c0e4e74e3e5e6a11b61bcc453ae").expect("Block bytes are in valid hex representation");
    }

    extern "C" fn sighash(
        sighash_out: *mut u8,
        sighash_out_len: c_uint,
        ctx: *const c_void,
        _script_code: *const u8,
        _script_code_len: c_uint,
        _hash_type: c_int,
    ) {
        unsafe {
            assert!(ctx.is_null());
            let sighash =
                hex::decode("e8c7bdac77f6bb1f3aba2eaa1fada551a9c8b3b5ecd1ef86e6e58a5f1aab952c")
                    .unwrap();
            assert!(sighash_out_len == sighash.len() as c_uint);
            ptr::copy_nonoverlapping(sighash.as_ptr(), sighash_out, sighash.len());
        }
    }

    extern "C" fn invalid_sighash(
        sighash_out: *mut u8,
        sighash_out_len: c_uint,
        ctx: *const c_void,
        _script_code: *const u8,
        _script_code_len: c_uint,
        _hash_type: c_int,
    ) {
        unsafe {
            assert!(ctx.is_null());
            let sighash =
                hex::decode("08c7bdac77f6bb1f3aba2eaa1fada551a9c8b3b5ecd1ef86e6e58a5f1aab952c")
                    .unwrap();
            assert!(sighash_out_len == sighash.len() as c_uint);
            ptr::copy_nonoverlapping(sighash.as_ptr(), sighash_out, sighash.len());
        }
    }

    #[test]
    fn it_works() {
        let nLockTime: i64 = 2410374;
        let isFinal: u8 = 1;
        let script_pub_key = &*SCRIPT_PUBKEY;
        let script_sig = &*SCRIPT_SIG;
        let flags: c_uint = 513;
        let mut err = 0;

        let ret = unsafe {
            super::zcash_script_verify_callback(
                ptr::null(),
                Some(sighash),
                nLockTime,
                isFinal,
                script_pub_key.as_ptr(),
                script_pub_key.len() as c_uint,
                script_sig.as_ptr(),
                script_sig.len() as c_uint,
                flags,
                &mut err,
            )
        };

        assert!(ret == 1);
    }

    #[test]
    fn it_fails_on_invalid_sighash() {
        let nLockTime: i64 = 2410374;
        let isFinal: u8 = 1;
        let script_pub_key = &*SCRIPT_PUBKEY;
        let script_sig = &*SCRIPT_SIG;
        let flags: c_uint = 513;
        let mut err = 0;

        let ret = unsafe {
            super::zcash_script_verify_callback(
                ptr::null(),
                Some(invalid_sighash),
                nLockTime,
                isFinal,
                script_pub_key.as_ptr(),
                script_pub_key.len() as c_uint,
                script_sig.as_ptr(),
                script_sig.len() as c_uint,
                flags,
                &mut err,
            )
        };

        assert!(ret != 1);
    }
}
