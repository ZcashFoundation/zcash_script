#![no_main]

use libfuzzer_sys::fuzz_target;
extern crate zcash_script;

use zcash_script::interpreter::CallbackTransactionSignatureChecker;
use zcash_script::*;

fn missing_sighash(_script_code: &[u8], _hash_type: HashType) -> Option<[u8; 32]> {
    None
}

fuzz_target!(|tup: (u32, bool, &[u8], &[u8], u32)| {
    // `fuzz_target!` doesn’t support pattern matching in the parameter list.
    let (lock_time, is_final, pub_key, sig, flag_bits) = tup;
    let flags = testing::repair_flags(VerificationFlags::from_bits_truncate(flag_bits));
    let ret = check_verify_callback(
        &CxxInterpreter {
            sighash: &missing_sighash,
            lock_time,
            is_final,
        },
        &rust_interpreter(
            flags,
            CallbackTransactionSignatureChecker {
                sighash: &missing_sighash,
                lock_time: lock_time.into(),
                is_final,
            },
        ),
        pub_key,
        sig,
        flags,
    );
    assert_eq!(
        ret.0.map_err(normalize_error),
        ret.1.map_err(normalize_error),
        "original Rust result: {:?}",
        ret.1
    );
});
