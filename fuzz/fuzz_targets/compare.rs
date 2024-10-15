#![no_main]

use libfuzzer_sys::fuzz_target;
extern crate zcash_script;

use zcash_script::*;

fn missing_sighash(_script_code: &[u8], _hash_type: HashType) -> Option<[u8; 32]> {
    None
}

fuzz_target!(|tup: (i64, bool, &[u8], &[u8], u32)| {
    // `fuzz_target!` doesn’t support pattern matching in the parameter list.
    let (lock_time, is_final, pub_key, sig, flags) = tup;
    let ret = check_verify_callback::<Cxx, Rust>(
        &missing_sighash,
        lock_time,
        is_final,
        pub_key,
        sig,
        testing::repair_flags(VerificationFlags::from_bits_truncate(flags)),
    );
    assert_eq!(ret.0, ret.1);
});
