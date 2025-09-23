#![no_main]

use libfuzzer_sys::fuzz_target;

use libzcash_script::{check_verify_callback, normalize_err, CxxInterpreter, RustInterpreter};
use zcash_script::{
    interpreter::{self, CallbackTransactionSignatureChecker},
    script,
    signature::HashType,
    testing,
};

fn missing_sighash(_script_code: &script::Code, _hash_type: &HashType) -> Option<[u8; 32]> {
    None
}

fuzz_target!(|tup: (u32, bool, &[u8], &[u8], u32)| {
    // `fuzz_target!` doesn’t support pattern matching in the parameter list.
    let (lock_time, is_final, pub_key, sig, flag_bits) = tup;
    let flags = testing::repair_flags(interpreter::Flags::from_bits_truncate(flag_bits));
    let script = script::Raw::from_raw_parts(sig.to_vec(), pub_key.to_vec());
    let ret = check_verify_callback(
        &CxxInterpreter {
            sighash: &missing_sighash,
            lock_time,
            is_final,
        },
        &RustInterpreter::new(CallbackTransactionSignatureChecker {
            sighash: &missing_sighash,
            lock_time: lock_time.into(),
            is_final,
        }),
        &script,
        flags,
    );
    assert_eq!(
        ret.0.clone().map_err(normalize_err),
        ret.1.clone().map_err(normalize_err),
        "\n• original Rust result: {:?}\n• parsed script: {:?}",
        ret.1,
        testing::annotate_script(&script, &flags)
    );
});
