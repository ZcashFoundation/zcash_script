// Copyright (c) 2020 The Zcash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

use blake2b_simd::{State, PERSONALBYTES};
use libc::{c_uchar, size_t};
use std::slice;

#[no_mangle]
pub extern "C" fn rust_blake2b_init(
    length: size_t,
    personalization: *const [c_uchar; PERSONALBYTES],
) -> *mut State {
    let personalization = unsafe { personalization.as_ref().unwrap() };

    Box::into_raw(Box::new(
        blake2b_simd::Params::new()
            .hash_length(length)
            .personal(personalization)
            .to_state(),
    ))
}

#[no_mangle]
pub extern "C" fn rust_blake2b_clone(state: *const State) -> *mut State {
    let state = unsafe { state.as_ref().unwrap() };

    Box::into_raw(Box::new(state.clone()))
}

#[no_mangle]
pub extern "C" fn rust_blake2b_free(state: *mut State) {
    drop(unsafe { Box::from_raw(state) });
}

#[no_mangle]
pub extern "C" fn rust_blake2b_update(state: *mut State, input: *const c_uchar, input_len: size_t) {
    let state = unsafe { state.as_mut().unwrap() };
    let input = unsafe { slice::from_raw_parts(input, input_len) };

    state.update(input);
}

#[no_mangle]
pub extern "C" fn rust_blake2b_finalize(
    state: *mut State,
    output: *mut c_uchar,
    output_len: size_t,
) {
    let state = unsafe { state.as_mut().unwrap() };
    let output = unsafe { slice::from_raw_parts_mut(output, output_len) };

    output.copy_from_slice(state.finalize().as_bytes());
}
