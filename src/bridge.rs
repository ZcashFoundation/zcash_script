// workaround for "expected outer doc comment" error when including bridge.rs
mod inner {
    //! Try me
    include!("../depend/zcash/src/rust/src/bridge.rs");
}

pub use inner::*;
