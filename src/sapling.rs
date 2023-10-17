// Note that don't include the original file directly; but rather
// a copy of sapling.rs with name changed. See build.rs for the explanation.
include!(concat!(env!("OUT_DIR"), "/rust/sapling/mod.rs"));
