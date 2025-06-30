pub(crate) mod invalid;
pub(crate) mod valid;

use crate::{
    interpreter::VerificationFlags,
    op,
    script::{serialize_num, Opcode},
    script_error::ScriptError,
};
use hex::{FromHex, FromHexError};

/// A shorthand syntax for writing possibly-incorrect scripts.
#[derive(Debug)]
pub(crate) enum Entry {
    /// An Opcode
    O(Opcode),
    /// A byte sequence encoded as a hex string
    H(&'static str),
    /// A PushValue encoded as an ASCII string
    A(&'static str),
    /// A PushValue encoded as a number
    N(i64),
}

impl Entry {
    fn val_to_pv(v: &[u8]) -> Vec<u8> {
        match v {
            [] => vec![0],
            [v] => {
                if *v <= 16 {
                    vec![*v + 0x50]
                } else {
                    vec![1, *v]
                }
            }
            v => {
                let mut vv = v.to_vec().clone();
                let l = v.len();
                if l < 0x4c {
                    let mut nv = vec![u8::try_from(l).unwrap()];
                    nv.append(&mut vv);
                    nv
                } else if l <= 0xff {
                    let mut nv = vec![0x4c];
                    nv.append(&mut serialize_num(v.len().try_into().unwrap()));
                    nv.append(&mut vv);
                    nv
                } else if l <= 0xffff {
                    let mut nv = vec![0x4d];
                    nv.append(&mut serialize_num(v.len().try_into().unwrap()));
                    nv.append(&mut vv);
                    nv
                } else {
                    // FIXME: Need to pad 3-byte lengths.
                    let mut nv = vec![0x4e];
                    nv.append(&mut serialize_num(v.len().try_into().unwrap()));
                    nv.append(&mut vv);
                    nv
                }
            }
        }
    }

    pub(crate) fn serialize(&self) -> Result<Vec<u8>, FromHexError> {
        match self {
            Entry::O(opcode) => Ok(vec![(*opcode).into()]),
            Entry::H(bytes) => <Vec<u8>>::from_hex(*bytes),
            Entry::A(string) => Ok(Self::val_to_pv(string.as_bytes())),
            Entry::N(num) => Ok(Self::val_to_pv(&serialize_num(*num))),
        }
    }
}

#[derive(Debug)]
pub(crate) struct TestVector {
    pub(crate) script_sig: &'static [Entry],
    pub(crate) script_pubkey: &'static [Entry],
    pub(crate) flags: VerificationFlags,
    pub(crate) result: Result<(), ScriptError>,
}

impl TestVector {
    /// A successful run is uninteresting, but a failure returns the actual `Result` in `Err`.
    pub(crate) fn run(
        &self,
        f: &dyn Fn(&[u8], &[u8], VerificationFlags) -> Result<(), ScriptError>,
    ) -> Result<(), Result<(), ScriptError>> {
        match (
            self.script_sig
                .iter()
                .map(Entry::serialize)
                .collect::<Result<Vec<Vec<u8>>, FromHexError>>()
                .map(|vs| vs.concat()),
            self.script_pubkey
                .iter()
                .map(Entry::serialize)
                .collect::<Result<Vec<Vec<u8>>, FromHexError>>()
                .map(|vs| vs.concat()),
        ) {
            (Ok(sig), Ok(pubkey)) => {
                let res = f(&sig, &pubkey, self.flags);
                if res == self.result {
                    Ok(())
                } else {
                    Err(res)
                }
            }
            (s, p) => panic!("{:?} has a bad hex value: {:?}", self, s.and_then(|_| p)),
        }
    }
}

pub(crate) const NOP2: Opcode = op::CHECKLOCKTIMEVERIFY;

pub(crate) mod bad {
    use crate::script::{
        Opcode::{self, *},
        Operation::*,
        PushValue::*,
    };

    pub const RESERVED: Opcode = PushValue(OP_RESERVED);
    pub const VERIF: Opcode = Operation(OP_VERIF);
    pub const VERNOTIF: Opcode = Operation(OP_VERNOTIF);
    pub const VER: Opcode = Operation(OP_VER);
    pub const RESERVED1: Opcode = Operation(OP_RESERVED1);
    pub const RESERVED2: Opcode = Operation(OP_RESERVED2);
}

pub(crate) mod disabled {
    use crate::script::{
        Opcode::{self, *},
        Operation::*,
    };

    pub const CAT: Opcode = Operation(OP_CAT);
    pub const SUBSTR: Opcode = Operation(OP_SUBSTR);
    pub const LEFT: Opcode = Operation(OP_LEFT);
    pub const RIGHT: Opcode = Operation(OP_RIGHT);
    pub const INVERT: Opcode = Operation(OP_INVERT);
    pub const AND: Opcode = Operation(OP_AND);
    pub const OR: Opcode = Operation(OP_OR);
    pub const XOR: Opcode = Operation(OP_XOR);
    pub const _2MUL: Opcode = Operation(OP_2MUL);
    pub const _2DIV: Opcode = Operation(OP_2DIV);
    pub const MUL: Opcode = Operation(OP_MUL);
    pub const DIV: Opcode = Operation(OP_DIV);
    pub const MOD: Opcode = Operation(OP_MOD);
    pub const LSHIFT: Opcode = Operation(OP_LSHIFT);
    pub const RSHIFT: Opcode = Operation(OP_RSHIFT);
}

pub(crate) const DEFAULT_FLAGS: VerificationFlags =
    VerificationFlags::P2SH.union(VerificationFlags::StrictEnc);
pub(crate) const EMPTY_FLAGS: VerificationFlags = VerificationFlags::empty();
