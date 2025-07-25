use crate::{
    external::pubkey::PubKey,
    op,
    opcode::{LargeValue::PushdataBytelength, Opcode, PushValue},
    script,
};

/// Parses a `script::PubKey` and detects standard scripts.
///
/// If successful, returns the script kind, and any relevant properties parsed from the
/// script. For example, for a P2SH script, the result will contain the script hash; for
/// P2PKH it will contain the key hash, etc.
///
/// Returns `None` if the script is non-standard.
pub fn solver(script_code: &script::PubKey) -> Option<ScriptKind> {
    match &script_code.0[..] {
        // Pay-to-Script-Hash (P2SH)
        [op::HASH160, Opcode::PushValue(PushValue::LargeValue(PushdataBytelength(v))), op::EQUAL] => {
            v.as_slice()
                .try_into()
                .ok()
                .map(|hash| ScriptKind::ScriptHash { hash })
        }

        // Pay-to-Public-Key-Hash (P2PKH)
        [op::DUP, op::HASH160, Opcode::PushValue(PushValue::LargeValue(PushdataBytelength(v))), op::EQUALVERIFY, op::CHECKSIG] => {
            v.as_slice()
                .try_into()
                .ok()
                .map(|hash| ScriptKind::PubKeyHash { hash })
        }

        // Provably prunable, data-carrying output.
        //
        // So long as the script passes the `is_unspendable()` test, and all but the first
        // byte passes the `is_push_only()` test, we don't care what exactly is in the
        // script.
        [op::RETURN, rest @ ..] if script::PubKey::is_push_only(rest) => Some(ScriptKind::NullData),

        // Legacy Pay-to-Public-Key (P2PK), which only occurred in early Zcash coinbase outputs.
        [Opcode::PushValue(PushValue::LargeValue(PushdataBytelength(v))), op::CHECKSIG] => {
            (v.len() == PubKey::SIZE || v.len() == PubKey::COMPRESSED_SIZE)
                .then(|| ScriptKind::PubKey { data: v.clone() })
        }

        // Pay-to-Multi-Signature (P2MS)
        [Opcode::PushValue(PushValue::SmallValue(required)), pubkeys @ .., Opcode::PushValue(PushValue::SmallValue(keys)), op::CHECKMULTISIG] =>
        {
            let required = script::PubKey::decode_op_n(*required);
            let keys = script::PubKey::decode_op_n(*keys);

            // The remaining opcodes must be `PushData`s that are valid lengths for pubkeys.
            let pubkeys = pubkeys
                .iter()
                .map(|op| match op {
                    Opcode::PushValue(data) => data.value().filter(|data| {
                        // Equivalent to `CPubKey::GetLen`
                        let expected_len = match data.first() {
                            Some(2 | 3) => crate::external::pubkey::PubKey::COMPRESSED_SIZE,
                            Some(4 | 6 | 7) => crate::external::pubkey::PubKey::SIZE,
                            _ => 0,
                        };
                        // Equivalent to `CPubKey::ValidSize`
                        !data.is_empty() && expected_len == data.len()
                    }),
                    _ => None,
                })
                .collect::<Option<Vec<_>>>();

            pubkeys.and_then(|pubkeys| {
                (pubkeys.len() == usize::from(keys) && required <= keys)
                    .then_some(ScriptKind::MultiSig { required, pubkeys })
            })
        }

        // Non-standard
        _ => None,
    }
}

/// Known kinds of standard scripts.
pub enum ScriptKind {
    /// A P2PKH script.
    PubKeyHash { hash: [u8; 20] },
    /// A P2SH script, used in transaction outputs to efficiently commit to other scripts.
    ScriptHash { hash: [u8; 20] },
    /// A transparent threshold multisig script.
    MultiSig { required: u8, pubkeys: Vec<Vec<u8>> },
    /// An unspendable `OP_RETURN` script that carries data.
    NullData,
    /// A legacy P2PK script.
    PubKey { data: Vec<u8> },
}
