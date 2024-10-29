use secp256k1::{ecdsa, Message, PublicKey, Secp256k1};

/// FIXME: `PUBLIC_KEY_SIZE` is meant to be an upper bound, it seems. Maybe parameterize the type
///        over the size.
pub struct PubKey<'a>(pub &'a [u8]);

impl PubKey<'_> {
    pub const PUBLIC_KEY_SIZE: usize = 65;
    pub const COMPRESSED_PUBLIC_KEY_SIZE: usize = 33;

    /// Check syntactic correctness.
    ///
    /// Note that this is consensus critical as CheckSig() calls it!
    pub fn is_valid(&self) -> bool {
        !self.0.is_empty()
    }

    /// Verify a DER signature (~72 bytes).
    /// If this public key is not fully valid, the return value will be false.
    pub fn verify(&self, hash: &[u8; 32], vch_sig: &[u8]) -> bool {
        if !self.is_valid() {
            return false;
        };

        if let Ok(pubkey) = PublicKey::from_slice(self.0) {
            // let sig: secp256k1_ecdsa_signature;
            if vch_sig.is_empty() {
                return false;
            };
            // Zcash, unlike Bitcoin, has always enforced strict DER signatures.
            if let Ok(mut sig) = ecdsa::Signature::from_der(vch_sig) {
                // libsecp256k1's ECDSA verification requires lower-S signatures, which have
                // not historically been enforced in Bitcoin or Zcash, so normalize them first.
                sig.normalize_s();
                let secp = Secp256k1::verification_only();
                secp.verify_ecdsa(&Message::from_digest(*hash), &sig, &pubkey)
                    .is_ok()
            } else {
                false
            }
        } else {
            false
        }
    }

    pub fn check_low_s(vch_sig: &[u8]) -> bool {
        /* Zcash, unlike Bitcoin, has always enforced strict DER signatures. */
        if let Ok(sig) = ecdsa::Signature::from_der(vch_sig) {
            let mut check = sig;
            check.normalize_s();
            sig == check
        } else {
            false
        }
    }
}
