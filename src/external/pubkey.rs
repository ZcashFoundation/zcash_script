use secp256k1::{ecdsa, Message, PublicKey, Secp256k1};

/// FIXME: `PUBLIC_KEY_SIZE` is meant to be an upper bound, it seems. Maybe parameterize the type
///        over the size.
pub struct PubKey<'a>(pub &'a [u8]);

impl PubKey<'_> {
    pub const PUBLIC_KEY_SIZE: usize = 65;
    pub const COMPRESSED_PUBLIC_KEY_SIZE: usize = 33;

    /// Check syntactic correctness.
    ///
    /// Note that this is consensus critical as `check_sig` calls it!
    pub fn is_valid(&self) -> bool {
        !self.0.is_empty()
    }

    /// Verify a DER signature (~72 bytes).
    /// If this public key is not fully valid, the return value will be false.
    pub fn verify(&self, hash: &[u8; 32], sig: &ecdsa::Signature) -> bool {
        if !self.is_valid() {
            return false;
        };

        if let Ok(pubkey) = PublicKey::from_slice(self.0) {
            let secp = Secp256k1::verification_only();
            secp.verify_ecdsa(&Message::from_digest(*hash), sig, &pubkey)
                .is_ok()
        } else {
            false
        }
    }

    pub fn check_low_s(sig: &ecdsa::Signature) -> bool {
        let mut check = *sig;
        check.normalize_s();
        *sig == check
    }
}
