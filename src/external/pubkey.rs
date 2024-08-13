use super::uint256::*;

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
        self.0.len() > 0
    }

    /// Verify a DER signature (~72 bytes).
    /// If this public key is not fully valid, the return value will be false.
    pub fn verify(&self, hash: &UInt256, vch_sig: &[u8]) -> bool {
        todo!()
    }
}
