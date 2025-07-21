//! Signature handling.
//!
//! This is in a separate module so we can minimize the code that has access to the internals,
//! making it easier to ensure that we check the encoding correctly.

use secp256k1::ecdsa;
use thiserror::Error;

use crate::external::pubkey::PubKey;

/// Things that can go wrong when constructing a `HashType` from bit flags.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Error)]
pub enum InvalidHashType {
    /// Either or both of the two least-significant bits must be set.
    #[error("unknowned signed outputs")]
    UnknownSignedOutputs,
    /// With v5 transactions, bits other than those specified for `HashType` must be 0. The `i32`
    /// includes only the bits that are undefined by `HashType`.
    #[error("extra bits set")]
    ExtraBitsSet(i32),
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Error)]
pub enum Error {
    // BIP62
    #[error(
        "{}",
        .0.map_or(
            "unknown signature hash type error".to_owned(),
            |iht| format!("signature hash type error: {}", iht)
        )
    )]
    SigHashType(Option<InvalidHashType>),

    #[error("signature DER encoding error")]
    SigDER(Option<secp256k1::Error>),

    #[error("signature s value is too high")]
    SigHighS,
}

/// The ways in which a transparent input may commit to the transparent outputs of its
/// transaction.
///
/// Note that:
/// - Transparent inputs always commit to all shielded outputs.
/// - Shielded inputs always commit to all outputs.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SignedOutputs {
    /// The input signature commits to all transparent outputs in the transaction.
    All,
    /// The transparent input's signature commits to the transparent output at the same
    /// index as the transparent input.
    ///
    /// If the specified transparent output along with any shielded outputs only consume
    /// part of this input, anyone is permitted to modify the transaction to claim the
    /// remainder.
    Single,
    /// The transparent input's signature does not commit to any transparent outputs.
    ///
    /// If the shielded outputs only consume part (or none) of this input, anyone is
    /// permitted to modify the transaction to claim the remainder.
    None,
}

/// The different SigHash types, as defined in <https://zips.z.cash/zip-0143>
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct HashType {
    signed_outputs: SignedOutputs,
    anyone_can_pay: bool,
}

impl HashType {
    /// Construct a `HashType` from bit flags.
    ///
    /// ## Consensus rules
    ///
    /// [§4.10](https://zips.z.cash/protocol/protocol.pdf#sighash):
    /// - Any `HashType` in a v5 transaction must have no undefined bits set.
    pub fn from_bits(bits: i32, is_strict: bool) -> Result<Self, InvalidHashType> {
        let unknown_bits = (bits | 0x83) ^ 0x83;
        if is_strict && unknown_bits != 0 {
            Err(InvalidHashType::ExtraBitsSet(unknown_bits))
        } else {
            let msigned_outputs = match (bits & 2 != 0, bits & 1 != 0) {
                (false, false) => Err(InvalidHashType::UnknownSignedOutputs),
                (false, true) => Ok(SignedOutputs::All),
                (true, false) => Ok(SignedOutputs::None),
                (true, true) => Ok(SignedOutputs::Single),
            };
            msigned_outputs.map(|signed_outputs| HashType {
                signed_outputs,
                anyone_can_pay: bits & 0x80 != 0,
            })
        }
    }

    pub fn signed_outputs(&self) -> SignedOutputs {
        self.signed_outputs
    }

    /// Allows anyone to add transparent inputs to this transaction.
    pub fn anyone_can_pay(&self) -> bool {
        self.anyone_can_pay
    }
}

/// This contains a validated ECDSA signature and the Zcash hash type. It’s an opaque value, so we
/// can ensure all values are valid (e.g., signature is “low-S” if required, and the hash type was
/// created without any extra bits, if required).
#[derive(Clone)]
pub struct Decoded {
    sig: ecdsa::Signature,
    sighash: HashType,
}

impl Decoded {
    /// Checks the properties of individual integers in a DER signature.
    fn is_valid_integer(int_bytes: &[u8]) -> bool {
        match int_bytes {
            // Zero-length integers are not allowed.
            [] => false,
            // Null bytes at the start are not allowed, unless it would otherwise be interpreted as
            // a negative number.
            [0x00, next, ..] => next & 0x80 != 0,
            // Negative numbers are not allowed.
            [first, ..] => first & 0x80 == 0,
        }
    }

    /// A canonical signature consists of: <30> <total len> <02> <len R> <R> <02> <len S> <S>
    ///
    /// Where R and S are not negative (their first byte has its highest bit not set), and not
    /// excessively padded (do not start with a 0 byte, unless an otherwise negative number follows,
    /// in which case a single 0 byte is necessary and even required).
    ///
    /// See https://bitcointalk.org/index.php?topic=8392.msg127623#msg127623
    ///
    /// This function is consensus-critical since BIP66.
    ///
    /// __NB__: This doesn’t rely on [ecdsa::Signature::from_der] because it is consensus critical,
    ///         so we need to ensure that these exact checks happen.
    fn is_valid_encoding(sig: &[u8]) -> bool {
        // Format: 0x30 [total-length] 0x02 [R-length] [R] 0x02 [S-length] [S]
        // * total-length: 1-byte length descriptor of everything that follows
        // * R-length: 1-byte length descriptor of the R value that follows.
        // * R: arbitrary-length big-endian encoded R value. It must use the shortest
        //   possible encoding for a positive integer (which means no null bytes at
        //   the start, except a single one when the next byte has its highest bit set).
        // * S-length: 1-byte length descriptor of the S value that follows.
        // * S: arbitrary-length big-endian encoded S value. The same rules apply.

        // implied checks:
        // - Minimum size constraint.
        // - Verify that the length of the signature matches the sum of the length of the elements.
        match sig {
            // A signature is of type 0x30 (compound).
            [0x30, total_len, content @ ..] => {
                // Maximum size constraint.
                *total_len <= 70
                // Make sure the length covers the entire signature.
                    && usize::from(*total_len) == content.len()
                    && match content {
                        // Check whether the R element is an integer.
                        // Extract the length of the R element.
                        [0x02, r_len, r_s @ ..] => match r_s.split_at((*r_len).into()) {
                            // Check whether the S element is an integer.
                            // Extract the length of the S element.
                            // Make sure the length of the S element is still inside the signature.
                            (r, [0x02, s_len, s @ ..]) => {
                                Self::is_valid_integer(r)
                                    && usize::from(*s_len) == s.len()
                                    && Self::is_valid_integer(s)
                            }
                            ([..], [..]) => false,
                        },
                        [..] => false,
                    }
            }
            [..] => false,
        }
    }

    /// This decodes an ECDSA signature and Zcash hash type from bytes. It ensures that the encoding
    /// was valid.
    ///
    /// __NB__: An empty signature is not strictly DER encoded, but will result in `Ok(None)` as a
    ///         compact way to provide an invalid signature for use with CHECK(MULTI)SIG.
    pub fn from_bytes(
        vch_sig_in: &[u8],
        require_low_s: bool,
        is_strict: bool,
    ) -> Result<Option<Self>, Error> {
        match vch_sig_in.split_last() {
            None => Ok(None),
            Some((hash_type, vch_sig)) => {
                if Self::is_valid_encoding(vch_sig) {
                    HashType::from_bits((*hash_type).into(), is_strict)
                        .map_err(|e| Error::SigHashType(Some(e)))
                        .and_then(|sighash| {
                            match ecdsa::Signature::from_der(vch_sig) {
                                Err(_) => Ok(None),
                                Ok(sig) => {
                                    if require_low_s && !PubKey::check_low_s(&sig) {
                                        Err(Error::SigHighS)
                                    } else {
                                        Ok(Some(sig))
                                    }
                                }
                            }
                            .map(|msig| msig.map(|sig| Decoded { sig, sighash }))
                        })
                } else {
                    Err(Error::SigDER(None))
                }
            }
        }
    }

    pub fn sig(&self) -> &ecdsa::Signature {
        &self.sig
    }

    pub fn sighash(&self) -> &HashType {
        &self.sighash
    }
}
