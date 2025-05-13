/*++
Licensed under the Apache-2.0 license.
Abstract:
    Generic trait definition of Cryptographic functions.
--*/
#![cfg_attr(not(any(feature = "openssl", feature = "rustcrypto", test)), no_std)]

#[cfg(feature = "openssl")]
pub use crate::openssl::*;
pub use signer::*;

#[cfg(feature = "rustcrypto")]
pub use crate::rustcrypto::*;

#[cfg(feature = "openssl")]
pub mod openssl;

#[cfg(feature = "rustcrypto")]
pub mod rustcrypto;

#[cfg(feature = "deterministic_rand")]
pub use rand::*;

#[cfg(any(feature = "openssl", feature = "rustcrypto"))]
mod hkdf;
mod signer;

pub const MAX_EXPORTED_CDI_SIZE: usize = 32;
pub type ExportedCdiHandle = [u8; MAX_EXPORTED_CDI_SIZE];

#[derive(Debug, Clone, Copy)]
#[cfg_attr(test, derive(strum_macros::EnumIter))]
pub enum EcdsaAlgorithm {
    Bit256,
    Bit384,
}

pub trait DpeProfile {
    const SIGNATURE_ALGORITHM: SignatureAlgorithm;
}

#[cfg(test)]
impl Default for EcdsaAlgorithm {
    fn default() -> Self {
        Self::Bit384
    }
}

impl EcdsaAlgorithm {
    const fn curve_size(self) -> usize {
        match self {
            EcdsaAlgorithm::Bit256 => 256 / 8,
            EcdsaAlgorithm::Bit384 => 384 / 8,
        }
    }
}

#[derive(Debug, Clone, Copy)]
#[cfg_attr(test, derive(strum_macros::EnumIter))]
#[cfg(feature = "ml-dsa")]
pub enum MldsaAlgorithm {
    KL87,
}

#[cfg(all(test, feature = "ml-dsa"))]
impl Default for MldsaAlgorithm {
    fn default() -> Self {
        Self::KL87
    }
}

#[cfg(feature = "ml-dsa")]
impl MldsaAlgorithm {
    const fn xi_size(self) -> usize {
        match self {
            MldsaAlgorithm::KL87 => 32,
        }
    }
}
#[derive(Debug, Clone, Copy)]
#[cfg_attr(test, derive(strum_macros::EnumIter))]
pub enum SignatureAlgorithm {
    Ecdsa(EcdsaAlgorithm),
    #[cfg(feature = "ml-dsa")]
    MlDsa(MldsaAlgorithm),
    // NOTE: If a larger length is added, MUST update Algorithm::MAX_ALG_LEN
}

impl SignatureAlgorithm {
    #[cfg(feature = "ml-dsa")]
    const MAX_ALG_LEN: Self = Self::MlDsa(MldsaAlgorithm::KL87);
    #[cfg(feature = "ml-dsa")]
    // The ML-DSA private key will be the largest item.
    pub(crate) const MAX_ALG_LEN_BYTES: usize = Self::MAX_ALG_LEN.private_key_size();

    #[cfg(not(feature = "ml-dsa"))]
    const MAX_ALG_LEN: Self = Self::Ecdsa(EcdsaAlgorithm::Bit384);
    #[cfg(not(feature = "ml-dsa"))]
    // When ML-DSA is not enabled, the largest item in the set of (private key, public key, and
    // signature) is the signature.
    pub(crate) const MAX_ALG_LEN_BYTES: usize = Self::MAX_ALG_LEN.signature_size();

    pub const fn digest_size(self) -> usize {
        match self {
            SignatureAlgorithm::Ecdsa(ec) => ec.curve_size(),
            #[cfg(feature = "ml-dsa")]
            // TODO(clundin): Need to figure out what digest size is appropriate.
            SignatureAlgorithm::MlDsa(MldsaAlgorithm::KL87) => 32,
        }
    }

    pub const fn signature_size(self) -> usize {
        match self {
            SignatureAlgorithm::Ecdsa(ec) => ec.curve_size() * 2,
            #[cfg(feature = "ml-dsa")]
            SignatureAlgorithm::MlDsa(MldsaAlgorithm::KL87) => 4627,
        }
    }
    pub const fn public_key_size(self) -> usize {
        match self {
            SignatureAlgorithm::Ecdsa(ec) => ec.curve_size(),
            #[cfg(feature = "ml-dsa")]
            SignatureAlgorithm::MlDsa(MldsaAlgorithm::KL87) => 2592,
        }
    }
    pub const fn private_key_size(self) -> usize {
        match self {
            SignatureAlgorithm::Ecdsa(ec) => ec.curve_size(),
            #[cfg(feature = "ml-dsa")]
            SignatureAlgorithm::MlDsa(MldsaAlgorithm::KL87) => 4896,
        }
    }
}

// For errors which come from lower layers, include the error code returned
// from platform libraries.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[repr(u16)]
pub enum CryptoError {
    AbstractionLayer(u32) = 0x1,
    CryptoLibError(u32) = 0x2,
    Size = 0x3,
    NotImplemented = 0x4,
    HashError(u32) = 0x5,
    InvalidExportedCdiHandle = 0x6,
    ExportedCdiHandleDuplicateCdi = 0x7,
    ExportedCdiHandleLimitExceeded = 0x8,
}

impl CryptoError {
    pub fn discriminant(&self) -> u16 {
        // SAFETY: Because `Self` is marked `repr(u16)`, its layout is a `repr(C)` `union`
        // between `repr(C)` structs, each of which has the `u16` discriminant as its first
        // field, so we can read the discriminant without offsetting the pointer.
        unsafe { *<*const _>::from(self).cast::<u16>() }
    }

    pub fn get_error_detail(&self) -> Option<u32> {
        match self {
            CryptoError::AbstractionLayer(code)
            | CryptoError::CryptoLibError(code)
            | CryptoError::HashError(code) => Some(*code),
            CryptoError::Size
            | CryptoError::InvalidExportedCdiHandle
            | CryptoError::ExportedCdiHandleLimitExceeded
            | CryptoError::ExportedCdiHandleDuplicateCdi
            | CryptoError::NotImplemented => None,
        }
    }
}

pub trait Hasher: Sized {
    /// Adds a chunk to the running hash.
    ///
    /// # Arguments
    ///
    /// * `bytes` - Value to add to hash.
    fn update(&mut self, bytes: &[u8]) -> Result<(), CryptoError>;

    /// Finish a running hash operation and return the result.
    ///
    /// Once this function has been called, the object can no longer be used and
    /// a new one must be created to hash more data.
    fn finish(self) -> Result<Digest, CryptoError>;
}

pub type Digest = CryptoBuf;

#[derive(Clone)]
pub enum ExportedPubKey {
    Ecdsa(EcdsaPubKey),
}

#[derive(Clone)]
pub enum EcdsaPubKey {
    Ecdsa256(EcdsaPub256),
    Ecdsa384(EcdsaPub384),
}

impl EcdsaPubKey {
    pub fn as_slice(&self) -> Result<(&[u8], &[u8]), CryptoError> {
        match self {
            Self::Ecdsa256(key) => {
                let (x, y) = key.as_slice().unwrap();
                Ok((x.as_slice(), y.as_slice()))
            }
            Self::Ecdsa384(key) => {
                let (x, y) = key.as_slice().unwrap();
                Ok((x.as_slice(), y.as_slice()))
            }
        }
    }

    pub fn curve_size(&self) -> usize {
        match self {
            Self::Ecdsa256(key) => key.curve_size(),
            Self::Ecdsa384(key) => key.curve_size(),
        }
    }
}

pub enum Signature {
    Ecdsa(EcdsaSig),
}

pub trait Crypto: DpeProfile {
    type Cdi;
    type Hasher<'c>: Hasher
    where
        Self: 'c;
    type PrivKey;
    type PubKey;

    /// Fills the buffer with random values.
    ///
    /// # Arguments
    ///
    /// * `dst` - The buffer to be filled.
    fn rand_bytes(&mut self, dst: &mut [u8]) -> Result<(), CryptoError>;

    /// Cryptographically hashes the given buffer.
    ///
    /// # Arguments
    ///
    /// * `algs` - Which length of algorithm to use.
    /// * `bytes` - Value to be hashed.
    fn hash(&mut self, bytes: &[u8]) -> Result<Digest, CryptoError> {
        let mut hasher = self.hash_initialize()?;
        hasher.update(bytes)?;
        hasher.finish()
    }

    /// Compute the serial number of an ECDSA public key by computing the hash
    /// over the point in uncompressed format.
    ///
    /// This function outputs the serial number as a hex string
    ///
    /// # Arguments
    ///
    /// * `algs` - Length of algorithm to use.
    /// * `pub_key` - EC public key
    /// * `serial` - Output buffer to write serial number
    fn get_pubkey_serial(
        &mut self,
        pub_key: &ExportedPubKey,
        serial: &mut [u8],
    ) -> Result<(), CryptoError>;

    /// Initialize a running hash. Returns an object that will be able to complete the rest.
    ///
    /// Used for hashing multiple buffers that may not be in consecutive memory.
    ///
    /// # Arguments
    ///
    /// * `algs` - Which length of algorithm to use.
    fn hash_initialize(&mut self) -> Result<Self::Hasher<'_>, CryptoError>;

    /// Derive a CDI based on the current base CDI and measurements
    ///
    /// # Arguments
    ///
    /// * `algs` - Which length of algorithms to use.
    /// * `measurement` - A digest of the measurements which should be used for CDI derivation
    /// * `info` - Caller-supplied info string to use in CDI derivation
    fn derive_cdi(&mut self, measurement: &Digest, info: &[u8]) -> Result<Self::Cdi, CryptoError>;

    /// Derive a CDI for an exported private key based on the current base CDI and measurements
    ///
    /// # Arguments
    ///
    /// * `algs` - Which length of algorithms to use.
    /// * `measurement` - A digest of the measurements which should be used for CDI derivation
    /// * `info` - Caller-supplied info string to use in CDI derivation
    fn derive_exported_cdi(
        &mut self,
        measurement: &Digest,
        info: &[u8],
    ) -> Result<ExportedCdiHandle, CryptoError>;

    /// CFI wrapper around derive_cdi
    ///
    /// To implement this function, you need to add the
    /// cfi_impl_fn proc_macro to derive_cdi.
    #[cfg(not(feature = "no-cfi"))]
    fn __cfi_derive_cdi(
        &mut self,
        measurement: &Digest,
        info: &[u8],
    ) -> Result<Self::Cdi, CryptoError>;

    /// CFI wrapper around derive_cdi_exported
    ///
    /// To implement this function, you need to add the
    /// cfi_impl_fn proc_macro to derive_exported_cdi.
    #[cfg(not(feature = "no-cfi"))]
    fn __cfi_derive_exported_cdi(
        &mut self,
        measurement: &Digest,
        info: &[u8],
    ) -> Result<ExportedCdiHandle, CryptoError>;

    /// Derives a key pair using a cryptographically secure KDF
    ///
    /// # Arguments
    ///
    /// * `algs` - Which length of algorithms to use.
    /// * `cdi` - Caller-supplied private key to use in public key derivation
    /// * `label` - Caller-supplied label to use in asymmetric key derivation
    /// * `info` - Caller-supplied info string to use in asymmetric key derivation
    ///
    fn derive_key_pair(
        &mut self,
        cdi: &Self::Cdi,
        label: &[u8],
        info: &[u8],
    ) -> Result<(Self::PrivKey, Self::PubKey), CryptoError>;

    /// Derives an exported key pair using a cryptographically secure KDF
    ///
    /// # Arguments
    ///
    /// * `algs` - Which length of algorithms to use.
    /// * `exported_handle` - The handle associated with an existing CDI. Created by
    ///   `derive_cdi_exported`
    /// * `label` - Caller-supplied label to use in asymmetric key derivation
    /// * `info` - Caller-supplied info string to use in asymmetric key derivation
    ///
    fn derive_key_pair_exported(
        &mut self,
        exported_handle: &ExportedCdiHandle,
        label: &[u8],
        info: &[u8],
    ) -> Result<(Self::PrivKey, Self::PubKey), CryptoError>;

    /// CFI wrapper around derive_key_pair
    ///
    /// To implement this function, you need to add the
    /// cfi_impl_fn proc_macro to derive_key_pair.
    #[cfg(not(feature = "no-cfi"))]
    fn __cfi_derive_key_pair(
        &mut self,
        cdi: &Self::Cdi,
        label: &[u8],
        info: &[u8],
    ) -> Result<(Self::PrivKey, Self::PubKey), CryptoError>;

    /// CFI wrapper around derive_key_pair_exported
    ///
    /// To implement this function, you need to add the
    /// cfi_impl_fn proc_macro to derive_key_pair.
    #[cfg(not(feature = "no-cfi"))]
    fn __cfi_derive_key_pair_exported(
        &mut self,
        exported_handle: &ExportedCdiHandle,
        label: &[u8],
        info: &[u8],
    ) -> Result<(Self::PrivKey, Self::PubKey), CryptoError>;

    /// Sign `digest` with the platform Alias Key
    ///
    /// # Arguments
    ///
    /// * `algs` - Which length of algorithms to use.
    /// * `digest` - Digest of data to be signed.
    fn sign_with_alias(&mut self, digest: &Digest) -> Result<Signature, CryptoError>;

    /// Sign `digest` with a derived key-pair from the CDI and caller-supplied private key
    ///
    /// # Arguments
    ///
    /// * `algs` - Which length of algorithms to use.
    /// * `digest` - Digest of data to be signed.
    /// * `priv_key` - Caller-supplied private key to use in public key derivation
    /// * `pub_key` - The public key corresponding to `priv_key`. An implementation may
    ///    optionally use pub_key to validate any generated signatures.
    fn sign_with_derived(
        &mut self,
        digest: &Digest,
        priv_key: &Self::PrivKey,
        pub_key: &Self::PubKey,
    ) -> Result<Signature, CryptoError>;

    /// Converts the internel `PubKey` into a `CryptoBuf` based struct.
    ///
    /// # Arguments
    ///
    /// * `pub_key` - The public key previously created in a derivation.
    fn export_public_key(&self, pub_key: &Self::PubKey) -> Result<ExportedPubKey, CryptoError>;
}
#[cfg(test)]
mod tests {
    use super::*;
    use strum::IntoEnumIterator;

    #[test]
    fn test_max_alg_len_size() {
        let max_len = SignatureAlgorithm::iter()
            .map(|x| {
                [
                    x.private_key_size(),
                    x.public_key_size(),
                    x.signature_size(),
                ]
                .into_iter()
                .max()
                .unwrap()
            })
            .max()
            .unwrap();
        assert_eq!(SignatureAlgorithm::MAX_ALG_LEN_BYTES, max_len);
    }
}
