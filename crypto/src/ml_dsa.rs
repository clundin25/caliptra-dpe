use super::DigestAlgorithm;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

#[derive(Debug, Clone, Copy)]
pub enum MldsaAlgorithm {
    KL87,
}

#[cfg(test)]
impl Default for MldsaAlgorithm {
    fn default() -> Self {
        Self::KL87
    }
}

impl MldsaAlgorithm {
    pub const fn seed_size(self) -> usize {
        match self {
            Self::KL87 => 32,
        }
    }
    pub const fn signature_size(self) -> usize {
        match self {
            Self::KL87 => 4627,
        }
    }
    pub const fn public_key_size(self) -> usize {
        match self {
            Self::KL87 => 2592,
        }
    }
    pub const fn private_key_size(self) -> usize {
        match self {
            Self::KL87 => 4896,
        }
    }
}

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable)]
#[repr(C)]
pub struct ExternalMu(pub [u8; DigestAlgorithm::ExternalMu.size()]);

#[derive(Clone, FromBytes, IntoBytes, KnownLayout, Immutable)]
#[repr(C)]
pub struct MldsaPublicKey(pub [u8; MldsaAlgorithm::KL87.public_key_size()]);

#[derive(Clone, FromBytes, IntoBytes, KnownLayout, Immutable)]
#[repr(C)]
pub struct MldsaSignature(pub [u8; MldsaAlgorithm::KL87.signature_size()]);
