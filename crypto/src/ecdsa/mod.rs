/*++
Licensed under the Apache-2.0 license.
Abstract:
    Generic trait definition of Cryptographic functions.
--*/

use crate::CryptoError;
use core::marker::PhantomData;
use zeroize::ZeroizeOnDrop;

// TODO(clundin): Filter by feature flag?
pub mod curve_256;
pub mod curve_384;

pub trait EcdsaCurveParams {
    const CURVE_SIZE: usize;
}

#[derive(Debug, Clone, Copy)]
#[cfg_attr(test, derive(strum_macros::EnumIter))]
pub enum EcdsaAlgorithm {
    Bit256,
    Bit384,
}

impl EcdsaAlgorithm {
    pub const fn curve_size(self) -> usize {
        match self {
            EcdsaAlgorithm::Bit256 => 256 / 8,
            EcdsaAlgorithm::Bit384 => 384 / 8,
        }
    }
}

#[derive(Clone)]
pub enum EcdsaPubKey {
    Ecdsa256(curve_256::EcdsaPub256),
    Ecdsa384(curve_384::EcdsaPub384),
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

#[derive(Clone)]
pub struct EcdsaSig<const K: usize, T: EcdsaCurveParams> {
    pub r: [u8; K],
    pub s: [u8; K],
    _alg: PhantomData<T>,
}

#[derive(Clone)]
pub enum EcdsaSignature {
    Ecdsa256(curve_256::EcdsaSignature256),
}

impl EcdsaSignature {
    pub fn as_slice(&self) -> Result<(&[u8], &[u8]), CryptoError> {
        match self {
            Self::Ecdsa256(sig) => {
                let (r, s) = sig.as_slice().unwrap();
                Ok((r.as_slice(), s.as_slice()))
            }
        }
    }

    pub fn curve_size(&self) -> usize {
        match self {
            Self::Ecdsa256(key) => key.curve_size(),
        }
    }
}

/// An ECDSA public key
#[derive(ZeroizeOnDrop, Clone)]
pub struct EcdsaPub<const K: usize, T: EcdsaCurveParams> {
    x: [u8; K],
    y: [u8; K],
    _alg: PhantomData<T>,
}

impl<const K: usize, T: EcdsaCurveParams> Default for EcdsaPub<K, T> {
    fn default() -> Self {
        Self {
            x: [0; K],
            y: [0; K],
            _alg: PhantomData::default(),
        }
    }
}

impl<const K: usize, T: EcdsaCurveParams> EcdsaPub<K, T> {
    pub const CURVE_SIZE: usize = K;
    pub fn from_slice(x: &[u8; K], y: &[u8; K]) -> Result<Self, CryptoError> {
        let mut key = Self::default();
        key.x.clone_from_slice(x);
        key.y.clone_from_slice(y);
        Ok(key)
    }

    pub fn as_slice(&self) -> Result<(&[u8; K], &[u8; K]), CryptoError> {
        Ok((&self.x, &self.y))
    }

    pub const fn curve_size(&self) -> usize {
        K
    }
}

impl<const K: usize, T: EcdsaCurveParams> Default for EcdsaSig<K, T> {
    fn default() -> Self {
        Self {
            r: [0; K],
            s: [0; K],
            _alg: PhantomData::default(),
        }
    }
}

impl<const K: usize, T: EcdsaCurveParams> EcdsaSig<K, T> {
    pub const CURVE_SIZE: usize = K;
    pub fn from_slice(r: &[u8; K], s: &[u8; K]) -> Result<Self, CryptoError> {
        let mut key = Self::default();
        key.r.clone_from_slice(r);
        key.s.clone_from_slice(s);
        Ok(key)
    }

    pub fn as_slice(&self) -> Result<(&[u8; K], &[u8; K]), CryptoError> {
        Ok((&self.r, &self.s))
    }

    pub const fn curve_size(&self) -> usize {
        K
    }
}
