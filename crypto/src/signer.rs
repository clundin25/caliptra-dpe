// Licensed under the Apache-2.0 license

use core::marker::PhantomData;

use crate::{Algorithm, CryptoError, EcdsaAlgorithm};
use arrayvec::ArrayVec;
use zeroize::ZeroizeOnDrop;

pub trait EcdsaCurveParams {
    const CURVE_SIZE: usize;
}

/// Marker type to statically check conversions.
#[derive(Clone)]
pub struct Curve256;
impl EcdsaCurveParams for Curve256 {
    const CURVE_SIZE: usize = EcdsaAlgorithm::Bit256.curve_size();
}

#[derive(Clone)]
pub struct Curve384;
impl EcdsaCurveParams for Curve384 {
    const CURVE_SIZE: usize = EcdsaAlgorithm::Bit384.curve_size();
}

// TODO(clundin): Is there a cleaner way that avoids two generics?
pub type EcdsaPub256 = EcdsaPub<{ Curve256::CURVE_SIZE }, Curve256>;
pub type EcdsaPub384 = EcdsaPub<{ Curve384::CURVE_SIZE }, Curve384>;

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

/// An ECDSA signature
pub struct EcdsaSig {
    pub r: CryptoBuf,
    pub s: CryptoBuf,
}

/// A common base struct that can be used for all digests, signatures, and keys.
#[derive(Debug, PartialEq, Eq, ZeroizeOnDrop)]
pub struct CryptoBuf(ArrayVec<u8, { Self::MAX_SIZE }>);

impl Default for CryptoBuf {
    fn default() -> Self {
        let mut vec = ArrayVec::new();
        for _ in 0..Self::MAX_SIZE {
            vec.push(0);
        }
        CryptoBuf(vec)
    }
}

impl CryptoBuf {
    pub const MAX_SIZE: usize = Algorithm::MAX_ALG_LEN_BYTES;

    pub fn new(bytes: &[u8]) -> Result<CryptoBuf, CryptoError> {
        let mut vec = ArrayVec::new();
        vec.try_extend_from_slice(bytes)
            .map_err(|_| CryptoError::Size)?;
        Ok(CryptoBuf(vec))
    }

    pub fn bytes(&self) -> &[u8] {
        self.0.as_slice()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.len() == 0
    }

    /// Writes the hex representation of the CryptoBuf to `dest`
    pub fn write_hex_str(&self, dest: &mut [u8]) -> Result<(), CryptoError> {
        let src = self.bytes();
        if dest.len() != src.len() * 2 {
            return Err(CryptoError::Size);
        }

        let mut curr_idx = 0;
        const HEX_CHARS: &[u8; 16] = b"0123456789ABCDEF";
        for &b in src {
            let h1 = (b >> 4) as usize;
            let h2 = (b & 0xF) as usize;
            if h1 >= HEX_CHARS.len()
                || h2 >= HEX_CHARS.len()
                || curr_idx >= dest.len()
                || curr_idx + 1 >= dest.len()
            {
                return Err(CryptoError::CryptoLibError(0));
            }
            dest[curr_idx] = HEX_CHARS[h1];
            dest[curr_idx + 1] = HEX_CHARS[h2];
            curr_idx += 2;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::EcdsaAlgorithm;

    use super::*;

    #[test]
    fn test_crypto_buf_init() {
        let arr = &[1u8; CryptoBuf::MAX_SIZE + 1];

        // array length must not exceed MAX_SIZE
        assert_eq!(CryptoBuf::new(arr), Err(CryptoError::Size));

        let arr = &[1u8; Algorithm::Ecdsa(EcdsaAlgorithm::Bit256).signature_size()];
        // test new
        match CryptoBuf::new(arr) {
            Ok(buf) => {
                assert_eq!(arr, buf.bytes());
                assert_eq!(
                    buf.len(),
                    Algorithm::Ecdsa(EcdsaAlgorithm::Bit256).signature_size()
                );
            }
            Err(_) => panic!("CryptoBuf::new failed"),
        };

        // test default
        let default_buf = CryptoBuf::default();
        assert_eq!(default_buf.bytes(), [0; CryptoBuf::MAX_SIZE]);
    }
}
