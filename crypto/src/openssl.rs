// Licensed under the Apache-2.0 license

use crate::{
    hkdf::*, Algorithm, Crypto, CryptoBuf, CryptoError, Digest, EcdsaAlgorithm, EcdsaCurveParams,
    EcdsaPub256, EcdsaPub384, EcdsaPubKey, ExportedCdiHandle, ExportedPubKey, Hasher, Signature,
    MAX_EXPORTED_CDI_SIZE,
};
#[cfg(not(feature = "no-cfi"))]
use caliptra_cfi_derive_git::cfi_impl_fn;
use openssl::{
    bn::{BigNum, BigNumContext},
    ec::{EcGroup, EcKey, EcPoint},
    ecdsa::EcdsaSig,
    error::ErrorStack,
    hash::MessageDigest,
    nid::Nid,
    pkey::Private,
};
#[cfg(feature = "deterministic_rand")]
use rand::{rngs::StdRng, RngCore, SeedableRng};

impl From<ErrorStack> for CryptoError {
    fn from(e: ErrorStack) -> Self {
        // Just return the top error on the stack
        let s = e.errors();
        let e_code = if !s.is_empty() {
            s[0].code().try_into().unwrap_or(0u32)
        } else {
            0u32
        };

        CryptoError::CryptoLibError(e_code)
    }
}

pub struct OpensslHasher(openssl::hash::Hasher);

impl Hasher for OpensslHasher {
    fn update(&mut self, bytes: &[u8]) -> Result<(), CryptoError> {
        Ok(self.0.update(bytes)?)
    }

    fn finish(mut self) -> Result<Digest, CryptoError> {
        Digest::new(&self.0.finish()?)
    }
}

// Currently only supports one CDI handle but in the future we may want to support multiple.
const MAX_CDI_HANDLES: usize = 1;

#[cfg(feature = "deterministic_rand")]
pub struct OpensslCrypto {
    rng: StdRng,
    export_cdi_slots: Vec<(<OpensslCrypto as Crypto>::Cdi, ExportedCdiHandle)>,
}

#[cfg(not(feature = "deterministic_rand"))]
pub struct OpensslCrypto {
    export_cdi_slots: Vec<(<OpensslCrypto as Crypto>::Cdi, ExportedCdiHandle)>,
}

impl OpensslCrypto {
    #[cfg(feature = "deterministic_rand")]
    pub fn new() -> Self {
        const SEED: [u8; 32] = [1; 32];
        let seeded_rng = StdRng::from_seed(SEED);
        Self {
            rng: seeded_rng,
            export_cdi_slots: Vec::new(),
        }
    }

    #[cfg(not(feature = "deterministic_rand"))]
    pub fn new() -> Self {
        Self {
            export_cdi_slots: Vec::new(),
        }
    }

    fn get_digest(algs: Algorithm) -> MessageDigest {
        match algs {
            Algorithm::Ecdsa(EcdsaAlgorithm::Bit256) => MessageDigest::sha256(),
            Algorithm::Ecdsa(EcdsaAlgorithm::Bit384) => MessageDigest::sha384(),
            #[cfg(feature = "ml-dsa")]
            Algorithm::MlDsa(_) => unimplemented!("This module does not yet support ML-DSA!"),
        }
    }

    fn get_curve(algs: Algorithm) -> Nid {
        match algs {
            Algorithm::Ecdsa(EcdsaAlgorithm::Bit256) => Nid::X9_62_PRIME256V1,
            Algorithm::Ecdsa(EcdsaAlgorithm::Bit384) => Nid::SECP384R1,
            #[cfg(feature = "ml-dsa")]
            Algorithm::MlDsa(_) => panic!("ML-DSA does not use EC curves!"),
        }
    }

    fn ec_key_from_priv_key(
        algs: Algorithm,
        priv_key: &OpensslPrivKey,
    ) -> Result<EcKey<Private>, ErrorStack> {
        let nid = Self::get_curve(algs);
        let group = EcGroup::from_curve_name(nid).unwrap();

        let mut pub_point = EcPoint::new(&group).unwrap();
        let bn_ctx = BigNumContext::new().unwrap();
        let priv_key_bn = &BigNum::from_slice(priv_key.bytes()).unwrap();
        pub_point
            .mul_generator(&group, priv_key_bn, &bn_ctx)
            .unwrap();

        EcKey::from_private_components(&group, priv_key_bn, &pub_point)
    }

    fn derive_key_pair_inner(
        &mut self,
        algs: Algorithm,
        cdi: &<OpensslCrypto as Crypto>::Cdi,
        label: &[u8],
        info: &[u8],
    ) -> Result<
        (
            <OpensslCrypto as Crypto>::PrivKey,
            <OpensslCrypto as Crypto>::PubKey,
        ),
        CryptoError,
    > {
        let priv_key = hkdf_get_priv_key(algs, cdi, label, info)?;

        let ec_priv_key = OpensslCrypto::ec_key_from_priv_key(algs, &priv_key)?;
        let nid = OpensslCrypto::get_curve(algs);

        let group = EcGroup::from_curve_name(nid).unwrap();
        let mut bn_ctx = BigNumContext::new().unwrap();

        let mut x = BigNum::new().unwrap();
        let mut y = BigNum::new().unwrap();

        ec_priv_key
            .public_key()
            .affine_coordinates(&group, &mut x, &mut y, &mut bn_ctx)
            .unwrap();

        let pub_key = match algs {
            Algorithm::Ecdsa(EcdsaAlgorithm::Bit256) => {
                let x: &[u8; EcdsaPub256::CURVE_SIZE] = &x
                    .to_vec_padded(algs.signature_size() as i32)
                    .unwrap()
                    .try_into()
                    .unwrap();
                let y: &[u8; EcdsaPub256::CURVE_SIZE] = &y
                    .to_vec_padded(algs.signature_size() as i32)
                    .unwrap()
                    .try_into()
                    .unwrap();
                EcdsaPubKey::Ecdsa256(EcdsaPub256::from_slice(x, y)?)
            }
            Algorithm::Ecdsa(EcdsaAlgorithm::Bit384) => {
                let x: &[u8; EcdsaPub384::CURVE_SIZE] = &x
                    .to_vec_padded(algs.signature_size() as i32)
                    .unwrap()
                    .try_into()
                    .unwrap();
                let y: &[u8; EcdsaPub384::CURVE_SIZE] = &y
                    .to_vec_padded(algs.signature_size() as i32)
                    .unwrap()
                    .try_into()
                    .unwrap();
                EcdsaPubKey::Ecdsa384(EcdsaPub384::from_slice(x, y)?)
            }
        };

        Ok((priv_key, ExportedPubKey::Ecdsa(pub_key)))
    }
}

impl Default for OpensslCrypto {
    fn default() -> Self {
        Self::new()
    }
}

type OpensslCdi = Vec<u8>;

type OpensslPrivKey = CryptoBuf;
type OpensslPubKey = ExportedPubKey;

impl Crypto for OpensslCrypto {
    type Cdi = OpensslCdi;
    type Hasher<'c>
        = OpensslHasher
    where
        Self: 'c;
    type PrivKey = OpensslPrivKey;
    type PubKey = OpensslPubKey;

    #[cfg(feature = "deterministic_rand")]
    fn rand_bytes(&mut self, dst: &mut [u8]) -> Result<(), CryptoError> {
        StdRng::fill_bytes(&mut self.rng, dst);
        Ok(())
    }

    #[cfg(not(feature = "deterministic_rand"))]
    fn rand_bytes(&mut self, dst: &mut [u8]) -> Result<(), CryptoError> {
        Ok(openssl::rand::rand_bytes(dst)?)
    }

    fn hash_initialize(&mut self, algs: Algorithm) -> Result<Self::Hasher<'_>, CryptoError> {
        let md = Self::get_digest(algs);
        Ok(OpensslHasher(openssl::hash::Hasher::new(md)?))
    }

    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    fn derive_cdi(
        &mut self,
        algs: Algorithm,
        measurement: &Digest,
        info: &[u8],
    ) -> Result<Self::Cdi, CryptoError> {
        let cdi = hkdf_derive_cdi(algs, measurement, info)?;
        Ok(cdi)
    }

    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    fn derive_exported_cdi(
        &mut self,
        algs: Algorithm,
        measurement: &Digest,
        info: &[u8],
    ) -> Result<ExportedCdiHandle, CryptoError> {
        let cdi = hkdf_derive_cdi(algs, measurement, info)?;

        for (stored_cdi, _) in self.export_cdi_slots.iter() {
            if *stored_cdi == cdi {
                return Err(CryptoError::ExportedCdiHandleDuplicateCdi);
            }
        }

        if self.export_cdi_slots.len() >= MAX_CDI_HANDLES {
            return Err(CryptoError::ExportedCdiHandleLimitExceeded);
        }

        let mut exported_cdi_handle = [0; MAX_EXPORTED_CDI_SIZE];
        self.rand_bytes(&mut exported_cdi_handle)?;
        self.export_cdi_slots.push((cdi, exported_cdi_handle));
        Ok(exported_cdi_handle)
    }

    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    fn derive_key_pair(
        &mut self,
        algs: Algorithm,
        cdi: &Self::Cdi,
        label: &[u8],
        info: &[u8],
    ) -> Result<(Self::PrivKey, Self::PubKey), CryptoError> {
        self.derive_key_pair_inner(algs, cdi, label, info)
    }

    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    fn derive_key_pair_exported(
        &mut self,
        algs: Algorithm,
        exported_handle: &ExportedCdiHandle,
        label: &[u8],
        info: &[u8],
    ) -> Result<(Self::PrivKey, Self::PubKey), CryptoError> {
        let cdi = {
            let mut cdi = None;
            for (stored_cdi, stored_handle) in self.export_cdi_slots.iter() {
                if stored_handle == exported_handle {
                    cdi = Some(stored_cdi.clone());
                }
            }
            cdi.ok_or(CryptoError::InvalidExportedCdiHandle)
        }?;
        self.derive_key_pair_inner(algs, &cdi, label, info)
    }

    fn sign_with_alias(
        &mut self,
        algs: Algorithm,
        digest: &Digest,
    ) -> Result<Signature, CryptoError> {
        match algs {
            Algorithm::Ecdsa(curve) => {
                let ec_priv: EcKey<Private> =
                    match curve {
                        EcdsaAlgorithm::Bit256 => EcKey::private_key_from_pem(include_bytes!(
                            concat!(env!("OUT_DIR"), "/alias_priv_256.pem")
                        ))
                        .unwrap(),
                        EcdsaAlgorithm::Bit384 => EcKey::private_key_from_pem(include_bytes!(
                            concat!(env!("OUT_DIR"), "/alias_priv_384.pem")
                        ))
                        .unwrap(),
                    };

                let sig = EcdsaSig::sign::<Private>(digest.bytes(), &ec_priv)?;

                let r = CryptoBuf::new(&sig.r().to_vec_padded(curve.curve_size() as i32).unwrap())
                    .unwrap();
                let s = CryptoBuf::new(&sig.s().to_vec_padded(curve.curve_size() as i32).unwrap())
                    .unwrap();

                Ok(Signature::Ecdsa(super::EcdsaSig { r, s }))
            }
            #[cfg(feature = "ml-dsa")]
            Algorithm::MlDsa(_) => {
                unimplemented!("This module does not yet support ML-DSA!");
            }
        }
    }

    fn sign_with_derived(
        &mut self,
        algs: Algorithm,
        digest: &Digest,
        priv_key: &Self::PrivKey,
        _pub_key: &Self::PubKey,
    ) -> Result<Signature, CryptoError> {
        match algs {
            Algorithm::Ecdsa(curve) => {
                let ec_priv_key = OpensslCrypto::ec_key_from_priv_key(algs, priv_key)?;
                let sig = EcdsaSig::sign::<Private>(digest.bytes(), &ec_priv_key).unwrap();

                let r = CryptoBuf::new(&sig.r().to_vec_padded(curve.curve_size() as i32).unwrap())
                    .unwrap();
                let s = CryptoBuf::new(&sig.s().to_vec_padded(curve.curve_size() as i32).unwrap())
                    .unwrap();

                Ok(Signature::Ecdsa(super::EcdsaSig { r, s }))
            }
            #[cfg(feature = "ml-dsa")]
            Algorithm::MlDsa(_) => {
                unimplemented!("This module does not yet support ML-DSA!");
            }
        }
    }

    fn export_public_key(&self, pub_key: &Self::PubKey) -> Result<ExportedPubKey, CryptoError> {
        Ok(pub_key.clone())
    }
}
