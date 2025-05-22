// Licensed under the Apache-2.0 license

use crate::{
    ecdsa::{
        curve_256::{Curve256, EcdsaPub256, EcdsaSignature256},
        curve_384::{Curve384, EcdsaSignature384},
        EcdsaAlgorithm, EcdsaCurveParams, EcdsaPubKey, EcdsaSignature,
    },
    hkdf::*,
    Crypto, CryptoBuf, CryptoError, Digest, DpeSignatureAlgorithm, ExportedCdiHandle,
    ExportedPubKey, Hasher, Algorithm, MAX_EXPORTED_CDI_SIZE,
};
use core::marker::PhantomData;
use core::ops::Deref;
use ecdsa::{signature::hazmat::PrehashSigner, Signature};
use p256::NistP256;
use p384::NistP384;
use rand::{rngs::StdRng, RngCore, SeedableRng};
use sec1::DecodeEcPrivateKey;
use sha2::{digest::DynDigest, Sha256, Sha384};
use std::boxed::Box;

#[cfg(not(feature = "no-cfi"))]
use caliptra_cfi_derive_git::cfi_impl_fn;

const RUSTCRYPTO_ECDSA_ERROR: CryptoError = CryptoError::CryptoLibError(1);
const RUSTCRYPTO_SEC_ERROR: CryptoError = CryptoError::CryptoLibError(2);

impl From<ecdsa::Error> for CryptoError {
    fn from(_value: ecdsa::Error) -> Self {
        RUSTCRYPTO_ECDSA_ERROR
    }
}

impl From<sec1::Error> for CryptoError {
    fn from(_value: sec1::Error) -> Self {
        RUSTCRYPTO_SEC_ERROR
    }
}

impl TryFrom<Signature<NistP256>> for EcdsaSignature256 {
    type Error = CryptoError;

    fn try_from(value: Signature<NistP256>) -> Result<Self, Self::Error> {
        let mut r = [0; Curve256::CURVE_SIZE];
        let mut s = [0; Curve256::CURVE_SIZE];
        r.clone_from_slice(value.r().deref().to_bytes().as_slice());
        s.clone_from_slice(value.s().deref().to_bytes().as_slice());

        EcdsaSignature256::from_slice(&r, &s)
    }
}
impl TryFrom<Signature<NistP384>> for EcdsaSignature384 {
    type Error = CryptoError;

    fn try_from(value: Signature<NistP384>) -> Result<Self, Self::Error> {
        let mut r = [0; Curve384::CURVE_SIZE];
        let mut s = [0; Curve384::CURVE_SIZE];
        r.clone_from_slice(value.r().deref().to_bytes().as_slice());
        s.clone_from_slice(value.s().deref().to_bytes().as_slice());

        EcdsaSignature384::from_slice(&r, &s)
    }
}

pub struct RustCryptoHasher(Box<dyn DynDigest>);
impl Hasher for RustCryptoHasher {
    fn update(&mut self, bytes: &[u8]) -> Result<(), CryptoError> {
        self.0.update(bytes);
        Ok(())
    }
    fn finish(self) -> Result<Digest, CryptoError> {
        Digest::new(&self.0.finalize())
    }
}

// Currently only supports one CDI handle but in the future we may want to support multiple.
const MAX_CDI_HANDLES: usize = 1;

pub type Ecdsa256RustCrypto = RustCryptoImpl<Curve256>;
impl DpeSignatureAlgorithm for Curve256 {
    const SIGNATURE_ALGORITHM: Algorithm = Algorithm::Ecdsa(EcdsaAlgorithm::Bit256);
}

pub type Ecdsa384RustCrypto = RustCryptoImpl<Curve384>;
impl DpeSignatureAlgorithm for Curve384 {
    const SIGNATURE_ALGORITHM: Algorithm = Algorithm::Ecdsa(EcdsaAlgorithm::Bit384);
}

pub struct RustCryptoImpl<S: DpeSignatureAlgorithm> {
    rng: StdRng,
    export_cdi_slots: Vec<(<RustCryptoImpl<S> as Crypto>::Cdi, ExportedCdiHandle)>,
    _signature_alg: PhantomData<S>,
}

impl<S: DpeSignatureAlgorithm> Default for RustCryptoImpl<S> {
    fn default() -> Self {
        Self::new()
    }
}

impl<S: DpeSignatureAlgorithm> RustCryptoImpl<S> {
    #[cfg(not(feature = "deterministic_rand"))]
    pub fn new() -> Self {
        Self {
            rng: StdRng::from_entropy(),
            export_cdi_slots: Vec::new(),
            _marker: PhantomData::default(),
        }
    }

    #[cfg(feature = "deterministic_rand")]
    pub fn new() -> Self {
        const SEED: [u8; 32] = [1; 32];
        let seeded_rng = StdRng::from_seed(SEED);
        Self {
            rng: seeded_rng,
            export_cdi_slots: Vec::new(),
            _signature_alg: PhantomData::default(),
        }
    }

    fn derive_key_pair_inner(
        &mut self,
        algs: Algorithm,
        cdi: &<RustCryptoImpl<S> as Crypto>::Cdi,
        label: &[u8],
        info: &[u8],
    ) -> Result<
        (
            <RustCryptoImpl<S> as Crypto>::PrivKey,
            <RustCryptoImpl<S> as Crypto>::PubKey,
        ),
        CryptoError,
    > {
        let secret = hkdf_get_priv_key(
            Algorithm::Ecdsa(EcdsaAlgorithm::Bit256),
            cdi,
            label,
            info,
        )?;
        let signing = p256::ecdsa::SigningKey::from_slice(secret.as_slice())?;
        let verifying = p256::ecdsa::VerifyingKey::from(&signing);
        let point = verifying.to_encoded_point(false);
        todo!()
    }
}

pub struct RustCryptoPrivKey(Vec<u8>);

impl<S: DpeSignatureAlgorithm> Crypto for RustCryptoImpl<S> {
    type Cdi = Vec<u8>;
    type Hasher<'c>
        = RustCryptoHasher
    where
        Self: 'c;
    type PrivKey = RustCryptoPrivKey;
    type PubKey = ExportedPubKey;

    fn hash_initialize(&mut self) -> Result<Self::Hasher<'_>, CryptoError> {
        let hasher = match S::SIGNATURE_ALGORITHM {
            Algorithm::Ecdsa(EcdsaAlgorithm::Bit256) => {
                RustCryptoHasher(Box::new(Sha256::default()))
            }
            _ => todo!(),
            //AlgLen::Bit384 => RustCryptoHasher(Box::new(Sha384::default())),
        };
        Ok(hasher)
    }

    fn rand_bytes(&mut self, dst: &mut [u8]) -> Result<(), CryptoError> {
        StdRng::fill_bytes(&mut self.rng, dst);
        Ok(())
    }

    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    fn derive_cdi(&mut self, measurement: &Digest, info: &[u8]) -> Result<Self::Cdi, CryptoError> {
        hkdf_derive_cdi(S::SIGNATURE_ALGORITHM, measurement, info)
    }

    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    fn derive_exported_cdi(
        &mut self,
        measurement: &Digest,
        info: &[u8],
    ) -> Result<ExportedCdiHandle, CryptoError> {
        let cdi = hkdf_derive_cdi(S::SIGNATURE_ALGORITHM, measurement, info)?;

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
        cdi: &Self::Cdi,
        label: &[u8],
        info: &[u8],
    ) -> Result<(Self::PrivKey, Self::PubKey), CryptoError> {
        self.derive_key_pair_inner(S::SIGNATURE_ALGORITHM, cdi, label, info)
    }

    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    fn derive_key_pair_exported(
        &mut self,
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
        self.derive_key_pair_inner(S::SIGNATURE_ALGORITHM, &cdi, label, info)
    }

    fn sign_with_alias(&mut self, digest: &Digest) -> Result<super::Signature, CryptoError> {
        todo!()
        //let sig =
        //    match S::SIGNATURE_ALGORITHM {
        //        SignatureAlgorithm::Ecdsa(EcdsaAlgorithm::Bit256) => {
        //            let signing_key = p256::ecdsa::SigningKey::from_sec1_pem(include_str!(
        //                concat!(env!("OUT_DIR"), "/alias_priv_256.pem")
        //            ))?;
        //            let sig: p256::ecdsa::Signature = signing_key.sign_prehash(digest.bytes())?;
        //            //sig.try_into()
        //            //sig.try_into()
        //            todo!()
        //        }
        //        SignatureAlgorithm::Ecdsa(EcdsaAlgorithm::Bit384) => {
        //            let signing_key = p384::ecdsa::SigningKey::from_sec1_pem(include_str!(
        //                concat!(env!("OUT_DIR"), "/alias_priv_384.pem")
        //            ))?;
        //            let sig: p384::ecdsa::Signature = signing_key.sign_prehash(digest.bytes())?;
        //            //sig.try_into()
        //            todo!()
        //
        //        }
        //    }?;
        //Ok(super::Signature::Ecdsa(sig))
    }

    fn sign_with_derived(
        &mut self,
        digest: &Digest,
        priv_key: &Self::PrivKey,
        _pub_key: &Self::PubKey,
    ) -> Result<super::Signature, CryptoError> {
        todo!()
        //let sig = match S::SIGNATURE_ALGORITHM {
        //    SignatureAlgorithm::Ecdsa(EcdsaAlgorithm::Bit256) => {
        //        let sig: p256::ecdsa::Signature =
        //            p256::ecdsa::SigningKey::from_slice(priv_key.0.as_slice())?
        //                .sign_prehash(digest.bytes())?;
        //        sig.try_into()
        //    }
        //    SignatureAlgorithm::Ecdsa(EcdsaAlgorithm::Bit384) => {
        //        let sig: p384::ecdsa::Signature =
        //            p384::ecdsa::SigningKey::from_slice(priv_key.0.as_slice())?
        //                .sign_prehash(digest.bytes())?;
        //        sig.try_into()
        //    }
        //}?;
        //Ok(super::Signature::Ecdsa(sig))
    }

    fn get_pubkey_serial(
        &mut self,
        pub_key: &ExportedPubKey,
        serial: &mut [u8],
    ) -> Result<(), CryptoError> {
        if serial.len() < S::SIGNATURE_ALGORITHM.digest_size() {
            return Err(CryptoError::Size);
        }

        let mut hasher = self.hash_initialize()?;
        let ExportedPubKey::Ecdsa(pub_key) = pub_key;
        let (x, y) = pub_key.as_slice()?;

        hasher.update(&[0x4u8])?;
        hasher.update(x)?;
        hasher.update(y)?;
        let digest = hasher.finish()?;

        CryptoBuf::write_hex_str(&digest, serial)
    }

    fn export_public_key(
        &self,
        pub_key: &Self::PubKey,
    ) -> Result<crate::ExportedPubKey, CryptoError> {
        Ok(pub_key.clone())
    }
}

