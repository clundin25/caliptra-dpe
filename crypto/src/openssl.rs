// Licensed under the Apache-2.0 license

use core::marker::PhantomData;

use crate::{
    ecdsa::{
        curve_256::{Curve256, EcdsaPub256},
        *,
    },
    hkdf::*,
    Crypto, CryptoBuf, CryptoError, Digest, DpeProfile, ExportedCdiHandle, ExportedPubKey, Hasher,
    Signature, SignatureAlgorithm, MAX_EXPORTED_CDI_SIZE,
};
#[cfg(not(feature = "no-cfi"))]
use caliptra_cfi_derive_git::cfi_impl_fn;
use curve_256::EcdsaSignature256;
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
pub struct OpensslCrypto<T> {
    rng: StdRng,
    export_cdi_slots: Vec<(<OpensslCrypto<T> as Crypto>::Cdi, ExportedCdiHandle)>,
    _sig_alg: PhantomData<T>,
}

#[cfg(not(feature = "deterministic_rand"))]
pub struct OpensslCrypto<T> {
    export_cdi_slots: Vec<(<OpensslCrypto<T> as Crypto>::Cdi, ExportedCdiHandle)>,
    _sig_alg: PhantomData<T>,
}

impl<Curve256> DpeProfile for OpensslCrypto<Curve256> {
    const SIGNATURE_ALGORITHM: SignatureAlgorithm =
        SignatureAlgorithm::Ecdsa(EcdsaAlgorithm::Bit256);
}

impl<Curve256> OpensslCrypto<Curve256> {
    #[cfg(feature = "deterministic_rand")]
    pub fn new() -> Self {
        const SEED: [u8; 32] = [1; 32];
        let seeded_rng = StdRng::from_seed(SEED);
        Self {
            rng: seeded_rng,
            export_cdi_slots: Vec::new(),
            _sig_alg: PhantomData::default(),
        }
    }

    #[cfg(not(feature = "deterministic_rand"))]
    pub fn new() -> Self {
        Self {
            export_cdi_slots: Vec::new(),
            _sig_alg: PhantomData::default(),
        }
    }

    fn get_digest() -> MessageDigest {
        MessageDigest::sha256()
    }

    fn get_curve() -> Nid {
        Nid::X9_62_PRIME256V1
    }

    fn ec_key_from_priv_key(priv_key: &OpensslPrivKey) -> Result<EcKey<Private>, ErrorStack> {
        let nid = Self::get_curve();
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
        cdi: &<OpensslCrypto<Curve256> as Crypto>::Cdi,
        label: &[u8],
        info: &[u8],
    ) -> Result<
        (
            <OpensslCrypto<Curve256> as Crypto>::PrivKey,
            <OpensslCrypto<Curve256> as Crypto>::PubKey,
        ),
        CryptoError,
    > {
        let priv_key = hkdf_get_priv_key(
            SignatureAlgorithm::Ecdsa(EcdsaAlgorithm::Bit256),
            cdi,
            label,
            info,
        )?;

        let ec_priv_key = <OpensslCrypto<Curve256>>::ec_key_from_priv_key(&priv_key)?;
        let nid = <OpensslCrypto<Curve256>>::get_curve();

        let group = EcGroup::from_curve_name(nid).unwrap();
        let mut bn_ctx = BigNumContext::new().unwrap();

        let mut x = BigNum::new().unwrap();
        let mut y = BigNum::new().unwrap();

        ec_priv_key
            .public_key()
            .affine_coordinates(&group, &mut x, &mut y, &mut bn_ctx)
            .unwrap();

        let pub_key = {
            let x: &[u8; EcdsaPub256::CURVE_SIZE] = &x
                .to_vec_padded(EcdsaPub256::CURVE_SIZE as i32)
                .unwrap()
                .try_into()
                .unwrap();
            let y: &[u8; EcdsaPub256::CURVE_SIZE] = &y
                .to_vec_padded(EcdsaPub256::CURVE_SIZE as i32)
                .unwrap()
                .try_into()
                .unwrap();
            EcdsaPubKey::Ecdsa256(EcdsaPub256::from_slice(x, y)?)
        };

        Ok((priv_key, ExportedPubKey::Ecdsa(pub_key)))
    }
}

impl<Curve256> Default for OpensslCrypto<Curve256> {
    fn default() -> Self {
        Self::new()
    }
}

type OpensslCdi = Vec<u8>;

type OpensslPrivKey = CryptoBuf;
type OpensslPubKey = ExportedPubKey;

impl<Curve256> Crypto for OpensslCrypto<Curve256> {
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

    fn get_pubkey_serial(
        &mut self,
        pub_key: &ExportedPubKey,
        serial: &mut [u8],
    ) -> Result<(), CryptoError> {
        if serial.len() < Self::SIGNATURE_ALGORITHM.digest_size() {
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

    #[cfg(not(feature = "deterministic_rand"))]
    fn rand_bytes(&mut self, dst: &mut [u8]) -> Result<(), CryptoError> {
        Ok(openssl::rand::rand_bytes(dst)?)
    }

    fn hash_initialize(&mut self) -> Result<Self::Hasher<'_>, CryptoError> {
        let md = Self::get_digest();
        Ok(OpensslHasher(openssl::hash::Hasher::new(md)?))
    }

    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    fn derive_cdi(&mut self, measurement: &Digest, info: &[u8]) -> Result<Self::Cdi, CryptoError> {
        let cdi = hkdf_derive_cdi(
            SignatureAlgorithm::Ecdsa(EcdsaAlgorithm::Bit256),
            measurement,
            info,
        )?;
        Ok(cdi)
    }

    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    fn derive_exported_cdi(
        &mut self,
        measurement: &Digest,
        info: &[u8],
    ) -> Result<ExportedCdiHandle, CryptoError> {
        let cdi = hkdf_derive_cdi(
            SignatureAlgorithm::Ecdsa(EcdsaAlgorithm::Bit256),
            measurement,
            info,
        )?;

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
        self.derive_key_pair_inner(cdi, label, info)
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
        self.derive_key_pair_inner(&cdi, label, info)
    }

    fn sign_with_alias(&mut self, digest: &Digest) -> Result<Signature, CryptoError> {
        let ec_priv: EcKey<Private> = EcKey::private_key_from_pem(include_bytes!(concat!(
            env!("OUT_DIR"),
            "/alias_priv_256.pem"
        )))
        .unwrap();
        let sig = EcdsaSig::sign::<Private>(digest.bytes(), &ec_priv)?;
        let r: [u8; EcdsaAlgorithm::Bit256.curve_size()] = sig
            .r()
            .to_vec_padded(EcdsaAlgorithm::Bit256.curve_size() as i32)
            .unwrap()
            .try_into()
            .unwrap();
        let s: [u8; EcdsaAlgorithm::Bit256.curve_size()] = sig
            .s()
            .to_vec_padded(EcdsaAlgorithm::Bit256.curve_size() as i32)
            .unwrap()
            .try_into()
            .unwrap();
        Ok(Signature::Ecdsa(EcdsaSignature::Ecdsa256(
            EcdsaSignature256::from_slice(&r, &s).unwrap(),
        )))
    }

    fn sign_with_derived(
        &mut self,
        digest: &Digest,
        priv_key: &Self::PrivKey,
        _pub_key: &Self::PubKey,
    ) -> Result<Signature, CryptoError> {
        let ec_priv_key = <OpensslCrypto<Curve256>>::ec_key_from_priv_key(priv_key)?;
        let sig = EcdsaSig::sign::<Private>(digest.bytes(), &ec_priv_key).unwrap();

        let r: [u8; EcdsaAlgorithm::Bit256.curve_size()] = sig
            .r()
            .to_vec_padded(EcdsaAlgorithm::Bit256.curve_size() as i32)
            .unwrap()
            .try_into()
            .unwrap();
        let s: [u8; EcdsaAlgorithm::Bit256.curve_size()] = sig
            .s()
            .to_vec_padded(EcdsaAlgorithm::Bit256.curve_size() as i32)
            .unwrap()
            .try_into()
            .unwrap();

        Ok(Signature::Ecdsa(EcdsaSignature::Ecdsa256(
            EcdsaSignature256::from_slice(&r, &s).unwrap(),
        )))
    }

    fn export_public_key(&self, pub_key: &Self::PubKey) -> Result<ExportedPubKey, CryptoError> {
        Ok(pub_key.clone())
    }
}
