// Licensed under the Apache-2.0 license.
#![cfg_attr(not(any(test, target_arch = "x86_64")), no_std)]

use caliptra_dpe_crypto::CryptoError;
use caliptra_dpe_crypto::{ecdsa::EcdsaAlgorithm, SignatureAlgorithm};
use caliptra_dpe_platform::PlatformError;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, TryFromBytes};
use zeroize::Zeroize;

#[derive(
    Copy, Clone, Debug, PartialEq, Eq, IntoBytes, TryFromBytes, KnownLayout, Immutable, Zeroize,
)]
#[repr(u32)]
pub enum DpeProfile {
    P256Sha256 = 3,
    P384Sha384 = 4,
    #[cfg(feature = "ml-dsa")]
    Mldsa87 = 5,
}

impl DpeProfile {
    pub const fn tci_size(&self) -> usize {
        match self {
            DpeProfile::P256Sha256 => 32,
            DpeProfile::P384Sha384 => 48,
            #[cfg(feature = "ml-dsa")]
            DpeProfile::Mldsa87 => 48,
        }
    }
    pub const fn ecc_int_size(&self) -> usize {
        self.tci_size()
    }
    pub const fn hash_size(&self) -> usize {
        self.tci_size()
    }
    pub const fn alg(&self) -> SignatureAlgorithm {
        match self {
            DpeProfile::P256Sha256 => SignatureAlgorithm::Ecdsa(EcdsaAlgorithm::Bit256),
            DpeProfile::P384Sha384 => SignatureAlgorithm::Ecdsa(EcdsaAlgorithm::Bit384),
            #[cfg(feature = "ml-dsa")]
            DpeProfile::Mldsa87 => {
                SignatureAlgorithm::Mldsa(caliptra_dpe_crypto::ml_dsa::MldsaAlgorithm::Mldsa87)
            }
        }
    }
    pub fn key_context(&self) -> &[u8] {
        match self {
            DpeProfile::P256Sha256 | DpeProfile::P384Sha384 => b"ECC",
            #[cfg(feature = "ml-dsa")]
            DpeProfile::Mldsa87 => b"MLDSA",
        }
    }
}

impl From<DpeProfile> for u32 {
    fn from(item: DpeProfile) -> Self {
        item as u32
    }
}

#[cfg(feature = "p256")]
pub const TCI_SIZE: usize = 32;

#[cfg(not(feature = "p256"))]
pub const TCI_SIZE: usize = 48;

#[repr(C, align(4))]
#[derive(
    Default, Copy, Clone, IntoBytes, FromBytes, PartialEq, Eq, KnownLayout, Immutable, Zeroize,
)]
pub struct TciNodeData {
    pub tci_type: u32,
    pub tci_cumulative: TciMeasurement,
    pub tci_current: TciMeasurement,
    pub locality: u32,
    pub svn: u32,
}

impl TciNodeData {
    pub const fn new() -> TciNodeData {
        TciNodeData {
            tci_type: 0,
            tci_cumulative: TciMeasurement([0; TCI_SIZE]),
            tci_current: TciMeasurement([0; TCI_SIZE]),
            locality: 0,
            svn: 0,
        }
    }
}

#[repr(transparent)]
#[derive(
    Copy, Clone, Debug, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq, Zeroize,
)]
pub struct TciMeasurement(pub [u8; TCI_SIZE]);

impl Default for TciMeasurement {
    fn default() -> Self {
        Self([0; TCI_SIZE])
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[repr(u32)]
pub enum DpeErrorCode {
    NoError = 0,
    InternalError = 1,
    InvalidCommand = 2,
    InvalidArgument = 3,
    ArgumentNotSupported = 4,
    X509CsrUnset = 5,
    X509InvalidState = 6,
    X509SkipsExhausted = 7,
    X509InvalidWidth = 8,
    X509AlgorithmMismatch = 9,
    InvalidHandle = 0x1000,
    InvalidLocality = 0x1001,
    MaxTcis = 0x1003,
    InvalidMutRefBuf = 0x1004,
    InvalidResponseBuf = 0x1005,
    UninitializedResponseHeader = 0x1006,
    InvalidParentLocality = 0x85,
    Platform(PlatformError) = 0x01000000,
    Crypto(CryptoError) = 0x02000000,
    Validation(ValidationError) = 0x03000000,
}

impl From<PlatformError> for DpeErrorCode {
    fn from(e: PlatformError) -> Self {
        DpeErrorCode::Platform(e)
    }
}

impl From<CryptoError> for DpeErrorCode {
    fn from(e: CryptoError) -> Self {
        DpeErrorCode::Crypto(e)
    }
}

impl From<ValidationError> for DpeErrorCode {
    fn from(e: ValidationError) -> Self {
        DpeErrorCode::Validation(e)
    }
}

impl DpeErrorCode {
    /// Get the spec-defined numeric error code. This does not include the
    /// extended error information returned from the Platform and Crypto
    /// implementations.
    pub fn discriminant(&self) -> u32 {
        // SAFETY: Because `Self` is marked `repr(u32)`, its layout is a `repr(C)` `union`
        // between `repr(C)` structs, each of which has the `u32` discriminant as its first
        // field, so we can read the discriminant without offsetting the pointer.
        unsafe { *<*const _>::from(self).cast::<u32>() }
    }

    pub fn get_error_code(&self) -> u32 {
        match self {
            DpeErrorCode::Platform(e) => self.discriminant() | e.discriminant() as u32,
            DpeErrorCode::Crypto(e) => self.discriminant() | e.discriminant() as u32,
            DpeErrorCode::Validation(e) => self.discriminant() | e.discriminant() as u32,
            _ => self.discriminant(),
        }
    }

    /// For error variants which have extended error info returned from
    /// underlying libraries (Platform and Crypto), return that extended error
    /// code. For all other variants, return None.
    ///
    /// Reporting of detailed error information is platform-defined.
    pub fn get_error_detail(&self) -> Option<u32> {
        match self {
            DpeErrorCode::Platform(e) => e.get_error_detail(),
            DpeErrorCode::Crypto(e) => e.get_error_detail(),
            _ => None,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[repr(u16)]
pub enum ValidationError {
    MultipleNormalConnectedComponents = 0x0,
    CyclesInTree = 0x1,
    InactiveContextInvalidParent = 0x2,
    InactiveContextWithChildren = 0x3,
    BadContextState = 0x4,
    BadContextType = 0x5,
    InactiveContextWithMeasurement = 0x6,
    MixedContextLocality = 0x7,
    MultipleDefaultContexts = 0x8,
    SimulationNotSupported = 0x9,
    ParentDoesNotExist = 0xA,
    InternalDiceNotSupported = 0xB,
    InternalInfoNotSupported = 0xC,
    ChildDoesNotExist = 0xD,
    InactiveContextWithFlagSet = 0xE,
    LocalityMismatch = 0xF,
    DanglingRetiredContext = 0x10,
    MixedContextTypeConnectedComponents = 0x11,
    ChildWithMultipleParents = 0x12,
    ParentChildLinksCorrupted = 0x13,
    AllowCaNotSupported = 0x14,
    AllowX509NotSupported = 0x15,
    InactiveParent = 0x16,
    InactiveChild = 0x17,
    DpeNotMarkedInitialized = 0x18,
    InvalidMarker = 0x19,
    VersionMismatch = 0x1A,
}

impl ValidationError {
    pub fn discriminant(&self) -> u16 {
        *self as u16
    }
}
