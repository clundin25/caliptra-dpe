// Licensed under the Apache-2.0 license

use super::*;

/// Marker type to statically check conversions.
#[derive(Clone)]
pub struct Curve256;
impl EcdsaCurveParams for Curve256 {
    const CURVE_SIZE: usize = EcdsaAlgorithm::Bit256.curve_size();
}

pub type EcdsaPub256 = EcdsaPub<{ Curve256::CURVE_SIZE }, Curve256>;
