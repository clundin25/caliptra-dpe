// Licensed under the Apache-2.0 license

use super::*;

#[derive(Clone)]
pub struct Curve384;
impl EcdsaCurveParams for Curve384 {
    const CURVE_SIZE: usize = EcdsaAlgorithm::Bit384.curve_size();
}

// TODO(clundin): Is there a cleaner way that avoids two generics?
pub type EcdsaPub384 = EcdsaPub<{ Curve384::CURVE_SIZE }, Curve384>;

