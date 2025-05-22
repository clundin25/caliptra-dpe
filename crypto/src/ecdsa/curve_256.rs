// Licensed under the Apache-2.0 license

use super::*;

/// Marker type to statically check conversions.
#[derive(Clone)]
pub struct Curve256;
const CURVE_SIZE: usize = 256 / 8;

pub type EcdsaPub256 = EcdsaPub<CURVE_SIZE>;
pub type EcdsaSignature256 = EcdsaSig<CURVE_SIZE>;
