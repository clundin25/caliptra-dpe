// Licensed under the Apache-2.0 license

use super::*;

/// Marker type to statically check conversions.
#[derive(Clone)]
pub struct Curve384;
const CURVE_SIZE: usize = 384 / 8;

// TODO(clundin): Is there a cleaner way that avoids two generics?
pub type EcdsaPub384 = EcdsaPub<CURVE_SIZE>;
pub type EcdsaSignature384 = EcdsaSig<CURVE_SIZE>;
