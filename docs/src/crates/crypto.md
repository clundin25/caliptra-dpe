# `caliptra-dpe-crypto` (Crypto Driver)

The `caliptra-dpe-crypto` crate provides cryptographic abstraction traits and standard software/hardware implementations.

---

## The `Crypto` Trait

The core interface defining required cryptographic capabilities:

```rust
pub trait Crypto {
    type Cdi;
    type PrivKey;
    type PubKey;
    type Signature;

    fn derive_cdi(&mut self, parent_cdi: &Self::Cdi, tcb: &[u8]) -> Result<Self::Cdi, DpeErrorCode>;
    fn derive_key_pair(&mut self, cdi: &Self::Cdi, label: &[u8]) -> Result<(Self::PrivKey, Self::PubKey), DpeErrorCode>;
    fn sign(&mut self, priv_key: &Self::PrivKey, digest: &[u8]) -> Result<Self::Signature, DpeErrorCode>;
    fn hash(&mut self, data: &[u8], digest: &mut [u8]) -> Result<(), DpeErrorCode>;
    fn trng(&mut self, dst: &mut [u8]) -> Result<(), DpeErrorCode>;
}
```

---

## Software Fallback (`RustCrypto`)

For testing, emulation, and simulator targets, `caliptra-dpe-crypto` provides a pure-software backend using open-source Rust cryptography libraries:
- `p256` / `p384` for elliptic curve operations.
- `sha2` for cryptographic hashing.
- `hkdf` and `hmac` for key derivation.
- `ml-dsa` for post-quantum lattice signatures.
