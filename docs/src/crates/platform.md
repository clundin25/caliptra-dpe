# `caliptra-dpe-platform` (Platform Abstraction)

The `caliptra-dpe-platform` crate defines the hardware integration boundaries between the DPE state machine and the host SoC.

---

## The `Platform` Trait

```rust
pub trait Platform {
    fn get_certificate_chain(&self, offset: u32, size: u32, out: &mut [u8]) -> Result<u32, DpeErrorCode>;
    fn get_issuer_name(&self, out: &mut [u8]) -> Result<usize, DpeErrorCode>;
    fn read_persistent_state(&self, out: &mut [u8]) -> Result<(), DpeErrorCode>;
    fn write_persistent_state(&mut self, data: &[u8]) -> Result<(), DpeErrorCode>;
}
```

---

## Key Capabilities

1. **Certificate Chain Provisioning**: Serves the Root CA and Intermediate CA certificates provisioned at device manufacturing time into attestation bundles.
2. **Persistent Storage**: Saves non-volatile context tables and monotonic counters across low-power sleep states or SoC resets.
3. **Issuer Name Configuration**: Provides the canonical X.500 Distinguished Name (DN) of the parent Root-of-Trust issuing authority.
