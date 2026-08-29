# Cryptographic Profiles

Caliptra DPE supports multiple cryptographic profiles configured via Cargo feature flags. Each profile determines the asymmetric signature algorithm, key sizes, and hash functions used across all operations.

---

## Supported Profiles

| Profile Name | Cargo Feature | Asymmetric Algorithm | Hash Function | Key Size | TCI Size |
|---|---|---|---|---|---|
| **P-256 (ECC)** | `p256` | ECDSA (NIST P-256 curve) | SHA-256 | 256-bit (32 bytes) | 32 bytes |
| **P-384 (ECC)** | `p384` | ECDSA (NIST P-384 curve) | SHA-384 | 384-bit (48 bytes) | 48 bytes |
| **ML-DSA (PQC)** | `ml-dsa` | ML-DSA-87 (NIST FIPS 204) | SHA-384 | 2592-byte public key | 48 bytes |
| **Hybrid** | `hybrid` | ML-DSA-87 + ECDSA P-384 | SHA-384 | Dual classical + PQC keys | 48 bytes |

---

## Profile Capabilities

### 1. Profile P-256 (`p256`)
- Standard 128-bit classical security level.
- Ultra-compact signatures (64 bytes) and public keys (64 bytes uncompressed).
- Optimized for lightweight embedded environments and constrained bandwidth.

### 2. Profile P-384 (`p384`)
- Standard 192-bit classical security level (CNSA 1.0 compliant).
- Signature size: 96 bytes; Public key: 96 bytes uncompressed.
- Caliptra default hardware cryptographic engine profile.

### 3. Profile ML-DSA-87 (`ml-dsa`)
- NIST Post-Quantum Cryptography (PQC) digital signature standard (Module-Lattice-Based Digital Signature Standard, FIPS 204).
- Category 5 security level (equivalent to AES-256 / SHA-384).
- Quantum-resistant against Shor's algorithm and future quantum computing threats.
- Public key size: 2,592 bytes; Signature size: 4,627 bytes.

### 4. Profile Hybrid (`hybrid`)
- Dual-key attestation combining classical ECDSA P-384 and post-quantum ML-DSA-87.
- Generates composite certificate extensions and signatures ensuring security even if one of the underlying mathematical primitives is compromised.
- Compliant with CNSA 2.0 quantum transition roadmaps.

---

## Profile Constants & Types

In Rust code, profiles define:
```rust
// Defined in caliptra-dpe
pub const TCI_SIZE: usize = /* 32 for p256, 48 for p384/ml-dsa/hybrid */;
pub const DPE_PROFILE: DpeProfile = /* DpeProfile::Ieee8021aHash256, etc. */;
```

The active profile is selected at compile time using `--features=<profile>`.
