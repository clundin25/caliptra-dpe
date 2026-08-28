# `dice-asn1` (DICE ASN.1 Encoding)

The `dice-asn1` crate implements zero-allocation ASN.1 Distinguished Encoding Rules (DER) serialization specifically tailored for TCG DICE certificates.

---

## Supported Structures

- **`TcbInfo`**: Encodes vendor, model, version, SVN, flags, and firmware ID digest tuples.
- **`MultiTcbInfo`**: Encodes a sequence of `TcbInfo` records within the `2.23.133.5.4.5` OID extension.
- **`Ueid`**: Universal Entity Identifier (`2.23.133.5.4.4`).
- **`SubjectPublicKeyInfo`**: X.509 standard public key wrapper for NIST P-256, NIST P-384, and ML-DSA-87 algorithm identifiers.
- **X.509 Standard Extensions**: Basic Constraints, Key Usage, Extended Key Usage, SKID, and AKID.

---

## Design Principles

- **Zero Allocation**: Encodes DER TLV (Type-Length-Value) tokens directly into a caller-provided byte slice.
- **Memory Bounded**: Computes precise lengths before serialization to prevent out-of-bounds writes.
- **`no_std` Pure Rust**: Fully compatible with bare-metal RISC-V embedded targets.
