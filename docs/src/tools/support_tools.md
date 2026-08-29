# Support CLI Tools

The `tools/` directory contains CLI utilities for certificate inspection and size profiling.

---

## 1. `sample_dpe_cert`

Generates sample DER-encoded DPE certificates across various derivation depths and cryptographic profiles.

```bash
cargo run --bin sample_dpe_cert -- --profile p384 --depth 3 --out sample_cert.der
```

---

## 2. `cert_size`

Measures maximum DER certificate and CSR sizes across cryptographic profiles to assist in sizing firmware buffer allocations.

```bash
cargo run --bin cert_size
```
