# Python X.509 Certificate Parser

The `verification/cert-parser/` test suite uses Python and industry-standard cryptography libraries (`cryptography`, `pyOpenSSL`, `asn1crypto`) to parse and validate DPE-generated certificates.

---

## Test Coverage

- **X.509 Compliance**: Asserts DER encoding validity, valid validity dates, and standard extension critical flags.
- **TCG DICE Schema Validation**: Decodes `tcg-dice-MultiTcbInfo` extensions and validates that all component measurements match golden hash expectations.
- **Signature Verification**: Verifies cryptographic signatures across certificate chains up to the Root CA.

---

## Running Cert Parser Tests

```bash
cargo xtask test cert-parser
```
