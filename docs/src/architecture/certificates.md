# X.509 Certificates and DICE Extensions

Caliptra DPE contains an embedded, zero-copy X.509 DER serializer (`dice-asn1` and `x509` module) to generate standard X.509 v3 certificates and PKCS#10 Certificate Signing Requests (CSRs).

---

## Certificate Structure

DPE certificates conform to RFC 5280 and the TCG DICE Attestation Architecture:

```
Certificate
├── To Be Signed (TBS) Certificate
│   ├── Version: v3 (2)
│   ├── Serial Number: Unique 20-byte integer derived from key digest
│   ├── Signature Algorithm: ecdsa-with-SHA256 / ecdsa-with-SHA384 / ml-dsa-87
│   ├── Issuer: Distinguished Name (e.g., CN=Caliptra DPE Intermediate CA)
│   ├── Validity: Not Before / Not After
│   ├── Subject: Distinguished Name (e.g., CN=Caliptra DPE Context 0x...)
│   ├── Subject Public Key Info: Context Public Key
│   └── Extensions:
│       ├── Key Usage (Digital Signature, Key Cert Sign)
│       ├── Subject Key Identifier (SKID)
│       ├── Authority Key Identifier (AKID)
│       └── TCG DICE MultiTcbInfo Extension (OID: 2.23.133.5.4.5)
│           ├── TcbInfo [0] (Root Boot Measurement)
│           ├── TcbInfo [1] (Firmware Stage 1)
│           └── TcbInfo [N] (Workload / Context Measurement)
└── Signature Value: Asymmetric signature computed by parent key
```

---

## TCG DICE Extensions

### `tcg-dice-MultiTcbInfo` (`2.23.133.5.4.5`)
Contains a sequence of `TcbInfo` structures representing the chronological measurement lineage of all ancestor contexts leading to the certified context.

Each `TcbInfo` record contains:
- **Vendor & Model**: Platform identifier strings.
- **Version / SVN**: Security Version Number for anti-rollback checks.
- **FWIDs (Firmware Identifiers)**: Hash algorithm OID (SHA-256 / SHA-384) and binary digest.
- **Type**: Component classification identifier.

### `tcg-dice-Ueid` (`2.23.133.5.4.4`)
Universal Entity ID encoding unique device serial numbers and RoT identifiers.

---

## CSR Generation (PKCS#10)

Clients can invoke `CertifyKey` with the `AddIsCsr` flag to produce a Certificate Signing Request instead of a self-signed or intermediate certificate. The CSR contains:
- Certification Request Info (CRI) with Subject and Subject Public Key Info.
- Requested Attributes containing `MultiTcbInfo` extension requests.
- Digital signature generated using the context's private key.
