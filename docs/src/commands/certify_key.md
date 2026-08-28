# CertifyKey

The `CertifyKey` command derives an asymmetric key pair for the target context and creates an X.509 certificate or Certificate Signing Request (CSR) describing its measurement history.

---

## Command Details

- **Command ID**: `0x0009`
- **Requires Valid Handle**: Yes

---

## Request Structure

```rust
#[repr(C)]
pub struct CertifyKeyCmd {
    pub handle: ContextHandle,
    pub flags: CertifyKeyFlags,
    pub label: [u8; DPE_LABEL_SIZE],
}
```

### Flags
| Flag Bit | Name | Description |
|---|---|---|
| `Bit 0` | `AddIsCsr` | Produce a PKCS#10 Certificate Signing Request (CSR) instead of an X.509 certificate. |

---

## Response Structure

```rust
#[repr(C)]
pub struct CertifyKeyResp {
    pub new_context_handle: ContextHandle,
    pub pub_key: SubjectPublicKey,
    pub cert_size: u32,
    pub cert: [u8; MAX_CERT_SIZE],
}
```

- **`new_context_handle`**: Rotated context handle for subsequent operations.
- **`pub_key`**: Derived public key corresponding to the certified context.
- **`cert`**: DER-encoded X.509 certificate or PKCS#10 CSR containing the `tcg-dice-MultiTcbInfo` measurement sequence.
