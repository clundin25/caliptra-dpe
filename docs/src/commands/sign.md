# Sign

The `Sign` command generates an asymmetric digital signature over a caller-supplied digest using the private key derived from the target context.

---

## Command Details

- **Command ID**: `0x000A`
- **Requires Valid Handle**: Yes

---

## Request Structure

```rust
#[repr(C)]
pub struct SignCmd {
    pub handle: ContextHandle,
    pub label: [u8; DPE_LABEL_SIZE],
    pub flags: SignFlags,
    pub digest: [u8; DIGEST_SIZE],
}
```

### Flags
| Flag Bit | Name | Description |
|---|---|---|
| `Bit 0` | `IsSymmetric` | Reserved for future symmetric HMAC signing operations. |

---

## Response Structure

```rust
#[repr(C)]
pub struct SignResp {
    pub new_context_handle: ContextHandle,
    pub sig_r_or_sig: SignatureBytes,
    pub sig_s: SignatureSBytes, // If applicable for ECDSA
}
```

- **`new_context_handle`**: Rotated handle replacing the input handle.
- **Signature Payload**:
  - For **P-256 / P-384**: Returns raw ECDSA components $r$ and $s$.
  - For **ML-DSA-87**: Returns the serialized ML-DSA signature.
