# DeriveContext

The `DeriveContext` command records software measurements, derives child contexts, and optionally exports raw Compound Device Identifiers (CDIs).

---

## Command Details

- **Command ID**: `0x0008`
- **Requires Valid Handle**: Yes

---

## Request Structure

```rust
#[repr(C)]
pub struct DeriveContextCmd {
    pub handle: ContextHandle,
    pub flags: DeriveContextFlags,
    pub tci_type: u32,
    pub target_locality: u32,
    pub tci_data: [u8; TCI_SIZE],
}
```

### Derive Context Flags
| Flag Bit | Name | Description |
|---|---|---|
| `Bit 0` | `RetainParent` | Keep the parent context alive in `Retired` state instead of replacing it. |
| `Bit 1` | `AllowPromote` | Allow the child context to be promoted or certified as a CA. |
| `Bit 2` | `CreateCertificate` | Issue an X.509 certificate for this derivation step immediately. |
| `Bit 3` | `ExportCdi` | Derive and export the raw CDI to the caller instead of maintaining key isolation. |
| `Bit 4` | `IsDefault` | Assign the derived context as the default context of `target_locality`. |
| `Bit 5` | `ChangeLocality` | Transfer context ownership to `target_locality`. |
| `Bit 6` | `IsRecursive` | Fold measurement recursively into the existing context rather than branching. |

---

## Response Structure

```rust
#[repr(C)]
pub struct DeriveContextResp {
    pub handle: ContextHandle,
    pub parent_handle: ContextHandle,
    pub exported_cdi: [u8; TCI_SIZE],
    pub certificate_size: u32,
    pub certificate: [u8; MAX_CERT_SIZE],
}
```
