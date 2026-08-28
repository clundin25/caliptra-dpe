# GetProfile

The `GetProfile` command retrieves static configuration, profile attributes, and feature flags supported by the running DPE instance.

---

## Command Details

- **Command ID**: `0x0001`
- **Requires Valid Handle**: No (Public discovery command)

### Request Structure
`GetProfile` has no command-specific payload:

```rust
#[repr(C)]
pub struct GetProfileCmd {
    // Empty payload
}
```

---

## Response Structure

```rust
#[repr(C)]
pub struct GetProfileResp {
    pub magic: u32,
    pub dpe_version: u32,
    pub max_context_count: u32,
    pub flags: ProfileFlags,
}
```

### Profile Flags
| Flag Bit | Name | Description |
|---|---|---|
| `Bit 0` | `SupportsSimulation` | DPE instance supports simulation contexts. |
| `Bit 1` | `SupportsRecursive` | DPE supports recursive derivation inside contexts. |
| `Bit 2` | `SupportsAutoInit` | Platform automatically initializes default contexts at boot. |
| `Bit 3` | `SupportsRotateContext` | DPE supports dynamic handle rotation. |
| `Bit 4` | `SupportsCdiExport` | DPE supports exporting Compound Device Identifiers to callers. |
| `Bit 5` | `SupportsCsr` | DPE supports generating Certificate Signing Requests. |
| `Bit 6` | `SupportsInternalDice` | DPE uses internal Root-of-Trust DICE derivation keys. |
