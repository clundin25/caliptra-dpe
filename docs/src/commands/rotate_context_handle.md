# RotateContextHandle

The `RotateContextHandle` command updates an existing context handle to a new random value or converts a default handle into a non-default handle.

---

## Command Details

- **Command ID**: `0x000E`
- **Requires Valid Handle**: Yes

---

## Request Structure

```rust
#[repr(C)]
pub struct RotateContextHandleCmd {
    pub handle: ContextHandle,
    pub flags: RotateContextHandleFlags,
}
```

### Flags
| Flag Bit | Name | Description |
|---|---|---|
| `Bit 0` | `TargetIsDefault` | Set the rotated handle as the default handle for the locality. |

---

## Response Structure

```rust
#[repr(C)]
pub struct RotateContextHandleResp {
    pub new_context_handle: ContextHandle,
}
```

If `TargetIsDefault` is false, `new_context_handle` returns a fresh 32-byte pseudo-random token, and the previous handle becomes immediately invalid.
