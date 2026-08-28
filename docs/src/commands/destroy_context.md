# DestroyContext

The `DestroyContext` command terminates an active context and releases its resources.

---

## Command Details

- **Command ID**: `0x000F`
- **Requires Valid Handle**: Yes

---

## Request Structure

```rust
#[repr(C)]
pub struct DestroyContextCmd {
    pub handle: ContextHandle,
    pub flags: DestroyContextFlags,
}
```

### Flags
| Flag Bit | Name | Description |
|---|---|---|
| `Bit 0` | `DestroyDescendants` | Recursively destroy all child and descendant contexts rooted at this context. |

---

## Response Structure

```rust
#[repr(C)]
pub struct DestroyContextResp {
    // Empty response payload; Status code 0 indicates success.
}
```

### Destruction Semantics
- If `DestroyDescendants` is set, all descendant contexts are recursively transitioned to `Inactive` and zeroized.
- If `DestroyDescendants` is not set and the target context has active children, DPE returns `DpeErrorCode::HasChildren`.
- If destroying this context leaves its retired parent with zero remaining children, the retired parent is also automatically reclaimed.
