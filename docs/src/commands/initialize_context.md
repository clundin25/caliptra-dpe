# InitializeContext

The `InitializeContext` command creates a root context for the calling locality.

---

## Command Details

- **Command ID**: `0x0007`
- **Requires Valid Handle**: Only when initializing simulation contexts.

---

## Request Structure

```rust
#[repr(C)]
pub struct InitializeContextCmd {
    pub flags: InitFlags,
}
```

### Flags
| Flag Bit | Name | Description |
|---|---|---|
| `Bit 0` | `IsSimulation` | Create a simulation context disconnected from hardware secrets. |
| `Bit 1` | `IsDefault` | Initialize the default context for the calling locality. |

---

## Response Structure

```rust
#[repr(C)]
pub struct InitializeContextResp {
    pub handle: ContextHandle,
}
```

- If `IsDefault` was set, `handle` returns `[0u8; 32]`.
- If non-default or simulation, `handle` returns a newly generated 32-byte pseudo-random token.
