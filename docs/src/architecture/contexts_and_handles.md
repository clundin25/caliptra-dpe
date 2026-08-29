# Contexts and Handles

In Caliptra DPE, a **Context** represents an identity and its measurement history. Contexts are organized into trees where child contexts inherit and extend their parent's measurements.

---

## Context Handles

A **Context Handle** is a 32-byte cryptographically secure token passed between the caller and DPE.

There are two handle types:
1. **Default Handle (`[0u8; 32]`)**: Used for the default context associated with a specific hardware locality. A locality may only possess at most one default context at any time.
2. **Dynamic / Non-Default Handle**: A 32-byte pseudo-random token generated using the platform TRNG.

### Handle Rotation & Single-Use Semantics
To prevent replay attacks and race conditions:
- Executing certain mutating commands (e.g., `DeriveContext`, `RotateContextHandle`) replaces the previous handle with a new randomly generated handle.
- If a handle is leaked or intercepted, rotating it invalidates the old handle immediately.

---

## Context Lifecycle & States

Each context in the DPE context table exists in one of three states:

```
                  +---------------+
                  |    Inactive   |
                  +-------+-------+
                          |
                          | InitializeContext / DeriveContext
                          v
                  +---------------+
                  |     Active    | <----+
                  +-------+-------+      |
                          |              |
                          | DeriveContext| RotateContextHandle
                          | (retain_parent = true)
                          v              |
                  +---------------+      |
                  |    Retired    | -----+
                  +-------+-------+
                          |
                          | DestroyContext / Parent Destruction
                          v
                  +---------------+
                  |    Inactive   |
                  +---------------+
```

1. **`Inactive`**: Unused slot in the context array.
2. **`Active`**: Currently in use and can be referenced by its handle to derive child contexts, generate certificates, or sign digests.
3. **`Retired`**: A parent context that has derived child contexts with `retain_parent = true`. A retired context can no longer be used directly for derivation or signing unless reactivated, but its measurement log is retained as long as its children exist.

---

## Context Hierarchy (Tree of Derivations)

When `DeriveContext` is invoked:
- A new child context is allocated.
- The child stores the index of its parent context (`parent_idx`).
- When generating an X.509 certificate for a context, DPE traverses from the context up through its ancestors to the root to collect the full measurement chain (`MultiTcbInfo`).

```
                Root Context (Index 0)
                 [FWID: ROM Boot]
                       |
                       +-------------------------------+
                       |                               |
                       v                               v
             Active Context (Index 1)        Active Context (Index 2)
              [FWID: Runtime FW]              [FWID: Recovery FW]
                       |
                       v
             Active Context (Index 3)
              [FWID: Workload App]
```

### Context Destruction
Invoking `DestroyContext` on a handle can destroy:
- A single leaf context.
- An entire subtree recursively (`destroy_descendants = true`).

When all children of a retired parent are destroyed, the retired parent slot is automatically reclaimed.
