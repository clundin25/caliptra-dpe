# `caliptra-dpe` (Core DPE Engine)

The `caliptra-dpe` crate implements the core TCG DICE Protection Environment state machine in pure, `no_std` Rust.

---

## Key Modules

- **`dpe_instance`**: The central `DpeInstance` struct coordinating command parsing, execution, and state persistence.
- **`context`**: Context table management, child/parent hierarchy traversal, and active/retired state tracking.
- **`tci`**: Target Component Identifier (TCI) measurement accumulation and hashing.
- **`commands`**: Command packet deserialization and dispatch handlers (`get_profile`, `initialize_context`, `derive_context`, `certify_key`, `sign`, `rotate_context`, `destroy_context`).
- **`x509`**: Generation of X.509 certificates and PKCS#10 CSRs containing `tcg-dice-MultiTcbInfo` extensions.
- **`validation`**: Defensive state invariant verification routines.

---

## Primary Types

```rust
pub struct DpeInstance<'a, C: Crypto, P: Platform> {
    pub contexts: [Context; MAX_HANDLES],
    pub support: Support,
    pub crypto: C,
    pub platform: &'a mut P,
    // ...
}
```

### Instantiation Example

```rust
use caliptra_dpe::{DpeInstance, Support};
use caliptra_dpe_crypto::RustCrypto;
use caliptra_dpe_platform::DefaultPlatform;

let mut platform = DefaultPlatform::new();
let mut crypto = RustCrypto::new();
let mut dpe = DpeInstance::new(&mut platform, crypto, Support::default())
    .expect("Failed to initialize DPE instance");

let mut response_buf = [0u8; 4096];
let resp_len = dpe.execute_serialized_command(locality, &cmd_bytes, &mut response_buf)
    .expect("Command execution failed");
```
