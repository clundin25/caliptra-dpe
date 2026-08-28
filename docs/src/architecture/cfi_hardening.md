# Control-Flow Integrity (CFI) & Security Hardening

Hardware Roots of Trust operate in physically exposed environments where attackers can perform **fault injection (voltage, clock, electromagnetic glitching, laser fault injection)** to bypass security checks or skip instructions.

Caliptra DPE incorporates extensive **Control-Flow Integrity (CFI)** and defensive coding patterns to mitigate physical and logical attacks.

---

## CFI Architecture

Caliptra DPE uses `caliptra-cfi-lib` and `caliptra-cfi-derive` to enforce fine-grained control flow validation.

```
                  +--------------------------------+
                  | Entry: cfi_counter += Expected |
                  +---------------+----------------+
                                  |
                                  v
                  +--------------------------------+
                  |  Critical Security Decision    |
                  |  (e.g., Validate Handle/Loc)   |
                  +---------------+----------------+
                                  |
                                  v
                  +--------------------------------+
                  | Step A: cfi_counter.assert_eq()|
                  +---------------+----------------+
                                  |
                                  v
                  +--------------------------------+
                  | Exit: cfi_counter.validate()   |
                  +--------------------------------+
```

### 1. Dual-Rail State & Execution Counters
- Critical code blocks increment an internal CFI counter at every step.
- Prior to releasing sensitive cryptographic material or updating state, the counter is checked against a deterministic expected value.
- If an instruction was skipped or an unexpected branch was taken due to a fault, the counter check fails immediately, triggering a secure panic or platform reset.

### 2. Multi-bit Booleans (`U8Bool`)
Standard single-bit boolean values (`0` vs `1`) can be flipped by a single electrical glitch. DPE employs multi-bit patterns:
```rust
pub struct U8Bool(pub u8);

pub const FALSE: U8Bool = U8Bool(0x5A); // Multi-bit pattern
pub const TRUE:  U8Bool = U8Bool(0xA5); // Multi-bit inverse pattern
```
Values other than `TRUE` or `FALSE` are treated as invalid and abort execution.

### 3. Constant-Time & Memory Safety
- **Zero Heap Allocations**: All buffers, context tables, and scratch areas are statically sized at compile time.
- **Zeroization**: Cryptographic keys, intermediate digests, and sensitive context handles are wiped (`zeroize`) on drop or context destruction.
- **Panic Check Verification**: Automated CI tests ensure the RISC-V firmware build contains zero panics, unwinds, or unbounded format strings.
