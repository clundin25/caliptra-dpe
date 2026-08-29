# Control-Flow Integrity (CFI) & Security Hardening

Hardware Roots of Trust operate in physically exposed environments where attackers can perform **fault injection (voltage, clock, electromagnetic glitching, laser fault injection)** to bypass security checks or skip instructions.

Caliptra DPE incorporates extensive **Control-Flow Integrity (CFI)** and defensive coding patterns to mitigate physical and logical attacks.

---

## CFI Architecture

Caliptra DPE uses the [`caliptra-cfi`](https://github.com/chipsalliance/caliptra-cfi) crates (`caliptra-cfi-lib` and `caliptra-cfi-derive`) to enforce fine-grained control flow validation and fault injection mitigation.

For detailed design, architecture, and usage of CFI primitives (such as dual-rail execution counters and multi-bit booleans), see the upstream [caliptra-cfi repository](https://github.com/chipsalliance/caliptra-cfi).

---

## Defensive Coding & Hardening

In addition to CFI, Caliptra DPE employs several defensive coding practices:

- **Zero Heap Allocations**: All buffers, context tables, and scratch areas are statically sized at compile time.
- **Zeroization**: Cryptographic keys, intermediate digests, and sensitive context handles are wiped (`zeroize`) on drop or context destruction.
- **Panic Check Verification**: Automated CI tests ensure the RISC-V firmware build contains zero panics, unwinds, or unbounded format strings.
