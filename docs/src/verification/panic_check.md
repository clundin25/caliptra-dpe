# Panic Checks

In bare-metal embedded firmware environments, a panic causes a system halt or watchdog reset. Therefore, critical firmware must be provably panic-free.

---

## The Panic Checker Harness

The `verification/panic-check/` harness compiles a standalone RISC-V firmware binary targeting `riscv32imc-unknown-none-elf` and analyzes the resulting ELF binary symbols:
- Ensures no symbols matching `rust_begin_unwind`, `core::panicking::*`, or string formatting routines are linked into the binary.
- Guarantees statically bounded memory and deterministic control flow.

---

## Running the Panic Check

```bash
cargo xtask test panic-check
```
