# Fuzzing and Miri Verification

To ensure memory safety and resilience against malformed inputs, Caliptra DPE supports fuzzing and undefined-behavior analysis with Miri.

---

## Fuzzing

Fuzzers test the command deserialization engine and X.509 DER parser with pseudo-random mutated inputs to detect edge cases or unexpected branches:
- AFL++ and `cargo fuzz` harnesses targeting `execute_serialized_command`.
- ASN.1 DER parser fuzzing.

---

## Miri (Undefined Behavior Detection)

Miri executes Rust MIR to detect undefined behavior, memory leaks, and unaligned reads in `no_std` state operations:

```bash
cargo miri test -p caliptra-dpe --features=p256
```
