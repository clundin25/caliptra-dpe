# Crates Overview

The Caliptra DPE codebase is organized into several modular crates:

```
 caliptra-dpe Workspace
 ├── dpe/                     # caliptra-dpe: Core DPE State Machine (no_std)
 ├── crypto/                  # caliptra-dpe-crypto: Cryptographic abstraction & SW/HW drivers
 ├── platform/                # caliptra-dpe-platform: Platform integration & storage traits
 ├── dice-asn1/               # dice-asn1: Zero-copy DICE X.509 DER serializer
 ├── response-buffer/         # caliptra-dpe-response-buffer: Bounded serialization buffers
 ├── simulator/               # caliptra-dpe-simulator: Userspace DPE daemon
 ├── tools/                   # caliptra-dpe-tools: WebAssembly cert visualizer & CLIs
 ├── verification/            # Go, Python, and panic-check test harnesses
 └── xtask/                   # cargo-xtask: Build automation, testing, linting, & doc generation
```

---

## Crate Responsibilities

| Crate | Primary Role | `no_std` Support |
|---|---|---|
| [`caliptra-dpe`](dpe.md) | Core DPE firmware engine, command dispatcher, context table, CFI instrumentation. | Yes |
| [`caliptra-dpe-crypto`](crypto.md) | `Crypto` trait definition, software fallback implementations, and hardware wrappers. | Yes |
| [`caliptra-dpe-platform`](platform.md) | `Platform` trait for persistent storage, platform certificate retrieval, TRNG, and resets. | Yes |
| [`dice-asn1`](dice_asn1.md) | Zero-copy DER encoding of DICE X.509 certificates, extensions, and CSRs. | Yes |
| [`caliptra-dpe-response-buffer`](response_buffer.md) | Helper primitives for safe serialization into fixed-size hardware buffers. | Yes |
| [Simulator](../tools/simulator.md) | Standalone daemon hosting DPE over a UNIX domain socket. | No (Hosts DPE in `std`) |
| [Tools / Visualizer](../tools/visualizer.md) | WASM interactive certificate visualizer web application and diagnostic utilities. | WASM / Std |
