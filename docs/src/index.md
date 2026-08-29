# Caliptra DICE Protection Environment (DPE)

Welcome to the documentation for **Caliptra DPE**. This repository contains a pure Rust, `no_std`-compatible implementation of the [TCG DICE Protection Environment (DPE) Specification](https://trustedcomputinggroup.org/resource/dice-protection-environment-specification/), developed for the [Caliptra Open Source Hardware Root of Trust (RoT)](https://github.com/chipsalliance/caliptra-dpe).

```
 +-------------------------------------------------------------+
 |                       Host / SoC Clients                    |
 |     (OS / Hypervisor / Applications / Cryptographic Apps)   |
 +------------------------------+------------------------------+
                                | Transport / Mailbox
                                v
 +-------------------------------------------------------------+
 |                        Caliptra DPE                         |
 |  +-------------------------------------------------------+  |
 |  | Context & Handle Manager (Forest of Context Nodes)    |  |
 |  +-------------------------------------------------------+  |
 |  | TCB Measurement Logs & Compound Device IDs (CDIs)     |  |
 |  +-------------------------------------------------------+  |
 |  | X.509 DER Certificate & CSR Engine (dice-asn1)        |  |
 |  +-------------------------------------------------------+  |
 |  | Cryptographic Engine (P-256, P-384, ML-DSA, Hybrid)   |  |
 |  +-------------------------------------------------------+  |
 |  | Control-Flow Integrity & Glitch Hardening (CFI)       |  |
 |  +-------------------------------------------------------+  |
 +------------------------------+------------------------------+
                                | Hardware Hooks
                                v
 +-------------------------------------------------------------+
 |           Caliptra Hardware Root of Trust Engine            |
 +-------------------------------------------------------------+
```

## What is DPE?

The **DICE Protection Environment (DPE)** is a standardized framework by the Trusted Computing Group (TCG) that isolates cryptographic attestation keys and operations from untrusted software layers. Rather than passing raw Compound Device Identifiers (CDIs) or private asymmetric keys to firmware layers or operating system components, the Root of Trust maintains custody of keys inside an isolated environment.

Clients interact with DPE via structured commands to:
- **Derive Contexts**: Record software measurements (FWIDs, SVNs) and create isolated child contexts.
- **Certify Keys**: Generate X.509 attestation certificates or Certificate Signing Requests (CSRs) embedded with TCG DICE measurement extensions (`tcg-dice-MultiTcbInfo`).
- **Sign**: Compute asymmetric digital signatures over application digests without exposing private signing keys.
- **Manage Handles**: Rotate or destroy context handles across software lifecycle transitions.

## Key Features

- **`no_std` Pure Rust**: Zero heap allocation in firmware builds; statically bounded memory usage.
- **Post-Quantum Cryptography (PQC)**: First-class support for NIST ML-DSA-87 (FIPS 204) and hybrid classical/PQC profiles alongside NIST P-256 and P-384.
- **Embedded X.509 DER Engine**: Zero-copy ASN.1 encoding with DICE `tcg-dice-MultiTcbInfo` extensions directly into caller response buffers.
- **Control-Flow Integrity (CFI)**: Instrumented with glitch-resistant execution tokens and verification counters.
- **Extensible Architecture**: Modular separation between the state machine (`caliptra-dpe`), crypto primitives (`caliptra-dpe-crypto`), and platform hardware bindings (`caliptra-dpe-platform`).
- **Rich Tooling & Simulator**: Includes a WebAssembly-powered interactive certificate visualizer, user-space socket simulator, Go client/conformance test suite, and Python X.509 verification harness.

## Documentation Structure

- **[Getting Started](getting_started.md)**: Prerequisites, Nix build environment, and rapid onboarding.
- **[Architecture & Design](architecture/overview.md)**: Deep dive into context trees, measurement logging, crypto profiles, and CFI hardening.
- **[DPE API Specification](commands/overview.md)**: Wire protocol specifications, command structures, and error codes.
- **[Crates & Modules](crates/overview.md)**: Tour of each crate and module within the repository.
- **[Tooling & Applications](tools/visualizer.md)**: Guide to the certificate visualizer, simulator, and diagnostic CLI tools.
- **[Verification & Testing](verification/overview.md)**: Conformance testing, panic prevention checks, and fuzzing.
- **[Developer Guide](development/xtask.md)**: Command reference for `cargo xtask` and CI/CD pipelines.
