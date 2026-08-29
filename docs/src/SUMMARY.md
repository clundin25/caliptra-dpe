# Summary

[Introduction](index.md)
[Getting Started](getting_started.md)

# Architecture & Design
- [Architectural Overview](architecture/overview.md)
- [Contexts and Handles](architecture/contexts_and_handles.md)
- [TCB and Measurements](architecture/tcb_and_measurements.md)
- [Cryptographic Profiles](architecture/crypto_profiles.md)
- [X.509 Certificates & DICE Extensions](architecture/certificates.md)
- [Control-Flow Integrity (CFI) & Hardening](architecture/cfi_hardening.md)

# DPE API Specification
- [Command Protocol & Wire Format](commands/overview.md)
- [GetProfile](commands/get_profile.md)
- [InitializeContext](commands/initialize_context.md)
- [DeriveContext](commands/derive_context.md)
- [CertifyKey](commands/certify_key.md)
- [Sign](commands/sign.md)
- [RotateContextHandle](commands/rotate_context_handle.md)
- [DestroyContext](commands/destroy_context.md)
- [Error Codes Reference](commands/error_codes.md)

# Crates & Modules
- [Crates Overview](crates/overview.md)
- [caliptra-dpe (Core DPE Engine)](crates/dpe.md)
- [caliptra-dpe-crypto (Crypto Driver)](crates/crypto.md)
- [caliptra-dpe-platform (Platform Abstraction)](crates/platform.md)
- [dice-asn1 (DICE ASN.1 Encoding)](crates/dice_asn1.md)
- [caliptra-dpe-response-buffer](crates/response_buffer.md)

# Tooling & Applications
- [DPE Certificate Visualizer WASM App](tools/visualizer.md)
- [DPE Simulator](tools/simulator.md)
- [Support CLI Tools](tools/support_tools.md)

# Verification & Quality Assurance
- [Verification Overview](verification/overview.md)
- [Go Test Suite & Client](verification/go_testing.md)
- [Python X.509 Cert Parser](verification/cert_parser.md)
- [Panic Checks](verification/panic_check.md)
- [Fuzzing & Miri](verification/fuzz_and_miri.md)

# Developer Guide
- [Cargo xtask Automation Reference](development/xtask.md)
- [CI/CD & Deployment Pipeline](development/ci.md)
