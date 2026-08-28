# Architectural Overview

The **Caliptra DICE Protection Environment (DPE)** sits at the foundation of hardware-enforced device attestation and cryptographic security. It provides an isolated, compartmentalized execution boundary where attestation keys are derived and maintained securely on behalf of system software.

```
       +-------------------------------------------------------------+
       |                   Platform RoT / Hardware                   |
       |  (e.g., Caliptra Core, Unique Device Secret / UDS, CryptEng)|
       +------------------------------+------------------------------+
                                      |
                                      v
       +-------------------------------------------------------------+
       |                     DPE Root Context                        |
       |               (Derived from Hardware Secret)                |
       +------------------------------+------------------------------+
                                      |
                      +---------------+---------------+
                      | DeriveContext                 | DeriveContext
                      v                               v
       +-----------------------------+ +-----------------------------+
       |   Layer 1: Secure Monitor   | |   Layer 1: Hypervisor       |
       |   (Measurement: FWID_1)     | |   (Measurement: FWID_2)     |
       +--------------+--------------+ +--------------+--------------+
                      |                               |
              +-------+-------+                       +-------+
              v               v                               v
       +-------------+ +-------------+                 +-------------+
       | Guest OS A  | | Guest OS B  |                 | Control App |
       | (FWID_3)    | | (FWID_4)    |                 | (FWID_5)    |
       +-------------+ +-------------+                 +-------------+
```

---

## The Attestation Hierarchy

Traditional attestation architectures hand off cryptographic secrets (Compound Device Identifiers or private keys) directly from one boot stage to the next. This model has several critical weaknesses:
1. **Unbounded Key Exposure**: If any layer contains a memory safety or logic vulnerability, its private keys and all subsequent keys can be leaked.
2. **Lack of Dynamic Compartmentalization**: Multitenant or layered environments (e.g., hypervisors running virtual machines) cannot safely dynamically create sub-contexts without risking key theft.
3. **No Retraction or Revocation**: Once a secret is handed over, the parent layer cannot revoke or rotate it without restarting the machine.

DPE solves these problems by **retaining all secrets inside the RoT boundary**. Instead of raw private keys, clients receive opaque **32-byte Context Handles**.

---

## Core Subsystems

Caliptra DPE is partitioned into modular subsystems:

### 1. The DPE State Machine (`DpeInstance`)
The central engine managing:
- The **Context Table**: An array of `Context` entries forming a forest of directed trees representing software derivation hierarchies.
- **TCB Measurement Log**: Storage of Target Component Identifiers (TCIs) and Security Version Numbers (SVNs) per context.
- **Locality Filtering**: Hardware-enforced isolation where contexts created by locality $L$ can only be accessed or modified by commands originating from locality $L$.

### 2. The Cryptographic Abstraction (`Crypto` Trait)
Abstracts all underlying cryptographic operations:
- Key generation (ECDSA over NIST P-256 and P-384, Post-Quantum ML-DSA-87).
- Key Derivation Functions (HKDF-SHA256, HKDF-SHA384).
- Hash algorithms and Message Authentication Codes (HMAC).
- Asymmetric signing and ECDH operations.

### 3. The Platform Abstraction (`Platform` Trait)
Interfaces with host platform peripherals and storage:
- Non-volatile configuration and state storage.
- High-entropy True Random Number Generator (TRNG).
- Platform certificate chain retrieval (RoT root and intermediate certificates).
- Diagnostic logging and hardware reset events.

### 4. Zero-Copy X.509 ASN.1 Engine (`dice-asn1` & `x509`)
Generates RFC 5280 X.509 DER certificates and RFC 2986 Certificate Signing Requests (CSRs) without dynamic heap allocation.
- Injects standard DICE extensions (`tcg-dice-MultiTcbInfo`, `tcg-dice-TcbInfo`).
- Encodes Subject Key Identifiers (SKID), Authority Key Identifiers (AKID), Key Usage, and Extended Key Usage.
- Serializes DER bytes directly into the caller's output response buffer.
