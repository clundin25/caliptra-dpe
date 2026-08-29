# TCB and Measurements

The **Trusted Computing Base (TCB)** in Caliptra DPE captures the hardware, firmware, and software state of the device. Attestation allows a remote party or verifier to evaluate this state cryptographically.

---

## Target Component Identifiers (TCIs)

Each context in DPE can record one or more TCB measurement entries. A measurement record contains:

| Field | Description |
|---|---|
| **TCI Type** | A 4-byte identifier designating the measurement type (e.g., Core Firmware, Configuration Data, Kernel). |
| **Current TCI** | The cryptographic hash digest (SHA-256, SHA-384) of the software binary or configuration data. |
| **Cumulative TCI** | The running hash extending previous measurements in the chain: `Cumulative_n = Hash(Cumulative_{n-1} || Current_n)`. |
| **SVN (Security Version Number)** | A 32-bit monotonic version counter used to enforce anti-rollback policies. |

---

## Measurement Operations

### 1. Context Creation & Extension
During `DeriveContext`:
- The caller supplies a new TCI measurement and SVN.
- DPE can either extend the existing cumulative measurement or record a new discrete TCI entry.

### 2. Compound Device Identifier (CDI) Derivation
DPE computes the **Compound Device Identifier (CDI)** for a context by combining:
1. The hardware Root CDI or parent context CDI.
2. The context's cumulative TCI measurement.
3. Context configuration flags and metadata.

$$\text{CDI}_{\text{child}} = \text{HKDF-Extract}(\text{CDI}_{\text{parent}}, \text{TCB}_{\text{child\_measurements}})$$

$$\text{AttestationKey}_{\text{child}} = \text{HKDF-Expand}(\text{CDI}_{\text{child}}, \text{"DPE Asymmetric Key"})$$

Because the private attestation key is derived mathematically from the exact software measurements:
- **Any modification to the software binary** produces a completely different CDI and private key.
- A compromised or rogue firmware image cannot forge certificates or signatures that claim to be an authentic, uncompromised version.
