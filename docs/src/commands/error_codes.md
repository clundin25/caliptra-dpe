# Error Codes Reference

When a command cannot be completed, DPE returns a non-zero status code in the response header.

---

## Status Codes Table

| Code (Hex) | Name | Description |
|---|---|---|
| `0x00000000` | `NoError` | Command executed successfully. |
| `0x00010000` | `InternalError` | An unexpected internal fault or unrecoverable error occurred. |
| `0x00010001` | `InvalidCommand` | The requested command ID is unknown or unrecognized. |
| `0x00010002` | `InvalidArgument` | A field in the command payload was malformed or out of range. |
| `0x00010003` | `ArgumentNotSupported` | A requested flag or mode is not supported by the active configuration. |
| `0x00010004` | `InvalidHandle` | The supplied context handle was not found or does not belong to the caller's locality. |
| `0x00010005` | `InvalidLocality` | Access denied: Context belongs to a different locality. |
| `0x00010006` | `MaxContexts` | No available context slots remain in the context table. |
| `0x00010007` | `HasChildren` | Context cannot be destroyed because it has active child contexts (use `DestroyDescendants`). |
| `0x00010008` | `CryptoError` | An error occurred inside the cryptographic driver or key derivation engine. |
| `0x00010009` | `SerializationError` | Failed to serialize or deserialize command/response packets. |
| `0x0001000A` | `InvalidArgumentCfi` | CFI assertion failed during argument validation. |
| `0x0001000B` | `Validation` | State validation or integrity assertion check failed. |
