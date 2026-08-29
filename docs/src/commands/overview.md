# DPE Command Protocol & Wire Format

Communication between clients and Caliptra DPE uses binary request/response packets transferred over mailbox registers, MMIO, or socket transports.

---

## Packet Layouts

All integer fields in DPE command packets are serialized in **Little-Endian** format using `zerocopy` layout rules.

### Command Request Packet

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Magic (0x4450)       |            Command ID         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Profile Identifier (0x01..04) | Flags / Reserved              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                     Command-Specific Payload                  +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### Response Packet

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Magic (0x4450)       |          Status (0x0000 = OK) |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Profile Identifier (0x01..04) | Flags / Reserved              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                    Response-Specific Payload                  +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

---

## Supported Commands Summary

| Command | Command ID | Purpose |
|---|---|---|
| [`GetProfile`](get_profile.md) | `0x0001` | Query DPE version, crypto profile, max context count, and capabilities. |
| [`InitializeContext`](initialize_context.md) | `0x0007` | Create a default or simulation root context for the caller's locality. |
| [`DeriveContext`](derive_context.md) | `0x0008` | Measure software component and derive a new child context or export CDI. |
| [`CertifyKey`](certify_key.md) | `0x0009` | Generate an X.509 attestation certificate or CSR for a context. |
| [`Sign`](sign.md) | `0x000A` | Compute an asymmetric digital signature over a digest. |
| [`RotateContextHandle`](rotate_context_handle.md) | `0x000E` | Rotate an existing context handle to prevent replay or theft. |
| [`DestroyContext`](destroy_context.md) | `0x000F` | Destroy an active or retired context and release resources. |
