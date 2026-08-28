# `caliptra-dpe-response-buffer`

The `caliptra-dpe-response-buffer` crate provides bounded memory buffer wrappers used across command execution and hardware packet responses.

---

## Overview

When executing DPE commands in embedded environments, responses must be serialized into fixed-size hardware mailboxes or memory-mapped buffers without risk of buffer overflow or dynamic heap allocation.

The `ResponseBuffer` type provides:
- Safe slicing and offset tracking.
- Bounded append operations that return error codes instead of panicking on truncation.
- Seamless compatibility with `zerocopy` traits.
