# DPE Simulator

The `caliptra-dpe-simulator` is a user-space daemon that exposes a fully functional DPE instance over a UNIX domain socket.

---

## Overview

The simulator enables host-side development and testing of DPE client libraries without requiring physical hardware or FPGA boards.

```
 +------------------------+                  +---------------------------+
 |  Client Application    |                  |  caliptra-dpe-simulator   |
 |  (Go, Python, C, Rust) |  UNIX Socket     |  +---------------------+  |
 |                        | ---------------> |  | DpeInstance (Rust)  |  |
 |  Connects to socket    |  /tmp/dpe.sock   |  +---------------------+  |
 +------------------------+                  +---------------------------+
```

---

## Running the Simulator

To launch the simulator on `/tmp/dpe.sock`:

```bash
# Build and run simulator with default profile
cargo run -p caliptra-dpe-simulator --features=p256 -- --socket /tmp/dpe.sock
```

### Command Line Options

- `--socket <PATH>`: Path to UNIX domain socket (default: `/tmp/dpe.sock`).
- `--supports-simulation`: Enable simulation context support.
- `--supports-recursive`: Enable recursive context support.
- `--supports-auto-init`: Enable automatic default context initialization.
