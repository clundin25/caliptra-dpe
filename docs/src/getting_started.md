# Getting Started

This guide explains how to set up the development environment, build the repository, run tests, and generate documentation.

## Prerequisites

Caliptra DPE development uses [Nix](https://nixos.org/) for reproducible builds and pinned toolchains.

The Nix flake provides:
- **Rust Toolchain**: `rustup` configured with Rust 1.83+ and `riscv32imc-unknown-none-elf` target.
- **Go Toolchain**: Go 1.22+ and `golint` for client and verification test suites.
- **Python**: `uv` and Python 3.11+ for X.509 certificate parsing test runners.
- **WASM Tools**: `wasm-bindgen-cli` and `trunk` for the certificate visualizer.
- **Code Quality**: `taplo` for TOML formatting, `cargo-clippy`, and `mdbook`.

### Entering the Nix Shell

```bash
# Enter reproducible development environment
nix develop
```

Alternatively, if developing without Nix, ensure you have:
- Rust toolchain (`cargo`, `rustc`, `clippy`, `rustfmt`)
- `mdbook` (`cargo install mdbook`)
- `wasm-bindgen-cli` (`cargo install wasm-bindgen-cli --version 0.2.100`)
- Go 1.22+
- Python 3.11+ with `uv` or `pip`

---

## Building the Workspace

Use the workspace build tool (`xtask`) for all standard tasks:

```bash
# Build all host targets and tools
cargo build

# Run formatting, clippy, license, and TOML lint checks
cargo xtask precheckin
```

---

## Running Tests

Due to profile features (CFI single-threaded constraints and embedded `no_std` targets), tests are organized and executed via `cargo xtask`:

```bash
# Run unit tests across all crypto profiles (P-256, P-384, ML-DSA, Hybrid)
cargo xtask test unit

# Run Go client verification tests (starts simulator in background)
cargo xtask test verification

# Run Python certificate parser tests
cargo xtask test cert-parser

# Run RISC-V zero-panic binary assertions
cargo xtask test panic-check

# Run full CI test suite (includes all above)
cargo xtask ci
```

---

## Viewing and Building Documentation

The documentation is built with [mdBook](https://rust-lang.github.io/mdBook/) and published online at **https://chipsalliance.github.io/caliptra-dpe/**:

```bash
# Build the documentation into docs/book/
cargo xtask doc

# Serve the documentation locally with hot reloading
cargo xtask doc --serve
# Or specify a custom port
cargo xtask doc --serve --port 8080
```

Once served, open `http://localhost:3000` (or your custom port) in your web browser.


---

## Running the Interactive Certificate Visualizer

Caliptra DPE includes a browser-based WebAssembly application to visualize DPE certificate chains:

```bash
# Build and host the visualizer locally on port 8080
cargo xtask run-tool
```

Navigate to `http://localhost:8080` to inspect context graphs, DER certificate chains, and decoded DICE extensions interactively.
