# Cargo xtask Automation Reference

The `xtask` workspace crate provides unified CLI commands for building, linting, testing, and documenting Caliptra DPE.

---

## Command Reference

### `cargo xtask precheckin`
Runs pre-commit checks:
- Code formatting (`cargo fmt --check`)
- TOML formatting (`taplo format --check`)
- Clippy lints (`cargo clippy --workspace --all-targets`)
- License header verification

---

### `cargo xtask test <SUBCOMMAND>`
Runs specific test suites:
- `unit`: Runs unit tests across all crypto profiles (`p256`, `p384`, `ml-dsa`, `hybrid`) with CFI test-thread constraints.
- `verification`: Runs the Go client conformance test suite against the simulator.
- `cert-parser`: Runs the Python X.509 certificate validation suite.
- `panic-check`: Verifies the RISC-V firmware build contains zero panics.

---

### `cargo xtask doc`
Builds and serves the mdBook documentation:
- `cargo xtask doc`: Builds documentation into `docs/book/`.
- `cargo xtask doc --serve`: Serves the documentation with hot-reloading.
- `cargo xtask doc --serve --port <PORT>`: Serves documentation on a specific port.

---

### `cargo xtask cert-graph`
Compiles the WASM-based DPE certificate visualizer web application and outputs assets into `tools/pkg/`.

---

### `cargo xtask run-tool`
Builds the WASM certificate visualizer and starts a local development server on port 8080.
