# DPE Certificate Visualizer

The **DPE Certificate Visualizer** is a browser-based WebAssembly application developed in Rust that provides interactive visualization of DPE certificate hierarchies, context graphs, and decoded DICE extensions.

---

## Features

- **Interactive Context Graph**: Visual representation of the parent-child derivation tree rendered using SVG/D3.js.
- **X.509 Certificate Inspector**: Human-readable decoding of DER certificate fields, public keys, and signatures.
- **TCG DICE Extension Parsing**: Decodes `tcg-dice-MultiTcbInfo` sequences to show individual firmware component hashes, SVNs, and vendor metadata.
- **Simulation Mode**: Run simulated DPE command sequences directly inside the browser using WASM-compiled DPE instances.

---

## Running Locally

To build and launch the visualizer:

```bash
# Build WASM package and host local HTTP server on port 8080
cargo xtask run-tool
```

Then open your browser to `http://localhost:8080`.

---

## Live Deployment

The visualizer is automatically compiled and published to GitHub Pages via CI workflows at:
`https://chipsalliance.github.io/caliptra-dpe/cert-printer/`
