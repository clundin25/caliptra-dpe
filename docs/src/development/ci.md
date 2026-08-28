# CI/CD & Deployment Pipeline

Caliptra DPE uses GitHub Actions workflows for continuous integration and automated documentation/tool deployment.

---

## Workflow Overview

### 1. `ci.yml`
Triggered on pull requests and pushes to `main`:
- Checks environment within `nix develop`.
- Executes `cargo xtask ci` covering formatting, linting, doc builds, unit tests, Go verification, Python cert tests, and panic checks.

### 2. `deploy-visualizer.yml`
Triggered on pushes to `main`:
- Builds the WebAssembly Certificate Visualizer (`cargo xtask cert-graph`).
- Builds the mdBook documentation (`cargo xtask doc`).
- Deploys the static site to GitHub Pages (`dist/`).
