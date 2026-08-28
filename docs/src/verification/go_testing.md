# Go Test Suite & Client

The `verification/` directory contains an idiomatic Go client and exhaustive conformance test harness for DPE.

---

## The Go DPE Client

The Go client library provides a high-level API for issuing DPE commands over UNIX sockets or direct memory transports:

```go
client, err := dpe.NewClient(transport)
profile, err := client.GetProfile()
handle, err := client.InitializeContext(dpe.InitDefault)
```

---

## Running Verification Tests

The test suite launches the simulator in the background and executes positive and negative test cases against every DPE command:

```bash
cargo xtask test verification
```
