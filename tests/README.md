# Integration tests

The loopback end-to-end tests live in `crates/lanfp/tests/e2e.rs` so they can
use the `lanfp` crate's dev-dependencies and the `CARGO_BIN_EXE_lanfp`
environment variable. Run them with:

```sh
cargo test --workspace
```

The file starts with `#![cfg(unix)]`, so on Windows it compiles to an empty
test binary and only the unit tests run there.
