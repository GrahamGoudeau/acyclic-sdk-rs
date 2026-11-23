# Working in acyclic-sdk-rs

- The core (no features) is std only. Do not add dependencies to it. `ureq` and `rsa` are optional features; anything new that needs a crate goes behind a feature, and RSA or other private-key math is never hand-rolled.
- `spec/` is a copy of acyclic-sdk-spec. Change it there, then copy it in again (`rsync -a --delete --exclude .git ../spec/ spec/`). `src/tools.rs` loads `spec/tools.json` with `include_str!`.
- Behavior follows the JavaScript reference (`acyclic-sdk-js/src`). If it looks wrong there, report it; do not quietly diverge.
- Projections must match `spec/fixtures/projections` exactly (`tests/projections.rs`). Add a fixture when a projection rule changes.
- Telemetry: every attribute passes `telemetry::ALLOWED`. Never put query strings, bodies, resource ids, prompts, tool arguments or results, tokens or OperationOutcome diagnostics into spans, logs or `Display` of an error.
- Vendor differences live in `src/vendors.rs` with a source in `spec/vendors.md`. Do not special-case vendors anywhere else.
- Only GETs are retried. Every URL that carries a token must share the FHIR base's origin.
- Tests: `cargo test`, `cargo test --features full`, `cargo clippy --all-features --all-targets`. End-to-end: `SANDBOX_URL=https://sandbox.acyclic.sh cargo test --features full --test sandbox_e2e` (or a local acyclic-sandbox on its port).
- Keep `rust-version = "1.75"` building for the core.
