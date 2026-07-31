## What changed

Describe the runtime behavior and invariant affected by this change.

## Trust boundary

Explain which inputs remain untrusted and which verifier or transaction
establishes validity.

## Verification

- [ ] `cargo fmt --all -- --check`
- [ ] `cargo clippy --locked --all-targets --all-features -- -D warnings`
- [ ] `cargo test --locked --all-targets`
- [ ] PostgreSQL-backed smoke test, when persistence or API behavior changes
- [ ] OpenAPI and semantic documentation updated
- [ ] No secrets, `.env`, build output, or private data included

## DCO

- [ ] Every commit contains a `Signed-off-by` line.
