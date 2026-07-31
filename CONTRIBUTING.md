# Contributing

Thank you for contributing to the Jacobian Fiber Runtime.

## Before opening a change

- Use GitHub Discussions or an issue for substantial semantic changes.
- Do not report security vulnerabilities in a public issue; follow
  [SECURITY.md](SECURITY.md).
- Keep proof boundaries explicit. A heuristic may propose a candidate, but it
  must not silently become a trusted verifier.
- Preserve tenant isolation, optimistic case versions, transaction atomicity,
  append-only history, and exact certificate reproducibility.

## Development workflow

Install Rust 1.94 or newer, Docker, Docker Compose, `jq`, and `uuidgen`.

Run the local quality gates:

```bash
cargo fmt --all -- --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all-targets
cargo build --locked --release
```

Run the PostgreSQL-backed integration suite:

```bash
cp .env.example .env
# Replace every placeholder secret in .env.
set -a
source .env
set +a
docker compose up --build --detach
./scripts/e2e-smoke.sh
docker compose down --volumes
```

Changes to API behavior must update `web/openapi.yaml`. Changes to runtime
semantics must update the relevant document under `docs/`.

## Pull requests

Pull requests should:

1. explain the invariant or failure mode being addressed;
2. include tests for success and rejection paths;
3. preserve unrelated behavior;
4. pass all CI jobs;
5. contain no secrets, generated build output, or local environment files.

## Developer Certificate of Origin

Contributions use the [Developer Certificate of Origin 1.1](DCO). Sign every
commit with:

```text
Signed-off-by: Your Name <your.email@example.com>
```

Use `git commit -s` to add this line automatically. The sign-off certifies that
you have the right to submit the contribution under Apache-2.0.
