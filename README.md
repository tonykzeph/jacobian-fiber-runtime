# Jacobian Fiber Runtime

[![CI](https://github.com/tonykzeph/jacobian-fiber-runtime/actions/workflows/ci.yml/badge.svg)](https://github.com/tonykzeph/jacobian-fiber-runtime/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)

JFR is a production-oriented epistemic execution system for computations in which one
observable state corresponds to several globally distinct hidden states.

It maintains those alternatives as durable branches with identity, evidence,
weights, lineage, validation certificates, risk, and an append-only transition
history. Models and operators can propose branches. Only an authorized
validation transition backed by evidence or a formal certificate can activate
or contradict them.

Version 0.4 adds a second persistent fiber for assumptions. Exact guarantees
bind to those assumption branches, and durable action permits bind to both the
world fiber and the assumption fiber. When a premise is contradicted or a
guarantee is refuted, dependent permits are revoked in the same PostgreSQL
transaction.

The application is implemented in Rust. Python is not used. Its algebraic
kernel can now discover the complete three-sheet fiber of the announced
three-dimensional Keller map automatically; operators no longer need to enter
the known preimages.

## What is included

- Rust 2024 runtime and HTTP service built with Axum and Tokio.
- PostgreSQL 17 as the authoritative transactional store.
- Tenant-scoped API keys stored as HMAC-SHA-256 digests.
- Scoped authorization for reads, writes, and validation.
- Authenticated API-key provisioning, revocation, and append-only security events.
- Optimistic case versions plus PostgreSQL row locks.
- Idempotent mutation requests that work across service replicas.
- Persistent branch splitting, merging, contradiction, and genealogy.
- Automatic inverse-fiber materialization for rational targets.
- Hybrid numerical/exact root isolation: fast floating-point proposals followed
  by exact arbitrary-precision Rouché certificates.
- Atomic continuation between observations with globally optimal sheet matching.
- Hidden-state escape telemetry comparing source norm with bounded observation norm.
- Evidence and observation records with explicit sources and times.
- Bayesian log-likelihood updates with log-sum-exp normalization, entropy, and
  realized information-gain accounting.
- Expected-utility, maximin, and KL-distributionally-robust action evaluation.
- Persistent assumption fibers with evidence, validation, lineage, and weights.
- Exact finite integer-domain refutation using arbitrary-precision rational
  arithmetic, complete enumeration certificates, and immutable counterexamples.
- Joint world × assumption maximin authorization with complete Cartesian
  coverage checks.
- Atomic guarantee suspension and durable action-permit revocation when a
  premise fails.
- Semantic proof audit that independently recomputes verified guarantees,
  counterexample witnesses, authorization dependencies, and canonical inputs.
- Experiment ranking by mutual information.
- RFC 8785 canonical JSON and SHA-256 per-case event chains.
- Database-enforced append-only events and committed ledger heads.
- A self-contained exact Jacobian counterexample verifier using arbitrary
  precision rational and sparse-polynomial arithmetic.
- Embedded operator console with no external frontend runtime or CDN.
- Prometheus/OpenMetrics, readiness/liveness probes, request IDs, structured
  logging, timeouts, request limits, compression, CSP, and graceful shutdown.
- Reproducible Docker image, Compose stack, smoke test, and CI workflow.

## Start the complete stack

Create a local environment file:

```bash
git clone https://github.com/tonykzeph/jacobian-fiber-runtime.git
cd jacobian-fiber-runtime
cp .env.example .env
```

Replace the three placeholder secrets. Suitable values can be generated with:

```bash
openssl rand -hex 32
openssl rand -hex 32
printf 'jfr_live_%s\n' "$(openssl rand -hex 32)"
```

Then start PostgreSQL and the runtime:

```bash
docker compose up --build -d
docker compose ps
```

Open `http://127.0.0.1:18080` and enter `JFR_BOOTSTRAP_API_KEY`.

Run the full API smoke test:

```bash
set -a
source .env
set +a
./scripts/e2e-smoke.sh
```

The smoke test verifies authentication, readiness, idempotent replay, case
creation, three independent branches, exact Jacobian validation, assumption
activation, proof and refutation, joint authorization, cascading revocation,
optimistic versions, persistence, and the complete audit chain.

The browser smoke test requires Chrome or Chromium and validates the
authenticated desktop and mobile operator console without adding a JavaScript
test framework:

```bash
node --experimental-websocket ./scripts/ui-smoke.mjs
```

## Local Rust development

Start only PostgreSQL:

```bash
docker compose up -d postgres
```

Export local service configuration:

```bash
export JFR_DATABASE_URL='postgresql://jfr:YOUR_PASSWORD@127.0.0.1:55432/jfr'
export JFR_API_KEY_PEPPER='YOUR_32_CHARACTER_OR_LONGER_PEPPER'
export JFR_BOOTSTRAP_API_KEY='jfr_live_YOUR_32_CHARACTER_OR_LONGER_KEY'
export JFR_LOG_FORMAT=pretty
```

Run the service:

```bash
cargo run --bin jfr-server
```

Quality gates:

```bash
make check
make test
cargo build --locked --release
```

## Runtime API

All mutation requests require:

```http
Authorization: Bearer <api-key>
Idempotency-Key: <unique-request-id>
Content-Type: application/json
```

Every mutation after case creation also includes `expected_case_version`.
Stale writers receive `409 version_conflict`; the server never silently merges
concurrent epistemic transitions.

Principal endpoints:

| Method | Endpoint | Purpose |
| --- | --- | --- |
| `GET` | `/api/v1/session` | Resolve key, tenant, and scopes |
| `GET/POST` | `/api/v1/keys` | List or provision scoped API keys |
| `POST` | `/api/v1/keys/{id}/revoke` | Revoke a key without deleting its history |
| `GET/POST` | `/api/v1/cases` | List or create state spaces |
| `GET` | `/api/v1/cases/{id}` | Complete materialized case snapshot |
| `POST` | `/api/v1/cases/{id}/evidence` | Add immutable evidence |
| `POST` | `/api/v1/cases/{id}/evidence/likelihood` | Commit evidence and a normalized Bayesian posterior |
| `POST` | `/api/v1/cases/{id}/observations` | Advance the shared observation |
| `POST` | `/api/v1/cases/{id}/fiber/materialize/jacobian` | Discover and activate the complete certified fiber |
| `POST` | `/api/v1/cases/{id}/fiber/advance/jacobian` | Solve a successor fiber and preserve sheet lineage |
| `POST` | `/api/v1/cases/{id}/branches` | Propose a hidden state |
| `POST` | `/api/v1/branches/{id}/validate` | Activate or contradict with a certificate |
| `POST` | `/api/v1/branches/{id}/split` | Supersede a branch with descendants |
| `POST` | `/api/v1/cases/{id}/branches/merge` | Merge certified-equivalent branches |
| `POST` | `/api/v1/cases/{id}/assumptions` | Propose an assumption branch |
| `POST` | `/api/v1/assumptions/{id}/validate` | Activate or contradict a premise |
| `POST` | `/api/v1/cases/{id}/guarantees` | Declare an exact finite-domain guarantee |
| `POST` | `/api/v1/guarantees/{id}/search/exhaustive` | Prove or refute a guarantee exactly |
| `POST` | `/api/v1/guarantees/{id}/counterexamples` | Submit an independently checked witness |
| `POST` | `/api/v1/cases/{id}/actions/authorize` | Record a revocable joint-maximin permit |
| `POST` | `/api/v1/cases/{id}/decisions/evaluate` | Expected or maximin action policy |
| `POST` | `/api/v1/cases/{id}/experiments/rank` | Rank branch-separating observations |
| `GET` | `/api/v1/cases/{id}/audit` | Recompute the complete event chain |
| `GET` | `/api/v1/cases/{id}/audit/semantic/jacobian` | Re-solve and verify active-fiber completeness |
| `GET` | `/api/v1/cases/{id}/audit/semantic/guarantees` | Recompute proof and permit semantics |
| `GET` | `/api/v1/cases/{id}/events` | Incremental ledger consumption |

The machine-readable API description is available at
`/openapi.yaml` when the service is running.

## Runtime invariants

1. Tenant IDs constrain every persisted read and mutation.
2. A case mutation locks the case row and checks its expected version.
3. Branch activation, contradiction, pruning, splitting, and merging require
   evidence or a non-empty certificate.
4. Historical branches are retained; state transitions do not erase them.
5. Split weight is conserved and genealogy is explicit.
6. Only active branches participate in decisions or experiment ranking.
7. Solver-created active branches require pairwise-disjoint one-root certificates
   that account for the complete inverse polynomial degree.
8. A likelihood update covers every active branch and normalizes in log space.
9. A continuation supersedes the old fiber and commits the successor observation,
   complete fiber, and globally matched genealogy atomically.
10. An exhaustive proof covers the entire declared finite domain using exact
    rational arithmetic; a refutation contains a verifier-checkable witness.
11. Action authorization requires one finite utility for every active world ×
    assumption pair and can select only the joint-maximin action.
12. An authorized action stores the transitive assumption premises of its
    required guarantees.
13. Contradicting a premise suspends dependent guarantees and revokes every
    affected permit atomically; refuting a guarantee revokes its permits.
14. Counterexamples and ledger events cannot be updated or deleted by the
    application database role.
15. Every committed mutation adds exactly one event and advances the case head.
16. Reusing an idempotency key with different request content is rejected.
17. The browser never becomes a source of truth; it only invokes the API.

## Documentation

- [Architecture](docs/ARCHITECTURE.md)
- [Fiber kernel and certificate semantics](docs/FIBER-KERNEL.md)
- [Assurance kernel and revocation semantics](docs/ASSURANCE-KERNEL.md)
- [Security model](docs/SECURITY.md)
- [Operations](docs/OPERATIONS.md)
- [OpenAPI contract](web/openapi.yaml)

## Contributing and license

JFR is licensed under the [Apache License 2.0](LICENSE), including its explicit
patent grant. Contributions are accepted under the same license and require a
Developer Certificate of Origin sign-off. See [CONTRIBUTING.md](CONTRIBUTING.md),
[SECURITY.md](SECURITY.md), and [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
