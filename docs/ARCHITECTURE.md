# Architecture

## System boundary

JFR has three runtime components:

```text
┌──────────────────┐        HTTPS        ┌──────────────────────────┐
│ Operator / agent │ ──────────────────▶ │ Rust / Axum API          │
│                  │ ◀────────────────── │                          │
└──────────────────┘                     │ command validation       │
                                         │ decision mathematics     │
                                         │ exact verifier registry  │
                                         │ canonical audit hashing  │
                                         └────────────┬─────────────┘
                                                      │ SQL transactions
                                         ┌────────────▼─────────────┐
                                         │ PostgreSQL               │
                                         │ snapshots + evidence     │
                                         │ branch genealogy         │
                                         │ append-only event ledger │
                                         │ idempotency state        │
                                         └──────────────────────────┘
```

The UI is embedded in the Rust binary and is an ordinary authenticated API
client. No state transition is implemented only in browser code.

## State model

A case contains the current observation \(y_t\), a durable set of hidden-world
branches, and a second durable set of assumption branches:

\[
\mathcal R_t =
(y_t,\mathcal X_t,\mathcal M_t,\mathcal G_t,\mathcal A_t).
\]

- \(\mathcal X_t\): compatible hidden-world states.
- \(\mathcal M_t\): compatible model or premise states.
- \(\mathcal G_t\): exact guarantees and their dependency graph.
- \(\mathcal A_t\): durable authorized, denied, or revoked action records.
- \(x_i\): JSON-serializable hidden-world state.
- \(w_i\): non-negative branch weight.
- \(s_i\): lifecycle status.
- \(c_i\): certificate and evidence basis.
- \(\ell_i\): parent IDs and generation.
- \(r_i\): optional domain risk score.

Branch states are:

```text
proposed ──certificate──▶ active
    │                       │
    └──contradiction────────┤
                            ├──evidence──▶ contradicted
                            ├──split─────▶ superseded ──▶ children
                            └──merge─────▶ merged ──────▶ merged child
```

Contradicted, superseded, merged, and archived rows remain queryable. They are
lineage, not garbage.

For the built-in algebraic domain, the branch set is no longer supplied
manually. The fiber kernel derives all finite complex preimages, emits exact
one-root certificates, and activates the complete set in one transaction.

## Transaction protocol

Every mutation touching an existing case follows the same protocol:

1. Begin a PostgreSQL transaction.
2. Lock the tenant-scoped case row with `SELECT … FOR UPDATE`.
3. Compare `expected_case_version` with the locked version.
4. Validate branch status, evidence ownership, numeric bounds, and certificate
   structure.
5. Update materialized evidence or branch state.
6. Construct the event payload.
7. Canonicalize the complete event material using RFC 8785 JSON.
8. Hash it with SHA-256, including:
   - tenant and case IDs;
   - monotonically increasing sequence;
   - event type and payload;
   - previous event hash;
   - actor API-key ID;
   - timestamp.
9. Insert the append-only event.
10. Atomically advance case version, event count, head hash, and update time.
11. Commit.

A concurrent writer either obtains the next version intentionally or receives a
conflict. There is no last-write-wins behavior.

## Audit verification

The verifier:

1. requires sequence numbers to be contiguous from one;
2. checks every predecessor link;
3. recomputes every canonical event hash;
4. compares row count with the case commitment;
5. compares the terminal hash with the committed head.

PostgreSQL triggers reject `UPDATE` and `DELETE` on the event table. An operator
can export and sign the terminal head to move trust outside the database
administrator boundary.

The semantic Jacobian audit is deliberately separate. It re-solves the current
observation, recomputes exact isolation certificates, and checks a complete
one-to-one match with the recorded active fiber. Hash-chain validity therefore
cannot be mistaken for mathematical branch validity.

The guarantee semantic audit is separate again. It re-enumerates exact bounded
proofs, validates immutable counterexamples, checks suspended premises, and
recomputes live authorization dependencies and canonical input hashes.

## Idempotency

Every HTTP mutation requires `Idempotency-Key`.

The API hashes the request body and atomically claims
`(tenant_id, idempotency_key)` in PostgreSQL before invoking the command:

- A completed matching request returns its stored JSON response.
- A matching pending request returns a conflict until the first finishes.
- Reuse for another method, path, or body is rejected.
- Failed requests release their claim.
- Claims expire after 24 hours.

This works across horizontally scaled API replicas.

## Authorization

API keys are high-entropy bearer tokens. PostgreSQL stores only:

\[
\operatorname{HMAC-SHA256}(\text{deployment pepper},\text{API key}).
\]

Keys resolve to a tenant, name, and scopes. Queries retain explicit tenant
predicates even when they start from globally unique UUIDs. The bootstrap key
has the wildcard scope; its administrative API can provision narrower keys
without ever persisting plaintext secret material. Provisioning and revocation
produce append-only tenant security events.

## Decision semantics

Active branch weights are normalized at query time. For action \(a\):

\[
\mathbb E[U(a)] = \sum_i w_i U(x_i,a),
\]

and the runtime also computes:

\[
\min_iU(x_i,a), \qquad \max_iU(x_i,a).
\]

The `expected` policy maximizes expected utility. The `robust` policy maximizes
worst-case utility, then expected utility.

The `distributionally_robust` policy minimizes expected utility over every
branch distribution \(q\) inside a supplied KL-divergence radius:

\[
\min_{q:D_{\mathrm{KL}}(q\Vert p)\le\rho} q\cdot U.
\]

The kernel solves the exponential-tilt dual and returns the adversarial
distribution, making the source of the robustness penalty inspectable.

Experiments are ranked by mutual information:

\[
I(B;O)=H(B)-\mathbb E_O[H(B\mid O)].
\]

Requests must supply a value or outcome distribution for every active branch.
Partial branch coverage is rejected.

The durable authorization path operates on the product fiber:

\[
\mathcal X_t\times\mathcal M_t.
\]

It requires one finite utility for every active world and assumption pair and
selects the joint-maximin action. Verified guarantees act as proof gates.
Contradicting an assumption suspends its dependent gates and revokes affected
permits in the same transaction.

See [Assurance kernel and revocation semantics](ASSURANCE-KERNEL.md).

## Certified fiber discovery and continuation

For a rational target, the algebraic solver reduces the inverse map to a cubic
or to the exact special-plane quadratic. Durand-Kerner iteration supplies only
candidate centers. The runtime converts their exact binary representations to
arbitrary-precision rationals and proves one root per disc with conservative
Rouché inequalities.

Completeness is structural: three disjoint one-root discs exhaust the cubic.
The target plane \(C=0\) is exhausted by one exact flat-sheet identity and
every root of its curved-sheet quadratic.

When an observation advances, the runtime solves a minimum-cost bipartite
assignment between predecessor and successor coordinates with the Hungarian
algorithm. The observation, evidence, complete successor fiber, predecessor
supersession, parent IDs, correspondence cost, certificates, and event-chain
head commit atomically.

See [Fiber kernel and certificate semantics](FIBER-KERNEL.md).

Each solver branch also receives an escape score based on hidden-state norm
amplification relative to observation norm. This surfaces nonproper sequences
whose internal coordinates diverge while their visible target stays bounded.

## Bayesian evidence

Likelihood evidence is a mutation, not a read-side score. The runtime:

1. requires one finite log likelihood for every active branch;
2. names the likelihood model, its version, and its conditional-independence
   assumption;
3. normalizes with log-sum-exp;
4. updates every weight in the locked case transaction;
5. records entropy, log evidence, and realized KL information gain;
6. appends one audit event containing the complete prior-to-posterior mapping.

## Exact Jacobian verifier

The built-in verifier is an example of a privileged validity mechanism, not a
special storage path. It:

- parses rational coordinates into arbitrary-precision integers;
- evaluates the polynomial map without floating point;
- computes the symbolic Jacobian determinant using sparse polynomials;
- verifies the determinant is the constant `-2`;
- emits the exact input, computed image, expected image, and verifier identity.

The resulting certificate enters the same branch-validation command and audit
chain as any other verifier.

## Scaling

The API is stateless outside PostgreSQL and can run with multiple replicas.
Contention is per case because each case is its own serialized epistemic state
machine. Unrelated cases mutate concurrently.

Read paths use indexed tenant/case keys. Ledger verification currently loads one
case ledger into memory; incremental event consumption is paginated. Very large
ledgers should add streaming verification or periodic externally anchored
checkpoints without weakening the underlying hash chain.
