# Assurance kernel

## Purpose

The assurance kernel makes assumptions, mathematical guarantees, and action
permissions part of the runtime state. It closes a gap in ordinary decision
systems: a decision can be correct under the current world estimate and still
be invalid because the model assumptions used to justify it have failed.

For a case at time \(t\), JFR now persists:

\[
\mathcal R_t =
(y_t,\mathcal X_t,\mathcal M_t,\mathcal G_t,\mathcal A_t).
\]

- \(y_t\) is the shared observation.
- \(\mathcal X_t\) is the active world-state fiber.
- \(\mathcal M_t\) is the active assumption fiber.
- \(\mathcal G_t\) is the guarantee graph.
- \(\mathcal A_t\) is the set of durable action-authorization records.

This is deliberately two-dimensional. World ambiguity and model ambiguity are
not collapsed into one list.

## Assumption fiber

An assumption is a versioned branch with a JSON statement, non-negative weight,
status, evidence links, certificate material, parent IDs, and generation:

```text
proposed ──validation──▶ active
    │                       │
    └──contradiction────────┴──▶ contradicted
```

The runtime does not interpret an arbitrary assumption statement as true.
Activation records who asserted it, why, and under which certificate. Its
identity is nevertheless first-class: guarantees reference assumption UUIDs,
not mutable labels or copied prose.

## Exact finite-domain guarantees

The first trusted guarantee verifier is:

```text
jfr.finite-rational-refutation.v1
```

A specification declares:

1. one to twelve integer variables;
2. a closed finite interval for each variable;
3. zero or more Boolean premises;
4. one Boolean claim.

Scalar expressions support exact constants, variables, addition,
subtraction, multiplication, division, negation, absolute value, and bounded
integer powers. Boolean expressions support exact comparisons and `all`,
`any`, and `not`.

Constants are parsed as integers, fractions, or decimals and evaluated with
arbitrary-precision `BigRational`. Floating point does not participate in proof
truth.

The declared Cartesian domain is capped at one million assignments. Expression
depth, node count, variable count, integer magnitude, rational magnitude, and
power are also bounded before execution. These are verifier resource limits,
not mathematical approximations.

### Proof

The verifier enumerates the complete Cartesian domain in deterministic
lexicographic order. For assignment \(z\), it first evaluates every premise:

\[
P(z)=\bigwedge_j P_j(z).
\]

Only eligible assignments \(P(z)=\mathrm{true}\) enter the claim check. A
guarantee is verified iff:

\[
\forall z\in D,\quad P(z)\Rightarrow C(z).
\]

The certificate records the verifier ID, canonical specification hash, total
domain size, examined assignments, eligible assignments, completion flag,
method, and certificate digest. Verification therefore means the declared
bounded theorem was exhausted; it does not mean the claim holds outside the
declared domain.

### Refutation

Search stops at the first lexicographic assignment satisfying every premise and
falsifying the claim. That assignment is an exact counterexample:

\[
P(z^\*)=\mathrm{true},\qquad C(z^\*)=\mathrm{false}.
\]

Submitted witnesses use the same parser and evaluator. The server rejects an
out-of-domain assignment, an assignment missing a variable, a failed premise,
or a witness that satisfies the claim.

Counterexample rows are append-only. Their RFC 8785 canonical certificate hash
is committed separately from the case event chain so later semantic audit can
verify both content integrity and mathematical validity.

## Guarantee lifecycle

```text
declared
   │
   ├── complete search ──▶ verified
   │
   ├── exact witness ────▶ contradicted
   │
   └── premise failure ──▶ suspended
```

A guarantee stores direct premise-assumption IDs and optional parent-guarantee
IDs. Its exact specification is immutable through the current API. A new
statement is a new guarantee, preserving the old one as lineage.

A suspended guarantee can be searched only after all premises are active
again. A verified or contradicted guarantee is terminal in the current
lifecycle. This prevents an operator from overwriting an inconvenient proof
outcome.

## Joint authorization

An authorization request contains candidate actions and a utility for every
active pair:

\[
(x_i,m_j)\in\mathcal X_t\times\mathcal M_t.
\]

Partial coverage, duplicate cells, non-finite utilities, duplicate action IDs,
an empty fiber, and excessive Cartesian products are rejected.

For action \(a\), the kernel computes:

\[
L(a)=\min_{x_i\in\mathcal X_t,\;m_j\in\mathcal M_t} U(a,x_i,m_j).
\]

It selects:

\[
a^\*=\arg\max_a L(a),
\]

breaking ties by best-case utility and then stable action ID. A requested action
is authorized only if:

1. it is \(a^\*\);
2. every required guarantee is verified;
3. every explicitly required assumption is active;
4. every premise of every required guarantee is active.

The durable record includes the canonical SHA-256 hash of the complete request,
all scores, the exact worst-case world and assumption IDs, direct guarantee
dependencies, and the transitive assumption dependencies introduced by those
guarantees.

A denial is also persisted. It answers what was evaluated and why no permit was
issued, without pretending that a failed request never happened.

## Atomic revocation

Premise contradiction is one transaction:

1. lock and version-check the case;
2. mark the assumption contradicted;
3. suspend every proposed or verified guarantee that directly references it;
4. revoke every authorized decision referencing the assumption or any newly
   suspended guarantee;
5. write the assumption event containing all affected IDs;
6. advance the case audit head;
7. commit.

Guarantee refutation follows the same pattern: insert the immutable
counterexample, mark the guarantee contradicted, revoke dependent permits,
append the event, and commit.

There is no interval in which the database exposes a failed premise alongside
an apparently valid dependent permit.

## Semantic audit

Ledger verification proves that recorded history has not changed. It does not
prove that the mathematical claims remain reproducible.

`GET /api/v1/cases/{id}/audit/semantic/guarantees` independently checks:

- verifier IDs and specification parsing;
- complete re-enumeration of every verified guarantee;
- stored specification hashes;
- exact validity of at least one witness for every contradicted guarantee;
- canonical certificate hashes for counterexamples;
- inactive premises for suspended guarantees;
- current guarantee and assumption dependencies for every live permit;
- the RFC 8785 input hash of every live permit.

The audit has a cumulative two-million-assignment budget. Exceeding that budget
produces an invalid audit entry rather than silently skipping proof
recomputation.

## Trust boundary

The generator is untrusted. It may propose a theorem, action set, utility table,
or counterexample. The Rust verifier decides whether the finite-domain proof or
witness is valid. PostgreSQL decides whether the lifecycle transition is
serializable. The audit chain commits what happened.

The kernel does not establish:

- that an arbitrary activated assumption is true in the external world;
- that supplied utilities are morally or economically correct;
- that a bounded theorem generalizes outside its declared domain;
- that the chosen finite variables capture every real hazard;
- that a database superuser cannot rewrite the database.

Those boundaries are intentional. The kernel turns hidden premises and proof
dependencies into explicit, recomputable state; it does not manufacture truth
from incomplete observations.
