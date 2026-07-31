# Fiber kernel and certificate semantics

## Purpose

The fiber kernel turns an observation into a complete, machine-checkable branch
set. It is not an LLM branch generator. For the built-in Keller map it solves
the inverse problem, proves that every returned sheet exists, proves that the
returned sheets are distinct, and proves that their count exhausts the inverse
equation.

The implementation deliberately separates:

1. numerical proposal;
2. exact admissibility;
3. complete fiber materialization;
4. continuation through a new observation.

Floating-point arithmetic may suggest isolating discs, but cannot activate a
branch. Activation requires exact arbitrary-precision rational inequalities.

## Inverse reduction

For the announced map, write:

\[
F(x,y,z)=
\left(
u^3z+y^2u(4+3xy),
y+3xu^2z+3xy^2(4+3xy),
2x-3x^2y-x^3z
\right),
\qquad u=1+xy.
\]

For a rational target \((A,B,C)\) with \(C\neq0\), define:

\[
P=\frac{BC}{4},
\qquad
Q=\frac{AC^2}{4}.
\]

Every finite preimage corresponds to a root of:

\[
f(w)=w^3-w^2+Pw-Q.
\]

For a root \(w\), reconstruction is:

\[
\gamma=P-2w+3w^2,
\quad
u=\frac{w}{\gamma},
\quad
v=u-1,
\]

\[
x=\frac{C}{2\gamma},
\quad
y=\frac{v}{x},
\quad
t=2\left(1-\frac32v-\gamma\right),
\quad
z=\frac{t}{x^2}.
\]

The kernel also proves that the isolating disc excludes every zero of
\(\gamma\). The reconstruction is therefore analytic throughout the certified
disc and defines exactly one finite preimage.

## Exact Rouché certificate

Durand-Kerner iteration proposes a complex center \(c\). The exact IEEE-754
value of each center component is converted to a dyadic `BigRational`; it is
not rounded to a decimal.

For \(h=w-c\):

\[
f(c+h)=
f(c)+f'(c)h+(3c-1)h^2+h^3.
\]

For a positive rational radius \(r\), the kernel evaluates the sufficient
inequality:

\[
\lVert f(c)\rVert_1
+
\lVert3c-1\rVert_1r^2
+
r^3
<
\lVert f'(c)\rVert_\infty r.
\]

The left side is an exact upper bound for the nonlinear terms on
\(|h|=r\). The right side is an exact lower bound for the linear term.
Rouché's theorem therefore gives exactly one root inside the disc.

The use of the complex \(L_1\) norm for upper bounds and \(L_\infty\) norm for
lower bounds is conservative but keeps the certificate entirely rational.
No floating-point comparison participates in branch validity.

The three discs are then checked for pairwise disjointness with exact rational
inequalities. Three disjoint one-root discs exhaust a cubic, which is the
fiber-completeness certificate.

## The target plane \(C=0\)

The inverse reduction has a separate exact chart at \(C=0\).

The flat sheet is:

\[
(x,y,z)=(0,B,A-4B^2).
\]

The curved sheets are parameterized by every root of:

\[
(B^2-16A)x^2-4=0,
\]

followed by:

\[
v=\frac{Bx-6}{4},
\qquad
y=\frac vx,
\qquad
z=\frac{2-3v}{x^2}.
\]

The quadratic roots receive the same exact one-root-disc treatment. Thus the
announced target \((-1/4,0,0)\) is materialized automatically as one flat and
two curved sheets.

## Continuation

Advancing a case performs a single PostgreSQL transaction:

1. lock and version-check the case;
2. solve and certify the complete successor fiber;
3. store the new observation as evidence;
4. compute normalized complex-coordinate distances between predecessor and
   successor sheet centers;
5. solve the minimum-cost bipartite assignment with the Hungarian algorithm;
6. supersede every predecessor;
7. create every certified successor as active with explicit parentage;
8. append one hash-chained event;
9. advance the case commitment and commit.

The assignment is global rather than greedy. This prevents two locally
attractive matches from producing a worse overall sheet identity mapping.
Correspondence distances and both endpoint IDs enter the audit event.

Continuation does not claim topological monodromy from one large jump. It
records the minimum-cost correspondence for the supplied observation step.
Applications requiring path-certified monodromy should submit sufficiently
fine steps or add a path tracker verifier.

## Escape telemetry

For every reconstructed sheet, the kernel reports:

\[
E(x,y)=
\max\left(
0,
\log_{10}\frac{1+\lVert x\rVert_2}{1+\lVert y\rVert_2}
\right).
\]

This is not a probability. It is a scale-free operational indicator that the
hidden preimage is becoming large relative to its observation. A branch can
therefore surface the counterexample's nonproper behavior before a coordinate
overflows or disappears at the asymptotic boundary.

## Bayesian evidence transition

For active branch prior \(p_i\) and supplied log likelihood \(\ell_i\), the
runtime computes:

\[
\log Z=\operatorname{logsumexp}_i(\log p_i+\ell_i),
\qquad
p_i'=\exp(\log p_i+\ell_i-\log Z).
\]

The evidence record, declared likelihood-model identity, conditional
independence assumption, prior, likelihoods, posterior, entropy change, and
realized KL information gain are committed in one event. Every active branch
must be covered exactly once.

The runtime validates the arithmetic and transition. It does not prove that a
domain likelihood model is calibrated; that responsibility is deliberately
named and auditable.

## Distributionally robust decisions

Besides expected utility and maximin, the decision kernel supports a
KL-divergence ambiguity set:

\[
\min_q \sum_i q_i U_i
\quad\text{subject to}\quad
D_{\mathrm{KL}}(q\Vert p)\le \rho.
\]

The adversarial distribution has the exponential-tilt form:

\[
q_i(\eta)
\propto
p_i\exp\left(-\frac{U_i}{\eta}\right).
\]

The runtime solves the one-dimensional dual temperature by bisection and
returns both the robust utility and the adversarial branch distribution. As
\(\rho\) moves from zero toward the concentration threshold, the policy moves
continuously from expected utility toward maximin.

## Trust boundary

The algebraic certificate is stronger than an arbitrary JSON certificate:

- its numerical proposal is not trusted;
- all decisive inequalities are recomputed with `BigRational`;
- the determinant identity is recomputed symbolically;
- completeness is tied to the exact inverse-polynomial degree;
- the certificate and transition are included in the case hash chain.

This is still ordinary verified Rust, not a proof-assistant kernel. Independent
Lean and Isabelle formalizations of the underlying counterexample exist. A
future high-assurance deployment can require a proof-assistant artifact hash in
addition to the runtime certificate.

Ledger verification and semantic verification are separate endpoints. The
ledger audit proves event integrity. The semantic audit re-solves the current
observation, reissues exact root certificates, and matches the recomputed
complete fiber against every recorded active branch. Neither result substitutes
for the other.

## Provenance

The inverse reduction and reconstruction formulas are described in
<https://jacobianfun.org/jacobian-explained>. Independent formal verification
of the map is available from the Archive of Formal Proofs:
<https://isa-afp.org/entries/Jacobian_Counterexample.html>.
