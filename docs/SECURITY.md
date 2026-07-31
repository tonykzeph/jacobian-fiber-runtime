# Security model

## Protected assets

- Hidden branch states and evidence.
- Tenant isolation.
- The ability to activate, contradict, split, or merge branches.
- Audit-chain integrity and attribution.
- Database and API-key secrets.

## Authentication

Bearer API keys must contain at least 32 characters. The service stores only an
HMAC-SHA-256 digest using a deployment-specific pepper. The pepper and bootstrap
key must come from a secret manager in production, not an image or repository.

The bootstrap key is reconciled at startup. Rotation procedure:

1. Replace `JFR_BOOTSTRAP_API_KEY` in the secret manager.
2. Roll the service.
3. Confirm authentication with the new key.
4. Remove the old key from clients.

The environment value replaces the stored digest atomically during startup.

## Authorization

Scopes are:

- `runtime:read`
- `runtime:write`
- `runtime:validate`
- `admin:keys`
- `*`

Validation is separate because it changes which hidden states are permitted to
influence decisions. Give verifier services `runtime:validate`; do not give
ordinary proposal agents that scope.

The wildcard bootstrap key can provision narrower keys through `POST
/api/v1/keys`. The caller supplies a high-entropy token over TLS; JFR persists
only its HMAC digest and returns only non-secret metadata. Key creation and
revocation are recorded in an append-only tenant security-event table. The API
refuses to revoke the key authenticating the current request.

## Browser boundary

The operator console stores its API key in `sessionStorage`, not persistent
browser storage or cookies. It is therefore protected from CSRF by the bearer
header model. It remains sensitive to malicious JavaScript executing on the
same origin, so:

- CSP permits only same-origin scripts and styles.
- No CDN or third-party analytics are loaded.
- Secrets must never be placed in URLs.
- Deploy TLS at the ingress.
- Keep the JFR origin dedicated to JFR.

## HTTP controls

The server configures:

- one-megabyte default request-body limit;
- request timeout;
- concurrency limit;
- request IDs and structured traces;
- panic containment;
- gzip compression;
- `nosniff`, CSP, referrer, and permissions policies;
- explicit CORS origin when configured;
- sensitive `Authorization` header treatment.

Production ingress should additionally provide TLS, IP policy where applicable,
and volumetric denial-of-service protection.

## Persistence boundary

Case mutations are transactionally serialized. Event updates and deletions are
rejected by database triggers. This protects against application bugs and
ordinary role misuse.

A PostgreSQL superuser can still disable triggers or rewrite commitments.
For protection from the database administrator, export each important case head
and sign or anchor it in an independent system.

Backups contain sensitive hidden states. Encrypt them, restrict restore
permissions, and test restoration regularly.

## Certificate trust

The runtime proves that a named API key recorded a certificate. A generic JSON
certificate is not automatically true. Trust comes from:

- the validator key’s authorization;
- the verifier implementation and version named in the certificate;
- referenced evidence;
- reproducible inputs;
- external signatures when needed.

The built-in Jacobian verifier is stronger because the Rust service recomputes
the exact certificate itself.

The finite-domain guarantee verifier has the same privileged boundary. It
validates expression size, enumerates every declared integer assignment, and
uses arbitrary-precision rational arithmetic. Generated proofs and witnesses
are treated as untrusted proposals. Only the in-process verifier can transition
a guarantee to `verified` or `contradicted`.

Guarantee scope is finite and explicit. A certificate for `x ∈ [-12,12]` is not
evidence about `x = 13`, continuous inputs, omitted variables, or the external
truth of an assumption referenced by the guarantee.

Action permits are durable and revocable. Their complete input is canonically
hashed, their direct and transitive dependencies are stored, and invalidating a
dependency revokes them atomically. Downstream executors must check that a
permit is still `authorized` immediately before acting; caching a prior response
turns revocation into a best-effort signal and is outside JFR's guarantee.

The algebraic fiber solver has an explicit numerical/exact boundary:

- floating-point root finding can only propose disc centers;
- the exact IEEE-754 centers are converted to dyadic rationals;
- branch activation requires exact Rouché inequalities;
- reconstruction denominators must be certified nonzero;
- root discs must be pairwise disjoint;
- the certified roots must exhaust the inverse polynomial degree.

A numerical failure therefore produces no branch rather than a weakly
validated branch. This prevents a convergence heuristic from silently becoming
an authorization decision.

Likelihood updates name their model and conditional-independence assumption,
but JFR does not establish model calibration. A compromised validator can still
submit systematically misleading likelihoods. Separate model review, signed
artifacts, and calibration monitoring are required for high-consequence use.
