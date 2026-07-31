# Operations

## Required configuration

| Variable | Meaning |
| --- | --- |
| `JFR_DATABASE_URL` | PostgreSQL connection URL |
| `JFR_API_KEY_PEPPER` | Deployment secret, at least 32 characters |
| `JFR_BOOTSTRAP_API_KEY` | Initial operator key, at least 32 characters |
| `JFR_BOOTSTRAP_TENANT` | Initial tenant name |
| `JFR_BOOTSTRAP_KEY_NAME` | Audit-visible key name |
| `JFR_BIND` | Listener address, default `0.0.0.0:8080` |
| `JFR_LOG_FORMAT` | `json` or `pretty` |
| `JFR_MAX_REQUEST_BYTES` | Request limit, default 1 MiB |
| `JFR_REQUEST_TIMEOUT_SECONDS` | Request timeout, default 20 |
| `JFR_DATABASE_MAX_CONNECTIONS` | Pool maximum, default 20 |
| `JFR_DATABASE_MIN_CONNECTIONS` | Pool minimum, default 2 |
| `JFR_ALLOWED_ORIGIN` | Optional cross-origin console origin |
| `RUST_LOG` | Tracing filter |

## Startup

Startup is fail-closed:

1. Configuration and secret lengths are validated.
2. PostgreSQL connections are established.
3. Embedded SQL migrations run.
4. The bootstrap tenant and key are reconciled.
5. The listener starts.

The service does not listen if any required stage fails.

## Health

- `/health/live` confirms the process event loop is serving.
- `/health/ready` performs a PostgreSQL query.
- `/metrics` exposes OpenMetrics counters.

Minimum alerts:

- readiness unavailable for two consecutive intervals;
- elevated `jfr_request_failures_total`;
- authentication-failure bursts;
- database pool exhaustion;
- PostgreSQL disk or replication lag;
- failed case audit verification.

## Logs

JSON is the default. HTTP traces carry `x-request-id`; the same ID is propagated
in the response. Authorization values are marked sensitive before tracing.

Never increase body logging globally. Evidence and branch state can contain
secrets.

## Backups

Use PostgreSQL-native continuous archiving or managed point-in-time recovery.
At minimum:

```bash
pg_dump --format=custom --no-owner --file=jfr.dump "$JFR_DATABASE_URL"
pg_restore --clean --if-exists --no-owner --dbname="$RESTORE_DATABASE_URL" jfr.dump
```

After restore:

1. Start JFR against the restored database.
2. Query every critical case’s `/audit` endpoint.
3. Compare head hashes with externally stored anchors.
4. Exercise a new mutation on a disposable case.

## Horizontal deployment

Multiple service replicas may share one PostgreSQL database:

- mutation idempotency is stored in PostgreSQL;
- expected versions prevent stale writes;
- `FOR UPDATE` serializes one case at a time;
- different cases remain concurrent;
- the UI and static assets are embedded identically in every binary.

Use rolling replacement with readiness gates and graceful SIGTERM. The service
stops accepting connections and allows in-flight requests to finish.

## Migrations

Migrations are embedded and run before the listener starts. They must be
forward-compatible with the previous service version for zero-downtime rolling
deployments. Destructive schema changes require a separate expand/migrate/
contract sequence.

Event ledger rows are immutable. Never edit a migration already applied to a
shared environment; add a new numbered migration.
