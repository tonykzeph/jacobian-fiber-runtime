CREATE TABLE tenants (
    id UUID PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE api_keys (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    name TEXT NOT NULL,
    prefix TEXT NOT NULL,
    secret_hash BYTEA NOT NULL UNIQUE CHECK (octet_length(secret_hash) = 32),
    scopes TEXT[] NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    last_used_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    UNIQUE (tenant_id, name)
);
CREATE INDEX api_keys_active_hash_idx
    ON api_keys(secret_hash)
    WHERE revoked_at IS NULL;

CREATE TABLE cases (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    name TEXT NOT NULL CHECK (char_length(name) BETWEEN 1 AND 256),
    observation JSONB NOT NULL,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    version BIGINT NOT NULL DEFAULT 0 CHECK (version >= 0),
    audit_event_count BIGINT NOT NULL DEFAULT 0 CHECK (audit_event_count >= 0),
    audit_head_hash BYTEA NOT NULL CHECK (octet_length(audit_head_hash) = 32),
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    UNIQUE (tenant_id, id)
);
CREATE INDEX cases_tenant_updated_idx ON cases(tenant_id, updated_at DESC, id DESC);

CREATE TABLE evidence (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL,
    case_id UUID NOT NULL,
    kind TEXT NOT NULL CHECK (char_length(kind) BETWEEN 1 AND 128),
    payload JSONB NOT NULL,
    source TEXT NOT NULL CHECK (char_length(source) BETWEEN 1 AND 256),
    observed_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    FOREIGN KEY (tenant_id, case_id) REFERENCES cases(tenant_id, id),
    UNIQUE (tenant_id, id)
);
CREATE INDEX evidence_case_time_idx
    ON evidence(tenant_id, case_id, observed_at, id);

CREATE TABLE branches (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL,
    case_id UUID NOT NULL,
    label TEXT NOT NULL CHECK (char_length(label) BETWEEN 1 AND 256),
    state JSONB NOT NULL,
    weight DOUBLE PRECISION NOT NULL CHECK (
        weight >= 0
        AND weight::TEXT NOT IN ('NaN', 'Infinity', '-Infinity')
    ),
    status TEXT NOT NULL CHECK (
        status IN (
            'proposed',
            'active',
            'contradicted',
            'superseded',
            'merged',
            'archived'
        )
    ),
    generation INTEGER NOT NULL CHECK (generation >= 0),
    parent_ids UUID[] NOT NULL DEFAULT '{}',
    validity JSONB NOT NULL DEFAULT '{}'::jsonb,
    risk_score DOUBLE PRECISION CHECK (
        risk_score IS NULL
        OR (
            risk_score >= 0
            AND risk_score::TEXT NOT IN ('NaN', 'Infinity', '-Infinity')
        )
    ),
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    FOREIGN KEY (tenant_id, case_id) REFERENCES cases(tenant_id, id),
    UNIQUE (tenant_id, id)
);
CREATE INDEX branches_case_status_idx
    ON branches(tenant_id, case_id, status, generation, created_at);
CREATE INDEX branches_parent_ids_idx ON branches USING GIN(parent_ids);

CREATE TABLE branch_evidence (
    tenant_id UUID NOT NULL,
    branch_id UUID NOT NULL,
    evidence_id UUID NOT NULL,
    relation TEXT NOT NULL CHECK (
        relation IN ('supports', 'contradicts', 'derives', 'qualifies')
    ),
    note TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    FOREIGN KEY (tenant_id, branch_id) REFERENCES branches(tenant_id, id),
    FOREIGN KEY (tenant_id, evidence_id) REFERENCES evidence(tenant_id, id),
    PRIMARY KEY (tenant_id, branch_id, evidence_id, relation)
);

CREATE TABLE events (
    case_id UUID NOT NULL,
    sequence BIGINT NOT NULL CHECK (sequence > 0),
    tenant_id UUID NOT NULL,
    event_type TEXT NOT NULL CHECK (char_length(event_type) BETWEEN 1 AND 128),
    payload JSONB NOT NULL,
    previous_hash BYTEA NOT NULL CHECK (octet_length(previous_hash) = 32),
    event_hash BYTEA NOT NULL CHECK (octet_length(event_hash) = 32),
    actor_key_id UUID NOT NULL REFERENCES api_keys(id),
    created_at TIMESTAMPTZ NOT NULL,
    FOREIGN KEY (tenant_id, case_id) REFERENCES cases(tenant_id, id),
    PRIMARY KEY (case_id, sequence),
    UNIQUE (event_hash)
);
CREATE INDEX events_tenant_case_idx ON events(tenant_id, case_id, sequence);

CREATE TABLE idempotency_keys (
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    key TEXT NOT NULL CHECK (char_length(key) BETWEEN 8 AND 200),
    method TEXT NOT NULL,
    path TEXT NOT NULL,
    request_hash BYTEA NOT NULL CHECK (octet_length(request_hash) = 32),
    state TEXT NOT NULL CHECK (state IN ('pending', 'completed')),
    response_status INTEGER,
    response_body JSONB,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    CHECK (
        (state = 'pending' AND response_status IS NULL AND response_body IS NULL)
        OR
        (state = 'completed' AND response_status IS NOT NULL AND response_body IS NOT NULL)
    ),
    PRIMARY KEY (tenant_id, key)
);
CREATE INDEX idempotency_expiry_idx ON idempotency_keys(expires_at);

CREATE FUNCTION reject_event_mutation()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'events are append-only';
END;
$$;

CREATE TRIGGER events_reject_update
BEFORE UPDATE ON events
FOR EACH ROW EXECUTE FUNCTION reject_event_mutation();

CREATE TRIGGER events_reject_delete
BEFORE DELETE ON events
FOR EACH ROW EXECUTE FUNCTION reject_event_mutation();
