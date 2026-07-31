CREATE TABLE assumptions (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL,
    case_id UUID NOT NULL,
    label TEXT NOT NULL CHECK (char_length(label) BETWEEN 1 AND 256),
    statement JSONB NOT NULL,
    weight DOUBLE PRECISION NOT NULL CHECK (
        weight >= 0
        AND weight::TEXT NOT IN ('NaN', 'Infinity', '-Infinity')
    ),
    status TEXT NOT NULL CHECK (
        status IN ('proposed', 'active', 'contradicted', 'superseded', 'archived')
    ),
    generation INTEGER NOT NULL CHECK (generation >= 0),
    parent_ids UUID[] NOT NULL DEFAULT '{}',
    validity JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    FOREIGN KEY (tenant_id, case_id) REFERENCES cases(tenant_id, id),
    UNIQUE (tenant_id, id),
    UNIQUE (tenant_id, case_id, id)
);
CREATE INDEX assumptions_case_status_idx
    ON assumptions(tenant_id, case_id, status, generation, created_at);
CREATE INDEX assumptions_parent_ids_idx ON assumptions USING GIN(parent_ids);

CREATE TABLE assumption_evidence (
    tenant_id UUID NOT NULL,
    assumption_id UUID NOT NULL,
    evidence_id UUID NOT NULL,
    relation TEXT NOT NULL CHECK (
        relation IN ('supports', 'contradicts', 'derives', 'qualifies')
    ),
    note TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    FOREIGN KEY (tenant_id, assumption_id) REFERENCES assumptions(tenant_id, id),
    FOREIGN KEY (tenant_id, evidence_id) REFERENCES evidence(tenant_id, id),
    PRIMARY KEY (tenant_id, assumption_id, evidence_id, relation)
);

CREATE TABLE guarantees (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL,
    case_id UUID NOT NULL,
    label TEXT NOT NULL CHECK (char_length(label) BETWEEN 1 AND 256),
    description TEXT NOT NULL CHECK (char_length(description) BETWEEN 1 AND 4000),
    verifier_id TEXT NOT NULL CHECK (char_length(verifier_id) BETWEEN 1 AND 128),
    specification JSONB NOT NULL,
    premise_assumption_ids UUID[] NOT NULL DEFAULT '{}',
    parent_ids UUID[] NOT NULL DEFAULT '{}',
    status TEXT NOT NULL CHECK (
        status IN (
            'proposed',
            'verified',
            'contradicted',
            'suspended',
            'superseded',
            'archived'
        )
    ),
    verification JSONB NOT NULL DEFAULT '{}'::jsonb,
    counterexample_count BIGINT NOT NULL DEFAULT 0 CHECK (counterexample_count >= 0),
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    FOREIGN KEY (tenant_id, case_id) REFERENCES cases(tenant_id, id),
    UNIQUE (tenant_id, id),
    UNIQUE (tenant_id, case_id, id)
);
CREATE INDEX guarantees_case_status_idx
    ON guarantees(tenant_id, case_id, status, created_at);
CREATE INDEX guarantees_premise_ids_idx
    ON guarantees USING GIN(premise_assumption_ids);
CREATE INDEX guarantees_parent_ids_idx ON guarantees USING GIN(parent_ids);

CREATE TABLE guarantee_evidence (
    tenant_id UUID NOT NULL,
    guarantee_id UUID NOT NULL,
    evidence_id UUID NOT NULL,
    relation TEXT NOT NULL CHECK (
        relation IN ('supports', 'contradicts', 'derives', 'qualifies')
    ),
    note TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    FOREIGN KEY (tenant_id, guarantee_id) REFERENCES guarantees(tenant_id, id),
    FOREIGN KEY (tenant_id, evidence_id) REFERENCES evidence(tenant_id, id),
    PRIMARY KEY (tenant_id, guarantee_id, evidence_id, relation)
);

CREATE TABLE counterexamples (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL,
    case_id UUID NOT NULL,
    guarantee_id UUID NOT NULL,
    verifier_id TEXT NOT NULL CHECK (char_length(verifier_id) BETWEEN 1 AND 128),
    witness JSONB NOT NULL,
    certificate JSONB NOT NULL,
    certificate_hash BYTEA NOT NULL CHECK (octet_length(certificate_hash) = 32),
    source TEXT NOT NULL CHECK (char_length(source) BETWEEN 1 AND 256),
    created_at TIMESTAMPTZ NOT NULL,
    FOREIGN KEY (tenant_id, case_id, guarantee_id)
        REFERENCES guarantees(tenant_id, case_id, id),
    UNIQUE (tenant_id, id)
);
CREATE INDEX counterexamples_guarantee_idx
    ON counterexamples(tenant_id, case_id, guarantee_id, created_at);

CREATE TRIGGER counterexamples_reject_update
BEFORE UPDATE ON counterexamples
FOR EACH ROW EXECUTE FUNCTION reject_event_mutation();

CREATE TRIGGER counterexamples_reject_delete
BEFORE DELETE ON counterexamples
FOR EACH ROW EXECUTE FUNCTION reject_event_mutation();

CREATE TABLE decision_authorizations (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL,
    case_id UUID NOT NULL,
    requested_action_id TEXT NOT NULL CHECK (
        char_length(requested_action_id) BETWEEN 1 AND 128
    ),
    selected_action_id TEXT NOT NULL CHECK (
        char_length(selected_action_id) BETWEEN 1 AND 128
    ),
    status TEXT NOT NULL CHECK (status IN ('authorized', 'denied', 'revoked')),
    policy TEXT NOT NULL CHECK (policy = 'joint_maximin'),
    required_guarantee_ids UUID[] NOT NULL DEFAULT '{}',
    required_assumption_ids UUID[] NOT NULL DEFAULT '{}',
    input JSONB NOT NULL,
    result JSONB NOT NULL,
    input_hash BYTEA NOT NULL CHECK (octet_length(input_hash) = 32),
    created_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    revocation JSONB,
    updated_at TIMESTAMPTZ NOT NULL,
    FOREIGN KEY (tenant_id, case_id) REFERENCES cases(tenant_id, id),
    UNIQUE (tenant_id, id),
    CHECK (
        (status IN ('authorized', 'denied') AND revoked_at IS NULL AND revocation IS NULL)
        OR
        (status = 'revoked' AND revoked_at IS NOT NULL AND revocation IS NOT NULL)
    )
);
CREATE INDEX decision_authorizations_case_status_idx
    ON decision_authorizations(tenant_id, case_id, status, created_at DESC);
CREATE INDEX decision_authorizations_guarantees_idx
    ON decision_authorizations USING GIN(required_guarantee_ids);
CREATE INDEX decision_authorizations_assumptions_idx
    ON decision_authorizations USING GIN(required_assumption_ids);

CREATE TRIGGER decision_authorizations_reject_delete
BEFORE DELETE ON decision_authorizations
FOR EACH ROW EXECUTE FUNCTION reject_event_mutation();
