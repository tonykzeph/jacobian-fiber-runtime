CREATE TABLE api_key_events (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    actor_key_id UUID NOT NULL REFERENCES api_keys(id),
    target_key_id UUID NOT NULL REFERENCES api_keys(id),
    action TEXT NOT NULL CHECK (action IN ('api_key.created', 'api_key.revoked')),
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX api_key_events_tenant_id_idx
    ON api_key_events(tenant_id, id DESC);

CREATE TRIGGER api_key_events_reject_update
BEFORE UPDATE ON api_key_events
FOR EACH ROW EXECUTE FUNCTION reject_event_mutation();

CREATE TRIGGER api_key_events_reject_delete
BEFORE DELETE ON api_key_events
FOR EACH ROW EXECUTE FUNCTION reject_event_mutation();
