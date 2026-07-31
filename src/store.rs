use std::time::Duration;

use secrecy::ExposeSecret;
use sqlx::{
    PgPool,
    postgres::{PgConnectOptions, PgPoolOptions},
};
use uuid::Uuid;

use crate::{
    Config, JfrError, Result,
    model::{
        AssumptionRecord, AssumptionRow, BranchRecord, BranchRow, CaseRecord, CounterexampleRecord,
        DecisionAuthorizationRecord, EventRecord, EvidenceRecord, GuaranteeRecord, GuaranteeRow,
    },
};

#[derive(Clone)]
pub struct PgStore {
    pool: PgPool,
}

impl PgStore {
    pub async fn connect(config: &Config) -> Result<Self> {
        let options: PgConnectOptions =
            config
                .database_url
                .expose_secret()
                .parse()
                .map_err(|error| {
                    JfrError::Configuration(format!("invalid JFR_DATABASE_URL: {error}"))
                })?;
        let pool = PgPoolOptions::new()
            .min_connections(config.database_min_connections)
            .max_connections(config.database_max_connections)
            .acquire_timeout(config.database_acquire_timeout)
            .idle_timeout(Some(Duration::from_mins(10)))
            .max_lifetime(Some(Duration::from_mins(30)))
            .connect_with(options)
            .await?;
        Ok(Self { pool })
    }

    #[must_use]
    pub const fn pool(&self) -> &PgPool {
        &self.pool
    }

    pub async fn migrate(&self) -> Result<()> {
        sqlx::migrate!("./migrations")
            .run(&self.pool)
            .await
            .map_err(|error| JfrError::Internal(format!("migration failed: {error}")))
    }

    pub async fn ping(&self) -> Result<()> {
        sqlx::query("SELECT 1").execute(&self.pool).await?;
        Ok(())
    }

    pub async fn list_cases(&self, tenant_id: Uuid, limit: i64) -> Result<Vec<CaseRecord>> {
        Ok(sqlx::query_as::<_, CaseRecord>(
            r"
            SELECT id, tenant_id, name, observation, metadata, version,
                   audit_event_count, audit_head_hash, created_at, updated_at
              FROM cases
             WHERE tenant_id = $1
             ORDER BY updated_at DESC, id DESC
             LIMIT $2
            ",
        )
        .bind(tenant_id)
        .bind(limit.clamp(1, 200))
        .fetch_all(&self.pool)
        .await?)
    }

    pub async fn get_case(&self, tenant_id: Uuid, case_id: Uuid) -> Result<CaseRecord> {
        sqlx::query_as::<_, CaseRecord>(
            r"
            SELECT id, tenant_id, name, observation, metadata, version,
                   audit_event_count, audit_head_hash, created_at, updated_at
              FROM cases
             WHERE tenant_id = $1 AND id = $2
            ",
        )
        .bind(tenant_id)
        .bind(case_id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| JfrError::NotFound(format!("case {case_id} was not found")))
    }

    pub async fn list_evidence(
        &self,
        tenant_id: Uuid,
        case_id: Uuid,
    ) -> Result<Vec<EvidenceRecord>> {
        Ok(sqlx::query_as::<_, EvidenceRecord>(
            r"
            SELECT id, tenant_id, case_id, kind, payload, source,
                   observed_at, created_at
              FROM evidence
             WHERE tenant_id = $1 AND case_id = $2
             ORDER BY observed_at, created_at, id
            ",
        )
        .bind(tenant_id)
        .bind(case_id)
        .fetch_all(&self.pool)
        .await?)
    }

    pub async fn list_branches(
        &self,
        tenant_id: Uuid,
        case_id: Uuid,
        status: Option<&str>,
    ) -> Result<Vec<BranchRecord>> {
        let rows = sqlx::query_as::<_, BranchRow>(
            r"
            SELECT id, tenant_id, case_id, label, state, weight, status,
                   generation, parent_ids, validity, risk_score,
                   created_at, updated_at
              FROM branches
             WHERE tenant_id = $1
               AND case_id = $2
               AND ($3::TEXT IS NULL OR status = $3)
             ORDER BY generation, created_at, id
            ",
        )
        .bind(tenant_id)
        .bind(case_id)
        .bind(status)
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter()
            .map(|row| row.try_into().map_err(JfrError::Internal))
            .collect()
    }

    pub async fn get_branch(&self, tenant_id: Uuid, branch_id: Uuid) -> Result<BranchRecord> {
        let row = sqlx::query_as::<_, BranchRow>(
            r"
            SELECT id, tenant_id, case_id, label, state, weight, status,
                   generation, parent_ids, validity, risk_score,
                   created_at, updated_at
              FROM branches
             WHERE tenant_id = $1 AND id = $2
            ",
        )
        .bind(tenant_id)
        .bind(branch_id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| JfrError::NotFound(format!("branch {branch_id} was not found")))?;
        row.try_into().map_err(JfrError::Internal)
    }

    pub async fn list_assumptions(
        &self,
        tenant_id: Uuid,
        case_id: Uuid,
        status: Option<&str>,
    ) -> Result<Vec<AssumptionRecord>> {
        let rows = sqlx::query_as::<_, AssumptionRow>(
            r"
            SELECT id, tenant_id, case_id, label, statement, weight, status,
                   generation, parent_ids, validity, created_at, updated_at
              FROM assumptions
             WHERE tenant_id = $1
               AND case_id = $2
               AND ($3::TEXT IS NULL OR status = $3)
             ORDER BY generation, created_at, id
            ",
        )
        .bind(tenant_id)
        .bind(case_id)
        .bind(status)
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter()
            .map(|row| row.try_into().map_err(JfrError::Internal))
            .collect()
    }

    pub async fn get_assumption(
        &self,
        tenant_id: Uuid,
        assumption_id: Uuid,
    ) -> Result<AssumptionRecord> {
        let row = sqlx::query_as::<_, AssumptionRow>(
            r"
            SELECT id, tenant_id, case_id, label, statement, weight, status,
                   generation, parent_ids, validity, created_at, updated_at
              FROM assumptions
             WHERE tenant_id = $1 AND id = $2
            ",
        )
        .bind(tenant_id)
        .bind(assumption_id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| JfrError::NotFound(format!("assumption {assumption_id} was not found")))?;
        row.try_into().map_err(JfrError::Internal)
    }

    pub async fn list_guarantees(
        &self,
        tenant_id: Uuid,
        case_id: Uuid,
    ) -> Result<Vec<GuaranteeRecord>> {
        let rows = sqlx::query_as::<_, GuaranteeRow>(
            r"
            SELECT id, tenant_id, case_id, label, description, verifier_id,
                   specification, premise_assumption_ids, parent_ids, status,
                   verification, counterexample_count, created_at, updated_at
              FROM guarantees
             WHERE tenant_id = $1 AND case_id = $2
             ORDER BY created_at, id
            ",
        )
        .bind(tenant_id)
        .bind(case_id)
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter()
            .map(|row| row.try_into().map_err(JfrError::Internal))
            .collect()
    }

    pub async fn get_guarantee(
        &self,
        tenant_id: Uuid,
        guarantee_id: Uuid,
    ) -> Result<GuaranteeRecord> {
        let row = sqlx::query_as::<_, GuaranteeRow>(
            r"
            SELECT id, tenant_id, case_id, label, description, verifier_id,
                   specification, premise_assumption_ids, parent_ids, status,
                   verification, counterexample_count, created_at, updated_at
              FROM guarantees
             WHERE tenant_id = $1 AND id = $2
            ",
        )
        .bind(tenant_id)
        .bind(guarantee_id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| JfrError::NotFound(format!("guarantee {guarantee_id} was not found")))?;
        row.try_into().map_err(JfrError::Internal)
    }

    pub async fn list_counterexamples(
        &self,
        tenant_id: Uuid,
        case_id: Uuid,
    ) -> Result<Vec<CounterexampleRecord>> {
        Ok(sqlx::query_as::<_, CounterexampleRecord>(
            r"
            SELECT id, tenant_id, case_id, guarantee_id, verifier_id, witness,
                   certificate, certificate_hash, source, created_at
              FROM counterexamples
             WHERE tenant_id = $1 AND case_id = $2
             ORDER BY created_at, id
            ",
        )
        .bind(tenant_id)
        .bind(case_id)
        .fetch_all(&self.pool)
        .await?)
    }

    pub async fn list_authorizations(
        &self,
        tenant_id: Uuid,
        case_id: Uuid,
    ) -> Result<Vec<DecisionAuthorizationRecord>> {
        Ok(sqlx::query_as::<_, DecisionAuthorizationRecord>(
            r"
            SELECT id, tenant_id, case_id, requested_action_id, selected_action_id,
                   status, policy, required_guarantee_ids, required_assumption_ids,
                   input, result, input_hash, created_at, revoked_at, revocation,
                   updated_at
              FROM decision_authorizations
             WHERE tenant_id = $1 AND case_id = $2
             ORDER BY created_at, id
            ",
        )
        .bind(tenant_id)
        .bind(case_id)
        .fetch_all(&self.pool)
        .await?)
    }

    pub async fn list_events(
        &self,
        tenant_id: Uuid,
        case_id: Uuid,
        after: i64,
        limit: i64,
    ) -> Result<Vec<EventRecord>> {
        Ok(sqlx::query_as::<_, EventRecord>(
            r"
            SELECT case_id, sequence, tenant_id, event_type, payload,
                   previous_hash, event_hash, actor_key_id, created_at
              FROM events
             WHERE tenant_id = $1
               AND case_id = $2
               AND sequence > $3
             ORDER BY sequence
             LIMIT $4
            ",
        )
        .bind(tenant_id)
        .bind(case_id)
        .bind(after.max(0))
        .bind(limit.clamp(1, 1_000))
        .fetch_all(&self.pool)
        .await?)
    }

    pub async fn all_events(&self, tenant_id: Uuid, case_id: Uuid) -> Result<Vec<EventRecord>> {
        Ok(sqlx::query_as::<_, EventRecord>(
            r"
            SELECT case_id, sequence, tenant_id, event_type, payload,
                   previous_hash, event_hash, actor_key_id, created_at
              FROM events
             WHERE tenant_id = $1 AND case_id = $2
             ORDER BY sequence
            ",
        )
        .bind(tenant_id)
        .bind(case_id)
        .fetch_all(&self.pool)
        .await?)
    }
}
