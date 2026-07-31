use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Timelike, Utc};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::{FromRow, Postgres, Transaction};
use uuid::Uuid;

use crate::{
    JfrError, Result,
    audit::{GENESIS_HASH, event_hash, verify_events},
    decision, jacobian,
    model::{
        ActionAuthorization, AddEvidence, AdvanceJacobianFiber, ApplyLikelihoodEvidence,
        AssumptionRecord, AssumptionRow, AssumptionStatus, AuditReport, AuthContext,
        AuthorizeAction, BayesianUpdate, BranchCandidate, BranchCorrespondence, BranchRecord,
        BranchRow, BranchStatus, CaseRecord, CaseSnapshot, CounterexampleRecord, CreateCase,
        CreateGuarantee, DecisionAuthorizationRecord, DecisionResult, EvaluateActions,
        EvidenceRecord, ExperimentRanking, FiberTransition, GuaranteeAuditEntry, GuaranteeRecord,
        GuaranteeRow, GuaranteeSemanticAudit, GuaranteeStatus, GuaranteeTransition,
        MaterializeJacobianFiber, MergeBranches, Mutation, PosteriorWeight, ProposeAssumption,
        ProposeBranch, PruneBranch, RankExperiments, RecordObservation, SearchGuarantee,
        SemanticBranchMatch, SemanticFiberAudit, SplitBranch, SubmitCounterexample,
        ValidateAssumption, ValidateBranch,
    },
    refutation,
    store::PgStore,
};

#[derive(Debug, FromRow)]
struct LockedCase {
    version: i64,
    audit_event_count: i64,
    audit_head_hash: Vec<u8>,
    observation: Value,
}

#[derive(Debug)]
struct LedgerCommit {
    case_version: i64,
    event_sequence: i64,
    event_hash: Vec<u8>,
}

#[derive(Clone)]
pub struct FiberRuntime {
    store: PgStore,
}

impl FiberRuntime {
    #[must_use]
    pub const fn new(store: PgStore) -> Self {
        Self { store }
    }

    #[must_use]
    pub const fn store(&self) -> &PgStore {
        &self.store
    }

    pub async fn create_case(
        &self,
        auth: &AuthContext,
        command: CreateCase,
    ) -> Result<Mutation<CaseRecord>> {
        validate_text(&command.name, "case name", 256)?;
        require_object(&command.metadata, "metadata")?;
        let case_id = Uuid::now_v7();
        let now = database_timestamp();
        let mut transaction = self.store.pool().begin().await?;
        sqlx::query(
            r"
            INSERT INTO cases
                (id, tenant_id, name, observation, metadata, version,
                 audit_event_count, audit_head_hash, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, 0, 0, $6, $7, $7)
            ",
        )
        .bind(case_id)
        .bind(auth.tenant_id)
        .bind(command.name.trim())
        .bind(&command.observation)
        .bind(&command.metadata)
        .bind(GENESIS_HASH.as_slice())
        .bind(now)
        .execute(&mut *transaction)
        .await?;
        let locked = LockedCase {
            version: 0,
            audit_event_count: 0,
            audit_head_hash: GENESIS_HASH.to_vec(),
            observation: command.observation.clone(),
        };
        let commit = append_event(
            &mut transaction,
            auth,
            case_id,
            &locked,
            "case.created",
            &json!({
                "case_id": case_id,
                "name": command.name.trim(),
                "observation": command.observation,
                "metadata": command.metadata
            }),
            now,
        )
        .await?;
        let record = fetch_case_tx(&mut transaction, auth.tenant_id, case_id).await?;
        transaction.commit().await?;
        Ok(mutation(record, commit))
    }

    pub async fn add_evidence(
        &self,
        auth: &AuthContext,
        case_id: Uuid,
        command: AddEvidence,
    ) -> Result<Mutation<EvidenceRecord>> {
        validate_text(&command.kind, "evidence kind", 128)?;
        validate_text(&command.source, "evidence source", 256)?;
        let mut transaction = self.store.pool().begin().await?;
        let locked = lock_case(&mut transaction, auth.tenant_id, case_id).await?;
        check_version(&locked, command.expected_case_version)?;
        let now = database_timestamp();
        let evidence = EvidenceRecord {
            id: Uuid::now_v7(),
            tenant_id: auth.tenant_id,
            case_id,
            kind: command.kind.trim().to_owned(),
            payload: command.payload,
            source: command.source.trim().to_owned(),
            observed_at: command.observed_at.unwrap_or(now),
            created_at: now,
        };
        insert_evidence(&mut transaction, &evidence).await?;
        let commit = append_event(
            &mut transaction,
            auth,
            case_id,
            &locked,
            "evidence.added",
            &json!({
                "evidence_id": evidence.id,
                "kind": evidence.kind,
                "payload": evidence.payload,
                "source": evidence.source,
                "observed_at": evidence.observed_at
            }),
            now,
        )
        .await?;
        transaction.commit().await?;
        Ok(mutation(evidence, commit))
    }

    pub async fn apply_likelihood_evidence(
        &self,
        auth: &AuthContext,
        case_id: Uuid,
        command: ApplyLikelihoodEvidence,
    ) -> Result<Mutation<BayesianUpdate>> {
        validate_text(&command.kind, "evidence kind", 128)?;
        validate_text(&command.source, "evidence source", 256)?;
        validate_text(&command.model.id, "likelihood model ID", 128)?;
        validate_text(&command.model.version, "likelihood model version", 128)?;
        validate_text(
            &command.model.conditional_independence,
            "conditional independence declaration",
            2_000,
        )?;
        if command
            .log_likelihood_by_branch
            .values()
            .any(|value| !value.is_finite())
        {
            return Err(JfrError::Validation(
                "log likelihoods must be finite".to_owned(),
            ));
        }

        let mut transaction = self.store.pool().begin().await?;
        let locked = lock_case(&mut transaction, auth.tenant_id, case_id).await?;
        check_version(&locked, command.expected_case_version)?;
        let rows = sqlx::query_as::<_, BranchRow>(
            r"
            SELECT id, tenant_id, case_id, label, state, weight, status,
                   generation, parent_ids, validity, risk_score,
                   created_at, updated_at
              FROM branches
             WHERE tenant_id = $1 AND case_id = $2 AND status = 'active'
             ORDER BY generation, created_at, id
             FOR UPDATE
            ",
        )
        .bind(auth.tenant_id)
        .bind(case_id)
        .fetch_all(&mut *transaction)
        .await?;
        let branches: Vec<BranchRecord> = rows
            .into_iter()
            .map(|row| row.try_into().map_err(JfrError::Internal))
            .collect::<Result<_>>()?;
        if branches.is_empty() {
            return Err(JfrError::Conflict(
                "the case has no active branches".to_owned(),
            ));
        }
        let active_ids = branches
            .iter()
            .map(|branch| branch.id)
            .collect::<BTreeSet<_>>();
        let supplied_ids = command
            .log_likelihood_by_branch
            .keys()
            .copied()
            .collect::<BTreeSet<_>>();
        if active_ids != supplied_ids {
            return Err(JfrError::Validation(
                "every active branch must have exactly one log likelihood".to_owned(),
            ));
        }
        let prior_total = branches.iter().map(|branch| branch.weight).sum::<f64>();
        if !prior_total.is_finite() || prior_total <= 0.0 {
            return Err(JfrError::Conflict(
                "active branches have no positive prior mass".to_owned(),
            ));
        }
        let priors = branches
            .iter()
            .map(|branch| branch.weight / prior_total)
            .collect::<Vec<_>>();
        let log_terms = branches
            .iter()
            .zip(&priors)
            .map(|(branch, prior)| {
                if *prior > 0.0 {
                    prior.ln() + command.log_likelihood_by_branch[&branch.id]
                } else {
                    f64::NEG_INFINITY
                }
            })
            .collect::<Vec<_>>();
        let maximum = log_terms.iter().copied().fold(f64::NEG_INFINITY, f64::max);
        if !maximum.is_finite() {
            return Err(JfrError::Validation(
                "likelihood update has no finite posterior support".to_owned(),
            ));
        }
        let normalizer = log_terms
            .iter()
            .map(|term| (*term - maximum).exp())
            .sum::<f64>();
        let log_evidence = maximum + normalizer.ln();
        let posteriors = log_terms
            .iter()
            .map(|term| (*term - log_evidence).exp())
            .collect::<Vec<_>>();
        let prior_entropy_bits = probability_entropy(&priors);
        let posterior_entropy_bits = probability_entropy(&posteriors);
        let information_gain_bits = posteriors
            .iter()
            .zip(&priors)
            .filter(|(posterior, prior)| **posterior > 0.0 && **prior > 0.0)
            .map(|(posterior, prior)| posterior * (posterior / prior).log2())
            .sum::<f64>();
        let now = database_timestamp();
        let evidence = EvidenceRecord {
            id: Uuid::now_v7(),
            tenant_id: auth.tenant_id,
            case_id,
            kind: command.kind.trim().to_owned(),
            payload: command.payload,
            source: command.source.trim().to_owned(),
            observed_at: command.observed_at.unwrap_or(now),
            created_at: now,
        };
        insert_evidence(&mut transaction, &evidence).await?;

        let mut weights = Vec::with_capacity(branches.len());
        for ((branch, prior), posterior) in branches.iter().zip(&priors).zip(&posteriors) {
            sqlx::query(
                "UPDATE branches SET weight = $1, updated_at = $2 WHERE tenant_id = $3 AND id = $4",
            )
            .bind(posterior)
            .bind(now)
            .bind(auth.tenant_id)
            .bind(branch.id)
            .execute(&mut *transaction)
            .await?;
            let ratio = if *prior > 0.0 { posterior / prior } else { 0.0 };
            let relation = if ratio > 1.0 + 1.0e-12 {
                "supports"
            } else if ratio < 1.0 - 1.0e-12 {
                "contradicts"
            } else {
                "qualifies"
            };
            link_evidence(
                &mut transaction,
                auth.tenant_id,
                branch.id,
                &[evidence.id],
                relation,
                "Bayesian likelihood update",
                now,
            )
            .await?;
            weights.push(PosteriorWeight {
                branch_id: branch.id,
                prior: *prior,
                log_likelihood: command.log_likelihood_by_branch[&branch.id],
                posterior: *posterior,
            });
        }
        let update = BayesianUpdate {
            evidence,
            model_id: command.model.id.trim().to_owned(),
            model_version: command.model.version.trim().to_owned(),
            prior_entropy_bits,
            posterior_entropy_bits,
            information_gain_bits,
            log_evidence,
            weights,
        };
        let commit = append_event(
            &mut transaction,
            auth,
            case_id,
            &locked,
            "evidence.likelihood_applied",
            &json!({
                "evidence_id": update.evidence.id,
                "kind": update.evidence.kind,
                "payload": update.evidence.payload,
                "source": update.evidence.source,
                "observed_at": update.evidence.observed_at,
                "model": {
                    "id": update.model_id,
                    "version": update.model_version,
                    "conditional_independence": command.model.conditional_independence.trim()
                },
                "prior_entropy_bits": update.prior_entropy_bits,
                "posterior_entropy_bits": update.posterior_entropy_bits,
                "information_gain_bits": update.information_gain_bits,
                "log_evidence": update.log_evidence,
                "weights": update.weights
            }),
            now,
        )
        .await?;
        transaction.commit().await?;
        Ok(mutation(update, commit))
    }

    pub async fn record_observation(
        &self,
        auth: &AuthContext,
        case_id: Uuid,
        command: RecordObservation,
    ) -> Result<Mutation<EvidenceRecord>> {
        validate_text(&command.kind, "observation kind", 128)?;
        validate_text(&command.source, "observation source", 256)?;
        let mut transaction = self.store.pool().begin().await?;
        let locked = lock_case(&mut transaction, auth.tenant_id, case_id).await?;
        check_version(&locked, command.expected_case_version)?;
        let now = database_timestamp();
        let evidence = EvidenceRecord {
            id: Uuid::now_v7(),
            tenant_id: auth.tenant_id,
            case_id,
            kind: command.kind.trim().to_owned(),
            payload: command.observation.clone(),
            source: command.source.trim().to_owned(),
            observed_at: command.observed_at.unwrap_or(now),
            created_at: now,
        };
        insert_evidence(&mut transaction, &evidence).await?;
        sqlx::query("UPDATE cases SET observation = $1 WHERE tenant_id = $2 AND id = $3")
            .bind(&command.observation)
            .bind(auth.tenant_id)
            .bind(case_id)
            .execute(&mut *transaction)
            .await?;
        let commit = append_event(
            &mut transaction,
            auth,
            case_id,
            &locked,
            "observation.recorded",
            &json!({
                "evidence_id": evidence.id,
                "observation": command.observation,
                "source": evidence.source,
                "observed_at": evidence.observed_at
            }),
            now,
        )
        .await?;
        transaction.commit().await?;
        Ok(mutation(evidence, commit))
    }

    pub async fn materialize_jacobian_fiber(
        &self,
        auth: &AuthContext,
        case_id: Uuid,
        command: MaterializeJacobianFiber,
    ) -> Result<Mutation<FiberTransition>> {
        let mut transaction = self.store.pool().begin().await?;
        let locked = lock_case(&mut transaction, auth.tenant_id, case_id).await?;
        check_version(&locked, command.expected_case_version)?;
        let discovery = jacobian::discover_fiber(&locked.observation)?;
        let now = database_timestamp();
        let (transition, commit) = persist_discovered_fiber(
            &mut transaction,
            auth,
            case_id,
            &locked,
            discovery,
            None,
            "fiber.materialized",
            now,
        )
        .await?;
        transaction.commit().await?;
        Ok(mutation(transition, commit))
    }

    pub async fn advance_jacobian_fiber(
        &self,
        auth: &AuthContext,
        case_id: Uuid,
        command: AdvanceJacobianFiber,
    ) -> Result<Mutation<FiberTransition>> {
        validate_text(&command.kind, "observation kind", 128)?;
        validate_text(&command.source, "observation source", 256)?;
        let discovery = jacobian::discover_fiber(&command.observation)?;
        let mut transaction = self.store.pool().begin().await?;
        let locked = lock_case(&mut transaction, auth.tenant_id, case_id).await?;
        check_version(&locked, command.expected_case_version)?;
        let now = database_timestamp();
        let evidence = EvidenceRecord {
            id: Uuid::now_v7(),
            tenant_id: auth.tenant_id,
            case_id,
            kind: command.kind.trim().to_owned(),
            payload: command.observation.clone(),
            source: command.source.trim().to_owned(),
            observed_at: command.observed_at.unwrap_or(now),
            created_at: now,
        };
        insert_evidence(&mut transaction, &evidence).await?;
        sqlx::query("UPDATE cases SET observation = $1 WHERE tenant_id = $2 AND id = $3")
            .bind(&command.observation)
            .bind(auth.tenant_id)
            .bind(case_id)
            .execute(&mut *transaction)
            .await?;
        let (transition, commit) = persist_discovered_fiber(
            &mut transaction,
            auth,
            case_id,
            &locked,
            discovery,
            Some(evidence),
            "fiber.advanced",
            now,
        )
        .await?;
        transaction.commit().await?;
        Ok(mutation(transition, commit))
    }

    pub async fn propose_branch(
        &self,
        auth: &AuthContext,
        case_id: Uuid,
        command: ProposeBranch,
    ) -> Result<Mutation<BranchRecord>> {
        validate_text(&command.label, "branch label", 256)?;
        validate_non_negative(command.weight, "branch weight")?;
        require_object(&command.proposal, "proposal")?;
        let parent_ids = unique_ids(&command.parent_ids, "parent IDs")?;
        let evidence_ids = unique_ids(&command.evidence_ids, "evidence IDs")?;
        let mut transaction = self.store.pool().begin().await?;
        let locked = lock_case(&mut transaction, auth.tenant_id, case_id).await?;
        check_version(&locked, command.expected_case_version)?;
        ensure_evidence(&mut transaction, auth.tenant_id, case_id, &evidence_ids).await?;
        let generation =
            parent_generation(&mut transaction, auth.tenant_id, case_id, &parent_ids).await?;
        let now = database_timestamp();
        let branch_id = Uuid::now_v7();
        sqlx::query(
            r"
            INSERT INTO branches
                (id, tenant_id, case_id, label, state, weight, status,
                 generation, parent_ids, validity, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6, 'proposed',
                    $7, $8, $9, $10, $10)
            ",
        )
        .bind(branch_id)
        .bind(auth.tenant_id)
        .bind(case_id)
        .bind(command.label.trim())
        .bind(&command.state)
        .bind(command.weight)
        .bind(generation)
        .bind(&parent_ids)
        .bind(&command.proposal)
        .bind(now)
        .execute(&mut *transaction)
        .await?;
        link_evidence(
            &mut transaction,
            auth.tenant_id,
            branch_id,
            &evidence_ids,
            "supports",
            "proposal basis",
            now,
        )
        .await?;
        let commit = append_event(
            &mut transaction,
            auth,
            case_id,
            &locked,
            "branch.proposed",
            &json!({
                "branch_id": branch_id,
                "label": command.label.trim(),
                "state": command.state,
                "weight": command.weight,
                "generation": generation,
                "parent_ids": parent_ids,
                "evidence_ids": evidence_ids,
                "proposal": command.proposal
            }),
            now,
        )
        .await?;
        let branch = fetch_branch_tx(&mut transaction, auth.tenant_id, branch_id).await?;
        transaction.commit().await?;
        Ok(mutation(branch, commit))
    }

    pub async fn validate_branch(
        &self,
        auth: &AuthContext,
        branch_id: Uuid,
        command: ValidateBranch,
    ) -> Result<Mutation<BranchRecord>> {
        validate_text(&command.reason, "validation reason", 2_000)?;
        validate_optional_risk(command.risk_score)?;
        require_basis(&command.evidence_ids, &command.certificate)?;
        let evidence_ids = unique_ids(&command.evidence_ids, "evidence IDs")?;
        let mut transaction = self.store.pool().begin().await?;
        let branch = lock_branch(&mut transaction, auth.tenant_id, branch_id).await?;
        if !matches!(branch.status, BranchStatus::Proposed | BranchStatus::Active) {
            return Err(JfrError::Conflict(format!(
                "branch cannot be validated from status {}",
                branch.status
            )));
        }
        let locked = lock_case(&mut transaction, auth.tenant_id, branch.case_id).await?;
        check_version(&locked, command.expected_case_version)?;
        ensure_evidence(
            &mut transaction,
            auth.tenant_id,
            branch.case_id,
            &evidence_ids,
        )
        .await?;
        let now = database_timestamp();
        let status = if command.valid {
            BranchStatus::Active
        } else {
            BranchStatus::Contradicted
        };
        let validity = json!({
            "valid": command.valid,
            "reason": command.reason.trim(),
            "evidence_ids": evidence_ids,
            "certificate": command.certificate,
            "validated_at": now,
            "actor_key_id": auth.key_id
        });
        sqlx::query(
            r"
            UPDATE branches
               SET status = $1, validity = $2, risk_score = $3, updated_at = $4
             WHERE tenant_id = $5 AND id = $6
            ",
        )
        .bind(status.as_str())
        .bind(&validity)
        .bind(command.risk_score)
        .bind(now)
        .bind(auth.tenant_id)
        .bind(branch_id)
        .execute(&mut *transaction)
        .await?;
        link_evidence(
            &mut transaction,
            auth.tenant_id,
            branch_id,
            &evidence_ids,
            if command.valid {
                "supports"
            } else {
                "contradicts"
            },
            command.reason.trim(),
            now,
        )
        .await?;
        let event_type = if command.valid {
            "branch.validated"
        } else {
            "branch.contradicted"
        };
        let commit = append_event(
            &mut transaction,
            auth,
            branch.case_id,
            &locked,
            event_type,
            &json!({
                "branch_id": branch_id,
                "status": status,
                "reason": command.reason.trim(),
                "evidence_ids": evidence_ids,
                "certificate": command.certificate,
                "risk_score": command.risk_score
            }),
            now,
        )
        .await?;
        let record = fetch_branch_tx(&mut transaction, auth.tenant_id, branch_id).await?;
        transaction.commit().await?;
        Ok(mutation(record, commit))
    }

    pub async fn verify_jacobian_branch(
        &self,
        auth: &AuthContext,
        branch_id: Uuid,
        expected_case_version: i64,
    ) -> Result<Mutation<BranchRecord>> {
        let branch = self.store.get_branch(auth.tenant_id, branch_id).await?;
        let case = self.store.get_case(auth.tenant_id, branch.case_id).await?;
        let certificate = jacobian::verify_branch(&branch.state, &case.observation)?;
        let valid = certificate["valid"].as_bool().unwrap_or(false);
        self.validate_branch(
            auth,
            branch_id,
            ValidateBranch {
                valid,
                reason: if valid {
                    "Exact rational substitution matches the observed fiber.".to_owned()
                } else {
                    "Exact rational substitution does not match the observation.".to_owned()
                },
                evidence_ids: Vec::new(),
                certificate,
                risk_score: None,
                expected_case_version,
            },
        )
        .await
    }

    pub async fn prune_branch(
        &self,
        auth: &AuthContext,
        branch_id: Uuid,
        command: PruneBranch,
    ) -> Result<Mutation<BranchRecord>> {
        self.validate_branch(
            auth,
            branch_id,
            ValidateBranch {
                valid: false,
                reason: command.reason,
                evidence_ids: command.evidence_ids,
                certificate: command.certificate,
                risk_score: None,
                expected_case_version: command.expected_case_version,
            },
        )
        .await
    }

    pub async fn split_branch(
        &self,
        auth: &AuthContext,
        branch_id: Uuid,
        command: SplitBranch,
    ) -> Result<Mutation<Vec<BranchRecord>>> {
        validate_text(&command.reason, "split reason", 2_000)?;
        require_basis(&command.evidence_ids, &command.certificate)?;
        if command.candidates.is_empty() || command.candidates.len() > 1_000 {
            return Err(JfrError::Validation(
                "a split requires between 1 and 1000 candidates".to_owned(),
            ));
        }
        let total_weight = validate_candidates(&command.candidates)?;
        let evidence_ids = unique_ids(&command.evidence_ids, "evidence IDs")?;
        let mut transaction = self.store.pool().begin().await?;
        let parent = lock_branch(&mut transaction, auth.tenant_id, branch_id).await?;
        if parent.status != BranchStatus::Active {
            return Err(JfrError::Conflict(
                "only an active branch can be split".to_owned(),
            ));
        }
        let locked = lock_case(&mut transaction, auth.tenant_id, parent.case_id).await?;
        check_version(&locked, command.expected_case_version)?;
        ensure_evidence(
            &mut transaction,
            auth.tenant_id,
            parent.case_id,
            &evidence_ids,
        )
        .await?;
        let now = database_timestamp();
        sqlx::query(
            r"
            UPDATE branches
               SET status = 'superseded',
                   validity = validity || $1::JSONB,
                   updated_at = $2
             WHERE tenant_id = $3 AND id = $4
            ",
        )
        .bind(json!({
            "superseded_reason": command.reason.trim(),
            "superseded_at": now
        }))
        .bind(now)
        .bind(auth.tenant_id)
        .bind(branch_id)
        .execute(&mut *transaction)
        .await?;
        let mut child_ids = Vec::with_capacity(command.candidates.len());
        for candidate in &command.candidates {
            let child_id = Uuid::now_v7();
            child_ids.push(child_id);
            sqlx::query(
                r"
                INSERT INTO branches
                    (id, tenant_id, case_id, label, state, weight, status,
                     generation, parent_ids, validity, created_at, updated_at)
                VALUES ($1, $2, $3, $4, $5, $6, 'proposed',
                        $7, $8, $9, $10, $10)
                ",
            )
            .bind(child_id)
            .bind(auth.tenant_id)
            .bind(parent.case_id)
            .bind(candidate.label.trim())
            .bind(&candidate.state)
            .bind(parent.weight * candidate.relative_weight / total_weight)
            .bind(parent.generation + 1)
            .bind(vec![parent.id])
            .bind(&candidate.validity)
            .bind(now)
            .execute(&mut *transaction)
            .await?;
            link_evidence(
                &mut transaction,
                auth.tenant_id,
                child_id,
                &evidence_ids,
                "derives",
                command.reason.trim(),
                now,
            )
            .await?;
        }
        let commit = append_event(
            &mut transaction,
            auth,
            parent.case_id,
            &locked,
            "branch.split",
            &json!({
                "parent_id": parent.id,
                "children": command.candidates.iter().zip(&child_ids).map(
                    |(candidate, id)| json!({
                        "branch_id": id,
                        "label": candidate.label.trim(),
                        "state": candidate.state,
                        "relative_weight": candidate.relative_weight,
                        "validity": candidate.validity
                    })
                ).collect::<Vec<_>>(),
                "reason": command.reason.trim(),
                "evidence_ids": evidence_ids,
                "certificate": command.certificate
            }),
            now,
        )
        .await?;
        let mut children = Vec::with_capacity(child_ids.len());
        for child_id in child_ids {
            children.push(fetch_branch_tx(&mut transaction, auth.tenant_id, child_id).await?);
        }
        transaction.commit().await?;
        Ok(mutation(children, commit))
    }

    pub async fn merge_branches(
        &self,
        auth: &AuthContext,
        case_id: Uuid,
        command: MergeBranches,
    ) -> Result<Mutation<BranchRecord>> {
        validate_text(&command.label, "merged branch label", 256)?;
        validate_text(&command.reason, "merge reason", 2_000)?;
        require_basis(&command.evidence_ids, &command.certificate)?;
        let branch_ids = unique_ids(&command.branch_ids, "branch IDs")?;
        if branch_ids.len() < 2 {
            return Err(JfrError::Validation(
                "a merge requires at least two distinct branches".to_owned(),
            ));
        }
        let evidence_ids = unique_ids(&command.evidence_ids, "evidence IDs")?;
        let mut transaction = self.store.pool().begin().await?;
        let locked = lock_case(&mut transaction, auth.tenant_id, case_id).await?;
        check_version(&locked, command.expected_case_version)?;
        ensure_evidence(&mut transaction, auth.tenant_id, case_id, &evidence_ids).await?;
        let rows = sqlx::query_as::<_, BranchRow>(
            r"
            SELECT id, tenant_id, case_id, label, state, weight, status,
                   generation, parent_ids, validity, risk_score,
                   created_at, updated_at
              FROM branches
             WHERE tenant_id = $1 AND case_id = $2 AND id = ANY($3)
             FOR UPDATE
            ",
        )
        .bind(auth.tenant_id)
        .bind(case_id)
        .bind(&branch_ids)
        .fetch_all(&mut *transaction)
        .await?;
        if rows.len() != branch_ids.len() {
            return Err(JfrError::Validation(
                "one or more merge branches do not belong to this case".to_owned(),
            ));
        }
        let branches: Vec<BranchRecord> = rows
            .into_iter()
            .map(|row| row.try_into().map_err(JfrError::Internal))
            .collect::<Result<_>>()?;
        if branches
            .iter()
            .any(|branch| branch.status != BranchStatus::Active)
        {
            return Err(JfrError::Conflict(
                "only active branches can be merged".to_owned(),
            ));
        }
        let weight: f64 = branches.iter().map(|branch| branch.weight).sum();
        validate_non_negative(weight, "merged branch weight")?;
        let generation = branches
            .iter()
            .map(|branch| branch.generation)
            .max()
            .unwrap_or(0)
            + 1;
        let merged_id = Uuid::now_v7();
        let now = database_timestamp();
        sqlx::query(
            r"
            UPDATE branches
               SET status = 'merged',
                   validity = validity || $1::JSONB,
                   updated_at = $2
             WHERE tenant_id = $3 AND id = ANY($4)
            ",
        )
        .bind(json!({
            "merged_into": merged_id,
            "merge_reason": command.reason.trim(),
            "merged_at": now
        }))
        .bind(now)
        .bind(auth.tenant_id)
        .bind(&branch_ids)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            r"
            INSERT INTO branches
                (id, tenant_id, case_id, label, state, weight, status,
                 generation, parent_ids, validity, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6, 'proposed',
                    $7, $8, $9, $10, $10)
            ",
        )
        .bind(merged_id)
        .bind(auth.tenant_id)
        .bind(case_id)
        .bind(command.label.trim())
        .bind(&command.state)
        .bind(weight)
        .bind(generation)
        .bind(&branch_ids)
        .bind(json!({"merge_certificate": command.certificate}))
        .bind(now)
        .execute(&mut *transaction)
        .await?;
        link_evidence(
            &mut transaction,
            auth.tenant_id,
            merged_id,
            &evidence_ids,
            "supports",
            command.reason.trim(),
            now,
        )
        .await?;
        let commit = append_event(
            &mut transaction,
            auth,
            case_id,
            &locked,
            "branches.merged",
            &json!({
                "parent_ids": branch_ids,
                "merged_id": merged_id,
                "label": command.label.trim(),
                "state": command.state,
                "weight": weight,
                "reason": command.reason.trim(),
                "evidence_ids": evidence_ids,
                "certificate": command.certificate
            }),
            now,
        )
        .await?;
        let merged = fetch_branch_tx(&mut transaction, auth.tenant_id, merged_id).await?;
        transaction.commit().await?;
        Ok(mutation(merged, commit))
    }

    pub async fn snapshot(&self, auth: &AuthContext, case_id: Uuid) -> Result<CaseSnapshot> {
        let case = self.store.get_case(auth.tenant_id, case_id).await?;
        let (evidence, branches, assumptions, guarantees, counterexamples, authorizations, events) =
            tokio::try_join!(
                self.store.list_evidence(auth.tenant_id, case_id),
                self.store.list_branches(auth.tenant_id, case_id, None),
                self.store.list_assumptions(auth.tenant_id, case_id, None),
                self.store.list_guarantees(auth.tenant_id, case_id),
                self.store.list_counterexamples(auth.tenant_id, case_id),
                self.store.list_authorizations(auth.tenant_id, case_id),
                self.store.all_events(auth.tenant_id, case_id)
            )?;
        let audit = verify_events(&events, case.audit_event_count, &case.audit_head_hash);
        Ok(CaseSnapshot {
            case,
            evidence,
            branches,
            assumptions,
            guarantees,
            counterexamples,
            authorizations,
            events,
            audit,
        })
    }

    pub async fn verify_audit(&self, auth: &AuthContext, case_id: Uuid) -> Result<AuditReport> {
        let case = self.store.get_case(auth.tenant_id, case_id).await?;
        let events = self.store.all_events(auth.tenant_id, case_id).await?;
        Ok(verify_events(
            &events,
            case.audit_event_count,
            &case.audit_head_hash,
        ))
    }

    pub async fn semantic_jacobian_audit(
        &self,
        auth: &AuthContext,
        case_id: Uuid,
    ) -> Result<SemanticFiberAudit> {
        let case = self.store.get_case(auth.tenant_id, case_id).await?;
        let recorded = self
            .store
            .list_branches(auth.tenant_id, case_id, Some("active"))
            .await?;
        let recomputed = jacobian::discover_fiber(&case.observation)?;
        let assignments = minimum_correspondence(&recorded, &recomputed.branches);
        let matches = assignments
            .iter()
            .enumerate()
            .filter_map(|(recomputed_index, assignment)| {
                assignment.map(|(recorded_index, distance)| {
                    let branch = &recorded[recorded_index];
                    let certificate_verifier = branch
                        .validity
                        .pointer("/certificate/verifier")
                        .and_then(Value::as_str)
                        .map(str::to_owned);
                    SemanticBranchMatch {
                        recorded_branch_id: branch.id,
                        recomputed_label: recomputed.branches[recomputed_index].label.clone(),
                        normalized_distance: distance,
                        valid: distance <= 1.0e-24
                            && certificate_verifier.as_deref()
                                == Some("jfr.alpoge-fiber-solver.v1"),
                        certificate_verifier,
                    }
                })
            })
            .collect::<Vec<_>>();
        let complete_match = recorded.len() == recomputed.branch_count
            && matches.len() == recomputed.branch_count
            && matches.iter().all(|mapping| mapping.valid);
        let valid = recomputed.complete && complete_match;
        let reason = (!valid).then(|| {
            if recorded.len() == recomputed.branch_count {
                "one or more active branches do not match the recomputed certified fiber".to_owned()
            } else {
                format!(
                    "recorded active branch count {} differs from recomputed complete count {}",
                    recorded.len(),
                    recomputed.branch_count
                )
            }
        });
        Ok(SemanticFiberAudit {
            valid,
            solver: recomputed.solver.to_owned(),
            complete: recomputed.complete,
            recorded_active_branches: recorded.len(),
            recomputed_branches: recomputed.branch_count,
            maximum_escape_score: recomputed
                .branches
                .iter()
                .map(|branch| branch.escape_score)
                .fold(0.0, f64::max),
            matches,
            reason,
        })
    }

    pub async fn semantic_guarantee_audit(
        &self,
        auth: &AuthContext,
        case_id: Uuid,
    ) -> Result<GuaranteeSemanticAudit> {
        const MAX_AUDIT_ASSIGNMENTS: u64 = 2_000_000;

        self.store.get_case(auth.tenant_id, case_id).await?;
        let (assumptions, guarantees, counterexamples, authorizations) = tokio::try_join!(
            self.store.list_assumptions(auth.tenant_id, case_id, None),
            self.store.list_guarantees(auth.tenant_id, case_id),
            self.store.list_counterexamples(auth.tenant_id, case_id),
            self.store.list_authorizations(auth.tenant_id, case_id)
        )?;
        let statuses = assumptions
            .iter()
            .map(|assumption| (assumption.id, assumption.status))
            .collect::<BTreeMap<_, _>>();
        let guarantee_statuses = guarantees
            .iter()
            .map(|guarantee| (guarantee.id, guarantee.status))
            .collect::<BTreeMap<_, _>>();
        let active_assumptions = statuses
            .values()
            .filter(|status| **status == AssumptionStatus::Active)
            .count();
        let verified_guarantees = guarantees
            .iter()
            .filter(|guarantee| guarantee.status == GuaranteeStatus::Verified)
            .count();
        let contradicted_guarantees = guarantees
            .iter()
            .filter(|guarantee| guarantee.status == GuaranteeStatus::Contradicted)
            .count();
        let suspended_guarantees = guarantees
            .iter()
            .filter(|guarantee| guarantee.status == GuaranteeStatus::Suspended)
            .count();
        let authorized = authorizations
            .iter()
            .filter(|authorization| authorization.status == "authorized")
            .collect::<Vec<_>>();
        let mut checked_assignments = 0_u64;
        let mut entries = Vec::with_capacity(guarantees.len());
        for guarantee in guarantees {
            let mut valid = guarantee.verifier_id == refutation::VERIFIER_ID;
            let mut reason = (guarantee.verifier_id != refutation::VERIFIER_ID).then(|| {
                format!(
                    "unsupported verifier {}; expected {}",
                    guarantee.verifier_id,
                    refutation::VERIFIER_ID
                )
            });
            let premises_active = guarantee
                .premise_assumption_ids
                .iter()
                .all(|id| statuses.get(id).copied() == Some(AssumptionStatus::Active));
            let parsed = refutation::parse_specification(guarantee.specification.clone());
            let mut entry_checked = 0_u64;
            match (guarantee.status, parsed) {
                (_, Err(error)) => {
                    valid = false;
                    reason = Some(error.to_string());
                }
                (GuaranteeStatus::Verified, Ok(specification)) => {
                    if premises_active {
                        let size = refutation::search_space_size(&specification)?;
                        if checked_assignments.saturating_add(size) > MAX_AUDIT_ASSIGNMENTS {
                            valid = false;
                            reason = Some(format!(
                                "audit budget of {MAX_AUDIT_ASSIGNMENTS} assignments was exhausted"
                            ));
                        } else {
                            let report = tokio::task::spawn_blocking(move || {
                                refutation::exhaustive_search(&specification)
                            })
                            .await
                            .map_err(|error| {
                                JfrError::Internal(format!(
                                    "semantic guarantee audit failed: {error}"
                                ))
                            })??;
                            entry_checked = report.examined_assignments;
                            checked_assignments = checked_assignments.saturating_add(entry_checked);
                            let stored_hash = guarantee
                                .verification
                                .get("specification_hash")
                                .and_then(Value::as_str);
                            if report.outcome != refutation::SearchOutcome::Verified
                                || stored_hash != Some(report.specification_hash.as_str())
                            {
                                valid = false;
                                reason = Some(
                                    "stored verification does not match exact recomputation"
                                        .to_owned(),
                                );
                            }
                        }
                    } else {
                        valid = false;
                        reason = Some("a verified guarantee has an inactive premise".to_owned());
                    }
                }
                (GuaranteeStatus::Contradicted, Ok(specification)) => {
                    let witnesses = counterexamples
                        .iter()
                        .filter(|counterexample| counterexample.guarantee_id == guarantee.id)
                        .collect::<Vec<_>>();
                    if witnesses.is_empty() || guarantee.counterexample_count == 0 {
                        valid = false;
                        reason = Some("contradicted guarantee has no counterexample".to_owned());
                    } else {
                        let mut witness_valid = false;
                        for counterexample in witnesses {
                            let assignment = serde_json::from_value::<BTreeMap<String, i64>>(
                                counterexample.witness.clone(),
                            );
                            let certificate_valid =
                                refutation::certificate_hash(&counterexample.certificate)
                                    .is_ok_and(|hash| hash == counterexample.certificate_hash);
                            if assignment.is_ok_and(|assignment| {
                                refutation::verify_witness(&specification, &assignment).is_ok()
                            }) && certificate_valid
                                && counterexample.verifier_id == refutation::VERIFIER_ID
                            {
                                witness_valid = true;
                                break;
                            }
                        }
                        entry_checked = 1;
                        checked_assignments = checked_assignments.saturating_add(1);
                        if !witness_valid {
                            valid = false;
                            reason = Some(
                                "no stored counterexample has a valid witness and certificate"
                                    .to_owned(),
                            );
                        }
                    }
                }
                (GuaranteeStatus::Suspended, Ok(_)) => {
                    if premises_active {
                        valid = false;
                        reason = Some("suspended guarantee has no inactive premise".to_owned());
                    }
                }
                (
                    GuaranteeStatus::Proposed
                    | GuaranteeStatus::Superseded
                    | GuaranteeStatus::Archived,
                    Ok(_),
                ) => {}
            }
            entries.push(GuaranteeAuditEntry {
                guarantee_id: guarantee.id,
                label: guarantee.label,
                status: guarantee.status,
                valid,
                checked_assignments: entry_checked,
                reason,
            });
        }
        let invalid_authorizations = authorized
            .iter()
            .filter(|authorization| {
                let hash_valid = canonical_hash(&authorization.input)
                    .is_ok_and(|hash| hash == authorization.input_hash);
                let guarantees_valid = authorization.required_guarantee_ids.iter().all(|id| {
                    guarantee_statuses.get(id).copied() == Some(GuaranteeStatus::Verified)
                });
                let assumptions_valid = authorization
                    .required_assumption_ids
                    .iter()
                    .all(|id| statuses.get(id).copied() == Some(AssumptionStatus::Active));
                !hash_valid || !guarantees_valid || !assumptions_valid
            })
            .count();
        let entries_valid = entries.iter().all(|entry| entry.valid);
        let valid = entries_valid && invalid_authorizations == 0;
        let reason = (!valid).then(|| {
            if invalid_authorizations > 0 {
                format!(
                    "{invalid_authorizations} active authorization(s) have stale dependencies or invalid input hashes"
                )
            } else {
                "one or more guarantee certificates failed semantic recomputation".to_owned()
            }
        });
        Ok(GuaranteeSemanticAudit {
            valid,
            verifier: refutation::VERIFIER_ID.to_owned(),
            checked_guarantees: entries.len(),
            checked_assignments,
            active_assumptions,
            verified_guarantees,
            contradicted_guarantees,
            suspended_guarantees,
            authorized_actions: authorized.len(),
            entries,
            reason,
        })
    }

    pub async fn propose_assumption(
        &self,
        auth: &AuthContext,
        case_id: Uuid,
        command: ProposeAssumption,
    ) -> Result<Mutation<AssumptionRecord>> {
        validate_text(&command.label, "assumption label", 256)?;
        validate_non_negative(command.weight, "assumption weight")?;
        require_object(&command.statement, "assumption statement")?;
        require_object(&command.proposal, "assumption proposal")?;
        let parent_ids = unique_ids(&command.parent_ids, "parent IDs")?;
        let evidence_ids = unique_ids(&command.evidence_ids, "evidence IDs")?;
        let mut transaction = self.store.pool().begin().await?;
        let locked = lock_case(&mut transaction, auth.tenant_id, case_id).await?;
        check_version(&locked, command.expected_case_version)?;
        ensure_evidence(&mut transaction, auth.tenant_id, case_id, &evidence_ids).await?;
        let generation =
            assumption_parent_generation(&mut transaction, auth.tenant_id, case_id, &parent_ids)
                .await?;
        let assumption_id = Uuid::now_v7();
        let now = database_timestamp();
        sqlx::query(
            r"
            INSERT INTO assumptions
                (id, tenant_id, case_id, label, statement, weight, status,
                 generation, parent_ids, validity, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6, 'proposed',
                    $7, $8, $9, $10, $10)
            ",
        )
        .bind(assumption_id)
        .bind(auth.tenant_id)
        .bind(case_id)
        .bind(command.label.trim())
        .bind(&command.statement)
        .bind(command.weight)
        .bind(generation)
        .bind(&parent_ids)
        .bind(json!({"proposal": command.proposal}))
        .bind(now)
        .execute(&mut *transaction)
        .await?;
        link_assumption_evidence(
            &mut transaction,
            auth.tenant_id,
            assumption_id,
            &evidence_ids,
            "supports",
            "proposal basis",
            now,
        )
        .await?;
        let commit = append_event(
            &mut transaction,
            auth,
            case_id,
            &locked,
            "assumption.proposed",
            &json!({
                "assumption_id": assumption_id,
                "label": command.label.trim(),
                "statement": command.statement,
                "weight": command.weight,
                "generation": generation,
                "parent_ids": parent_ids,
                "evidence_ids": evidence_ids
            }),
            now,
        )
        .await?;
        let assumption =
            fetch_assumption_tx(&mut transaction, auth.tenant_id, assumption_id).await?;
        transaction.commit().await?;
        Ok(mutation(assumption, commit))
    }

    pub async fn validate_assumption(
        &self,
        auth: &AuthContext,
        assumption_id: Uuid,
        command: ValidateAssumption,
    ) -> Result<Mutation<AssumptionRecord>> {
        validate_text(&command.reason, "validation reason", 2_000)?;
        require_basis(&command.evidence_ids, &command.certificate)?;
        let evidence_ids = unique_ids(&command.evidence_ids, "evidence IDs")?;
        let located = self
            .store
            .get_assumption(auth.tenant_id, assumption_id)
            .await?;
        let mut transaction = self.store.pool().begin().await?;
        let locked = lock_case(&mut transaction, auth.tenant_id, located.case_id).await?;
        check_version(&locked, command.expected_case_version)?;
        let assumption = lock_assumption(&mut transaction, auth.tenant_id, assumption_id).await?;
        if !matches!(
            assumption.status,
            AssumptionStatus::Proposed | AssumptionStatus::Active
        ) {
            return Err(JfrError::Conflict(format!(
                "assumption {assumption_id} cannot be validated from status {}",
                assumption.status
            )));
        }
        ensure_evidence(
            &mut transaction,
            auth.tenant_id,
            assumption.case_id,
            &evidence_ids,
        )
        .await?;
        let now = database_timestamp();
        let status = if command.valid {
            AssumptionStatus::Active
        } else {
            AssumptionStatus::Contradicted
        };
        sqlx::query(
            r"
            UPDATE assumptions
               SET status = $1,
                   validity = validity || $2::JSONB,
                   updated_at = $3
             WHERE tenant_id = $4 AND id = $5
            ",
        )
        .bind(status.as_str())
        .bind(json!({
            "valid": command.valid,
            "reason": command.reason.trim(),
            "certificate": command.certificate,
            "validated_at": now
        }))
        .bind(now)
        .bind(auth.tenant_id)
        .bind(assumption_id)
        .execute(&mut *transaction)
        .await?;
        link_assumption_evidence(
            &mut transaction,
            auth.tenant_id,
            assumption_id,
            &evidence_ids,
            if command.valid {
                "supports"
            } else {
                "contradicts"
            },
            command.reason.trim(),
            now,
        )
        .await?;
        let (suspended_guarantee_ids, revoked_authorization_ids) = if command.valid {
            (Vec::new(), Vec::new())
        } else {
            let suspended = sqlx::query_scalar::<_, Uuid>(
                r"
                UPDATE guarantees
                   SET status = 'suspended',
                       verification = verification || $1::JSONB,
                       updated_at = $2
                 WHERE tenant_id = $3
                   AND case_id = $4
                   AND status IN ('proposed', 'verified')
                   AND premise_assumption_ids @> ARRAY[$5]::UUID[]
                RETURNING id
                ",
            )
            .bind(json!({
                "suspended_by_assumption_id": assumption_id,
                "suspended_at": now
            }))
            .bind(now)
            .bind(auth.tenant_id)
            .bind(assumption.case_id)
            .bind(assumption_id)
            .fetch_all(&mut *transaction)
            .await?;
            let revoked = revoke_authorizations(
                &mut transaction,
                auth.tenant_id,
                assumption.case_id,
                &suspended,
                &[assumption_id],
                "assumption_contradicted",
                now,
            )
            .await?;
            (suspended, revoked)
        };
        let commit = append_event(
            &mut transaction,
            auth,
            assumption.case_id,
            &locked,
            if command.valid {
                "assumption.activated"
            } else {
                "assumption.contradicted"
            },
            &json!({
                "assumption_id": assumption_id,
                "valid": command.valid,
                "reason": command.reason.trim(),
                "evidence_ids": evidence_ids,
                "certificate": command.certificate,
                "suspended_guarantee_ids": suspended_guarantee_ids,
                "revoked_authorization_ids": revoked_authorization_ids
            }),
            now,
        )
        .await?;
        let assumption =
            fetch_assumption_tx(&mut transaction, auth.tenant_id, assumption_id).await?;
        transaction.commit().await?;
        Ok(mutation(assumption, commit))
    }

    pub async fn create_guarantee(
        &self,
        auth: &AuthContext,
        case_id: Uuid,
        command: CreateGuarantee,
    ) -> Result<Mutation<GuaranteeRecord>> {
        validate_text(&command.label, "guarantee label", 256)?;
        validate_text(&command.description, "guarantee description", 4_000)?;
        let premise_ids = unique_ids(&command.premise_assumption_ids, "premise assumption IDs")?;
        let parent_ids = unique_ids(&command.parent_ids, "parent guarantee IDs")?;
        let search_space = refutation::search_space_size(&command.specification)?;
        let specification = refutation::specification_value(&command.specification)?;
        let mut transaction = self.store.pool().begin().await?;
        let locked = lock_case(&mut transaction, auth.tenant_id, case_id).await?;
        check_version(&locked, command.expected_case_version)?;
        ensure_assumptions(
            &mut transaction,
            auth.tenant_id,
            case_id,
            &premise_ids,
            Some(AssumptionStatus::Active),
        )
        .await?;
        ensure_guarantees(&mut transaction, auth.tenant_id, case_id, &parent_ids).await?;
        let guarantee_id = Uuid::now_v7();
        let now = database_timestamp();
        sqlx::query(
            r"
            INSERT INTO guarantees
                (id, tenant_id, case_id, label, description, verifier_id,
                 specification, premise_assumption_ids, parent_ids, status,
                 verification, counterexample_count, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'proposed',
                    $10, 0, $11, $11)
            ",
        )
        .bind(guarantee_id)
        .bind(auth.tenant_id)
        .bind(case_id)
        .bind(command.label.trim())
        .bind(command.description.trim())
        .bind(refutation::VERIFIER_ID)
        .bind(&specification)
        .bind(&premise_ids)
        .bind(&parent_ids)
        .bind(json!({"declared_search_assignments": search_space}))
        .bind(now)
        .execute(&mut *transaction)
        .await?;
        let commit = append_event(
            &mut transaction,
            auth,
            case_id,
            &locked,
            "guarantee.declared",
            &json!({
                "guarantee_id": guarantee_id,
                "label": command.label.trim(),
                "description": command.description.trim(),
                "verifier_id": refutation::VERIFIER_ID,
                "specification": specification,
                "search_space_assignments": search_space,
                "premise_assumption_ids": premise_ids,
                "parent_ids": parent_ids
            }),
            now,
        )
        .await?;
        let guarantee = fetch_guarantee_tx(&mut transaction, auth.tenant_id, guarantee_id).await?;
        transaction.commit().await?;
        Ok(mutation(guarantee, commit))
    }

    pub async fn search_guarantee(
        &self,
        auth: &AuthContext,
        guarantee_id: Uuid,
        command: SearchGuarantee,
    ) -> Result<Mutation<GuaranteeTransition>> {
        let located = self
            .store
            .get_guarantee(auth.tenant_id, guarantee_id)
            .await?;
        let specification = refutation::parse_specification(located.specification.clone())?;
        let report =
            tokio::task::spawn_blocking(move || refutation::exhaustive_search(&specification))
                .await
                .map_err(|error| {
                    JfrError::Internal(format!("guarantee verifier failed: {error}"))
                })??;
        let mut transaction = self.store.pool().begin().await?;
        let locked = lock_case(&mut transaction, auth.tenant_id, located.case_id).await?;
        check_version(&locked, command.expected_case_version)?;
        let guarantee = lock_guarantee(&mut transaction, auth.tenant_id, guarantee_id).await?;
        if !matches!(
            guarantee.status,
            GuaranteeStatus::Proposed | GuaranteeStatus::Suspended
        ) {
            return Err(JfrError::Conflict(format!(
                "guarantee {guarantee_id} cannot be searched from status {}",
                guarantee.status
            )));
        }
        ensure_assumptions(
            &mut transaction,
            auth.tenant_id,
            guarantee.case_id,
            &guarantee.premise_assumption_ids,
            Some(AssumptionStatus::Active),
        )
        .await?;
        let now = database_timestamp();
        let mut counterexample = None;
        let mut revoked_authorization_ids = Vec::new();
        match report.outcome {
            refutation::SearchOutcome::Verified => {
                sqlx::query(
                    r"
                    UPDATE guarantees
                       SET status = 'verified',
                           verification = $1,
                           updated_at = $2
                     WHERE tenant_id = $3 AND id = $4
                    ",
                )
                .bind(serde_json::to_value(&report).map_err(|error| {
                    JfrError::Internal(format!("could not encode verification: {error}"))
                })?)
                .bind(now)
                .bind(auth.tenant_id)
                .bind(guarantee_id)
                .execute(&mut *transaction)
                .await?;
            }
            refutation::SearchOutcome::Counterexample => {
                let witness = report.witness.as_ref().ok_or_else(|| {
                    JfrError::Internal("counterexample report had no witness".to_owned())
                })?;
                let inserted = insert_counterexample(
                    &mut transaction,
                    auth.tenant_id,
                    guarantee.case_id,
                    guarantee_id,
                    witness,
                    &report.certificate,
                    "exhaustive_search",
                    now,
                )
                .await?;
                sqlx::query(
                    r"
                    UPDATE guarantees
                       SET status = 'contradicted',
                           verification = $1,
                           counterexample_count = counterexample_count + 1,
                           updated_at = $2
                     WHERE tenant_id = $3 AND id = $4
                    ",
                )
                .bind(serde_json::to_value(&report).map_err(|error| {
                    JfrError::Internal(format!("could not encode refutation: {error}"))
                })?)
                .bind(now)
                .bind(auth.tenant_id)
                .bind(guarantee_id)
                .execute(&mut *transaction)
                .await?;
                revoked_authorization_ids = revoke_authorizations(
                    &mut transaction,
                    auth.tenant_id,
                    guarantee.case_id,
                    &[guarantee_id],
                    &[],
                    "guarantee_contradicted",
                    now,
                )
                .await?;
                counterexample = Some(inserted);
            }
        }
        let commit = append_event(
            &mut transaction,
            auth,
            guarantee.case_id,
            &locked,
            match report.outcome {
                refutation::SearchOutcome::Verified => "guarantee.verified",
                refutation::SearchOutcome::Counterexample => "guarantee.refuted",
            },
            &json!({
                "guarantee_id": guarantee_id,
                "search": report,
                "counterexample_id": counterexample.as_ref().map(|item| item.id),
                "revoked_authorization_ids": revoked_authorization_ids
            }),
            now,
        )
        .await?;
        let guarantee = fetch_guarantee_tx(&mut transaction, auth.tenant_id, guarantee_id).await?;
        transaction.commit().await?;
        Ok(mutation(
            GuaranteeTransition {
                guarantee,
                search: report,
                counterexample,
                revoked_authorization_ids,
            },
            commit,
        ))
    }

    pub async fn submit_counterexample(
        &self,
        auth: &AuthContext,
        guarantee_id: Uuid,
        command: SubmitCounterexample,
    ) -> Result<Mutation<GuaranteeTransition>> {
        validate_text(&command.source, "counterexample source", 256)?;
        let located = self
            .store
            .get_guarantee(auth.tenant_id, guarantee_id)
            .await?;
        let specification = refutation::parse_specification(located.specification.clone())?;
        let assignment = command.assignment.clone();
        let report = tokio::task::spawn_blocking(move || {
            refutation::verify_witness(&specification, &assignment)
        })
        .await
        .map_err(|error| JfrError::Internal(format!("witness verifier failed: {error}")))??;
        let mut transaction = self.store.pool().begin().await?;
        let locked = lock_case(&mut transaction, auth.tenant_id, located.case_id).await?;
        check_version(&locked, command.expected_case_version)?;
        let guarantee = lock_guarantee(&mut transaction, auth.tenant_id, guarantee_id).await?;
        if matches!(
            guarantee.status,
            GuaranteeStatus::Superseded | GuaranteeStatus::Archived
        ) {
            return Err(JfrError::Conflict(format!(
                "guarantee {guarantee_id} cannot accept a witness from status {}",
                guarantee.status
            )));
        }
        let now = database_timestamp();
        let counterexample = insert_counterexample(
            &mut transaction,
            auth.tenant_id,
            guarantee.case_id,
            guarantee_id,
            &command.assignment,
            &report.certificate,
            command.source.trim(),
            now,
        )
        .await?;
        sqlx::query(
            r"
            UPDATE guarantees
               SET status = 'contradicted',
                   verification = $1,
                   counterexample_count = counterexample_count + 1,
                   updated_at = $2
             WHERE tenant_id = $3 AND id = $4
            ",
        )
        .bind(serde_json::to_value(&report).map_err(|error| {
            JfrError::Internal(format!("could not encode witness report: {error}"))
        })?)
        .bind(now)
        .bind(auth.tenant_id)
        .bind(guarantee_id)
        .execute(&mut *transaction)
        .await?;
        let revoked_authorization_ids = revoke_authorizations(
            &mut transaction,
            auth.tenant_id,
            guarantee.case_id,
            &[guarantee_id],
            &[],
            "guarantee_contradicted",
            now,
        )
        .await?;
        let commit = append_event(
            &mut transaction,
            auth,
            guarantee.case_id,
            &locked,
            "guarantee.refuted",
            &json!({
                "guarantee_id": guarantee_id,
                "search": report,
                "counterexample_id": counterexample.id,
                "source": command.source.trim(),
                "revoked_authorization_ids": revoked_authorization_ids
            }),
            now,
        )
        .await?;
        let guarantee = fetch_guarantee_tx(&mut transaction, auth.tenant_id, guarantee_id).await?;
        transaction.commit().await?;
        Ok(mutation(
            GuaranteeTransition {
                guarantee,
                search: report,
                counterexample: Some(counterexample),
                revoked_authorization_ids,
            },
            commit,
        ))
    }

    pub async fn authorize_action(
        &self,
        auth: &AuthContext,
        case_id: Uuid,
        command: AuthorizeAction,
    ) -> Result<Mutation<ActionAuthorization>> {
        validate_text(&command.requested_action_id, "requested action ID", 128)?;
        let requested_guarantee_ids =
            unique_ids(&command.required_guarantee_ids, "required guarantee IDs")?;
        let requested_assumption_ids =
            unique_ids(&command.required_assumption_ids, "required assumption IDs")?;
        let input = serde_json::to_value(&command).map_err(|error| {
            JfrError::Internal(format!("could not encode authorization input: {error}"))
        })?;
        let input_hash = canonical_hash(&input)?;
        let mut transaction = self.store.pool().begin().await?;
        let locked = lock_case(&mut transaction, auth.tenant_id, case_id).await?;
        check_version(&locked, command.expected_case_version)?;
        let branch_rows = sqlx::query_as::<_, BranchRow>(
            r"
            SELECT id, tenant_id, case_id, label, state, weight, status,
                   generation, parent_ids, validity, risk_score,
                   created_at, updated_at
              FROM branches
             WHERE tenant_id = $1 AND case_id = $2 AND status = 'active'
             ORDER BY generation, created_at, id
             FOR SHARE
            ",
        )
        .bind(auth.tenant_id)
        .bind(case_id)
        .fetch_all(&mut *transaction)
        .await?;
        let branches = branch_rows
            .into_iter()
            .map(|row| row.try_into().map_err(JfrError::Internal))
            .collect::<Result<Vec<_>>>()?;
        let assumption_rows = sqlx::query_as::<_, AssumptionRow>(
            r"
            SELECT id, tenant_id, case_id, label, statement, weight, status,
                   generation, parent_ids, validity, created_at, updated_at
              FROM assumptions
             WHERE tenant_id = $1 AND case_id = $2 AND status = 'active'
             ORDER BY generation, created_at, id
             FOR SHARE
            ",
        )
        .bind(auth.tenant_id)
        .bind(case_id)
        .fetch_all(&mut *transaction)
        .await?;
        let assumptions = assumption_rows
            .into_iter()
            .map(|row| row.try_into().map_err(JfrError::Internal))
            .collect::<Result<Vec<_>>>()?;
        let (selected, scores, scenario_count) =
            decision::evaluate_joint_actions(&branches, &assumptions, command.actions.clone())?;
        let guarantees = fetch_guarantees_by_id(
            &mut transaction,
            auth.tenant_id,
            case_id,
            &requested_guarantee_ids,
        )
        .await?;
        let required_assumptions = fetch_assumptions_by_id(
            &mut transaction,
            auth.tenant_id,
            case_id,
            &requested_assumption_ids,
        )
        .await?;
        let active_assumption_ids = assumptions
            .iter()
            .map(|assumption| assumption.id)
            .collect::<BTreeSet<_>>();
        let mut dependency_reasons = Vec::new();
        let mut effective_assumption_ids = requested_assumption_ids
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        for assumption in &required_assumptions {
            if assumption.status != AssumptionStatus::Active {
                dependency_reasons.push(format!(
                    "assumption {} has status {}",
                    assumption.id, assumption.status
                ));
            }
        }
        for guarantee in &guarantees {
            if guarantee.status != GuaranteeStatus::Verified {
                dependency_reasons.push(format!(
                    "guarantee {} has status {}",
                    guarantee.id, guarantee.status
                ));
            }
            for premise_id in &guarantee.premise_assumption_ids {
                effective_assumption_ids.insert(*premise_id);
                if !active_assumption_ids.contains(premise_id) {
                    dependency_reasons.push(format!(
                        "guarantee {} depends on inactive assumption {}",
                        guarantee.id, premise_id
                    ));
                }
            }
        }
        let requested_is_selected = command.requested_action_id == selected.id;
        if !requested_is_selected {
            dependency_reasons.push(format!(
                "requested action {} is not joint-maximin selection {}",
                command.requested_action_id, selected.id
            ));
        }
        dependency_reasons.sort();
        dependency_reasons.dedup();
        let authorized = dependency_reasons.is_empty() && requested_is_selected;
        let authorization_id = Uuid::now_v7();
        let now = database_timestamp();
        let result = json!({
            "selected": selected,
            "scores": scores,
            "scenario_count": scenario_count,
            "dependency_reasons": dependency_reasons,
            "authorized": authorized
        });
        let effective_assumption_ids = effective_assumption_ids.into_iter().collect::<Vec<_>>();
        sqlx::query(
            r"
            INSERT INTO decision_authorizations
                (id, tenant_id, case_id, requested_action_id, selected_action_id,
                 status, policy, required_guarantee_ids, required_assumption_ids,
                 input, result, input_hash, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6, 'joint_maximin', $7, $8,
                    $9, $10, $11, $12, $12)
            ",
        )
        .bind(authorization_id)
        .bind(auth.tenant_id)
        .bind(case_id)
        .bind(command.requested_action_id.trim())
        .bind(&selected.id)
        .bind(if authorized { "authorized" } else { "denied" })
        .bind(&requested_guarantee_ids)
        .bind(&effective_assumption_ids)
        .bind(&input)
        .bind(&result)
        .bind(&input_hash)
        .bind(now)
        .execute(&mut *transaction)
        .await?;
        let commit = append_event(
            &mut transaction,
            auth,
            case_id,
            &locked,
            if authorized {
                "action.authorized"
            } else {
                "action.denied"
            },
            &json!({
                "authorization_id": authorization_id,
                "requested_action_id": command.requested_action_id.trim(),
                "selected_action_id": selected.id,
                "policy": "joint_maximin",
                "scenario_count": scenario_count,
                "required_guarantee_ids": requested_guarantee_ids,
                "required_assumption_ids": effective_assumption_ids,
                "input_hash": hex::encode(&input_hash),
                "dependency_reasons": dependency_reasons
            }),
            now,
        )
        .await?;
        let authorization =
            fetch_authorization_tx(&mut transaction, auth.tenant_id, authorization_id).await?;
        transaction.commit().await?;
        Ok(mutation(
            ActionAuthorization {
                authorization,
                authorized,
                selected,
                scores,
                scenario_count,
                dependency_reasons,
            },
            commit,
        ))
    }

    pub async fn evaluate_actions(
        &self,
        auth: &AuthContext,
        case_id: Uuid,
        command: EvaluateActions,
    ) -> Result<DecisionResult> {
        let case = self.store.get_case(auth.tenant_id, case_id).await?;
        let branches = self
            .store
            .list_branches(auth.tenant_id, case_id, Some("active"))
            .await?;
        decision::evaluate_actions(case.version, &branches, command)
    }

    pub async fn rank_experiments(
        &self,
        auth: &AuthContext,
        case_id: Uuid,
        command: RankExperiments,
    ) -> Result<ExperimentRanking> {
        let case = self.store.get_case(auth.tenant_id, case_id).await?;
        let branches = self
            .store
            .list_branches(auth.tenant_id, case_id, Some("active"))
            .await?;
        decision::rank_experiments(case.version, &branches, command)
    }
}

async fn persist_discovered_fiber(
    transaction: &mut Transaction<'_, Postgres>,
    auth: &AuthContext,
    case_id: Uuid,
    locked: &LockedCase,
    discovery: jacobian::FiberDiscovery,
    evidence: Option<EvidenceRecord>,
    event_type: &str,
    now: DateTime<Utc>,
) -> Result<(FiberTransition, LedgerCommit)> {
    let rows = sqlx::query_as::<_, BranchRow>(
        r"
        SELECT id, tenant_id, case_id, label, state, weight, status,
               generation, parent_ids, validity, risk_score,
               created_at, updated_at
          FROM branches
         WHERE tenant_id = $1 AND case_id = $2 AND status = 'active'
         ORDER BY generation, created_at, id
         FOR UPDATE
        ",
    )
    .bind(auth.tenant_id)
    .bind(case_id)
    .fetch_all(&mut **transaction)
    .await?;
    let predecessors: Vec<BranchRecord> = rows
        .into_iter()
        .map(|row| row.try_into().map_err(JfrError::Internal))
        .collect::<Result<_>>()?;
    let assignments = minimum_correspondence(&predecessors, &discovery.branches);
    let successor_ids = (0..discovery.branches.len())
        .map(|_| Uuid::now_v7())
        .collect::<Vec<_>>();
    let next_generation = predecessors
        .iter()
        .map(|branch| branch.generation)
        .max()
        .map_or(0, |generation| generation + 1);

    let default_weight = if predecessors.is_empty() {
        1.0
    } else {
        let branch_count = u32::try_from(discovery.branches.len()).map_err(|_| {
            JfrError::Validation("fiber branch count exceeds the supported range".to_owned())
        })?;
        predecessors.iter().map(|branch| branch.weight).sum::<f64>() / f64::from(branch_count)
    };
    let mut raw_weights = assignments
        .iter()
        .map(|assignment| {
            assignment.map_or(default_weight, |(predecessor, _)| {
                predecessors[predecessor].weight
            })
        })
        .collect::<Vec<_>>();
    let raw_total = raw_weights.iter().sum::<f64>();
    if !raw_total.is_finite() || raw_total <= 0.0 {
        raw_weights.fill(1.0);
    }
    let weight_total = raw_weights.iter().sum::<f64>();
    for weight in &mut raw_weights {
        *weight /= weight_total;
    }

    let correspondence = assignments
        .iter()
        .enumerate()
        .filter_map(|(successor, assignment)| {
            assignment.map(|(predecessor, distance)| BranchCorrespondence {
                predecessor_id: predecessors[predecessor].id,
                successor_id: successor_ids[successor],
                normalized_distance: distance,
            })
        })
        .collect::<Vec<_>>();

    for predecessor in &predecessors {
        let successor = correspondence
            .iter()
            .find(|mapping| mapping.predecessor_id == predecessor.id)
            .map(|mapping| mapping.successor_id);
        sqlx::query(
            r"
            UPDATE branches
               SET status = 'superseded',
                   validity = validity || $1::JSONB,
                   updated_at = $2
             WHERE tenant_id = $3 AND id = $4
            ",
        )
        .bind(json!({
            "superseded_by_fiber_solver": discovery.solver,
            "continued_into": successor,
            "superseded_at": now
        }))
        .bind(now)
        .bind(auth.tenant_id)
        .bind(predecessor.id)
        .execute(&mut **transaction)
        .await?;
    }

    for (index, discovered) in discovery.branches.iter().enumerate() {
        let parent_ids = assignments[index]
            .map(|(predecessor, _)| vec![predecessors[predecessor].id])
            .unwrap_or_default();
        let validity = json!({
            "valid": true,
            "reason": "The privileged algebraic solver isolated this sheet and certified fiber completeness.",
            "certificate": discovered.certificate,
            "global_certificate": discovery.global_certificate,
            "validated_at": now,
            "actor_key_id": auth.key_id
        });
        sqlx::query(
            r"
            INSERT INTO branches
                (id, tenant_id, case_id, label, state, weight, status,
                 generation, parent_ids, validity, risk_score, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6, 'active',
                    $7, $8, $9, $10, $11, $11)
            ",
        )
        .bind(successor_ids[index])
        .bind(auth.tenant_id)
        .bind(case_id)
        .bind(&discovered.label)
        .bind(&discovered.state)
        .bind(raw_weights[index])
        .bind(
            assignments[index].map_or(next_generation, |(predecessor, _)| {
                predecessors[predecessor].generation + 1
            }),
        )
        .bind(&parent_ids)
        .bind(validity)
        .bind(discovered.escape_score)
        .bind(now)
        .execute(&mut **transaction)
        .await?;
        if let Some(evidence) = &evidence {
            link_evidence(
                transaction,
                auth.tenant_id,
                successor_ids[index],
                &[evidence.id],
                "derives",
                "observation used by certified algebraic fiber solver",
                now,
            )
            .await?;
        }
    }

    let event_payload = json!({
        "solver": discovery.solver,
        "observation": discovery.observation,
        "complete": discovery.complete,
        "global_certificate": discovery.global_certificate,
        "evidence_id": evidence.as_ref().map(|record| record.id),
        "superseded_branch_ids": predecessors.iter().map(|branch| branch.id).collect::<Vec<_>>(),
        "correspondence": correspondence,
        "branches": discovery.branches.iter().enumerate().map(|(index, branch)| json!({
            "branch_id": successor_ids[index],
            "label": branch.label,
            "state": branch.state,
            "weight": raw_weights[index],
            "certificate": branch.certificate,
            "image_residual": branch.image_residual,
            "hidden_norm": branch.hidden_norm,
            "observation_norm": branch.observation_norm,
            "escape_score": branch.escape_score
        })).collect::<Vec<_>>()
    });
    let commit = append_event(
        transaction,
        auth,
        case_id,
        locked,
        event_type,
        &event_payload,
        now,
    )
    .await?;
    let mut branches = Vec::with_capacity(successor_ids.len());
    for successor_id in successor_ids {
        branches.push(fetch_branch_tx(transaction, auth.tenant_id, successor_id).await?);
    }
    let transition = FiberTransition {
        solver: discovery.solver.to_owned(),
        observation: discovery.observation,
        complete: discovery.complete,
        superseded_branch_ids: predecessors.iter().map(|branch| branch.id).collect(),
        correspondence,
        branches,
        evidence,
        global_certificate: discovery.global_certificate,
    };
    Ok((transition, commit))
}

fn minimum_correspondence(
    predecessors: &[BranchRecord],
    successors: &[jacobian::DiscoveredBranch],
) -> Vec<Option<(usize, f64)>> {
    let predecessor_centers = predecessors
        .iter()
        .enumerate()
        .filter_map(|(index, branch)| {
            jacobian::point_center_from_state(&branch.state).map(|center| (index, center))
        })
        .collect::<Vec<_>>();
    if predecessor_centers.is_empty() || successors.is_empty() {
        return vec![None; successors.len()];
    }
    let costs = successors
        .iter()
        .map(|successor| {
            predecessor_centers
                .iter()
                .map(|(_, predecessor)| normalized_center_distance(&successor.center, predecessor))
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    let local_assignment = rectangular_assignment(&costs);
    local_assignment
        .into_iter()
        .enumerate()
        .map(|(successor, predecessor)| {
            predecessor.map(|local| (predecessor_centers[local].0, costs[successor][local]))
        })
        .collect()
}

fn normalized_center_distance(left: &[[f64; 2]; 3], right: &[[f64; 2]; 3]) -> f64 {
    left.iter()
        .zip(right)
        .map(|(left, right)| {
            let delta_re = left[0] - right[0];
            let delta_im = left[1] - right[1];
            let scale = 1.0
                + left[0].mul_add(left[0], left[1] * left[1])
                + right[0].mul_add(right[0], right[1] * right[1]);
            delta_re.mul_add(delta_re, delta_im * delta_im) / scale
        })
        .sum()
}

fn rectangular_assignment(costs: &[Vec<f64>]) -> Vec<Option<usize>> {
    let rows = costs.len();
    let columns = costs.first().map_or(0, Vec::len);
    if rows == 0 || columns == 0 {
        return vec![None; rows];
    }
    if rows <= columns {
        return hungarian_rows(costs).into_iter().map(Some).collect();
    }
    let transposed = (0..columns)
        .map(|column| (0..rows).map(|row| costs[row][column]).collect::<Vec<_>>())
        .collect::<Vec<_>>();
    let predecessor_to_successor = hungarian_rows(&transposed);
    let mut result = vec![None; rows];
    for (predecessor, successor) in predecessor_to_successor.into_iter().enumerate() {
        result[successor] = Some(predecessor);
    }
    result
}

fn hungarian_rows(costs: &[Vec<f64>]) -> Vec<usize> {
    let rows = costs.len();
    let columns = costs[0].len();
    debug_assert!(rows <= columns);
    let mut row_potential = vec![0.0; rows + 1];
    let mut column_potential = vec![0.0; columns + 1];
    let mut matched_row = vec![0_usize; columns + 1];
    let mut path = vec![0_usize; columns + 1];

    for row in 1..=rows {
        matched_row[0] = row;
        let mut column = 0;
        let mut minimum = vec![f64::INFINITY; columns + 1];
        let mut used = vec![false; columns + 1];
        loop {
            used[column] = true;
            let current_row = matched_row[column];
            let mut delta = f64::INFINITY;
            let mut next_column = 0;
            for candidate in 1..=columns {
                if used[candidate] {
                    continue;
                }
                let reduced = costs[current_row - 1][candidate - 1]
                    - row_potential[current_row]
                    - column_potential[candidate];
                if reduced < minimum[candidate] {
                    minimum[candidate] = reduced;
                    path[candidate] = column;
                }
                if minimum[candidate] < delta {
                    delta = minimum[candidate];
                    next_column = candidate;
                }
            }
            for candidate in 0..=columns {
                if used[candidate] {
                    row_potential[matched_row[candidate]] += delta;
                    column_potential[candidate] -= delta;
                } else {
                    minimum[candidate] -= delta;
                }
            }
            column = next_column;
            if matched_row[column] == 0 {
                break;
            }
        }
        loop {
            let previous = path[column];
            matched_row[column] = matched_row[previous];
            column = previous;
            if column == 0 {
                break;
            }
        }
    }
    let mut assignment = vec![0; rows];
    for column in 1..=columns {
        if matched_row[column] != 0 {
            assignment[matched_row[column] - 1] = column - 1;
        }
    }
    assignment
}

async fn lock_case(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    case_id: Uuid,
) -> Result<LockedCase> {
    sqlx::query_as::<_, LockedCase>(
        r"
        SELECT version, audit_event_count, audit_head_hash, observation
          FROM cases
         WHERE tenant_id = $1 AND id = $2
         FOR UPDATE
        ",
    )
    .bind(tenant_id)
    .bind(case_id)
    .fetch_optional(&mut **transaction)
    .await?
    .ok_or_else(|| JfrError::NotFound(format!("case {case_id} was not found")))
}

async fn lock_branch(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    branch_id: Uuid,
) -> Result<BranchRecord> {
    let row = sqlx::query_as::<_, BranchRow>(
        r"
        SELECT id, tenant_id, case_id, label, state, weight, status,
               generation, parent_ids, validity, risk_score,
               created_at, updated_at
          FROM branches
         WHERE tenant_id = $1 AND id = $2
         FOR UPDATE
        ",
    )
    .bind(tenant_id)
    .bind(branch_id)
    .fetch_optional(&mut **transaction)
    .await?
    .ok_or_else(|| JfrError::NotFound(format!("branch {branch_id} was not found")))?;
    row.try_into().map_err(JfrError::Internal)
}

async fn lock_assumption(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    assumption_id: Uuid,
) -> Result<AssumptionRecord> {
    let row = sqlx::query_as::<_, AssumptionRow>(
        r"
        SELECT id, tenant_id, case_id, label, statement, weight, status,
               generation, parent_ids, validity, created_at, updated_at
          FROM assumptions
         WHERE tenant_id = $1 AND id = $2
         FOR UPDATE
        ",
    )
    .bind(tenant_id)
    .bind(assumption_id)
    .fetch_optional(&mut **transaction)
    .await?
    .ok_or_else(|| JfrError::NotFound(format!("assumption {assumption_id} was not found")))?;
    row.try_into().map_err(JfrError::Internal)
}

async fn lock_guarantee(
    transaction: &mut Transaction<'_, Postgres>,
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
         FOR UPDATE
        ",
    )
    .bind(tenant_id)
    .bind(guarantee_id)
    .fetch_optional(&mut **transaction)
    .await?
    .ok_or_else(|| JfrError::NotFound(format!("guarantee {guarantee_id} was not found")))?;
    row.try_into().map_err(JfrError::Internal)
}

async fn append_event(
    transaction: &mut Transaction<'_, Postgres>,
    auth: &AuthContext,
    case_id: Uuid,
    locked: &LockedCase,
    event_type: &str,
    payload: &Value,
    created_at: DateTime<Utc>,
) -> Result<LedgerCommit> {
    let sequence = locked.audit_event_count + 1;
    let hash = event_hash(
        case_id,
        sequence,
        auth.tenant_id,
        event_type,
        payload,
        &locked.audit_head_hash,
        auth.key_id,
        created_at,
    )?;
    sqlx::query(
        r"
        INSERT INTO events
            (case_id, sequence, tenant_id, event_type, payload,
             previous_hash, event_hash, actor_key_id, created_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        ",
    )
    .bind(case_id)
    .bind(sequence)
    .bind(auth.tenant_id)
    .bind(event_type)
    .bind(payload)
    .bind(&locked.audit_head_hash)
    .bind(hash.as_slice())
    .bind(auth.key_id)
    .bind(created_at)
    .execute(&mut **transaction)
    .await?;
    let updated = sqlx::query(
        r"
        UPDATE cases
           SET version = version + 1,
               audit_event_count = $1,
               audit_head_hash = $2,
               updated_at = $3
         WHERE tenant_id = $4
           AND id = $5
           AND version = $6
        ",
    )
    .bind(sequence)
    .bind(hash.as_slice())
    .bind(created_at)
    .bind(auth.tenant_id)
    .bind(case_id)
    .bind(locked.version)
    .execute(&mut **transaction)
    .await?;
    if updated.rows_affected() != 1 {
        return Err(JfrError::VersionConflict(
            "case version changed during mutation".to_owned(),
        ));
    }
    Ok(LedgerCommit {
        case_version: locked.version + 1,
        event_sequence: sequence,
        event_hash: hash.to_vec(),
    })
}

async fn fetch_case_tx(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    case_id: Uuid,
) -> Result<CaseRecord> {
    Ok(sqlx::query_as::<_, CaseRecord>(
        r"
        SELECT id, tenant_id, name, observation, metadata, version,
               audit_event_count, audit_head_hash, created_at, updated_at
          FROM cases
         WHERE tenant_id = $1 AND id = $2
        ",
    )
    .bind(tenant_id)
    .bind(case_id)
    .fetch_one(&mut **transaction)
    .await?)
}

async fn fetch_branch_tx(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    branch_id: Uuid,
) -> Result<BranchRecord> {
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
    .fetch_one(&mut **transaction)
    .await?;
    row.try_into().map_err(JfrError::Internal)
}

async fn fetch_assumption_tx(
    transaction: &mut Transaction<'_, Postgres>,
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
    .fetch_one(&mut **transaction)
    .await?;
    row.try_into().map_err(JfrError::Internal)
}

async fn fetch_guarantee_tx(
    transaction: &mut Transaction<'_, Postgres>,
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
    .fetch_one(&mut **transaction)
    .await?;
    row.try_into().map_err(JfrError::Internal)
}

async fn fetch_authorization_tx(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    authorization_id: Uuid,
) -> Result<DecisionAuthorizationRecord> {
    Ok(sqlx::query_as::<_, DecisionAuthorizationRecord>(
        r"
        SELECT id, tenant_id, case_id, requested_action_id, selected_action_id,
               status, policy, required_guarantee_ids, required_assumption_ids,
               input, result, input_hash, created_at, revoked_at, revocation,
               updated_at
          FROM decision_authorizations
         WHERE tenant_id = $1 AND id = $2
        ",
    )
    .bind(tenant_id)
    .bind(authorization_id)
    .fetch_one(&mut **transaction)
    .await?)
}

async fn insert_evidence(
    transaction: &mut Transaction<'_, Postgres>,
    evidence: &EvidenceRecord,
) -> Result<()> {
    sqlx::query(
        r"
        INSERT INTO evidence
            (id, tenant_id, case_id, kind, payload, source,
             observed_at, created_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        ",
    )
    .bind(evidence.id)
    .bind(evidence.tenant_id)
    .bind(evidence.case_id)
    .bind(&evidence.kind)
    .bind(&evidence.payload)
    .bind(&evidence.source)
    .bind(evidence.observed_at)
    .bind(evidence.created_at)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

async fn ensure_evidence(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    case_id: Uuid,
    evidence_ids: &[Uuid],
) -> Result<()> {
    if evidence_ids.is_empty() {
        return Ok(());
    }
    let count = sqlx::query_scalar::<_, i64>(
        r"
        SELECT COUNT(*)
          FROM evidence
         WHERE tenant_id = $1 AND case_id = $2 AND id = ANY($3)
        ",
    )
    .bind(tenant_id)
    .bind(case_id)
    .bind(evidence_ids)
    .fetch_one(&mut **transaction)
    .await?;
    if usize::try_from(count).ok() != Some(evidence_ids.len()) {
        return Err(JfrError::Validation(
            "one or more evidence IDs do not belong to this case".to_owned(),
        ));
    }
    Ok(())
}

async fn ensure_assumptions(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    case_id: Uuid,
    assumption_ids: &[Uuid],
    required_status: Option<AssumptionStatus>,
) -> Result<()> {
    if assumption_ids.is_empty() {
        return Ok(());
    }
    let rows = sqlx::query_as::<_, (Uuid, String)>(
        r"
        SELECT id, status
          FROM assumptions
         WHERE tenant_id = $1 AND case_id = $2 AND id = ANY($3)
         FOR SHARE
        ",
    )
    .bind(tenant_id)
    .bind(case_id)
    .bind(assumption_ids)
    .fetch_all(&mut **transaction)
    .await?;
    if rows.len() != assumption_ids.len() {
        return Err(JfrError::Validation(
            "one or more assumption IDs do not belong to this case".to_owned(),
        ));
    }
    if let Some(required) = required_status
        && rows.iter().any(|(_, status)| status != required.as_str())
    {
        return Err(JfrError::Conflict(format!(
            "every premise assumption must have status {required}"
        )));
    }
    Ok(())
}

async fn ensure_guarantees(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    case_id: Uuid,
    guarantee_ids: &[Uuid],
) -> Result<()> {
    if guarantee_ids.is_empty() {
        return Ok(());
    }
    let count = sqlx::query_scalar::<_, i64>(
        r"
        SELECT COUNT(*)
          FROM guarantees
         WHERE tenant_id = $1 AND case_id = $2 AND id = ANY($3)
        ",
    )
    .bind(tenant_id)
    .bind(case_id)
    .bind(guarantee_ids)
    .fetch_one(&mut **transaction)
    .await?;
    if usize::try_from(count).ok() != Some(guarantee_ids.len()) {
        return Err(JfrError::Validation(
            "one or more guarantee IDs do not belong to this case".to_owned(),
        ));
    }
    Ok(())
}

async fn fetch_guarantees_by_id(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    case_id: Uuid,
    guarantee_ids: &[Uuid],
) -> Result<Vec<GuaranteeRecord>> {
    if guarantee_ids.is_empty() {
        return Ok(Vec::new());
    }
    let rows = sqlx::query_as::<_, GuaranteeRow>(
        r"
        SELECT id, tenant_id, case_id, label, description, verifier_id,
               specification, premise_assumption_ids, parent_ids, status,
               verification, counterexample_count, created_at, updated_at
          FROM guarantees
         WHERE tenant_id = $1 AND case_id = $2 AND id = ANY($3)
         FOR SHARE
        ",
    )
    .bind(tenant_id)
    .bind(case_id)
    .bind(guarantee_ids)
    .fetch_all(&mut **transaction)
    .await?;
    if rows.len() != guarantee_ids.len() {
        return Err(JfrError::Validation(
            "one or more required guarantee IDs do not belong to this case".to_owned(),
        ));
    }
    rows.into_iter()
        .map(|row| row.try_into().map_err(JfrError::Internal))
        .collect()
}

async fn fetch_assumptions_by_id(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    case_id: Uuid,
    assumption_ids: &[Uuid],
) -> Result<Vec<AssumptionRecord>> {
    if assumption_ids.is_empty() {
        return Ok(Vec::new());
    }
    let rows = sqlx::query_as::<_, AssumptionRow>(
        r"
        SELECT id, tenant_id, case_id, label, statement, weight, status,
               generation, parent_ids, validity, created_at, updated_at
          FROM assumptions
         WHERE tenant_id = $1 AND case_id = $2 AND id = ANY($3)
         FOR SHARE
        ",
    )
    .bind(tenant_id)
    .bind(case_id)
    .bind(assumption_ids)
    .fetch_all(&mut **transaction)
    .await?;
    if rows.len() != assumption_ids.len() {
        return Err(JfrError::Validation(
            "one or more required assumption IDs do not belong to this case".to_owned(),
        ));
    }
    rows.into_iter()
        .map(|row| row.try_into().map_err(JfrError::Internal))
        .collect()
}

async fn parent_generation(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    case_id: Uuid,
    parent_ids: &[Uuid],
) -> Result<i32> {
    if parent_ids.is_empty() {
        return Ok(0);
    }
    let rows = sqlx::query_as::<_, (Uuid, i32)>(
        r"
        SELECT id, generation
          FROM branches
         WHERE tenant_id = $1 AND case_id = $2 AND id = ANY($3)
        ",
    )
    .bind(tenant_id)
    .bind(case_id)
    .bind(parent_ids)
    .fetch_all(&mut **transaction)
    .await?;
    if rows.len() != parent_ids.len() {
        return Err(JfrError::Validation(
            "one or more parent IDs do not belong to this case".to_owned(),
        ));
    }
    Ok(rows
        .into_iter()
        .map(|(_, generation)| generation)
        .max()
        .unwrap_or(-1)
        + 1)
}

async fn assumption_parent_generation(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    case_id: Uuid,
    parent_ids: &[Uuid],
) -> Result<i32> {
    if parent_ids.is_empty() {
        return Ok(0);
    }
    let rows = sqlx::query_as::<_, (Uuid, i32)>(
        r"
        SELECT id, generation
          FROM assumptions
         WHERE tenant_id = $1 AND case_id = $2 AND id = ANY($3)
        ",
    )
    .bind(tenant_id)
    .bind(case_id)
    .bind(parent_ids)
    .fetch_all(&mut **transaction)
    .await?;
    if rows.len() != parent_ids.len() {
        return Err(JfrError::Validation(
            "one or more assumption parent IDs do not belong to this case".to_owned(),
        ));
    }
    Ok(rows
        .into_iter()
        .map(|(_, generation)| generation)
        .max()
        .unwrap_or(-1)
        + 1)
}

async fn link_evidence(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    branch_id: Uuid,
    evidence_ids: &[Uuid],
    relation: &str,
    note: &str,
    created_at: DateTime<Utc>,
) -> Result<()> {
    for evidence_id in evidence_ids {
        sqlx::query(
            r"
            INSERT INTO branch_evidence
                (tenant_id, branch_id, evidence_id, relation, note, created_at)
            VALUES ($1, $2, $3, $4, $5, $6)
            ON CONFLICT (tenant_id, branch_id, evidence_id, relation)
            DO UPDATE SET note = EXCLUDED.note
            ",
        )
        .bind(tenant_id)
        .bind(branch_id)
        .bind(evidence_id)
        .bind(relation)
        .bind(note)
        .bind(created_at)
        .execute(&mut **transaction)
        .await?;
    }
    Ok(())
}

async fn link_assumption_evidence(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    assumption_id: Uuid,
    evidence_ids: &[Uuid],
    relation: &str,
    note: &str,
    created_at: DateTime<Utc>,
) -> Result<()> {
    for evidence_id in evidence_ids {
        sqlx::query(
            r"
            INSERT INTO assumption_evidence
                (tenant_id, assumption_id, evidence_id, relation, note, created_at)
            VALUES ($1, $2, $3, $4, $5, $6)
            ON CONFLICT (tenant_id, assumption_id, evidence_id, relation)
            DO UPDATE SET note = EXCLUDED.note
            ",
        )
        .bind(tenant_id)
        .bind(assumption_id)
        .bind(evidence_id)
        .bind(relation)
        .bind(note)
        .bind(created_at)
        .execute(&mut **transaction)
        .await?;
    }
    Ok(())
}

async fn insert_counterexample(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    case_id: Uuid,
    guarantee_id: Uuid,
    assignment: &BTreeMap<String, i64>,
    certificate: &Value,
    source: &str,
    created_at: DateTime<Utc>,
) -> Result<CounterexampleRecord> {
    let id = Uuid::now_v7();
    let witness = serde_json::to_value(assignment)
        .map_err(|error| JfrError::Internal(format!("could not encode witness: {error}")))?;
    let certificate_hash = refutation::certificate_hash(certificate)?;
    sqlx::query(
        r"
        INSERT INTO counterexamples
            (id, tenant_id, case_id, guarantee_id, verifier_id, witness,
             certificate, certificate_hash, source, created_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
        ",
    )
    .bind(id)
    .bind(tenant_id)
    .bind(case_id)
    .bind(guarantee_id)
    .bind(refutation::VERIFIER_ID)
    .bind(&witness)
    .bind(certificate)
    .bind(&certificate_hash)
    .bind(source)
    .bind(created_at)
    .execute(&mut **transaction)
    .await?;
    Ok(CounterexampleRecord {
        id,
        tenant_id,
        case_id,
        guarantee_id,
        verifier_id: refutation::VERIFIER_ID.to_owned(),
        witness,
        certificate: certificate.clone(),
        certificate_hash,
        source: source.to_owned(),
        created_at,
    })
}

async fn revoke_authorizations(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    case_id: Uuid,
    guarantee_ids: &[Uuid],
    assumption_ids: &[Uuid],
    reason: &str,
    revoked_at: DateTime<Utc>,
) -> Result<Vec<Uuid>> {
    if guarantee_ids.is_empty() && assumption_ids.is_empty() {
        return Ok(Vec::new());
    }
    Ok(sqlx::query_scalar::<_, Uuid>(
        r"
        UPDATE decision_authorizations
           SET status = 'revoked',
               revoked_at = $1,
               revocation = $2,
               updated_at = $1
         WHERE tenant_id = $3
           AND case_id = $4
           AND status = 'authorized'
           AND (
               required_guarantee_ids && $5::UUID[]
               OR required_assumption_ids && $6::UUID[]
           )
        RETURNING id
        ",
    )
    .bind(revoked_at)
    .bind(json!({
        "reason": reason,
        "guarantee_ids": guarantee_ids,
        "assumption_ids": assumption_ids,
        "revoked_at": revoked_at
    }))
    .bind(tenant_id)
    .bind(case_id)
    .bind(guarantee_ids)
    .bind(assumption_ids)
    .fetch_all(&mut **transaction)
    .await?)
}

fn canonical_hash(value: &Value) -> Result<Vec<u8>> {
    let canonical = serde_jcs::to_vec(value)
        .map_err(|error| JfrError::Internal(format!("canonical encoding failed: {error}")))?;
    Ok(Sha256::digest(canonical).to_vec())
}

fn database_timestamp() -> DateTime<Utc> {
    let now = Utc::now();
    now.with_nanosecond((now.nanosecond() / 1_000) * 1_000)
        .unwrap_or(now)
}

fn check_version(case: &LockedCase, expected: i64) -> Result<()> {
    if case.version == expected {
        Ok(())
    } else {
        Err(JfrError::VersionConflict(format!(
            "expected case version {expected}, current version is {}",
            case.version
        )))
    }
}

fn unique_ids(ids: &[Uuid], field: &str) -> Result<Vec<Uuid>> {
    let unique: BTreeSet<_> = ids.iter().copied().collect();
    if unique.len() != ids.len() {
        return Err(JfrError::Validation(format!(
            "{field} cannot contain duplicates"
        )));
    }
    Ok(unique.into_iter().collect())
}

fn require_basis(evidence_ids: &[Uuid], certificate: &Value) -> Result<()> {
    if evidence_ids.is_empty()
        && certificate
            .as_object()
            .is_none_or(serde_json::Map::is_empty)
    {
        return Err(JfrError::Validation(
            "evidence or a non-empty formal certificate is required".to_owned(),
        ));
    }
    require_object(certificate, "certificate")
}

fn require_object(value: &Value, field: &str) -> Result<()> {
    if value.is_object() {
        Ok(())
    } else {
        Err(JfrError::Validation(format!(
            "{field} must be a JSON object"
        )))
    }
}

fn validate_text(value: &str, field: &str, max: usize) -> Result<()> {
    let length = value.trim().chars().count();
    if length == 0 || length > max {
        return Err(JfrError::Validation(format!(
            "{field} must contain between 1 and {max} characters"
        )));
    }
    Ok(())
}

fn validate_non_negative(value: f64, field: &str) -> Result<()> {
    if value.is_finite() && value >= 0.0 {
        Ok(())
    } else {
        Err(JfrError::Validation(format!(
            "{field} must be finite and non-negative"
        )))
    }
}

fn validate_optional_risk(value: Option<f64>) -> Result<()> {
    value.map_or(Ok(()), |risk| validate_non_negative(risk, "risk score"))
}

fn probability_entropy(probabilities: &[f64]) -> f64 {
    -probabilities
        .iter()
        .copied()
        .filter(|probability| *probability > 0.0)
        .map(|probability| probability * probability.log2())
        .sum::<f64>()
}

fn validate_candidates(candidates: &[BranchCandidate]) -> Result<f64> {
    let mut total = 0.0;
    for candidate in candidates {
        validate_text(&candidate.label, "candidate label", 256)?;
        validate_non_negative(candidate.relative_weight, "candidate relative weight")?;
        require_object(&candidate.validity, "candidate validity")?;
        total += candidate.relative_weight;
    }
    if total <= 0.0 || !total.is_finite() {
        return Err(JfrError::Validation(
            "candidate weights must have finite positive mass".to_owned(),
        ));
    }
    Ok(total)
}

fn mutation<T>(resource: T, commit: LedgerCommit) -> Mutation<T> {
    Mutation {
        case_version: commit.case_version,
        event_sequence: commit.event_sequence,
        event_hash: hex::encode(commit.event_hash),
        resource,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn correspondence_uses_global_minimum_instead_of_greedy_edges() {
        let assignment = rectangular_assignment(&[vec![1.0, 2.0], vec![1.1, 100.0]]);
        assert_eq!(assignment, vec![Some(1), Some(0)]);
    }

    #[test]
    fn rectangular_correspondence_leaves_only_surplus_successors_unmatched() {
        let assignment =
            rectangular_assignment(&[vec![0.0, 10.0], vec![10.0, 0.0], vec![5.0, 5.0]]);
        assert_eq!(assignment.iter().filter(|entry| entry.is_some()).count(), 2);
        assert_eq!(assignment[0], Some(0));
        assert_eq!(assignment[1], Some(1));
    }
}
