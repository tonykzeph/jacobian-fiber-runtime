use std::{collections::BTreeMap, fmt, str::FromStr};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::FromRow;
use uuid::Uuid;

use crate::refutation::FiniteDomainSpec;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BranchStatus {
    Proposed,
    Active,
    Contradicted,
    Superseded,
    Merged,
    Archived,
}

impl BranchStatus {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::Active => "active",
            Self::Contradicted => "contradicted",
            Self::Superseded => "superseded",
            Self::Merged => "merged",
            Self::Archived => "archived",
        }
    }
}

impl fmt::Display for BranchStatus {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for BranchStatus {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "proposed" => Ok(Self::Proposed),
            "active" => Ok(Self::Active),
            "contradicted" => Ok(Self::Contradicted),
            "superseded" => Ok(Self::Superseded),
            "merged" => Ok(Self::Merged),
            "archived" => Ok(Self::Archived),
            _ => Err(format!("unknown branch status: {value}")),
        }
    }
}

#[derive(Debug, Clone, Serialize, FromRow)]
pub struct CaseRecord {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub name: String,
    pub observation: Value,
    pub metadata: Value,
    pub version: i64,
    pub audit_event_count: i64,
    #[serde(serialize_with = "serialize_hash")]
    pub audit_head_hash: Vec<u8>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, FromRow)]
pub struct EvidenceRecord {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub case_id: Uuid,
    pub kind: String,
    pub payload: Value,
    pub source: String,
    pub observed_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, FromRow)]
pub struct BranchRow {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub case_id: Uuid,
    pub label: String,
    pub state: Value,
    pub weight: f64,
    pub status: String,
    pub generation: i32,
    pub parent_ids: Vec<Uuid>,
    pub validity: Value,
    pub risk_score: Option<f64>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize)]
pub struct BranchRecord {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub case_id: Uuid,
    pub label: String,
    pub state: Value,
    pub weight: f64,
    pub status: BranchStatus,
    pub generation: i32,
    pub parent_ids: Vec<Uuid>,
    pub validity: Value,
    pub risk_score: Option<f64>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl TryFrom<BranchRow> for BranchRecord {
    type Error = String;

    fn try_from(row: BranchRow) -> Result<Self, Self::Error> {
        Ok(Self {
            id: row.id,
            tenant_id: row.tenant_id,
            case_id: row.case_id,
            label: row.label,
            state: row.state,
            weight: row.weight,
            status: BranchStatus::from_str(&row.status)?,
            generation: row.generation,
            parent_ids: row.parent_ids,
            validity: row.validity,
            risk_score: row.risk_score,
            created_at: row.created_at,
            updated_at: row.updated_at,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssumptionStatus {
    Proposed,
    Active,
    Contradicted,
    Superseded,
    Archived,
}

impl AssumptionStatus {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::Active => "active",
            Self::Contradicted => "contradicted",
            Self::Superseded => "superseded",
            Self::Archived => "archived",
        }
    }
}

impl fmt::Display for AssumptionStatus {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for AssumptionStatus {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "proposed" => Ok(Self::Proposed),
            "active" => Ok(Self::Active),
            "contradicted" => Ok(Self::Contradicted),
            "superseded" => Ok(Self::Superseded),
            "archived" => Ok(Self::Archived),
            _ => Err(format!("unknown assumption status: {value}")),
        }
    }
}

#[derive(Debug, Clone, FromRow)]
pub struct AssumptionRow {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub case_id: Uuid,
    pub label: String,
    pub statement: Value,
    pub weight: f64,
    pub status: String,
    pub generation: i32,
    pub parent_ids: Vec<Uuid>,
    pub validity: Value,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AssumptionRecord {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub case_id: Uuid,
    pub label: String,
    pub statement: Value,
    pub weight: f64,
    pub status: AssumptionStatus,
    pub generation: i32,
    pub parent_ids: Vec<Uuid>,
    pub validity: Value,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl TryFrom<AssumptionRow> for AssumptionRecord {
    type Error = String;

    fn try_from(row: AssumptionRow) -> Result<Self, Self::Error> {
        Ok(Self {
            id: row.id,
            tenant_id: row.tenant_id,
            case_id: row.case_id,
            label: row.label,
            statement: row.statement,
            weight: row.weight,
            status: AssumptionStatus::from_str(&row.status)?,
            generation: row.generation,
            parent_ids: row.parent_ids,
            validity: row.validity,
            created_at: row.created_at,
            updated_at: row.updated_at,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GuaranteeStatus {
    Proposed,
    Verified,
    Contradicted,
    Suspended,
    Superseded,
    Archived,
}

impl GuaranteeStatus {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::Verified => "verified",
            Self::Contradicted => "contradicted",
            Self::Suspended => "suspended",
            Self::Superseded => "superseded",
            Self::Archived => "archived",
        }
    }
}

impl fmt::Display for GuaranteeStatus {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for GuaranteeStatus {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "proposed" => Ok(Self::Proposed),
            "verified" => Ok(Self::Verified),
            "contradicted" => Ok(Self::Contradicted),
            "suspended" => Ok(Self::Suspended),
            "superseded" => Ok(Self::Superseded),
            "archived" => Ok(Self::Archived),
            _ => Err(format!("unknown guarantee status: {value}")),
        }
    }
}

#[derive(Debug, Clone, FromRow)]
pub struct GuaranteeRow {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub case_id: Uuid,
    pub label: String,
    pub description: String,
    pub verifier_id: String,
    pub specification: Value,
    pub premise_assumption_ids: Vec<Uuid>,
    pub parent_ids: Vec<Uuid>,
    pub status: String,
    pub verification: Value,
    pub counterexample_count: i64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize)]
pub struct GuaranteeRecord {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub case_id: Uuid,
    pub label: String,
    pub description: String,
    pub verifier_id: String,
    pub specification: Value,
    pub premise_assumption_ids: Vec<Uuid>,
    pub parent_ids: Vec<Uuid>,
    pub status: GuaranteeStatus,
    pub verification: Value,
    pub counterexample_count: i64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl TryFrom<GuaranteeRow> for GuaranteeRecord {
    type Error = String;

    fn try_from(row: GuaranteeRow) -> Result<Self, Self::Error> {
        Ok(Self {
            id: row.id,
            tenant_id: row.tenant_id,
            case_id: row.case_id,
            label: row.label,
            description: row.description,
            verifier_id: row.verifier_id,
            specification: row.specification,
            premise_assumption_ids: row.premise_assumption_ids,
            parent_ids: row.parent_ids,
            status: GuaranteeStatus::from_str(&row.status)?,
            verification: row.verification,
            counterexample_count: row.counterexample_count,
            created_at: row.created_at,
            updated_at: row.updated_at,
        })
    }
}

#[derive(Debug, Clone, Serialize, FromRow)]
pub struct CounterexampleRecord {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub case_id: Uuid,
    pub guarantee_id: Uuid,
    pub verifier_id: String,
    pub witness: Value,
    pub certificate: Value,
    #[serde(serialize_with = "serialize_hash")]
    pub certificate_hash: Vec<u8>,
    pub source: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, FromRow)]
pub struct DecisionAuthorizationRecord {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub case_id: Uuid,
    pub requested_action_id: String,
    pub selected_action_id: String,
    pub status: String,
    pub policy: String,
    pub required_guarantee_ids: Vec<Uuid>,
    pub required_assumption_ids: Vec<Uuid>,
    pub input: Value,
    pub result: Value,
    #[serde(serialize_with = "serialize_hash")]
    pub input_hash: Vec<u8>,
    pub created_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub revocation: Option<Value>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, FromRow)]
pub struct EventRecord {
    pub case_id: Uuid,
    pub sequence: i64,
    pub tenant_id: Uuid,
    pub event_type: String,
    pub payload: Value,
    #[serde(serialize_with = "serialize_hash")]
    pub previous_hash: Vec<u8>,
    #[serde(serialize_with = "serialize_hash")]
    pub event_hash: Vec<u8>,
    pub actor_key_id: Uuid,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CaseSnapshot {
    pub case: CaseRecord,
    pub evidence: Vec<EvidenceRecord>,
    pub branches: Vec<BranchRecord>,
    pub assumptions: Vec<AssumptionRecord>,
    pub guarantees: Vec<GuaranteeRecord>,
    pub counterexamples: Vec<CounterexampleRecord>,
    pub authorizations: Vec<DecisionAuthorizationRecord>,
    pub events: Vec<EventRecord>,
    pub audit: AuditReport,
}

#[derive(Debug, Clone, Serialize)]
pub struct AuditReport {
    pub valid: bool,
    pub checked_events: i64,
    pub failed_sequence: Option<i64>,
    pub reason: Option<String>,
    pub head_hash: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SemanticBranchMatch {
    pub recorded_branch_id: Uuid,
    pub recomputed_label: String,
    pub normalized_distance: f64,
    pub certificate_verifier: Option<String>,
    pub valid: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct SemanticFiberAudit {
    pub valid: bool,
    pub solver: String,
    pub complete: bool,
    pub recorded_active_branches: usize,
    pub recomputed_branches: usize,
    pub matches: Vec<SemanticBranchMatch>,
    pub maximum_escape_score: f64,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct GuaranteeAuditEntry {
    pub guarantee_id: Uuid,
    pub label: String,
    pub status: GuaranteeStatus,
    pub valid: bool,
    pub checked_assignments: u64,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct GuaranteeSemanticAudit {
    pub valid: bool,
    pub verifier: String,
    pub checked_guarantees: usize,
    pub checked_assignments: u64,
    pub active_assumptions: usize,
    pub verified_guarantees: usize,
    pub contradicted_guarantees: usize,
    pub suspended_guarantees: usize,
    pub authorized_actions: usize,
    pub entries: Vec<GuaranteeAuditEntry>,
    pub reason: Option<String>,
}

#[derive(Debug, Clone)]
pub struct AuthContext {
    pub tenant_id: Uuid,
    pub key_id: Uuid,
    pub key_name: String,
    pub scopes: Vec<String>,
}

impl AuthContext {
    #[must_use]
    pub fn has_scope(&self, required: &str) -> bool {
        self.scopes
            .iter()
            .any(|scope| scope == "*" || scope == required)
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct CreateCase {
    pub name: String,
    pub observation: Value,
    #[serde(default = "empty_object")]
    pub metadata: Value,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AddEvidence {
    pub kind: String,
    pub payload: Value,
    pub source: String,
    pub observed_at: Option<DateTime<Utc>>,
    pub expected_case_version: i64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RecordObservation {
    pub observation: Value,
    pub source: String,
    #[serde(default = "observation_kind")]
    pub kind: String,
    pub observed_at: Option<DateTime<Utc>>,
    pub expected_case_version: i64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct MaterializeJacobianFiber {
    pub expected_case_version: i64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AdvanceJacobianFiber {
    pub observation: Value,
    pub source: String,
    #[serde(default = "observation_kind")]
    pub kind: String,
    pub observed_at: Option<DateTime<Utc>>,
    pub expected_case_version: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct BranchCorrespondence {
    pub predecessor_id: Uuid,
    pub successor_id: Uuid,
    pub normalized_distance: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct FiberTransition {
    pub solver: String,
    pub observation: Value,
    pub complete: bool,
    pub superseded_branch_ids: Vec<Uuid>,
    pub correspondence: Vec<BranchCorrespondence>,
    pub branches: Vec<BranchRecord>,
    pub evidence: Option<EvidenceRecord>,
    pub global_certificate: Value,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ProposeBranch {
    pub label: String,
    pub state: Value,
    #[serde(default = "unit_weight")]
    pub weight: f64,
    #[serde(default)]
    pub parent_ids: Vec<Uuid>,
    #[serde(default)]
    pub evidence_ids: Vec<Uuid>,
    #[serde(default = "empty_object")]
    pub proposal: Value,
    pub expected_case_version: i64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ValidateBranch {
    pub valid: bool,
    pub reason: String,
    #[serde(default)]
    pub evidence_ids: Vec<Uuid>,
    pub certificate: Value,
    pub risk_score: Option<f64>,
    pub expected_case_version: i64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct LikelihoodModel {
    pub id: String,
    pub version: String,
    pub conditional_independence: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ApplyLikelihoodEvidence {
    pub kind: String,
    pub payload: Value,
    pub source: String,
    pub observed_at: Option<DateTime<Utc>>,
    pub log_likelihood_by_branch: BTreeMap<Uuid, f64>,
    pub model: LikelihoodModel,
    pub expected_case_version: i64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ProposeAssumption {
    pub label: String,
    pub statement: Value,
    #[serde(default = "unit_weight")]
    pub weight: f64,
    #[serde(default)]
    pub parent_ids: Vec<Uuid>,
    #[serde(default)]
    pub evidence_ids: Vec<Uuid>,
    #[serde(default = "empty_object")]
    pub proposal: Value,
    pub expected_case_version: i64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ValidateAssumption {
    pub valid: bool,
    pub reason: String,
    #[serde(default)]
    pub evidence_ids: Vec<Uuid>,
    pub certificate: Value,
    pub expected_case_version: i64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CreateGuarantee {
    pub label: String,
    pub description: String,
    #[serde(default)]
    pub premise_assumption_ids: Vec<Uuid>,
    #[serde(default)]
    pub parent_ids: Vec<Uuid>,
    pub specification: FiniteDomainSpec,
    pub expected_case_version: i64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SearchGuarantee {
    pub expected_case_version: i64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SubmitCounterexample {
    pub assignment: BTreeMap<String, i64>,
    pub source: String,
    pub expected_case_version: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct GuaranteeTransition {
    pub guarantee: GuaranteeRecord,
    pub search: crate::refutation::SearchReport,
    pub counterexample: Option<CounterexampleRecord>,
    pub revoked_authorization_ids: Vec<Uuid>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PosteriorWeight {
    pub branch_id: Uuid,
    pub prior: f64,
    pub log_likelihood: f64,
    pub posterior: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct BayesianUpdate {
    pub evidence: EvidenceRecord,
    pub model_id: String,
    pub model_version: String,
    pub prior_entropy_bits: f64,
    pub posterior_entropy_bits: f64,
    pub information_gain_bits: f64,
    pub log_evidence: f64,
    pub weights: Vec<PosteriorWeight>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PruneBranch {
    pub reason: String,
    #[serde(default)]
    pub evidence_ids: Vec<Uuid>,
    pub certificate: Value,
    pub expected_case_version: i64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BranchCandidate {
    pub label: String,
    pub state: Value,
    #[serde(default = "unit_weight")]
    pub relative_weight: f64,
    #[serde(default = "empty_object")]
    pub validity: Value,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SplitBranch {
    pub reason: String,
    pub candidates: Vec<BranchCandidate>,
    #[serde(default)]
    pub evidence_ids: Vec<Uuid>,
    pub certificate: Value,
    pub expected_case_version: i64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct MergeBranches {
    pub branch_ids: Vec<Uuid>,
    pub label: String,
    pub state: Value,
    pub reason: String,
    #[serde(default)]
    pub evidence_ids: Vec<Uuid>,
    pub certificate: Value,
    pub expected_case_version: i64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ActionCandidate {
    pub id: String,
    pub label: String,
    pub utility_by_branch: BTreeMap<Uuid, f64>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionPolicy {
    Expected,
    Robust,
    DistributionallyRobust,
}

#[derive(Debug, Clone, Deserialize)]
pub struct EvaluateActions {
    pub policy: DecisionPolicy,
    pub actions: Vec<ActionCandidate>,
    pub ambiguity_radius: Option<f64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ActionScore {
    pub id: String,
    pub label: String,
    pub expected_utility: f64,
    pub worst_case_utility: f64,
    pub best_case_utility: f64,
    pub distributionally_robust_utility: Option<f64>,
    pub adversarial_distribution_by_branch: Option<BTreeMap<Uuid, f64>>,
    pub utility_by_branch: BTreeMap<Uuid, f64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DecisionResult {
    pub policy: DecisionPolicy,
    pub ambiguity_radius: Option<f64>,
    pub selected: ActionScore,
    pub scores: Vec<ActionScore>,
    pub active_branch_count: usize,
    pub case_version: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JointScenarioUtility {
    pub branch_id: Uuid,
    pub assumption_id: Uuid,
    pub utility: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JointActionCandidate {
    pub id: String,
    pub label: String,
    pub utilities: Vec<JointScenarioUtility>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizeAction {
    pub requested_action_id: String,
    pub actions: Vec<JointActionCandidate>,
    #[serde(default)]
    pub required_guarantee_ids: Vec<Uuid>,
    #[serde(default)]
    pub required_assumption_ids: Vec<Uuid>,
    pub expected_case_version: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct JointWorstCase {
    pub branch_id: Uuid,
    pub assumption_id: Uuid,
    pub utility: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct JointActionScore {
    pub id: String,
    pub label: String,
    pub worst_case: JointWorstCase,
    pub best_case_utility: f64,
    pub scenario_count: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct ActionAuthorization {
    pub authorization: DecisionAuthorizationRecord,
    pub authorized: bool,
    pub selected: JointActionScore,
    pub scores: Vec<JointActionScore>,
    pub scenario_count: usize,
    pub dependency_reasons: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ExperimentCandidate {
    pub id: String,
    pub label: String,
    pub predictions_by_branch: BTreeMap<Uuid, BTreeMap<String, f64>>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RankExperiments {
    pub experiments: Vec<ExperimentCandidate>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ExperimentScore {
    pub id: String,
    pub label: String,
    pub information_gain_bits: f64,
    pub possible_outcomes: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct ExperimentRanking {
    pub experiments: Vec<ExperimentScore>,
    pub active_branch_count: usize,
    pub case_version: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct Mutation<T> {
    pub case_version: i64,
    pub event_sequence: i64,
    pub event_hash: String,
    pub resource: T,
}

const fn unit_weight() -> f64 {
    1.0
}

fn empty_object() -> Value {
    Value::Object(serde_json::Map::new())
}

fn observation_kind() -> String {
    "observation".to_owned()
}

fn serialize_hash<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(&hex::encode(bytes))
}
