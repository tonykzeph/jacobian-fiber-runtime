use std::collections::{BTreeMap, BTreeSet};

use uuid::Uuid;

use crate::{
    JfrError, Result,
    model::{
        ActionScore, AssumptionRecord, BranchRecord, DecisionPolicy, DecisionResult,
        EvaluateActions, ExperimentRanking, ExperimentScore, JointActionCandidate,
        JointActionScore, JointWorstCase, RankExperiments,
    },
};

const MAX_JOINT_SCENARIOS: usize = 50_000;

pub fn evaluate_actions(
    case_version: i64,
    branches: &[BranchRecord],
    request: EvaluateActions,
) -> Result<DecisionResult> {
    let weights = normalized_weights(branches)?;
    let ambiguity_radius = match request.policy {
        DecisionPolicy::DistributionallyRobust => {
            let radius = request.ambiguity_radius.ok_or_else(|| {
                JfrError::Validation(
                    "distributionally robust decisions require ambiguity_radius".to_owned(),
                )
            })?;
            if !radius.is_finite() || radius < 0.0 {
                return Err(JfrError::Validation(
                    "ambiguity_radius must be finite and non-negative".to_owned(),
                ));
            }
            Some(radius)
        }
        DecisionPolicy::Expected | DecisionPolicy::Robust => {
            if request.ambiguity_radius.is_some() {
                return Err(JfrError::Validation(
                    "ambiguity_radius is only valid for distributionally_robust policy".to_owned(),
                ));
            }
            None
        }
    };
    if request.actions.is_empty() {
        return Err(JfrError::Validation(
            "at least one action is required".to_owned(),
        ));
    }
    let active_ids: BTreeSet<_> = branches.iter().map(|branch| branch.id).collect();
    let mut scores = Vec::with_capacity(request.actions.len());
    for action in request.actions {
        validate_identity(&action.id, "action ID")?;
        validate_label(&action.label, "action label")?;
        validate_branch_coverage(&active_ids, action.utility_by_branch.keys())?;
        if action
            .utility_by_branch
            .values()
            .any(|value| !value.is_finite())
        {
            return Err(JfrError::Validation("utilities must be finite".to_owned()));
        }
        let values: Vec<f64> = branches
            .iter()
            .map(|branch| action.utility_by_branch[&branch.id])
            .collect();
        let expected_utility = branches
            .iter()
            .map(|branch| weights[&branch.id] * action.utility_by_branch[&branch.id])
            .sum();
        let (distributionally_robust_utility, adversarial_distribution_by_branch) =
            if let Some(radius) = ambiguity_radius {
                let (value, distribution) =
                    kl_robust_value(branches, &weights, &action.utility_by_branch, radius);
                (Some(value), Some(distribution))
            } else {
                (None, None)
            };
        scores.push(ActionScore {
            id: action.id,
            label: action.label,
            expected_utility,
            worst_case_utility: values.iter().copied().fold(f64::INFINITY, f64::min),
            best_case_utility: values.iter().copied().fold(f64::NEG_INFINITY, f64::max),
            distributionally_robust_utility,
            adversarial_distribution_by_branch,
            utility_by_branch: action.utility_by_branch,
        });
    }
    scores.sort_by(|left, right| {
        let (left_primary, left_secondary) = match request.policy {
            DecisionPolicy::Expected => (left.expected_utility, left.worst_case_utility),
            DecisionPolicy::Robust => (left.worst_case_utility, left.expected_utility),
            DecisionPolicy::DistributionallyRobust => (
                left.distributionally_robust_utility
                    .unwrap_or(left.worst_case_utility),
                left.expected_utility,
            ),
        };
        let (right_primary, right_secondary) = match request.policy {
            DecisionPolicy::Expected => (right.expected_utility, right.worst_case_utility),
            DecisionPolicy::Robust => (right.worst_case_utility, right.expected_utility),
            DecisionPolicy::DistributionallyRobust => (
                right
                    .distributionally_robust_utility
                    .unwrap_or(right.worst_case_utility),
                right.expected_utility,
            ),
        };
        right_primary
            .total_cmp(&left_primary)
            .then_with(|| right_secondary.total_cmp(&left_secondary))
            .then_with(|| left.id.cmp(&right.id))
    });
    Ok(DecisionResult {
        policy: request.policy,
        ambiguity_radius,
        selected: scores[0].clone(),
        scores,
        active_branch_count: branches.len(),
        case_version,
    })
}

pub fn evaluate_joint_actions(
    branches: &[BranchRecord],
    assumptions: &[AssumptionRecord],
    actions: Vec<JointActionCandidate>,
) -> Result<(JointActionScore, Vec<JointActionScore>, usize)> {
    if branches.is_empty() {
        return Err(JfrError::Conflict(
            "the case has no active world branches".to_owned(),
        ));
    }
    if assumptions.is_empty() {
        return Err(JfrError::Conflict(
            "the case has no active assumption branches".to_owned(),
        ));
    }
    if actions.is_empty() {
        return Err(JfrError::Validation(
            "at least one action is required".to_owned(),
        ));
    }
    let expected = branches
        .len()
        .checked_mul(assumptions.len())
        .ok_or_else(|| JfrError::Validation("joint scenario count overflowed".to_owned()))?;
    let total = expected
        .checked_mul(actions.len())
        .ok_or_else(|| JfrError::Validation("joint utility count overflowed".to_owned()))?;
    if total > MAX_JOINT_SCENARIOS {
        return Err(JfrError::Validation(format!(
            "joint authorization has {total} utility cells; maximum is {MAX_JOINT_SCENARIOS}"
        )));
    }
    let expected_pairs = branches
        .iter()
        .flat_map(|branch| {
            assumptions
                .iter()
                .map(move |assumption| (branch.id, assumption.id))
        })
        .collect::<BTreeSet<_>>();
    let mut action_ids = BTreeSet::new();
    let mut scores = Vec::with_capacity(actions.len());
    for action in actions {
        validate_identity(&action.id, "action ID")?;
        validate_label(&action.label, "action label")?;
        if !action_ids.insert(action.id.clone()) {
            return Err(JfrError::Validation(format!(
                "duplicate action ID: {}",
                action.id
            )));
        }
        let mut supplied = BTreeMap::new();
        for scenario in action.utilities {
            if !scenario.utility.is_finite() {
                return Err(JfrError::Validation("utilities must be finite".to_owned()));
            }
            if supplied
                .insert(
                    (scenario.branch_id, scenario.assumption_id),
                    scenario.utility,
                )
                .is_some()
            {
                return Err(JfrError::Validation(format!(
                    "action {} supplies a joint scenario more than once",
                    action.id
                )));
            }
        }
        if supplied.keys().copied().collect::<BTreeSet<_>>() != expected_pairs {
            return Err(JfrError::Validation(format!(
                "action {} must supply exactly one utility for every active world x assumption scenario",
                action.id
            )));
        }
        let ((worst_branch, worst_assumption), worst_utility) = supplied
            .iter()
            .min_by(|left, right| left.1.total_cmp(right.1).then_with(|| left.0.cmp(right.0)))
            .map(|(pair, utility)| (*pair, *utility))
            .ok_or_else(|| JfrError::Internal("joint scenario set was empty".to_owned()))?;
        let best_case_utility = supplied.values().copied().fold(f64::NEG_INFINITY, f64::max);
        scores.push(JointActionScore {
            id: action.id,
            label: action.label,
            worst_case: JointWorstCase {
                branch_id: worst_branch,
                assumption_id: worst_assumption,
                utility: worst_utility,
            },
            best_case_utility,
            scenario_count: expected,
        });
    }
    scores.sort_by(|left, right| {
        right
            .worst_case
            .utility
            .total_cmp(&left.worst_case.utility)
            .then_with(|| right.best_case_utility.total_cmp(&left.best_case_utility))
            .then_with(|| left.id.cmp(&right.id))
    });
    Ok((scores[0].clone(), scores, expected))
}

fn kl_robust_value(
    branches: &[BranchRecord],
    weights: &BTreeMap<Uuid, f64>,
    utilities: &BTreeMap<Uuid, f64>,
    radius: f64,
) -> (f64, BTreeMap<Uuid, f64>) {
    let support = branches
        .iter()
        .filter_map(|branch| {
            let probability = weights[&branch.id];
            (probability > 0.0).then_some((branch.id, probability, utilities[&branch.id]))
        })
        .collect::<Vec<_>>();
    if radius == 0.0 {
        let expected = support
            .iter()
            .map(|(_, probability, utility)| probability * utility)
            .sum();
        return (
            expected,
            branches
                .iter()
                .map(|branch| (branch.id, weights[&branch.id]))
                .collect(),
        );
    }
    let minimum = support
        .iter()
        .map(|(_, _, utility)| *utility)
        .fold(f64::INFINITY, f64::min);
    let minimum_mass = support
        .iter()
        .filter(|(_, _, utility)| approximately_equal(*utility, minimum))
        .map(|(_, probability, _)| probability)
        .sum::<f64>();
    let concentration_divergence = -minimum_mass.ln();
    if radius >= concentration_divergence - 1.0e-12 {
        let distribution = branches
            .iter()
            .map(|branch| {
                let value = support
                    .iter()
                    .find(|(id, _, _)| *id == branch.id)
                    .filter(|(_, _, utility)| approximately_equal(*utility, minimum))
                    .map_or(0.0, |(_, probability, _)| probability / minimum_mass);
                (branch.id, value)
            })
            .collect();
        return (minimum, distribution);
    }

    let tilted = |temperature: f64| {
        let terms = support
            .iter()
            .map(|(_, probability, utility)| {
                probability * (-(utility - minimum) / temperature).exp()
            })
            .collect::<Vec<_>>();
        let normalizer = terms.iter().sum::<f64>();
        let distribution = terms
            .iter()
            .map(|term| term / normalizer)
            .collect::<Vec<_>>();
        let divergence = distribution
            .iter()
            .zip(&support)
            .filter(|(probability, _)| **probability > 0.0)
            .map(|(probability, (_, prior, _))| probability * (probability / prior).ln())
            .sum::<f64>();
        (distribution, divergence)
    };

    let mut upper = 1.0;
    for _ in 0..1_024 {
        if tilted(upper).1 <= radius {
            break;
        }
        upper = (upper * 2.0).min(f64::MAX);
    }
    let mut lower = 0.0;
    for _ in 0..160 {
        let midpoint = if lower == 0.0 {
            upper / 2.0
        } else {
            (lower * upper).sqrt()
        };
        if tilted(midpoint).1 > radius {
            lower = midpoint;
        } else {
            upper = midpoint;
        }
    }
    let (adversarial, _) = tilted(upper);
    let robust_value = adversarial
        .iter()
        .zip(&support)
        .map(|(probability, (_, _, utility))| probability * utility)
        .sum();
    let distribution = branches
        .iter()
        .map(|branch| {
            let probability = support
                .iter()
                .position(|(id, _, _)| *id == branch.id)
                .map_or(0.0, |index| adversarial[index]);
            (branch.id, probability)
        })
        .collect();
    (robust_value, distribution)
}

fn approximately_equal(left: f64, right: f64) -> bool {
    (left - right).abs() <= 1.0e-12 * (1.0 + left.abs().max(right.abs()))
}

pub fn rank_experiments(
    case_version: i64,
    branches: &[BranchRecord],
    request: RankExperiments,
) -> Result<ExperimentRanking> {
    let weights = normalized_weights(branches)?;
    if request.experiments.is_empty() {
        return Err(JfrError::Validation(
            "at least one experiment is required".to_owned(),
        ));
    }
    let active_ids: BTreeSet<_> = branches.iter().map(|branch| branch.id).collect();
    let prior_entropy = entropy(weights.values().copied());
    let mut scores = Vec::with_capacity(request.experiments.len());
    for experiment in request.experiments {
        validate_identity(&experiment.id, "experiment ID")?;
        validate_label(&experiment.label, "experiment label")?;
        validate_branch_coverage(&active_ids, experiment.predictions_by_branch.keys())?;
        let mut predictions = BTreeMap::new();
        let mut outcomes = BTreeSet::new();
        for branch in branches {
            let distribution = &experiment.predictions_by_branch[&branch.id];
            if distribution.is_empty()
                || distribution
                    .values()
                    .any(|probability| !probability.is_finite() || *probability < 0.0)
            {
                return Err(JfrError::Validation(
                    "prediction distributions must have finite non-negative values".to_owned(),
                ));
            }
            let total: f64 = distribution.values().sum();
            if total <= 0.0 {
                return Err(JfrError::Validation(
                    "prediction distributions must have positive mass".to_owned(),
                ));
            }
            let normalized: BTreeMap<_, _> = distribution
                .iter()
                .map(|(outcome, probability)| {
                    outcomes.insert(outcome.clone());
                    (outcome.clone(), probability / total)
                })
                .collect();
            predictions.insert(branch.id, normalized);
        }
        let conditional_entropy = outcomes
            .iter()
            .map(|outcome| {
                let outcome_probability: f64 = branches
                    .iter()
                    .map(|branch| {
                        weights[&branch.id]
                            * predictions[&branch.id]
                                .get(outcome)
                                .copied()
                                .unwrap_or_default()
                    })
                    .sum();
                if outcome_probability <= 0.0 {
                    return 0.0;
                }
                let posterior = branches.iter().map(|branch| {
                    weights[&branch.id]
                        * predictions[&branch.id]
                            .get(outcome)
                            .copied()
                            .unwrap_or_default()
                        / outcome_probability
                });
                outcome_probability * entropy(posterior)
            })
            .sum::<f64>();
        scores.push(ExperimentScore {
            id: experiment.id,
            label: experiment.label,
            information_gain_bits: (prior_entropy - conditional_entropy).max(0.0),
            possible_outcomes: outcomes.len(),
        });
    }
    scores.sort_by(|left, right| {
        right
            .information_gain_bits
            .total_cmp(&left.information_gain_bits)
            .then_with(|| right.possible_outcomes.cmp(&left.possible_outcomes))
            .then_with(|| left.id.cmp(&right.id))
    });
    Ok(ExperimentRanking {
        experiments: scores,
        active_branch_count: branches.len(),
        case_version,
    })
}

fn normalized_weights(branches: &[BranchRecord]) -> Result<BTreeMap<Uuid, f64>> {
    if branches.is_empty() {
        return Err(JfrError::Conflict(
            "the case has no active branches".to_owned(),
        ));
    }
    if branches
        .iter()
        .any(|branch| !branch.weight.is_finite() || branch.weight < 0.0)
    {
        return Err(JfrError::Internal(
            "active branch weights are invalid".to_owned(),
        ));
    }
    let total: f64 = branches.iter().map(|branch| branch.weight).sum();
    if total <= 0.0 || !total.is_finite() {
        return Err(JfrError::Conflict(
            "active branches have no positive weight mass".to_owned(),
        ));
    }
    Ok(branches
        .iter()
        .map(|branch| (branch.id, branch.weight / total))
        .collect())
}

fn validate_branch_coverage<'a>(
    active_ids: &BTreeSet<Uuid>,
    supplied_ids: impl Iterator<Item = &'a Uuid>,
) -> Result<()> {
    let supplied: BTreeSet<_> = supplied_ids.copied().collect();
    if supplied != *active_ids {
        return Err(JfrError::Validation(
            "every active branch must have exactly one supplied value".to_owned(),
        ));
    }
    Ok(())
}

fn validate_identity(value: &str, field: &str) -> Result<()> {
    if value.trim().is_empty() || value.len() > 128 {
        return Err(JfrError::Validation(format!(
            "{field} must contain between 1 and 128 characters"
        )));
    }
    Ok(())
}

fn validate_label(value: &str, field: &str) -> Result<()> {
    if value.trim().is_empty() || value.len() > 256 {
        return Err(JfrError::Validation(format!(
            "{field} must contain between 1 and 256 characters"
        )));
    }
    Ok(())
}

fn entropy(probabilities: impl Iterator<Item = f64>) -> f64 {
    -probabilities
        .filter(|probability| *probability > 0.0)
        .map(|probability| probability * probability.log2())
        .sum::<f64>()
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use serde_json::json;

    use super::*;
    use crate::model::{AssumptionStatus, BranchStatus, JointScenarioUtility};

    fn branch(kind: &str, weight: f64) -> BranchRecord {
        BranchRecord {
            id: Uuid::new_v4(),
            tenant_id: Uuid::nil(),
            case_id: Uuid::nil(),
            label: kind.to_owned(),
            state: json!({"kind": kind}),
            weight,
            status: BranchStatus::Active,
            generation: 0,
            parent_ids: Vec::new(),
            validity: json!({"valid": true}),
            risk_score: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    fn assumption(kind: &str) -> AssumptionRecord {
        AssumptionRecord {
            id: Uuid::new_v4(),
            tenant_id: Uuid::nil(),
            case_id: Uuid::nil(),
            label: kind.to_owned(),
            statement: json!({"kind": kind}),
            weight: 1.0,
            status: AssumptionStatus::Active,
            generation: 0,
            parent_ids: Vec::new(),
            validity: json!({"valid": true}),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    #[test]
    fn robust_and_expected_policies_can_disagree() {
        let branches = vec![branch("a", 0.8), branch("b", 0.2)];
        let target = BTreeMap::from([(branches[0].id, 3.0), (branches[1].id, -5.0)]);
        let safe = BTreeMap::from([(branches[0].id, 1.0), (branches[1].id, 1.0)]);
        let actions = vec![
            crate::model::ActionCandidate {
                id: "target".to_owned(),
                label: "Target A".to_owned(),
                utility_by_branch: target,
            },
            crate::model::ActionCandidate {
                id: "safe".to_owned(),
                label: "Safe".to_owned(),
                utility_by_branch: safe,
            },
        ];
        let expected = evaluate_actions(
            1,
            &branches,
            EvaluateActions {
                policy: DecisionPolicy::Expected,
                actions: actions.clone(),
                ambiguity_radius: None,
            },
        )
        .unwrap();
        let robust = evaluate_actions(
            1,
            &branches,
            EvaluateActions {
                policy: DecisionPolicy::Robust,
                actions,
                ambiguity_radius: None,
            },
        )
        .unwrap();

        assert_eq!(expected.selected.id, "target");
        assert_eq!(robust.selected.id, "safe");
    }

    #[test]
    fn kl_robust_policy_interpolates_between_expected_and_maximin() {
        let branches = vec![branch("likely", 0.9), branch("tail", 0.1)];
        let aggressive = BTreeMap::from([(branches[0].id, 10.0), (branches[1].id, -20.0)]);
        let safe = BTreeMap::from([(branches[0].id, 2.0), (branches[1].id, 2.0)]);
        let result = evaluate_actions(
            1,
            &branches,
            EvaluateActions {
                policy: DecisionPolicy::DistributionallyRobust,
                actions: vec![
                    crate::model::ActionCandidate {
                        id: "aggressive".to_owned(),
                        label: "Aggressive".to_owned(),
                        utility_by_branch: aggressive,
                    },
                    crate::model::ActionCandidate {
                        id: "safe".to_owned(),
                        label: "Safe".to_owned(),
                        utility_by_branch: safe,
                    },
                ],
                ambiguity_radius: Some(0.5),
            },
        )
        .unwrap();
        assert_eq!(result.selected.id, "safe");
        let adversarial_mass: f64 = result.scores[0]
            .adversarial_distribution_by_branch
            .as_ref()
            .unwrap()
            .values()
            .sum();
        assert!((adversarial_mass - 1.0).abs() < 1.0e-12);
    }

    #[test]
    fn joint_maximin_covers_both_fibers() {
        let branches = vec![branch("calm", 0.8), branch("stress", 0.2)];
        let assumptions = vec![assumption("normal"), assumption("degraded")];
        let scenarios = |values: [f64; 4]| {
            branches
                .iter()
                .flat_map(|branch| {
                    assumptions
                        .iter()
                        .map(move |assumption| (branch, assumption))
                })
                .zip(values)
                .map(|((branch, assumption), utility)| JointScenarioUtility {
                    branch_id: branch.id,
                    assumption_id: assumption.id,
                    utility,
                })
                .collect()
        };
        let (selected, scores, count) = evaluate_joint_actions(
            &branches,
            &assumptions,
            vec![
                JointActionCandidate {
                    id: "fast".to_owned(),
                    label: "Fast".to_owned(),
                    utilities: scenarios([9.0, -8.0, 2.0, -20.0]),
                },
                JointActionCandidate {
                    id: "safe".to_owned(),
                    label: "Safe".to_owned(),
                    utilities: scenarios([2.0, 1.0, 1.5, 0.5]),
                },
            ],
        )
        .unwrap();
        assert_eq!(selected.id, "safe");
        assert!((selected.worst_case.utility - 0.5).abs() < f64::EPSILON);
        assert_eq!(scores.len(), 2);
        assert_eq!(count, 4);
    }

    #[test]
    fn joint_maximin_rejects_incomplete_cartesian_coverage() {
        let branches = vec![branch("world", 1.0)];
        let assumptions = vec![assumption("a"), assumption("b")];
        let error = evaluate_joint_actions(
            &branches,
            &assumptions,
            vec![JointActionCandidate {
                id: "partial".to_owned(),
                label: "Partial".to_owned(),
                utilities: vec![JointScenarioUtility {
                    branch_id: branches[0].id,
                    assumption_id: assumptions[0].id,
                    utility: 1.0,
                }],
            }],
        )
        .unwrap_err();
        assert!(error.to_string().contains("every active world"));
    }
}
