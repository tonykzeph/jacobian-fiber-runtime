use std::collections::{BTreeMap, BTreeSet};

use num_bigint::BigInt;
use num_rational::BigRational;
use num_traits::{One, Signed, Zero};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::{JfrError, Result};

pub const VERIFIER_ID: &str = "jfr.finite-rational-refutation.v1";
pub const MAX_SEARCH_ASSIGNMENTS: u64 = 1_000_000;
const MAX_VARIABLES: usize = 12;
const MAX_EXPRESSION_DEPTH: usize = 64;
const MAX_EXPRESSION_NODES: usize = 4_096;
const MAX_INTEGER_ABS: i64 = 1_000_000;
const MAX_RATIONAL_BYTES: usize = 16_384;
const MAX_POWER: u32 = 32;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegerVariable {
    pub name: String,
    pub minimum: i64,
    pub maximum: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FiniteDomainSpec {
    pub variables: Vec<IntegerVariable>,
    #[serde(default)]
    pub premises: Vec<BooleanExpression>,
    pub claim: BooleanExpression,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum ScalarExpression {
    Constant {
        value: String,
    },
    Variable {
        name: String,
    },
    Add {
        arguments: Vec<Self>,
    },
    Subtract {
        left: Box<Self>,
        right: Box<Self>,
    },
    Multiply {
        arguments: Vec<Self>,
    },
    Divide {
        numerator: Box<Self>,
        denominator: Box<Self>,
    },
    Negate {
        argument: Box<Self>,
    },
    Absolute {
        argument: Box<Self>,
    },
    Power {
        base: Box<Self>,
        exponent: u32,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum BooleanExpression {
    LessThan {
        left: ScalarExpression,
        right: ScalarExpression,
    },
    LessThanOrEqual {
        left: ScalarExpression,
        right: ScalarExpression,
    },
    Equal {
        left: ScalarExpression,
        right: ScalarExpression,
    },
    NotEqual {
        left: ScalarExpression,
        right: ScalarExpression,
    },
    GreaterThanOrEqual {
        left: ScalarExpression,
        right: ScalarExpression,
    },
    GreaterThan {
        left: ScalarExpression,
        right: ScalarExpression,
    },
    All {
        arguments: Vec<Self>,
    },
    Any {
        arguments: Vec<Self>,
    },
    Not {
        argument: Box<Self>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SearchOutcome {
    Verified,
    Counterexample,
}

#[derive(Debug, Clone, Serialize)]
pub struct SearchReport {
    pub outcome: SearchOutcome,
    pub verifier_id: &'static str,
    pub specification_hash: String,
    pub total_domain_assignments: u64,
    pub examined_assignments: u64,
    pub eligible_assignments: u64,
    pub witness: Option<BTreeMap<String, i64>>,
    pub certificate: Value,
}

#[derive(Debug, Clone)]
struct ValidatedSpec {
    total_assignments: u64,
    specification_hash: String,
}

pub fn specification_value(specification: &FiniteDomainSpec) -> Result<Value> {
    serde_json::to_value(specification)
        .map_err(|error| JfrError::Internal(format!("could not encode guarantee: {error}")))
}

pub fn parse_specification(value: Value) -> Result<FiniteDomainSpec> {
    let specification: FiniteDomainSpec = serde_json::from_value(value).map_err(|error| {
        JfrError::Validation(format!(
            "invalid {VERIFIER_ID} guarantee specification: {error}"
        ))
    })?;
    validate_specification(&specification)?;
    Ok(specification)
}

pub fn search_space_size(specification: &FiniteDomainSpec) -> Result<u64> {
    Ok(validate_specification(specification)?.total_assignments)
}

pub fn exhaustive_search(specification: &FiniteDomainSpec) -> Result<SearchReport> {
    let validated = validate_specification(specification)?;
    let mut assignment = BTreeMap::new();
    let mut examined = 0_u64;
    let mut eligible = 0_u64;
    let witness = enumerate(
        specification,
        0,
        &mut assignment,
        &mut examined,
        &mut eligible,
    )?;
    let outcome = if witness.is_some() {
        SearchOutcome::Counterexample
    } else {
        SearchOutcome::Verified
    };
    let certificate = certificate(
        outcome,
        &validated,
        validated.total_assignments,
        examined,
        eligible,
        witness.as_ref(),
        "exhaustive_lexicographic",
    )?;
    Ok(SearchReport {
        outcome,
        verifier_id: VERIFIER_ID,
        specification_hash: validated.specification_hash,
        total_domain_assignments: validated.total_assignments,
        examined_assignments: examined,
        eligible_assignments: eligible,
        witness,
        certificate,
    })
}

pub fn verify_witness(
    specification: &FiniteDomainSpec,
    assignment: &BTreeMap<String, i64>,
) -> Result<SearchReport> {
    let validated = validate_specification(specification)?;
    validate_assignment(specification, assignment)?;
    if !premises_hold(specification, assignment)? {
        return Err(JfrError::Validation(
            "the supplied assignment does not satisfy every premise".to_owned(),
        ));
    }
    if evaluate_boolean(&specification.claim, assignment)? {
        return Err(JfrError::Validation(
            "the supplied assignment satisfies the claim and is not a counterexample".to_owned(),
        ));
    }
    let certificate = certificate(
        SearchOutcome::Counterexample,
        &validated,
        validated.total_assignments,
        1,
        1,
        Some(assignment),
        "submitted_witness",
    )?;
    Ok(SearchReport {
        outcome: SearchOutcome::Counterexample,
        verifier_id: VERIFIER_ID,
        specification_hash: validated.specification_hash,
        total_domain_assignments: validated.total_assignments,
        examined_assignments: 1,
        eligible_assignments: 1,
        witness: Some(assignment.clone()),
        certificate,
    })
}

pub fn certificate_hash(certificate: &Value) -> Result<Vec<u8>> {
    let canonical = serde_jcs::to_vec(certificate)
        .map_err(|error| JfrError::Internal(format!("certificate encoding failed: {error}")))?;
    Ok(Sha256::digest(canonical).to_vec())
}

fn validate_specification(specification: &FiniteDomainSpec) -> Result<ValidatedSpec> {
    if specification.variables.is_empty() || specification.variables.len() > MAX_VARIABLES {
        return Err(JfrError::Validation(format!(
            "a finite-domain guarantee requires 1 to {MAX_VARIABLES} variables"
        )));
    }
    let mut names = BTreeSet::new();
    let mut total_assignments = 1_u64;
    for variable in &specification.variables {
        if !valid_identifier(&variable.name) {
            return Err(JfrError::Validation(format!(
                "variable names must be ASCII identifiers of at most 64 characters: {}",
                variable.name
            )));
        }
        if !names.insert(variable.name.clone()) {
            return Err(JfrError::Validation(format!(
                "duplicate variable name: {}",
                variable.name
            )));
        }
        if variable.minimum > variable.maximum
            || variable.minimum.unsigned_abs() > MAX_INTEGER_ABS as u64
            || variable.maximum.unsigned_abs() > MAX_INTEGER_ABS as u64
        {
            return Err(JfrError::Validation(format!(
                "variable {} has an invalid or excessively large domain",
                variable.name
            )));
        }
        let width = u64::try_from(i128::from(variable.maximum) - i128::from(variable.minimum) + 1)
            .map_err(|_| JfrError::Validation("variable domain overflowed".to_owned()))?;
        total_assignments = total_assignments.checked_mul(width).ok_or_else(|| {
            JfrError::Validation("finite-domain search space overflowed".to_owned())
        })?;
        if total_assignments > MAX_SEARCH_ASSIGNMENTS {
            return Err(JfrError::Validation(format!(
                "search space has {total_assignments} assignments; maximum is {MAX_SEARCH_ASSIGNMENTS}"
            )));
        }
    }

    let mut nodes = 0_usize;
    for premise in &specification.premises {
        validate_boolean(premise, &names, 1, &mut nodes)?;
    }
    validate_boolean(&specification.claim, &names, 1, &mut nodes)?;
    if nodes > MAX_EXPRESSION_NODES {
        return Err(JfrError::Validation(format!(
            "guarantee has {nodes} expression nodes; maximum is {MAX_EXPRESSION_NODES}"
        )));
    }
    let canonical = serde_jcs::to_vec(specification)
        .map_err(|error| JfrError::Internal(format!("specification encoding failed: {error}")))?;
    Ok(ValidatedSpec {
        total_assignments,
        specification_hash: hex::encode(Sha256::digest(canonical)),
    })
}

fn validate_boolean(
    expression: &BooleanExpression,
    names: &BTreeSet<String>,
    depth: usize,
    nodes: &mut usize,
) -> Result<()> {
    check_depth_and_count(depth, nodes)?;
    match expression {
        BooleanExpression::LessThan { left, right }
        | BooleanExpression::LessThanOrEqual { left, right }
        | BooleanExpression::Equal { left, right }
        | BooleanExpression::NotEqual { left, right }
        | BooleanExpression::GreaterThanOrEqual { left, right }
        | BooleanExpression::GreaterThan { left, right } => {
            validate_scalar(left, names, depth + 1, nodes)?;
            validate_scalar(right, names, depth + 1, nodes)
        }
        BooleanExpression::All { arguments } | BooleanExpression::Any { arguments } => {
            if arguments.is_empty() {
                return Err(JfrError::Validation(
                    "boolean all/any expressions cannot be empty".to_owned(),
                ));
            }
            for argument in arguments {
                validate_boolean(argument, names, depth + 1, nodes)?;
            }
            Ok(())
        }
        BooleanExpression::Not { argument } => validate_boolean(argument, names, depth + 1, nodes),
    }
}

fn validate_scalar(
    expression: &ScalarExpression,
    names: &BTreeSet<String>,
    depth: usize,
    nodes: &mut usize,
) -> Result<()> {
    check_depth_and_count(depth, nodes)?;
    match expression {
        ScalarExpression::Constant { value } => {
            parse_rational(value)?;
            Ok(())
        }
        ScalarExpression::Variable { name } => {
            if names.contains(name) {
                Ok(())
            } else {
                Err(JfrError::Validation(format!(
                    "expression references undeclared variable: {name}"
                )))
            }
        }
        ScalarExpression::Add { arguments } | ScalarExpression::Multiply { arguments } => {
            if arguments.is_empty() {
                return Err(JfrError::Validation(
                    "add/multiply expressions cannot be empty".to_owned(),
                ));
            }
            for argument in arguments {
                validate_scalar(argument, names, depth + 1, nodes)?;
            }
            Ok(())
        }
        ScalarExpression::Subtract { left, right } => {
            validate_scalar(left, names, depth + 1, nodes)?;
            validate_scalar(right, names, depth + 1, nodes)
        }
        ScalarExpression::Divide {
            numerator,
            denominator,
        } => {
            validate_scalar(numerator, names, depth + 1, nodes)?;
            validate_scalar(denominator, names, depth + 1, nodes)
        }
        ScalarExpression::Negate { argument } | ScalarExpression::Absolute { argument } => {
            validate_scalar(argument, names, depth + 1, nodes)
        }
        ScalarExpression::Power { base, exponent } => {
            if *exponent > MAX_POWER {
                return Err(JfrError::Validation(format!(
                    "power exponent {exponent} exceeds maximum {MAX_POWER}"
                )));
            }
            validate_scalar(base, names, depth + 1, nodes)
        }
    }
}

fn check_depth_and_count(depth: usize, nodes: &mut usize) -> Result<()> {
    if depth > MAX_EXPRESSION_DEPTH {
        return Err(JfrError::Validation(format!(
            "expression depth exceeds {MAX_EXPRESSION_DEPTH}"
        )));
    }
    *nodes = nodes.saturating_add(1);
    Ok(())
}

fn enumerate(
    specification: &FiniteDomainSpec,
    variable_index: usize,
    assignment: &mut BTreeMap<String, i64>,
    examined: &mut u64,
    eligible: &mut u64,
) -> Result<Option<BTreeMap<String, i64>>> {
    if variable_index == specification.variables.len() {
        *examined += 1;
        if !premises_hold(specification, assignment)? {
            return Ok(None);
        }
        *eligible += 1;
        return if evaluate_boolean(&specification.claim, assignment)? {
            Ok(None)
        } else {
            Ok(Some(assignment.clone()))
        };
    }
    let variable = &specification.variables[variable_index];
    for value in variable.minimum..=variable.maximum {
        assignment.insert(variable.name.clone(), value);
        if let Some(witness) = enumerate(
            specification,
            variable_index + 1,
            assignment,
            examined,
            eligible,
        )? {
            return Ok(Some(witness));
        }
    }
    assignment.remove(&variable.name);
    Ok(None)
}

fn validate_assignment(
    specification: &FiniteDomainSpec,
    assignment: &BTreeMap<String, i64>,
) -> Result<()> {
    let expected = specification
        .variables
        .iter()
        .map(|variable| variable.name.clone())
        .collect::<BTreeSet<_>>();
    let supplied = assignment.keys().cloned().collect::<BTreeSet<_>>();
    if expected != supplied {
        return Err(JfrError::Validation(
            "witness must assign every declared variable exactly once".to_owned(),
        ));
    }
    for variable in &specification.variables {
        let value = assignment[&variable.name];
        if value < variable.minimum || value > variable.maximum {
            return Err(JfrError::Validation(format!(
                "witness value for {} is outside its declared domain",
                variable.name
            )));
        }
    }
    Ok(())
}

fn premises_hold(
    specification: &FiniteDomainSpec,
    assignment: &BTreeMap<String, i64>,
) -> Result<bool> {
    for premise in &specification.premises {
        if !evaluate_boolean(premise, assignment)? {
            return Ok(false);
        }
    }
    Ok(true)
}

fn evaluate_boolean(
    expression: &BooleanExpression,
    assignment: &BTreeMap<String, i64>,
) -> Result<bool> {
    match expression {
        BooleanExpression::LessThan { left, right } => {
            Ok(evaluate_scalar(left, assignment)? < evaluate_scalar(right, assignment)?)
        }
        BooleanExpression::LessThanOrEqual { left, right } => {
            Ok(evaluate_scalar(left, assignment)? <= evaluate_scalar(right, assignment)?)
        }
        BooleanExpression::Equal { left, right } => {
            Ok(evaluate_scalar(left, assignment)? == evaluate_scalar(right, assignment)?)
        }
        BooleanExpression::NotEqual { left, right } => {
            Ok(evaluate_scalar(left, assignment)? != evaluate_scalar(right, assignment)?)
        }
        BooleanExpression::GreaterThanOrEqual { left, right } => {
            Ok(evaluate_scalar(left, assignment)? >= evaluate_scalar(right, assignment)?)
        }
        BooleanExpression::GreaterThan { left, right } => {
            Ok(evaluate_scalar(left, assignment)? > evaluate_scalar(right, assignment)?)
        }
        BooleanExpression::All { arguments } => {
            for argument in arguments {
                if !evaluate_boolean(argument, assignment)? {
                    return Ok(false);
                }
            }
            Ok(true)
        }
        BooleanExpression::Any { arguments } => {
            for argument in arguments {
                if evaluate_boolean(argument, assignment)? {
                    return Ok(true);
                }
            }
            Ok(false)
        }
        BooleanExpression::Not { argument } => Ok(!evaluate_boolean(argument, assignment)?),
    }
}

fn evaluate_scalar(
    expression: &ScalarExpression,
    assignment: &BTreeMap<String, i64>,
) -> Result<BigRational> {
    let value = match expression {
        ScalarExpression::Constant { value } => parse_rational(value)?,
        ScalarExpression::Variable { name } => {
            BigRational::from_integer(BigInt::from(assignment.get(name).copied().ok_or_else(
                || JfrError::Internal(format!("missing validated variable assignment: {name}")),
            )?))
        }
        ScalarExpression::Add { arguments } => {
            let mut total = BigRational::zero();
            for argument in arguments {
                total += evaluate_scalar(argument, assignment)?;
                enforce_rational_size(&total)?;
            }
            total
        }
        ScalarExpression::Subtract { left, right } => {
            evaluate_scalar(left, assignment)? - evaluate_scalar(right, assignment)?
        }
        ScalarExpression::Multiply { arguments } => {
            let mut product = BigRational::one();
            for argument in arguments {
                product *= evaluate_scalar(argument, assignment)?;
                enforce_rational_size(&product)?;
            }
            product
        }
        ScalarExpression::Divide {
            numerator,
            denominator,
        } => {
            let denominator = evaluate_scalar(denominator, assignment)?;
            if denominator.is_zero() {
                return Err(JfrError::Validation(
                    "guarantee expression divides by zero for an eligible assignment".to_owned(),
                ));
            }
            evaluate_scalar(numerator, assignment)? / denominator
        }
        ScalarExpression::Negate { argument } => -evaluate_scalar(argument, assignment)?,
        ScalarExpression::Absolute { argument } => evaluate_scalar(argument, assignment)?.abs(),
        ScalarExpression::Power { base, exponent } => {
            let exponent = i32::try_from(*exponent).map_err(|_| {
                JfrError::Validation("expression power cannot be represented".to_owned())
            })?;
            evaluate_scalar(base, assignment)?.pow(exponent)
        }
    };
    enforce_rational_size(&value)?;
    Ok(value)
}

fn enforce_rational_size(value: &BigRational) -> Result<()> {
    if value.numer().to_signed_bytes_le().len() > MAX_RATIONAL_BYTES
        || value.denom().to_signed_bytes_le().len() > MAX_RATIONAL_BYTES
    {
        return Err(JfrError::Validation(
            "exact arithmetic exceeded the verifier magnitude limit".to_owned(),
        ));
    }
    Ok(())
}

fn parse_rational(value: &str) -> Result<BigRational> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.len() > 256 {
        return Err(JfrError::Validation(
            "rational constants must contain 1 to 256 characters".to_owned(),
        ));
    }
    let result = if let Some((numerator, denominator)) = trimmed.split_once('/') {
        if denominator.contains('/') {
            return Err(JfrError::Validation(format!(
                "invalid rational constant: {trimmed}"
            )));
        }
        let numerator = parse_integer(numerator)?;
        let denominator = parse_integer(denominator)?;
        if denominator.is_zero() {
            return Err(JfrError::Validation(
                "rational constant denominator cannot be zero".to_owned(),
            ));
        }
        BigRational::new(numerator, denominator)
    } else if let Some((integer, fraction)) = trimmed.split_once('.') {
        if fraction.is_empty() || !fraction.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(JfrError::Validation(format!(
                "invalid decimal constant: {trimmed}"
            )));
        }
        let negative = integer.starts_with('-');
        let unsigned_integer = integer.trim_start_matches(['-', '+']);
        if unsigned_integer.is_empty()
            || !unsigned_integer.bytes().all(|byte| byte.is_ascii_digit())
        {
            return Err(JfrError::Validation(format!(
                "invalid decimal constant: {trimmed}"
            )));
        }
        let digits = format!("{unsigned_integer}{fraction}");
        let mut numerator = parse_integer(&digits)?;
        if negative {
            numerator = -numerator;
        }
        let denominator = BigInt::from(10_u8).pow(
            u32::try_from(fraction.len())
                .map_err(|_| JfrError::Validation("decimal is too precise".to_owned()))?,
        );
        BigRational::new(numerator, denominator)
    } else {
        BigRational::from_integer(parse_integer(trimmed)?)
    };
    enforce_rational_size(&result)?;
    Ok(result)
}

fn parse_integer(value: &str) -> Result<BigInt> {
    value
        .trim()
        .parse::<BigInt>()
        .map_err(|_| JfrError::Validation(format!("invalid integer in rational constant: {value}")))
}

fn valid_identifier(value: &str) -> bool {
    let mut bytes = value.bytes();
    value.len() <= 64
        && bytes
            .next()
            .is_some_and(|byte| byte.is_ascii_alphabetic() || byte == b'_')
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

fn certificate(
    outcome: SearchOutcome,
    validated: &ValidatedSpec,
    total_domain_assignments: u64,
    examined_assignments: u64,
    eligible_assignments: u64,
    witness: Option<&BTreeMap<String, i64>>,
    method: &str,
) -> Result<Value> {
    let mut value = json!({
        "verifier": VERIFIER_ID,
        "arithmetic": "arbitrary_precision_rational",
        "method": method,
        "outcome": outcome,
        "specification_hash": validated.specification_hash,
        "total_domain_assignments": total_domain_assignments,
        "examined_assignments": examined_assignments,
        "eligible_assignments": eligible_assignments,
        "complete": outcome == SearchOutcome::Verified
            && examined_assignments == total_domain_assignments,
        "witness": witness
    });
    let unsigned = serde_jcs::to_vec(&value)
        .map_err(|error| JfrError::Internal(format!("certificate encoding failed: {error}")))?;
    value["certificate_digest"] = Value::String(hex::encode(Sha256::digest(unsigned)));
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn variable(name: &str) -> ScalarExpression {
        ScalarExpression::Variable {
            name: name.to_owned(),
        }
    }

    fn constant(value: &str) -> ScalarExpression {
        ScalarExpression::Constant {
            value: value.to_owned(),
        }
    }

    #[test]
    fn exhaustive_search_finds_exact_counterexample() {
        let x = variable("x");
        let specification = FiniteDomainSpec {
            variables: vec![IntegerVariable {
                name: "x".to_owned(),
                minimum: 0,
                maximum: 10,
            }],
            premises: Vec::new(),
            claim: BooleanExpression::LessThanOrEqual {
                left: ScalarExpression::Power {
                    base: Box::new(x.clone()),
                    exponent: 2,
                },
                right: ScalarExpression::Add {
                    arguments: vec![
                        ScalarExpression::Multiply {
                            arguments: vec![constant("2"), x],
                        },
                        constant("3"),
                    ],
                },
            },
        };
        let report = exhaustive_search(&specification).unwrap();
        assert_eq!(report.outcome, SearchOutcome::Counterexample);
        assert_eq!(report.witness.unwrap()["x"], 4);
        assert_eq!(report.examined_assignments, 5);
    }

    #[test]
    fn exhaustive_search_certifies_complete_finite_domain() {
        let x = variable("x");
        let specification = FiniteDomainSpec {
            variables: vec![IntegerVariable {
                name: "x".to_owned(),
                minimum: -12,
                maximum: 12,
            }],
            premises: Vec::new(),
            claim: BooleanExpression::GreaterThanOrEqual {
                left: ScalarExpression::Power {
                    base: Box::new(x),
                    exponent: 2,
                },
                right: constant("0"),
            },
        };
        let report = exhaustive_search(&specification).unwrap();
        assert_eq!(report.outcome, SearchOutcome::Verified);
        assert_eq!(report.examined_assignments, 25);
        assert_eq!(report.eligible_assignments, 25);
        assert_eq!(report.certificate["complete"], true);
    }

    #[test]
    fn false_premises_exclude_assignment_before_claim_evaluation() {
        let specification = FiniteDomainSpec {
            variables: vec![IntegerVariable {
                name: "x".to_owned(),
                minimum: 0,
                maximum: 1,
            }],
            premises: vec![BooleanExpression::NotEqual {
                left: variable("x"),
                right: constant("0"),
            }],
            claim: BooleanExpression::Equal {
                left: ScalarExpression::Divide {
                    numerator: Box::new(constant("1")),
                    denominator: Box::new(variable("x")),
                },
                right: constant("1"),
            },
        };
        let report = exhaustive_search(&specification).unwrap();
        assert_eq!(report.outcome, SearchOutcome::Verified);
        assert_eq!(report.examined_assignments, 2);
        assert_eq!(report.eligible_assignments, 1);
    }

    #[test]
    fn oversized_search_spaces_are_rejected() {
        let specification = FiniteDomainSpec {
            variables: vec![
                IntegerVariable {
                    name: "x".to_owned(),
                    minimum: 0,
                    maximum: 1_000,
                },
                IntegerVariable {
                    name: "y".to_owned(),
                    minimum: 0,
                    maximum: 1_000,
                },
            ],
            premises: Vec::new(),
            claim: BooleanExpression::Equal {
                left: variable("x"),
                right: variable("x"),
            },
        };
        assert!(exhaustive_search(&specification).is_err());
    }
}
