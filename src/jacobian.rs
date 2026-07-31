use std::collections::BTreeMap;

use num_bigint::BigInt;
use num_complex::Complex64;
use num_rational::BigRational;
use num_traits::{One, Signed, ToPrimitive, Zero};
use serde::Serialize;
use serde_json::{Value, json};

use crate::{JfrError, Result};

type Rational = BigRational;
type Point = [Rational; 3];
type Monomial = [u16; 3];
type Polynomial = BTreeMap<Monomial, Rational>;

const SOLVER_ID: &str = "jfr.alpoge-fiber-solver.v1";
const MAX_ROOT_ITERATIONS: usize = 512;

#[derive(Debug, Clone, Serialize)]
pub struct DiscoveredBranch {
    pub label: String,
    pub state: Value,
    pub certificate: Value,
    pub image_residual: f64,
    pub hidden_norm: f64,
    pub observation_norm: f64,
    pub escape_score: f64,
    #[serde(skip)]
    pub center: [[f64; 2]; 3],
}

#[derive(Debug, Clone, Serialize)]
pub struct FiberDiscovery {
    pub solver: &'static str,
    pub arithmetic: &'static str,
    pub observation: Value,
    pub branch_count: usize,
    pub complete: bool,
    pub global_certificate: Value,
    pub branches: Vec<DiscoveredBranch>,
}

#[derive(Debug, Clone)]
struct ExactComplex {
    re: Rational,
    im: Rational,
}

impl ExactComplex {
    fn real(value: Rational) -> Self {
        Self {
            re: value,
            im: Rational::zero(),
        }
    }

    fn from_f64(value: Complex64) -> Result<Self> {
        Ok(Self {
            re: rational_from_f64(value.re)?,
            im: rational_from_f64(value.im)?,
        })
    }

    fn add(&self, other: &Self) -> Self {
        Self {
            re: &self.re + &other.re,
            im: &self.im + &other.im,
        }
    }

    fn sub(&self, other: &Self) -> Self {
        Self {
            re: &self.re - &other.re,
            im: &self.im - &other.im,
        }
    }

    fn mul(&self, other: &Self) -> Self {
        Self {
            re: &self.re * &other.re - &self.im * &other.im,
            im: &self.re * &other.im + &self.im * &other.re,
        }
    }

    fn scale(&self, value: &Rational) -> Self {
        Self {
            re: &self.re * value,
            im: &self.im * value,
        }
    }

    fn l1(&self) -> Rational {
        self.re.abs() + self.im.abs()
    }

    fn linf(&self) -> Rational {
        self.re.abs().max(self.im.abs())
    }

    fn value(&self) -> Value {
        json!({
            "re": rational_string(&self.re),
            "im": rational_string(&self.im)
        })
    }
}

/// Discovers every finite complex preimage of the announced three-dimensional
/// Keller map for a regular rational target.
///
/// The numerical solver only proposes dyadic disc centers. Exact rational
/// Rouché inequalities certify that each disjoint disc contains exactly one
/// root. Three certified cubic discs account for the complete degree-three
/// fiber. The special target plane `C = 0` is handled by its exact flat sheet
/// and a certified quadratic for the curved sheets.
pub fn discover_fiber(observation: &Value) -> Result<FiberDiscovery> {
    let target = parse_point(observation)?;
    let branches = if target[2].is_zero() {
        discover_zero_plane(&target)?
    } else {
        discover_generic_fiber(&target)?
    };
    let global_certificate = json!({
        "solver": SOLVER_ID,
        "map": "alpoge_degree_7_c3",
        "target": point_value(&target),
        "finite_branch_count": branches.len(),
        "complete": true,
        "completeness_basis": if target[2].is_zero() {
            "one exact flat-sheet solution plus every root of the exact curved-sheet quadratic"
        } else {
            "three pairwise-disjoint exact Rouche discs for the degree-three inverse equation"
        },
        "jacobian_determinant": "-2"
    });
    Ok(FiberDiscovery {
        solver: SOLVER_ID,
        arithmetic: "f64_proposal_exact_dyadic_rouche_certificate",
        observation: point_value(&target),
        branch_count: branches.len(),
        complete: true,
        global_certificate,
        branches,
    })
}

#[must_use]
pub fn point_center_from_state(state: &Value) -> Option<[[f64; 2]; 3]> {
    let object = state.as_object()?;
    let coordinate = |name: &str| -> Option<[f64; 2]> {
        let value = object.get(name)?;
        match value {
            Value::Object(complex) => Some([
                scalar_f64(complex.get("re")?)?,
                scalar_f64(complex.get("im")?)?,
            ]),
            _ => Some([scalar_f64(value)?, 0.0]),
        }
    };
    Some([coordinate("x")?, coordinate("y")?, coordinate("z")?])
}

fn discover_generic_fiber(target: &Point) -> Result<Vec<DiscoveredBranch>> {
    let four = Rational::from_integer(4.into());
    let p = &target[1] * &target[2] / &four;
    let q = &target[0] * target[2].pow(2) / &four;
    let p_float = finite_f64(&p, "inverse coefficient P")?;
    let q_float = finite_f64(&q, "inverse coefficient Q")?;
    let roots = solve_cubic(p_float, q_float)?;
    let mut certified = Vec::with_capacity(roots.len());
    for (index, center) in roots.iter().copied().enumerate() {
        let separation = roots
            .iter()
            .enumerate()
            .filter(|(other, _)| *other != index)
            .map(|(_, other)| {
                (center.re - other.re)
                    .abs()
                    .max((center.im - other.im).abs())
            })
            .fold(f64::INFINITY, f64::min);
        let root = certify_cubic_root(center, &p, &q, separation / 4.0)?;
        certified.push(root);
    }
    ensure_disjoint(&certified)?;

    let target_float = point_to_complex(target)?;
    certified
        .into_iter()
        .enumerate()
        .map(|(index, root)| {
            let coordinates = reconstruct_generic(root.center_float, &target_float, p_float);
            let residual = image_residual(&coordinates, &target_float);
            let (hidden_norm, observation_norm, escape_score) =
                escape_diagnostics(&coordinates, &target_float);
            let state = complex_state(&coordinates);
            let certificate = json!({
                "verifier": SOLVER_ID,
                "kind": "isolated_cubic_inverse_root",
                "inverse_equation": {
                    "variable": "w",
                    "polynomial": ["1", "-1", rational_string(&p), rational_string(&(-&q))],
                    "meaning": "w^3 - w^2 + P*w - Q"
                },
                "root_disc": root.value(),
                "reconstruction": {
                    "P": rational_string(&p),
                    "Q": rational_string(&q),
                    "gamma_excludes_zero": true
                },
                "completeness": "three disjoint one-root discs exhaust a cubic",
                "jacobian_determinant": "-2"
            });
            Ok(DiscoveredBranch {
                label: format!("algebraic sheet {}", index + 1),
                center: center_array(&coordinates),
                state,
                certificate,
                image_residual: residual,
                hidden_norm,
                observation_norm,
                escape_score,
            })
        })
        .collect()
}

fn discover_zero_plane(target: &Point) -> Result<Vec<DiscoveredBranch>> {
    let mut branches = Vec::with_capacity(3);
    let flat_exact = [
        Rational::zero(),
        target[1].clone(),
        &target[0] - Rational::from_integer(4.into()) * target[1].pow(2),
    ];
    let flat = [
        Complex64::new(0.0, 0.0),
        Complex64::new(finite_f64(&target[1], "target B")?, 0.0),
        Complex64::new(finite_f64(&flat_exact[2], "flat-sheet z")?, 0.0),
    ];
    let target_float = point_to_complex(target)?;
    let (flat_hidden_norm, flat_observation_norm, flat_escape_score) =
        escape_diagnostics(&flat, &target_float);
    branches.push(DiscoveredBranch {
        label: "flat sheet".to_owned(),
        state: json!({
            "x": {"re": rational_string(&flat_exact[0]), "im": "0"},
            "y": {"re": rational_string(&flat_exact[1]), "im": "0"},
            "z": {"re": rational_string(&flat_exact[2]), "im": "0"},
            "representation": "exact_complex_rational_v1"
        }),
        certificate: json!({
            "verifier": SOLVER_ID,
            "kind": "exact_zero_plane_flat_sheet",
            "identity": "(0, B, A - 4*B^2) maps to (A, B, 0)",
            "target": point_value(target),
            "jacobian_determinant": "-2"
        }),
        image_residual: image_residual(&flat, &target_float),
        hidden_norm: flat_hidden_norm,
        observation_norm: flat_observation_norm,
        escape_score: flat_escape_score,
        center: center_array(&flat),
    });

    let sixteen = Rational::from_integer(16.into());
    let discriminant = target[1].pow(2) - &sixteen * &target[0];
    if discriminant.is_zero() {
        return Ok(branches);
    }
    let discriminant_float = finite_f64(&discriminant, "zero-plane discriminant")?;
    let square_root = Complex64::new(discriminant_float, 0.0).sqrt();
    if square_root.norm() == 0.0 || !square_root.re.is_finite() || !square_root.im.is_finite() {
        return Err(JfrError::Validation(
            "zero-plane quadratic could not be represented numerically".to_owned(),
        ));
    }
    let centers = [2.0 / square_root, -2.0 / square_root];
    let separation = (centers[0].re - centers[1].re)
        .abs()
        .max((centers[0].im - centers[1].im).abs());
    let roots = centers
        .into_iter()
        .map(|center| certify_quadratic_root(center, &discriminant, separation / 4.0))
        .collect::<Result<Vec<_>>>()?;
    ensure_disjoint(&roots)?;

    let b = finite_f64(&target[1], "target B")?;
    for (index, root) in roots.into_iter().enumerate() {
        let x = root.center_float;
        let v = (Complex64::new(b, 0.0) * x - Complex64::new(6.0, 0.0)) / 4.0;
        let coordinates = [x, v / x, (Complex64::new(2.0, 0.0) - 3.0 * v) / x.powu(2)];
        let certificate = json!({
            "verifier": SOLVER_ID,
            "kind": "isolated_zero_plane_curved_sheet",
            "inverse_equation": {
                "variable": "x",
                "polynomial": [
                    rational_string(&discriminant),
                    "0",
                    "-4"
                ],
                "meaning": "(B^2 - 16*A)*x^2 - 4"
            },
            "root_disc": root.value(),
            "reconstruction": {
                "v": "(B*x - 6)/4",
                "y": "v/x",
                "z": "(2 - 3*v)/x^2"
            },
            "completeness": "the exact zero-plane decomposition is one flat sheet plus both quadratic roots",
            "jacobian_determinant": "-2"
        });
        let (hidden_norm, observation_norm, escape_score) =
            escape_diagnostics(&coordinates, &target_float);
        branches.push(DiscoveredBranch {
            label: format!("curved sheet {}", index + 1),
            state: complex_state(&coordinates),
            certificate,
            image_residual: image_residual(&coordinates, &target_float),
            hidden_norm,
            observation_norm,
            escape_score,
            center: center_array(&coordinates),
        });
    }
    Ok(branches)
}

#[derive(Debug, Clone)]
struct CertifiedDisc {
    center: ExactComplex,
    center_float: Complex64,
    radius: Rational,
    rouche_margin: Rational,
    denominator_margin: Option<Rational>,
}

impl CertifiedDisc {
    fn value(&self) -> Value {
        json!({
            "center": self.center.value(),
            "radius": rational_string(&self.radius),
            "metric": "complex_euclidean_disc",
            "rouche_margin_lower_bound": rational_string(&self.rouche_margin),
            "denominator_margin_lower_bound": self.denominator_margin.as_ref().map(rational_string),
            "root_count": 1,
            "arithmetic": "exact_big_rational"
        })
    }
}

fn solve_cubic(p: f64, q: f64) -> Result<Vec<Complex64>> {
    let radius = 1.0 + p.abs().max(q.abs());
    if !radius.is_finite() {
        return Err(JfrError::Validation(
            "inverse cubic coefficients are outside the numerical proposal range".to_owned(),
        ));
    }
    let rotation = 0.173_205_080_756_887_73;
    let mut roots = [
        Complex64::from_polar(radius, rotation),
        Complex64::from_polar(radius, rotation + std::f64::consts::TAU / 3.0),
        Complex64::from_polar(radius, rotation + 2.0 * std::f64::consts::TAU / 3.0),
    ];
    let polynomial = |value: Complex64| value.powu(3) - value.powu(2) + p * value - q;
    let derivative = |value: Complex64| 3.0 * value.powu(2) - 2.0 * value + p;

    let mut converged = false;
    for _ in 0..MAX_ROOT_ITERATIONS {
        let previous = roots;
        let mut maximum_delta: f64 = 0.0;
        for index in 0..3 {
            let mut denominator = Complex64::new(1.0, 0.0);
            for other in 0..3 {
                if other != index {
                    denominator *= previous[index] - previous[other];
                }
            }
            if denominator.norm() <= f64::MIN_POSITIVE {
                return Err(JfrError::Validation(
                    "inverse cubic is numerically singular; no certificate was issued".to_owned(),
                ));
            }
            let delta = polynomial(previous[index]) / denominator;
            roots[index] = previous[index] - delta;
            maximum_delta = maximum_delta.max(delta.norm());
        }
        let scale = roots.iter().map(|root| root.norm()).fold(1.0, f64::max);
        if maximum_delta <= 64.0 * f64::EPSILON * scale {
            converged = true;
            break;
        }
    }
    if !converged {
        return Err(JfrError::Validation(
            "inverse cubic proposal did not converge; no certificate was issued".to_owned(),
        ));
    }
    for root in &mut roots {
        for _ in 0..12 {
            let slope = derivative(*root);
            if slope.norm() <= f64::MIN_POSITIVE {
                break;
            }
            let delta = polynomial(*root) / slope;
            *root -= delta;
            if delta.norm() <= 8.0 * f64::EPSILON * (1.0 + root.norm()) {
                break;
            }
        }
    }
    roots.sort_by(|left, right| {
        left.re
            .total_cmp(&right.re)
            .then_with(|| left.im.total_cmp(&right.im))
    });
    Ok(roots.to_vec())
}

fn certify_cubic_root(
    center_float: Complex64,
    p: &Rational,
    q: &Rational,
    maximum_radius: f64,
) -> Result<CertifiedDisc> {
    let center = ExactComplex::from_f64(center_float)?;
    let one = ExactComplex::real(Rational::one());
    let two = Rational::from_integer(2.into());
    let three = Rational::from_integer(3.into());
    let center_squared = center.mul(&center);
    let value = center_squared
        .mul(&center)
        .sub(&center_squared)
        .add(&center.scale(p))
        .sub(&ExactComplex::real(q.clone()));
    let derivative = center_squared
        .scale(&three)
        .sub(&center.scale(&two))
        .add(&ExactComplex::real(p.clone()));
    let quadratic = center.scale(&three).sub(&one);
    let gamma = ExactComplex::real(p.clone())
        .sub(&center.scale(&two))
        .add(&center_squared.scale(&three));
    let gamma_slope = center
        .scale(&Rational::from_integer(6.into()))
        .sub(&ExactComplex::real(two));
    let correction = {
        let denominator = derivative.linf().to_f64().unwrap_or(0.0);
        if denominator <= 0.0 {
            return Err(JfrError::Validation(
                "inverse cubic derivative is not certifiably nonzero".to_owned(),
            ));
        }
        value.l1().to_f64().unwrap_or(f64::INFINITY) / denominator
    };
    let mut radius_float =
        (correction * 16.0).max(256.0 * f64::EPSILON * (1.0 + center_float.norm()));
    if radius_float == 0.0 {
        radius_float = f64::EPSILON;
    }
    for _ in 0..96 {
        if !radius_float.is_finite() || radius_float >= maximum_radius {
            break;
        }
        let radius = rational_from_f64(radius_float)?;
        let radius_squared = &radius * &radius;
        let radius_cubed = &radius_squared * &radius;
        let upper = value.l1() + quadratic.l1() * &radius_squared + radius_cubed.clone();
        let lower = derivative.linf() * &radius;
        let gamma_variation = gamma_slope.l1() * &radius + &three * &radius_squared;
        let denominator_margin = gamma.linf() - gamma_variation;
        if lower > upper && denominator_margin.is_positive() {
            return Ok(CertifiedDisc {
                center,
                center_float,
                radius,
                rouche_margin: lower - upper,
                denominator_margin: Some(denominator_margin),
            });
        }
        radius_float *= 2.0;
    }
    Err(JfrError::Validation(
        "inverse cubic root could not be isolated with an exact certificate".to_owned(),
    ))
}

fn certify_quadratic_root(
    center_float: Complex64,
    coefficient: &Rational,
    maximum_radius: f64,
) -> Result<CertifiedDisc> {
    let center = ExactComplex::from_f64(center_float)?;
    let center_squared = center.mul(&center);
    let value = center_squared
        .scale(coefficient)
        .sub(&ExactComplex::real(Rational::from_integer(4.into())));
    let derivative = center.scale(&(Rational::from_integer(2.into()) * coefficient));
    let correction = {
        let denominator = derivative.linf().to_f64().unwrap_or(0.0);
        if denominator <= 0.0 {
            return Err(JfrError::Validation(
                "zero-plane inverse derivative is not certifiably nonzero".to_owned(),
            ));
        }
        value.l1().to_f64().unwrap_or(f64::INFINITY) / denominator
    };
    let mut radius_float =
        (correction * 16.0).max(256.0 * f64::EPSILON * (1.0 + center_float.norm()));
    for _ in 0..96 {
        if !radius_float.is_finite() || radius_float >= maximum_radius {
            break;
        }
        let radius = rational_from_f64(radius_float)?;
        let upper = value.l1() + coefficient.abs() * &radius * &radius;
        let lower = derivative.linf() * &radius;
        let zero_margin = center.linf() - &radius;
        if lower > upper && zero_margin.is_positive() {
            return Ok(CertifiedDisc {
                center,
                center_float,
                radius,
                rouche_margin: lower - upper,
                denominator_margin: Some(zero_margin),
            });
        }
        radius_float *= 2.0;
    }
    Err(JfrError::Validation(
        "zero-plane inverse root could not be isolated with an exact certificate".to_owned(),
    ))
}

fn ensure_disjoint(discs: &[CertifiedDisc]) -> Result<()> {
    for left in 0..discs.len() {
        for right in (left + 1)..discs.len() {
            let distance = discs[left].center.sub(&discs[right].center).linf();
            if distance <= &discs[left].radius + &discs[right].radius {
                return Err(JfrError::Validation(
                    "root discs overlap; fiber completeness is not certified".to_owned(),
                ));
            }
        }
    }
    Ok(())
}

fn reconstruct_generic(
    root: Complex64,
    target: &[Complex64; 3],
    inverse_coefficient: f64,
) -> [Complex64; 3] {
    let gamma = Complex64::new(inverse_coefficient, 0.0) - 2.0 * root + 3.0 * root.powu(2);
    let scaled_root = root / gamma;
    let product_coordinate = scaled_root - 1.0;
    let source_x = target[2] / (2.0 * gamma);
    let source_y = product_coordinate / source_x;
    let weighted_z = 2.0 * (Complex64::new(1.0, 0.0) - 1.5 * product_coordinate - gamma);
    let source_z = weighted_z / source_x.powu(2);
    [source_x, source_y, source_z]
}

fn point_to_complex(point: &Point) -> Result<[Complex64; 3]> {
    Ok([
        Complex64::new(finite_f64(&point[0], "target A")?, 0.0),
        Complex64::new(finite_f64(&point[1], "target B")?, 0.0),
        Complex64::new(finite_f64(&point[2], "target C")?, 0.0),
    ])
}

fn complex_map(point: &[Complex64; 3]) -> [Complex64; 3] {
    let [x, y, z] = point;
    let u = Complex64::new(1.0, 0.0) + x * y;
    let correction = Complex64::new(4.0, 0.0) + 3.0 * x * y;
    [
        u.powu(3) * z + y.powu(2) * u * correction,
        y + 3.0 * x * u.powu(2) * z + 3.0 * x * y.powu(2) * correction,
        2.0 * x - 3.0 * x.powu(2) * y - x.powu(3) * z,
    ]
}

fn image_residual(point: &[Complex64; 3], target: &[Complex64; 3]) -> f64 {
    complex_map(point)
        .iter()
        .zip(target)
        .map(|(actual, expected)| (*actual - *expected).norm())
        .fold(0.0, f64::max)
}

fn escape_diagnostics(point: &[Complex64; 3], target: &[Complex64; 3]) -> (f64, f64, f64) {
    let hidden_norm = point.iter().map(Complex64::norm_sqr).sum::<f64>().sqrt();
    let observation_norm = target.iter().map(Complex64::norm_sqr).sum::<f64>().sqrt();
    let amplification = (1.0 + hidden_norm) / (1.0 + observation_norm);
    (
        hidden_norm,
        observation_norm,
        amplification.log10().max(0.0),
    )
}

fn complex_state(point: &[Complex64; 3]) -> Value {
    json!({
        "x": approximate_complex(point[0]),
        "y": approximate_complex(point[1]),
        "z": approximate_complex(point[2]),
        "representation": "complex_center_with_certified_parameter_disc_v1"
    })
}

fn approximate_complex(value: Complex64) -> Value {
    json!({
        "re": approximate_float(value.re),
        "im": approximate_float(value.im)
    })
}

fn approximate_float(value: f64) -> String {
    if value == 0.0 {
        "0".to_owned()
    } else {
        format!("{value:.17e}")
    }
}

const fn center_array(point: &[Complex64; 3]) -> [[f64; 2]; 3] {
    [
        [point[0].re, point[0].im],
        [point[1].re, point[1].im],
        [point[2].re, point[2].im],
    ]
}

fn scalar_f64(value: &Value) -> Option<f64> {
    match value {
        Value::String(value) => {
            if let Some((numerator, denominator)) = value.split_once('/') {
                let numerator = numerator.parse::<f64>().ok()?;
                let denominator = denominator.parse::<f64>().ok()?;
                (denominator != 0.0).then_some(numerator / denominator)
            } else {
                value.parse().ok()
            }
        }
        Value::Number(value) => value.as_f64(),
        _ => None,
    }
}

fn finite_f64(value: &Rational, field: &str) -> Result<f64> {
    value
        .to_f64()
        .filter(|value| value.is_finite())
        .ok_or_else(|| {
            JfrError::Validation(format!(
                "{field} is outside the certified solver's finite proposal range"
            ))
        })
}

fn rational_from_f64(value: f64) -> Result<Rational> {
    if !value.is_finite() {
        return Err(JfrError::Validation(
            "non-finite numerical proposal cannot be certified".to_owned(),
        ));
    }
    if value == 0.0 {
        return Ok(Rational::zero());
    }
    let bits = value.to_bits();
    let negative = bits >> 63 != 0;
    let exponent_bits = i32::try_from((bits >> 52) & 0x7ff).unwrap_or_default();
    let fraction = bits & ((1_u64 << 52) - 1);
    let (mantissa, exponent) = if exponent_bits == 0 {
        (fraction, 1 - 1023 - 52)
    } else {
        ((1_u64 << 52) | fraction, exponent_bits - 1023 - 52)
    };
    let mut numerator = BigInt::from(mantissa);
    if negative {
        numerator = -numerator;
    }
    if exponent >= 0 {
        let shift = usize::try_from(exponent)
            .map_err(|_| JfrError::Validation("invalid binary exponent".to_owned()))?;
        Ok(Rational::from_integer(numerator << shift))
    } else {
        let shift = usize::try_from(-exponent)
            .map_err(|_| JfrError::Validation("invalid binary exponent".to_owned()))?;
        Ok(Rational::new(numerator, BigInt::one() << shift))
    }
}

pub fn verify_branch(state: &Value, observation: &Value) -> Result<Value> {
    let point = parse_point(state)?;
    let expected = parse_point(observation)?;
    let actual = map(&point);
    let valid = actual == expected;
    Ok(json!({
        "valid": valid,
        "verifier": "jfr.jacobian-counterexample.v1",
        "arithmetic": "exact_big_rational",
        "input": point_value(&point),
        "computed_image": point_value(&actual),
        "expected_image": point_value(&expected),
        "jacobian_determinant": "-2"
    }))
}

pub fn exact_certificate() -> Result<Value> {
    let points = [
        point(0, 1, 0, 1, -1, 4),
        point(1, 1, -3, 2, 13, 2),
        point(-1, 1, 3, 2, 13, 2),
    ];
    let images = points.iter().map(map).collect::<Vec<_>>();
    if !images.windows(2).all(|window| window[0] == window[1])
        || determinant_polynomial() != constant(-2)
    {
        return Err(JfrError::Crypto);
    }
    Ok(json!({
        "verifier": "jfr.jacobian-counterexample.v1",
        "arithmetic": "exact_big_rational_and_sparse_polynomial",
        "determinant": "-2",
        "points": points.iter().map(point_value).collect::<Vec<_>>(),
        "shared_image": point_value(&images[0]),
        "distinct_inputs": true
    }))
}

fn map(point: &Point) -> Point {
    let [x, y, z] = point;
    let u = Rational::one() + x * y;
    let two = Rational::from_integer(2.into());
    let three = Rational::from_integer(3.into());
    let four = Rational::from_integer(4.into());
    let correction = &four + &three * x * y;
    [
        u.pow(3) * z + y.pow(2) * &u * &correction,
        y + &three * x * u.pow(2) * z + &three * x * y.pow(2) * &correction,
        &two * x - &three * x.pow(2) * y - x.pow(3) * z,
    ]
}

fn parse_point(value: &Value) -> Result<Point> {
    let object = value.as_object().ok_or_else(|| {
        JfrError::Validation("point must be an object with x, y, and z".to_owned())
    })?;
    Ok([
        parse_rational(object.get("x"), "x")?,
        parse_rational(object.get("y"), "y")?,
        parse_rational(object.get("z"), "z")?,
    ])
}

fn parse_rational(value: Option<&Value>, coordinate: &str) -> Result<Rational> {
    let text = match value {
        Some(Value::String(value)) => value.clone(),
        Some(Value::Number(value)) => value.to_string(),
        _ => {
            return Err(JfrError::Validation(format!(
                "coordinate {coordinate} must be a rational number or string"
            )));
        }
    };
    if let Some((numerator, denominator)) = text.split_once('/') {
        let numerator = numerator.parse::<BigInt>().map_err(|_| {
            JfrError::Validation(format!("coordinate {coordinate} is not rational"))
        })?;
        let denominator = denominator.parse::<BigInt>().map_err(|_| {
            JfrError::Validation(format!("coordinate {coordinate} is not rational"))
        })?;
        if denominator.is_zero() {
            return Err(JfrError::Validation(format!(
                "coordinate {coordinate} has a zero denominator"
            )));
        }
        return Ok(Rational::new(numerator, denominator));
    }
    let integer = text
        .parse::<BigInt>()
        .map_err(|_| JfrError::Validation(format!("coordinate {coordinate} is not rational")))?;
    Ok(Rational::from_integer(integer))
}

fn point_value(point: &Point) -> Value {
    json!({
        "x": rational_string(&point[0]),
        "y": rational_string(&point[1]),
        "z": rational_string(&point[2])
    })
}

fn rational_string(value: &Rational) -> String {
    if value.denom().is_one() {
        value.numer().to_string()
    } else {
        format!("{}/{}", value.numer(), value.denom())
    }
}

fn point(
    x_numerator: i64,
    x_denominator: i64,
    y_numerator: i64,
    y_denominator: i64,
    z_numerator: i64,
    z_denominator: i64,
) -> Point {
    [
        Rational::new(x_numerator.into(), x_denominator.into()),
        Rational::new(y_numerator.into(), y_denominator.into()),
        Rational::new(z_numerator.into(), z_denominator.into()),
    ]
}

fn constant(value: i64) -> Polynomial {
    if value == 0 {
        Polynomial::new()
    } else {
        BTreeMap::from([([0, 0, 0], Rational::from_integer(value.into()))])
    }
}

fn variable(index: usize) -> Polynomial {
    let mut monomial = [0, 0, 0];
    monomial[index] = 1;
    BTreeMap::from([(monomial, Rational::one())])
}

fn add(polynomials: &[&Polynomial]) -> Polynomial {
    let mut result = Polynomial::new();
    for polynomial in polynomials {
        for (monomial, coefficient) in *polynomial {
            let value = result.entry(*monomial).or_insert_with(Rational::zero);
            *value += coefficient;
            if value.is_zero() {
                result.remove(monomial);
            }
        }
    }
    result
}

fn scale(coefficient: i64, polynomial: &Polynomial) -> Polynomial {
    let coefficient = Rational::from_integer(coefficient.into());
    polynomial
        .iter()
        .filter_map(|(monomial, value)| {
            let scaled = &coefficient * value;
            (!scaled.is_zero()).then_some((*monomial, scaled))
        })
        .collect()
}

fn multiply(polynomials: &[&Polynomial]) -> Polynomial {
    let mut result = constant(1);
    for polynomial in polynomials {
        let mut product = Polynomial::new();
        for (left_monomial, left_coefficient) in &result {
            for (right_monomial, right_coefficient) in *polynomial {
                let monomial = [
                    left_monomial[0] + right_monomial[0],
                    left_monomial[1] + right_monomial[1],
                    left_monomial[2] + right_monomial[2],
                ];
                *product.entry(monomial).or_insert_with(Rational::zero) +=
                    left_coefficient * right_coefficient;
            }
        }
        product.retain(|_, coefficient| !coefficient.is_zero());
        result = product;
    }
    result
}

fn power(polynomial: &Polynomial, exponent: u8) -> Polynomial {
    let mut result = constant(1);
    for _ in 0..exponent {
        result = multiply(&[&result, polynomial]);
    }
    result
}

fn derivative(polynomial: &Polynomial, index: usize) -> Polynomial {
    polynomial
        .iter()
        .filter_map(|(monomial, coefficient)| {
            let exponent = monomial[index];
            if exponent == 0 {
                return None;
            }
            let mut derived = *monomial;
            derived[index] -= 1;
            Some((
                derived,
                coefficient * Rational::from_integer(exponent.into()),
            ))
        })
        .collect()
}

fn determinant_polynomial() -> Polynomial {
    let x = variable(0);
    let y = variable(1);
    let z = variable(2);
    let xy = multiply(&[&x, &y]);
    let one = constant(1);
    let four = constant(4);
    let u = add(&[&one, &xy]);
    let three_xy = scale(3, &xy);
    let four_plus_three_xy = add(&[&four, &three_xy]);
    let u3z = multiply(&[&power(&u, 3), &z]);
    let y2u_term = multiply(&[&power(&y, 2), &u, &four_plus_three_xy]);
    let f1 = add(&[&u3z, &y2u_term]);
    let second_a = scale(3, &multiply(&[&x, &power(&u, 2), &z]));
    let second_b = scale(3, &multiply(&[&x, &power(&y, 2), &four_plus_three_xy]));
    let f2 = add(&[&y, &second_a, &second_b]);
    let two_x = scale(2, &x);
    let third_a = scale(-3, &multiply(&[&power(&x, 2), &y]));
    let third_b = scale(-1, &multiply(&[&power(&x, 3), &z]));
    let f3 = add(&[&two_x, &third_a, &third_b]);
    let coordinates = [f1, f2, f3];
    let jacobian: Vec<Vec<_>> = coordinates
        .iter()
        .map(|coordinate| (0..3).map(|index| derivative(coordinate, index)).collect())
        .collect();
    let positive_a = multiply(&[&jacobian[0][0], &jacobian[1][1], &jacobian[2][2]]);
    let positive_b = multiply(&[&jacobian[0][1], &jacobian[1][2], &jacobian[2][0]]);
    let positive_c = multiply(&[&jacobian[0][2], &jacobian[1][0], &jacobian[2][1]]);
    let negative_a = scale(
        -1,
        &multiply(&[&jacobian[0][2], &jacobian[1][1], &jacobian[2][0]]),
    );
    let negative_b = scale(
        -1,
        &multiply(&[&jacobian[0][1], &jacobian[1][0], &jacobian[2][2]]),
    );
    let negative_c = scale(
        -1,
        &multiply(&[&jacobian[0][0], &jacobian[1][2], &jacobian[2][1]]),
    );
    add(&[
        &positive_a,
        &positive_b,
        &positive_c,
        &negative_a,
        &negative_b,
        &negative_c,
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_certificate_recomputes_determinant_and_collision() {
        let certificate = exact_certificate().unwrap();
        assert_eq!(certificate["determinant"], "-2");
        assert_eq!(
            certificate["shared_image"],
            json!({"x": "-1/4", "y": "0", "z": "0"})
        );
    }

    #[test]
    fn verifier_rejects_a_point_outside_the_fiber() {
        let result = verify_branch(
            &json!({"x": "0", "y": "0", "z": "0"}),
            &json!({"x": "-1/4", "y": "0", "z": "0"}),
        )
        .unwrap();
        assert_eq!(result["valid"], false);
    }

    #[test]
    fn solver_materializes_complete_announced_zero_plane_fiber() {
        let discovery = discover_fiber(&json!({"x": "-1/4", "y": "0", "z": "0"})).unwrap();
        assert!(discovery.complete);
        assert_eq!(discovery.branch_count, 3);
        assert!(
            discovery
                .branches
                .iter()
                .all(|branch| branch.image_residual < 1.0e-12)
        );
    }

    #[test]
    fn solver_certifies_generic_three_sheet_fiber() {
        let discovery = discover_fiber(&json!({"x": "-8/27", "y": "0", "z": "1"})).unwrap();
        assert!(discovery.complete);
        assert_eq!(discovery.branch_count, 3);
        assert!(
            discovery
                .branches
                .iter()
                .all(|branch| branch.image_residual < 1.0e-10)
        );
    }

    #[test]
    fn solver_surfaces_hidden_escape_under_bounded_observation() {
        let discovery = discover_fiber(&json!({"x": "-1/4000000", "y": "0", "z": "0"})).unwrap();
        assert_eq!(discovery.branch_count, 3);
        let maximum_escape = discovery
            .branches
            .iter()
            .map(|branch| branch.escape_score)
            .fold(0.0, f64::max);
        assert!(maximum_escape > 2.9);
        assert!(
            discovery
                .branches
                .iter()
                .all(|branch| branch.observation_norm < 1.0)
        );
    }
}
