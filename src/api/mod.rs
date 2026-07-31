use std::iter::once;

use axum::{
    Extension, Json, Router,
    body::Body,
    body::to_bytes,
    extract::{Path, Query, Request, State},
    http::{
        HeaderName, HeaderValue, Method, StatusCode,
        header::{
            AUTHORIZATION, CACHE_CONTROL, CONTENT_SECURITY_POLICY, CONTENT_TYPE,
            X_CONTENT_TYPE_OPTIONS,
        },
    },
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use rust_embed::RustEmbed;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tower::limit::ConcurrencyLimitLayer;
use tower_http::{
    catch_panic::CatchPanicLayer,
    compression::CompressionLayer,
    cors::CorsLayer,
    limit::RequestBodyLimitLayer,
    request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer},
    sensitive_headers::SetSensitiveRequestHeadersLayer,
    set_header::SetResponseHeaderLayer,
    timeout::TimeoutLayer,
    trace::TraceLayer,
};
use uuid::Uuid;

use crate::{
    Config, FiberRuntime, JfrError, Result,
    auth::{ApiKeyEvent, ApiKeyRecord, AuthService, CreateApiKey, Session, require_scope},
    jacobian,
    metrics::Metrics,
    model::{
        AddEvidence, AdvanceJacobianFiber, ApplyLikelihoodEvidence, AuthContext, AuthorizeAction,
        CreateCase, CreateGuarantee, EvaluateActions, MaterializeJacobianFiber, MergeBranches,
        ProposeAssumption, ProposeBranch, PruneBranch, RankExperiments, RecordObservation,
        SearchGuarantee, SplitBranch, SubmitCounterexample, ValidateAssumption, ValidateBranch,
    },
    refutation,
};

#[derive(Clone)]
pub struct AppState {
    pub runtime: FiberRuntime,
    pub auth: AuthService,
    pub metrics: Metrics,
    pub max_request_bytes: usize,
}

#[derive(RustEmbed)]
#[folder = "web/"]
struct WebAssets;

#[derive(Debug, Deserialize)]
struct ListQuery {
    limit: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct EventQuery {
    after: Option<i64>,
    limit: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct JacobianVerify {
    expected_case_version: i64,
}

#[derive(Debug, Serialize)]
struct Liveness {
    status: &'static str,
    service: &'static str,
    version: &'static str,
}

#[derive(Debug, Serialize)]
struct Capabilities {
    runtime: &'static str,
    persistence: &'static str,
    audit: &'static str,
    concurrency: &'static str,
    verifiers: Vec<VerifierCapability>,
}

#[derive(Debug, Serialize)]
struct VerifierCapability {
    id: &'static str,
    arithmetic: &'static str,
    certificate: serde_json::Value,
}

pub fn router(state: AppState, config: &Config) -> Result<Router> {
    let protected = Router::new()
        .route("/api/v1/session", get(session))
        .route("/api/v1/keys", get(list_api_keys).post(create_api_key))
        .route("/api/v1/keys/events", get(list_api_key_events))
        .route("/api/v1/keys/{key_id}/revoke", post(revoke_api_key))
        .route("/api/v1/system/capabilities", get(capabilities))
        .route("/api/v1/cases", get(list_cases).post(create_case))
        .route("/api/v1/cases/{case_id}", get(case_snapshot))
        .route("/api/v1/cases/{case_id}/evidence", post(add_evidence))
        .route(
            "/api/v1/cases/{case_id}/evidence/likelihood",
            post(apply_likelihood_evidence),
        )
        .route(
            "/api/v1/cases/{case_id}/observations",
            post(record_observation),
        )
        .route(
            "/api/v1/cases/{case_id}/fiber/materialize/jacobian",
            post(materialize_jacobian_fiber),
        )
        .route(
            "/api/v1/cases/{case_id}/fiber/advance/jacobian",
            post(advance_jacobian_fiber),
        )
        .route("/api/v1/cases/{case_id}/branches", post(propose_branch))
        .route(
            "/api/v1/branches/{branch_id}/validate",
            post(validate_branch),
        )
        .route(
            "/api/v1/branches/{branch_id}/verify/jacobian",
            post(verify_jacobian),
        )
        .route("/api/v1/branches/{branch_id}/prune", post(prune_branch))
        .route("/api/v1/branches/{branch_id}/split", post(split_branch))
        .route(
            "/api/v1/cases/{case_id}/branches/merge",
            post(merge_branches),
        )
        .route(
            "/api/v1/cases/{case_id}/assumptions",
            post(propose_assumption),
        )
        .route(
            "/api/v1/assumptions/{assumption_id}/validate",
            post(validate_assumption),
        )
        .route("/api/v1/cases/{case_id}/guarantees", post(create_guarantee))
        .route(
            "/api/v1/guarantees/{guarantee_id}/search/exhaustive",
            post(search_guarantee),
        )
        .route(
            "/api/v1/guarantees/{guarantee_id}/counterexamples",
            post(submit_counterexample),
        )
        .route(
            "/api/v1/cases/{case_id}/actions/authorize",
            post(authorize_action),
        )
        .route(
            "/api/v1/cases/{case_id}/decisions/evaluate",
            post(evaluate_actions),
        )
        .route(
            "/api/v1/cases/{case_id}/experiments/rank",
            post(rank_experiments),
        )
        .route("/api/v1/cases/{case_id}/audit", get(verify_audit))
        .route(
            "/api/v1/cases/{case_id}/audit/semantic/jacobian",
            get(semantic_jacobian_audit),
        )
        .route(
            "/api/v1/cases/{case_id}/audit/semantic/guarantees",
            get(semantic_guarantee_audit),
        )
        .route("/api/v1/cases/{case_id}/events", get(list_events))
        .route_layer(middleware::from_fn_with_state(state.clone(), idempotency))
        .route_layer(middleware::from_fn_with_state(state.clone(), authenticate));

    let request_id = HeaderName::from_static("x-request-id");
    let mut cors = CorsLayer::new()
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        .allow_headers([
            AUTHORIZATION,
            CONTENT_TYPE,
            HeaderName::from_static("idempotency-key"),
        ]);
    if let Some(origin) = &config.allowed_origin {
        let origin = HeaderValue::from_str(origin).map_err(|error| {
            JfrError::Configuration(format!("invalid JFR_ALLOWED_ORIGIN: {error}"))
        })?;
        cors = cors.allow_origin(origin);
    }

    Ok(Router::new()
        .route("/health/live", get(live))
        .route("/health/ready", get(ready))
        .route("/metrics", get(metrics))
        .merge(protected)
        .fallback(get(static_asset))
        .with_state(state.clone())
        .layer(middleware::from_fn_with_state(state, track_request))
        .layer((
            SetResponseHeaderLayer::if_not_present(
                X_CONTENT_TYPE_OPTIONS,
                HeaderValue::from_static("nosniff"),
            ),
            SetResponseHeaderLayer::if_not_present(
                CONTENT_SECURITY_POLICY,
                HeaderValue::from_static(
                    "default-src 'self'; script-src 'self'; style-src 'self'; \
                     img-src 'self' data:; connect-src 'self'; object-src 'none'; \
                     base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
                ),
            ),
            SetResponseHeaderLayer::if_not_present(
                HeaderName::from_static("referrer-policy"),
                HeaderValue::from_static("no-referrer"),
            ),
            SetResponseHeaderLayer::if_not_present(
                HeaderName::from_static("permissions-policy"),
                HeaderValue::from_static("camera=(), microphone=(), geolocation=(), payment=()"),
            ),
        ))
        .layer((
            SetRequestIdLayer::new(request_id.clone(), MakeRequestUuid),
            PropagateRequestIdLayer::new(request_id),
            SetSensitiveRequestHeadersLayer::new(once(AUTHORIZATION)),
            TraceLayer::new_for_http(),
            CompressionLayer::new(),
            TimeoutLayer::with_status_code(StatusCode::REQUEST_TIMEOUT, config.request_timeout),
            RequestBodyLimitLayer::new(config.max_request_bytes),
            ConcurrencyLimitLayer::new(256),
            CatchPanicLayer::new(),
            cors,
        )))
}

async fn authenticate(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Result<Response> {
    let token = request
        .headers()
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "));
    let Some(token) = token else {
        state.metrics.authentication_failures.inc();
        return Err(JfrError::Unauthorized);
    };
    match state.auth.authenticate(token).await {
        Ok(auth) => {
            request.extensions_mut().insert(auth);
            Ok(next.run(request).await)
        }
        Err(error) => {
            state.metrics.authentication_failures.inc();
            Err(error)
        }
    }
}

async fn idempotency(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Result<Response> {
    if request.method() != Method::POST {
        return Ok(next.run(request).await);
    }
    let auth = request
        .extensions()
        .get::<AuthContext>()
        .cloned()
        .ok_or(JfrError::Unauthorized)?;
    let key = request
        .headers()
        .get("idempotency-key")
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
        .ok_or_else(|| {
            JfrError::Validation("Idempotency-Key header is required for mutations".to_owned())
        })?;
    if !(8..=200).contains(&key.len()) {
        return Err(JfrError::Validation(
            "Idempotency-Key must contain between 8 and 200 characters".to_owned(),
        ));
    }
    let method = request.method().as_str().to_owned();
    let path = request.uri().path().to_owned();
    let body = std::mem::replace(request.body_mut(), Body::empty());
    let bytes = to_bytes(body, state.max_request_bytes)
        .await
        .map_err(|error| JfrError::Validation(format!("request body: {error}")))?;
    let request_hash: [u8; 32] = Sha256::digest(&bytes).into();
    *request.body_mut() = Body::from(bytes);

    sqlx::query("DELETE FROM idempotency_keys WHERE expires_at < now() AND tenant_id = $1")
        .bind(auth.tenant_id)
        .execute(state.runtime.store().pool())
        .await?;
    let inserted = sqlx::query(
        r"
        INSERT INTO idempotency_keys
            (tenant_id, key, method, path, request_hash, state,
             created_at, expires_at)
        VALUES ($1, $2, $3, $4, $5, 'pending', now(), now() + interval '24 hours')
        ON CONFLICT (tenant_id, key) DO NOTHING
        ",
    )
    .bind(auth.tenant_id)
    .bind(&key)
    .bind(&method)
    .bind(&path)
    .bind(request_hash.as_slice())
    .execute(state.runtime.store().pool())
    .await?
    .rows_affected();
    if inserted == 0 {
        let existing =
            sqlx::query_as::<_, (String, String, Vec<u8>, String, Option<i32>, Option<Value>)>(
                r"
            SELECT method, path, request_hash, state, response_status, response_body
              FROM idempotency_keys
             WHERE tenant_id = $1 AND key = $2
            ",
            )
            .bind(auth.tenant_id)
            .bind(&key)
            .fetch_one(state.runtime.store().pool())
            .await?;
        if existing.0 != method || existing.1 != path || existing.2 != request_hash {
            return Err(JfrError::Conflict(
                "Idempotency-Key was already used for another request".to_owned(),
            ));
        }
        if existing.3 == "pending" {
            return Err(JfrError::Conflict(
                "the idempotent request is still in progress".to_owned(),
            ));
        }
        let status = existing
            .4
            .and_then(|status| u16::try_from(status).ok())
            .and_then(|status| StatusCode::from_u16(status).ok())
            .ok_or_else(|| JfrError::Internal("stored idempotency status is invalid".to_owned()))?;
        let payload = existing.5.ok_or_else(|| {
            JfrError::Internal("stored idempotency response is missing".to_owned())
        })?;
        return Ok((
            status,
            [
                (CONTENT_TYPE, "application/json"),
                (HeaderName::from_static("idempotency-replayed"), "true"),
            ],
            Json(payload),
        )
            .into_response());
    }

    let response = next.run(request).await;
    let status = response.status();
    let (parts, response_body) = response.into_parts();
    let response_bytes = to_bytes(response_body, state.max_request_bytes * 4)
        .await
        .map_err(|error| JfrError::Internal(format!("response body: {error}")))?;
    if status.is_success() {
        if let Ok(payload) = serde_json::from_slice::<Value>(&response_bytes) {
            sqlx::query(
                r"
                UPDATE idempotency_keys
                   SET state = 'completed',
                       response_status = $1,
                       response_body = $2
                 WHERE tenant_id = $3 AND key = $4
                ",
            )
            .bind(i32::from(status.as_u16()))
            .bind(payload)
            .bind(auth.tenant_id)
            .bind(&key)
            .execute(state.runtime.store().pool())
            .await?;
        } else {
            release_idempotency(&state, auth.tenant_id, &key).await?;
        }
    } else {
        release_idempotency(&state, auth.tenant_id, &key).await?;
    }
    Ok(Response::from_parts(parts, Body::from(response_bytes)))
}

async fn release_idempotency(state: &AppState, tenant_id: Uuid, key: &str) -> Result<()> {
    sqlx::query(
        "DELETE FROM idempotency_keys WHERE tenant_id = $1 AND key = $2 AND state = 'pending'",
    )
    .bind(tenant_id)
    .bind(key)
    .execute(state.runtime.store().pool())
    .await?;
    Ok(())
}

async fn track_request(State(state): State<AppState>, request: Request, next: Next) -> Response {
    state.metrics.http_requests.inc();
    let response = next.run(request).await;
    if response.status().is_client_error() || response.status().is_server_error() {
        state.metrics.request_failures.inc();
    }
    response
}

async fn live() -> Json<Liveness> {
    Json(Liveness {
        status: "live",
        service: "jacobian-fiber-runtime",
        version: env!("CARGO_PKG_VERSION"),
    })
}

async fn ready(State(state): State<AppState>) -> Result<Json<Liveness>> {
    state.runtime.store().ping().await?;
    Ok(live().await)
}

async fn metrics(State(state): State<AppState>) -> Result<Response> {
    Ok((
        [(CONTENT_TYPE, "application/openmetrics-text; version=1.0.0")],
        state.metrics.encode()?,
    )
        .into_response())
}

async fn session(Extension(auth): Extension<AuthContext>) -> Result<Json<Session>> {
    require_scope(&auth, "runtime:read")?;
    Ok(Json(auth.into()))
}

async fn list_api_keys(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
) -> Result<Json<Vec<ApiKeyRecord>>> {
    require_scope(&auth, "admin:keys")?;
    Ok(Json(state.auth.list_keys(&auth).await?))
}

async fn list_api_key_events(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
) -> Result<Json<Vec<ApiKeyEvent>>> {
    require_scope(&auth, "admin:keys")?;
    Ok(Json(state.auth.list_key_events(&auth).await?))
}

async fn create_api_key(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Json(command): Json<CreateApiKey>,
) -> Result<impl IntoResponse> {
    require_scope(&auth, "admin:keys")?;
    Ok((
        StatusCode::CREATED,
        Json(state.auth.create_key(&auth, command).await?),
    ))
}

async fn revoke_api_key(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(key_id): Path<Uuid>,
) -> Result<Json<ApiKeyRecord>> {
    require_scope(&auth, "admin:keys")?;
    Ok(Json(state.auth.revoke_key(&auth, key_id).await?))
}

async fn capabilities(Extension(auth): Extension<AuthContext>) -> Result<Json<Capabilities>> {
    require_scope(&auth, "runtime:read")?;
    let refutation_spec = refutation::parse_specification(serde_json::json!({
        "variables": [{"name": "x", "minimum": -2, "maximum": 2}],
        "claim": {
            "op": "greater_than_or_equal",
            "left": {
                "op": "power",
                "base": {"op": "variable", "name": "x"},
                "exponent": 2
            },
            "right": {"op": "constant", "value": "0"}
        }
    }))?;
    Ok(Json(Capabilities {
        runtime: "jfr/0.4",
        persistence: "postgresql",
        audit: "rfc8785-json + sha256 per-case chain",
        concurrency: "optimistic case versions + row locks",
        verifiers: vec![
            VerifierCapability {
                id: "jfr.jacobian-counterexample.v1",
                arithmetic: "exact_big_rational_and_sparse_polynomial",
                certificate: jacobian::exact_certificate()?,
            },
            VerifierCapability {
                id: "jfr.alpoge-fiber-solver.v1",
                arithmetic: "f64_proposal_exact_dyadic_rouche_certificate",
                certificate: jacobian::discover_fiber(&serde_json::json!({
                    "x": "-1/4",
                    "y": "0",
                    "z": "0"
                }))?
                .global_certificate,
            },
            VerifierCapability {
                id: refutation::VERIFIER_ID,
                arithmetic: "exact_big_rational_exhaustive_finite_domain",
                certificate: refutation::exhaustive_search(&refutation_spec)?.certificate,
            },
        ],
    }))
}

async fn list_cases(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Query(query): Query<ListQuery>,
) -> Result<Json<Vec<crate::model::CaseRecord>>> {
    require_scope(&auth, "runtime:read")?;
    Ok(Json(
        state
            .runtime
            .store()
            .list_cases(auth.tenant_id, query.limit.unwrap_or(50))
            .await?,
    ))
}

async fn create_case(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Json(command): Json<CreateCase>,
) -> Result<impl IntoResponse> {
    require_scope(&auth, "runtime:write")?;
    let result = state.runtime.create_case(&auth, command).await?;
    state.metrics.mutations.inc();
    Ok((StatusCode::CREATED, Json(result)))
}

async fn case_snapshot(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(case_id): Path<Uuid>,
) -> Result<Json<crate::model::CaseSnapshot>> {
    require_scope(&auth, "runtime:read")?;
    Ok(Json(state.runtime.snapshot(&auth, case_id).await?))
}

async fn add_evidence(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(case_id): Path<Uuid>,
    Json(command): Json<AddEvidence>,
) -> Result<impl IntoResponse> {
    require_scope(&auth, "runtime:write")?;
    let result = state.runtime.add_evidence(&auth, case_id, command).await?;
    state.metrics.mutations.inc();
    Ok((StatusCode::CREATED, Json(result)))
}

async fn apply_likelihood_evidence(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(case_id): Path<Uuid>,
    Json(command): Json<ApplyLikelihoodEvidence>,
) -> Result<impl IntoResponse> {
    require_scope(&auth, "runtime:validate")?;
    let result = state
        .runtime
        .apply_likelihood_evidence(&auth, case_id, command)
        .await?;
    state.metrics.mutations.inc();
    Ok((StatusCode::CREATED, Json(result)))
}

async fn record_observation(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(case_id): Path<Uuid>,
    Json(command): Json<RecordObservation>,
) -> Result<impl IntoResponse> {
    require_scope(&auth, "runtime:write")?;
    let result = state
        .runtime
        .record_observation(&auth, case_id, command)
        .await?;
    state.metrics.mutations.inc();
    Ok((StatusCode::CREATED, Json(result)))
}

async fn materialize_jacobian_fiber(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(case_id): Path<Uuid>,
    Json(command): Json<MaterializeJacobianFiber>,
) -> Result<impl IntoResponse> {
    require_scope(&auth, "runtime:validate")?;
    let result = state
        .runtime
        .materialize_jacobian_fiber(&auth, case_id, command)
        .await?;
    state.metrics.mutations.inc();
    Ok((StatusCode::CREATED, Json(result)))
}

async fn advance_jacobian_fiber(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(case_id): Path<Uuid>,
    Json(command): Json<AdvanceJacobianFiber>,
) -> Result<impl IntoResponse> {
    require_scope(&auth, "runtime:write")?;
    require_scope(&auth, "runtime:validate")?;
    let result = state
        .runtime
        .advance_jacobian_fiber(&auth, case_id, command)
        .await?;
    state.metrics.mutations.inc();
    Ok((StatusCode::CREATED, Json(result)))
}

async fn propose_branch(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(case_id): Path<Uuid>,
    Json(command): Json<ProposeBranch>,
) -> Result<impl IntoResponse> {
    require_scope(&auth, "runtime:write")?;
    let result = state
        .runtime
        .propose_branch(&auth, case_id, command)
        .await?;
    state.metrics.mutations.inc();
    Ok((StatusCode::CREATED, Json(result)))
}

async fn validate_branch(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(branch_id): Path<Uuid>,
    Json(command): Json<ValidateBranch>,
) -> Result<Json<crate::model::Mutation<crate::model::BranchRecord>>> {
    require_scope(&auth, "runtime:validate")?;
    let result = state
        .runtime
        .validate_branch(&auth, branch_id, command)
        .await?;
    state.metrics.mutations.inc();
    Ok(Json(result))
}

async fn verify_jacobian(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(branch_id): Path<Uuid>,
    Json(command): Json<JacobianVerify>,
) -> Result<Json<crate::model::Mutation<crate::model::BranchRecord>>> {
    require_scope(&auth, "runtime:validate")?;
    let result = state
        .runtime
        .verify_jacobian_branch(&auth, branch_id, command.expected_case_version)
        .await?;
    state.metrics.mutations.inc();
    Ok(Json(result))
}

async fn prune_branch(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(branch_id): Path<Uuid>,
    Json(command): Json<PruneBranch>,
) -> Result<Json<crate::model::Mutation<crate::model::BranchRecord>>> {
    require_scope(&auth, "runtime:validate")?;
    let result = state
        .runtime
        .prune_branch(&auth, branch_id, command)
        .await?;
    state.metrics.mutations.inc();
    Ok(Json(result))
}

async fn split_branch(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(branch_id): Path<Uuid>,
    Json(command): Json<SplitBranch>,
) -> Result<Json<crate::model::Mutation<Vec<crate::model::BranchRecord>>>> {
    require_scope(&auth, "runtime:write")?;
    let result = state
        .runtime
        .split_branch(&auth, branch_id, command)
        .await?;
    state.metrics.mutations.inc();
    Ok(Json(result))
}

async fn merge_branches(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(case_id): Path<Uuid>,
    Json(command): Json<MergeBranches>,
) -> Result<Json<crate::model::Mutation<crate::model::BranchRecord>>> {
    require_scope(&auth, "runtime:write")?;
    let result = state
        .runtime
        .merge_branches(&auth, case_id, command)
        .await?;
    state.metrics.mutations.inc();
    Ok(Json(result))
}

async fn propose_assumption(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(case_id): Path<Uuid>,
    Json(command): Json<ProposeAssumption>,
) -> Result<impl IntoResponse> {
    require_scope(&auth, "runtime:write")?;
    let result = state
        .runtime
        .propose_assumption(&auth, case_id, command)
        .await?;
    state.metrics.mutations.inc();
    Ok((StatusCode::CREATED, Json(result)))
}

async fn validate_assumption(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(assumption_id): Path<Uuid>,
    Json(command): Json<ValidateAssumption>,
) -> Result<Json<crate::model::Mutation<crate::model::AssumptionRecord>>> {
    require_scope(&auth, "runtime:validate")?;
    let result = state
        .runtime
        .validate_assumption(&auth, assumption_id, command)
        .await?;
    state.metrics.mutations.inc();
    Ok(Json(result))
}

async fn create_guarantee(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(case_id): Path<Uuid>,
    Json(command): Json<CreateGuarantee>,
) -> Result<impl IntoResponse> {
    require_scope(&auth, "runtime:validate")?;
    let result = state
        .runtime
        .create_guarantee(&auth, case_id, command)
        .await?;
    state.metrics.mutations.inc();
    Ok((StatusCode::CREATED, Json(result)))
}

async fn search_guarantee(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(guarantee_id): Path<Uuid>,
    Json(command): Json<SearchGuarantee>,
) -> Result<Json<crate::model::Mutation<crate::model::GuaranteeTransition>>> {
    require_scope(&auth, "runtime:validate")?;
    let result = state
        .runtime
        .search_guarantee(&auth, guarantee_id, command)
        .await?;
    state.metrics.mutations.inc();
    Ok(Json(result))
}

async fn submit_counterexample(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(guarantee_id): Path<Uuid>,
    Json(command): Json<SubmitCounterexample>,
) -> Result<Json<crate::model::Mutation<crate::model::GuaranteeTransition>>> {
    require_scope(&auth, "runtime:validate")?;
    let result = state
        .runtime
        .submit_counterexample(&auth, guarantee_id, command)
        .await?;
    state.metrics.mutations.inc();
    Ok(Json(result))
}

async fn authorize_action(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(case_id): Path<Uuid>,
    Json(command): Json<AuthorizeAction>,
) -> Result<Json<crate::model::Mutation<crate::model::ActionAuthorization>>> {
    require_scope(&auth, "runtime:validate")?;
    let result = state
        .runtime
        .authorize_action(&auth, case_id, command)
        .await?;
    state.metrics.mutations.inc();
    Ok(Json(result))
}

async fn evaluate_actions(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(case_id): Path<Uuid>,
    Json(command): Json<EvaluateActions>,
) -> Result<Json<crate::model::DecisionResult>> {
    require_scope(&auth, "runtime:read")?;
    Ok(Json(
        state
            .runtime
            .evaluate_actions(&auth, case_id, command)
            .await?,
    ))
}

async fn rank_experiments(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(case_id): Path<Uuid>,
    Json(command): Json<RankExperiments>,
) -> Result<Json<crate::model::ExperimentRanking>> {
    require_scope(&auth, "runtime:read")?;
    Ok(Json(
        state
            .runtime
            .rank_experiments(&auth, case_id, command)
            .await?,
    ))
}

async fn verify_audit(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(case_id): Path<Uuid>,
) -> Result<Json<crate::model::AuditReport>> {
    require_scope(&auth, "runtime:read")?;
    Ok(Json(state.runtime.verify_audit(&auth, case_id).await?))
}

async fn semantic_jacobian_audit(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(case_id): Path<Uuid>,
) -> Result<Json<crate::model::SemanticFiberAudit>> {
    require_scope(&auth, "runtime:read")?;
    Ok(Json(
        state
            .runtime
            .semantic_jacobian_audit(&auth, case_id)
            .await?,
    ))
}

async fn semantic_guarantee_audit(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(case_id): Path<Uuid>,
) -> Result<Json<crate::model::GuaranteeSemanticAudit>> {
    require_scope(&auth, "runtime:read")?;
    Ok(Json(
        state
            .runtime
            .semantic_guarantee_audit(&auth, case_id)
            .await?,
    ))
}

async fn list_events(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(case_id): Path<Uuid>,
    Query(query): Query<EventQuery>,
) -> Result<Json<Vec<crate::model::EventRecord>>> {
    require_scope(&auth, "runtime:read")?;
    state
        .runtime
        .store()
        .get_case(auth.tenant_id, case_id)
        .await?;
    Ok(Json(
        state
            .runtime
            .store()
            .list_events(
                auth.tenant_id,
                case_id,
                query.after.unwrap_or(0),
                query.limit.unwrap_or(200),
            )
            .await?,
    ))
}

async fn static_asset(request: Request) -> Response {
    let requested = request.uri().path().trim_start_matches('/');
    if requested.starts_with("api/") {
        return StatusCode::NOT_FOUND.into_response();
    }
    let path = if requested.is_empty() {
        "index.html"
    } else {
        requested
    };
    let asset = WebAssets::get(path);
    let Some(asset) = asset else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let content_type = mime_guess::from_path(path)
        .first_or_octet_stream()
        .to_string();
    let cache = if path == "index.html" {
        "no-store"
    } else {
        "no-cache"
    };
    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, content_type)
        .header(CACHE_CONTROL, cache)
        .body(Body::from(asset.data.into_owned()))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}
