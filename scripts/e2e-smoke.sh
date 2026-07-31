#!/usr/bin/env bash
set -euo pipefail

: "${JFR_BASE_URL:=http://127.0.0.1:18080}"
: "${JFR_BOOTSTRAP_API_KEY:?Set JFR_BOOTSTRAP_API_KEY}"

command -v curl >/dev/null
command -v jq >/dev/null
command -v uuidgen >/dev/null

api() {
  local method="$1"
  local path="$2"
  local body="${3:-}"
  if [[ -n "$body" ]]; then
    curl --fail-with-body --silent \
      --request "$method" \
      --header "Authorization: Bearer ${JFR_BOOTSTRAP_API_KEY}" \
      --header "Content-Type: application/json" \
      --header "Idempotency-Key: $(uuidgen)" \
      --data "$body" \
      "${JFR_BASE_URL}${path}"
  else
    curl --fail-with-body --silent \
      --request "$method" \
      --header "Authorization: Bearer ${JFR_BOOTSTRAP_API_KEY}" \
      "${JFR_BASE_URL}${path}"
  fi
}

curl --fail --silent "${JFR_BASE_URL}/health/ready" >/dev/null

unauthorized_status="$(curl --silent --output /dev/null --write-out '%{http_code}' \
  "${JFR_BASE_URL}/api/v1/cases")"
[[ "$unauthorized_status" == "401" ]]

managed_suffix="$(uuidgen | tr -d '-')"
managed_token="jfr_live_e2e_${managed_suffix}"
managed_name="e2e-read-${managed_suffix}"
managed_key="$(api POST "/api/v1/keys" \
  "$(jq -cn --arg name "$managed_name" --arg token "$managed_token" \
    '{name:$name,token:$token,scopes:["runtime:read"]}')")"
managed_key_id="$(jq -r '.id' <<<"$managed_key")"
[[ "$(api GET "/api/v1/keys" | jq --arg id "$managed_key_id" \
  '[.[] | select(.id == $id)] | length')" == "1" ]]

managed_read_status="$(curl --silent --output /dev/null --write-out '%{http_code}' \
  --header "Authorization: Bearer ${managed_token}" \
  "${JFR_BASE_URL}/api/v1/cases")"
[[ "$managed_read_status" == "200" ]]
managed_write_status="$(curl --silent --output /dev/null --write-out '%{http_code}' \
  --request POST \
  --header "Authorization: Bearer ${managed_token}" \
  --header "Content-Type: application/json" \
  --header "Idempotency-Key: $(uuidgen)" \
  --data '{"name":"forbidden","observation":{},"metadata":{}}' \
  "${JFR_BASE_URL}/api/v1/cases")"
[[ "$managed_write_status" == "403" ]]

revoked_key="$(api POST "/api/v1/keys/${managed_key_id}/revoke" '{}')"
[[ "$(jq -r '.revoked_at != null' <<<"$revoked_key")" == "true" ]]
revoked_status="$(curl --silent --output /dev/null --write-out '%{http_code}' \
  --header "Authorization: Bearer ${managed_token}" \
  "${JFR_BASE_URL}/api/v1/cases")"
[[ "$revoked_status" == "401" ]]
[[ "$(api GET "/api/v1/keys/events" | jq --arg id "$managed_key_id" \
  '[.[] | select(.target_key_id == $id)] | length')" == "2" ]]

concurrency_case="$(api POST "/api/v1/cases" \
  '{"name":"E2E concurrency","observation":{"kind":"race"},"metadata":{"suite":"e2e"}}')"
concurrency_case_id="$(jq -r '.resource.id' <<<"$concurrency_case")"
concurrency_version="$(jq -r '.case_version' <<<"$concurrency_case")"
concurrency_temp="$(mktemp -d)"
for contender in one two; do
  curl --silent --output /dev/null --write-out '%{http_code}' \
    --request POST \
    --header "Authorization: Bearer ${JFR_BOOTSTRAP_API_KEY}" \
    --header "Content-Type: application/json" \
    --header "Idempotency-Key: $(uuidgen)" \
    --data "$(jq -cn --arg label "$contender" --argjson version "$concurrency_version" \
      '{label:$label,state:{contender:$label},weight:1,parent_ids:[],evidence_ids:[],proposal:{source:"concurrency-test"},expected_case_version:$version}')" \
    "${JFR_BASE_URL}/api/v1/cases/${concurrency_case_id}/branches" \
    >"${concurrency_temp}/${contender}.status" &
done
wait
concurrency_statuses="$(sort "${concurrency_temp}"/*.status | tr '\n' ' ')"
[[ "$concurrency_statuses" == "201 409 " ]]
concurrency_snapshot="$(api GET "/api/v1/cases/${concurrency_case_id}")"
[[ "$(jq -r '.case.version' <<<"$concurrency_snapshot")" == "2" ]]
[[ "$(jq '.branches | length' <<<"$concurrency_snapshot")" == "1" ]]
[[ "$(jq -r '.audit.valid' <<<"$concurrency_snapshot")" == "true" ]]
rm -r "$concurrency_temp"

create_body='{
  "name": "E2E exact fiber",
  "observation": {"x":"-1/4","y":"0","z":"0"},
  "metadata": {"suite":"e2e","verifier":"jfr.jacobian-counterexample.v1"}
}'
replay_key="$(uuidgen)"
first="$(curl --fail-with-body --silent \
  --request POST \
  --header "Authorization: Bearer ${JFR_BOOTSTRAP_API_KEY}" \
  --header "Content-Type: application/json" \
  --header "Idempotency-Key: ${replay_key}" \
  --data "$create_body" \
  "${JFR_BASE_URL}/api/v1/cases")"
replayed="$(curl --fail-with-body --silent \
  --request POST \
  --header "Authorization: Bearer ${JFR_BOOTSTRAP_API_KEY}" \
  --header "Content-Type: application/json" \
  --header "Idempotency-Key: ${replay_key}" \
  --data "$create_body" \
  "${JFR_BASE_URL}/api/v1/cases")"

case_id="$(jq -r '.resource.id' <<<"$first")"
[[ "$case_id" == "$(jq -r '.resource.id' <<<"$replayed")" ]]
version="$(jq -r '.case_version' <<<"$first")"

mismatch_status="$(curl --silent --output /dev/null --write-out '%{http_code}' \
  --request POST \
  --header "Authorization: Bearer ${JFR_BOOTSTRAP_API_KEY}" \
  --header "Content-Type: application/json" \
  --header "Idempotency-Key: ${replay_key}" \
  --data '{"name":"different request","observation":{},"metadata":{}}' \
  "${JFR_BASE_URL}/api/v1/cases")"
[[ "$mismatch_status" == "409" ]]

points=(
  '{"x":"0","y":"0","z":"-1/4"}'
  '{"x":"1","y":"-3/2","z":"13/2"}'
  '{"x":"-1","y":"3/2","z":"13/2"}'
)

branch_ids=()
index=1
for point in "${points[@]}"; do
  body="$(jq -cn \
    --arg label "sheet-${index}" \
    --argjson state "$point" \
    --argjson version "$version" \
    '{label:$label,state:$state,weight:(1/3),parent_ids:[],evidence_ids:[],proposal:{source:"e2e"},expected_case_version:$version}')"
  proposed="$(api POST "/api/v1/cases/${case_id}/branches" "$body")"
  branch_id="$(jq -r '.resource.id' <<<"$proposed")"
  branch_ids+=("$branch_id")
  version="$(jq -r '.case_version' <<<"$proposed")"
  verified="$(api POST "/api/v1/branches/${branch_id}/verify/jacobian" \
    "$(jq -cn --argjson version "$version" '{expected_case_version:$version}')")"
  [[ "$(jq -r '.resource.status' <<<"$verified")" == "active" ]]
  version="$(jq -r '.case_version' <<<"$verified")"
  index=$((index + 1))
done

snapshot="$(api GET "/api/v1/cases/${case_id}")"
[[ "$(jq '[.branches[] | select(.status == "active")] | length' <<<"$snapshot")" == "3" ]]
[[ "$(jq -r '.audit.valid' <<<"$snapshot")" == "true" ]]
[[ "$(jq -r '.case.version' <<<"$snapshot")" == "$version" ]]

stale_status="$(curl --silent --output /dev/null --write-out '%{http_code}' \
  --request POST \
  --header "Authorization: Bearer ${JFR_BOOTSTRAP_API_KEY}" \
  --header "Content-Type: application/json" \
  --header "Idempotency-Key: $(uuidgen)" \
  --data '{"label":"stale writer","state":{},"weight":1,"parent_ids":[],"evidence_ids":[],"proposal":{},"expected_case_version":0}' \
  "${JFR_BASE_URL}/api/v1/cases/${case_id}/branches")"
[[ "$stale_status" == "409" ]]

evidence="$(api POST "/api/v1/cases/${case_id}/evidence" \
  "$(jq -cn --argjson version "$version" \
    '{kind:"e2e-test",payload:{result:"separating observation"},source:"e2e-smoke",expected_case_version:$version}')")"
evidence_id="$(jq -r '.resource.id' <<<"$evidence")"
version="$(jq -r '.case_version' <<<"$evidence")"

split="$(api POST "/api/v1/branches/${branch_ids[0]}/split" \
  "$(jq -cn --arg evidence "$evidence_id" --argjson version "$version" \
    '{reason:"refine first sheet",evidence_ids:[$evidence],certificate:{method:"e2e-refinement"},candidates:[
      {label:"sheet-1.a",state:{x:"0",y:"0",z:"-1/4",regime:"a"},relative_weight:1,validity:{}},
      {label:"sheet-1.b",state:{x:"0",y:"0",z:"-1/4",regime:"b"},relative_weight:1,validity:{}}
    ],expected_case_version:$version}')")"
version="$(jq -r '.case_version' <<<"$split")"
child_ids=(
  "$(jq -r '.resource[0].id' <<<"$split")"
  "$(jq -r '.resource[1].id' <<<"$split")"
)

for child_id in "${child_ids[@]}"; do
  validated="$(api POST "/api/v1/branches/${child_id}/validate" \
    "$(jq -cn --arg evidence "$evidence_id" --argjson version "$version" \
      '{valid:true,reason:"validated e2e refinement",evidence_ids:[$evidence],certificate:{method:"e2e-validation"},risk_score:0.1,expected_case_version:$version}')")"
  [[ "$(jq -r '.resource.status' <<<"$validated")" == "active" ]]
  version="$(jq -r '.case_version' <<<"$validated")"
done

merged="$(api POST "/api/v1/cases/${case_id}/branches/merge" \
  "$(jq -cn --arg first "${child_ids[0]}" --arg second "${child_ids[1]}" \
    --arg evidence "$evidence_id" --argjson version "$version" \
    '{branch_ids:[$first,$second],label:"sheet-1 consolidated",state:{x:"0",y:"0",z:"-1/4",regime:"merged"},reason:"certified equivalent for action policy",evidence_ids:[$evidence],certificate:{method:"e2e-equivalence"},expected_case_version:$version}')")"
merged_id="$(jq -r '.resource.id' <<<"$merged")"
version="$(jq -r '.case_version' <<<"$merged")"

validated_merge="$(api POST "/api/v1/branches/${merged_id}/validate" \
  "$(jq -cn --arg evidence "$evidence_id" --argjson version "$version" \
    '{valid:true,reason:"merged state is admissible",evidence_ids:[$evidence],certificate:{method:"e2e-validation"},risk_score:0.05,expected_case_version:$version}')")"
[[ "$(jq -r '.resource.status' <<<"$validated_merge")" == "active" ]]
version="$(jq -r '.case_version' <<<"$validated_merge")"

pruned="$(api POST "/api/v1/branches/${branch_ids[1]}/prune" \
  "$(jq -cn --arg evidence "$evidence_id" --argjson version "$version" \
    '{reason:"new evidence contradicts this sheet",evidence_ids:[$evidence],certificate:{method:"e2e-contradiction"},expected_case_version:$version}')")"
[[ "$(jq -r '.resource.status' <<<"$pruned")" == "contradicted" ]]
version="$(jq -r '.case_version' <<<"$pruned")"

decision="$(api POST "/api/v1/cases/${case_id}/decisions/evaluate" \
  "$(jq -cn --arg left "${branch_ids[2]}" --arg right "$merged_id" \
    '{policy:"robust",actions:[
      {id:"safe",label:"Safe across the fiber",utility_by_branch:{($left):2,($right):2}},
      {id:"target",label:"Target one sheet",utility_by_branch:{($left):5,($right):-4}}
    ]}')")"
[[ "$(jq -r '.selected.id' <<<"$decision")" == "safe" ]]
[[ "$(jq -r '.case_version' <<<"$decision")" == "$version" ]]

ranking="$(api POST "/api/v1/cases/${case_id}/experiments/rank" \
  "$(jq -cn --arg left "${branch_ids[2]}" --arg right "$merged_id" \
    '{experiments:[
      {id:"separating",label:"Separating test",predictions_by_branch:{($left):{left:1,right:0},($right):{left:0,right:1}}},
      {id:"uninformative",label:"Uninformative test",predictions_by_branch:{($left):{same:1},($right):{same:1}}}
    ]}')")"
[[ "$(jq -r '.experiments[0].id' <<<"$ranking")" == "separating" ]]
[[ "$(jq -r '.case_version' <<<"$ranking")" == "$version" ]]

observation="$(api POST "/api/v1/cases/${case_id}/observations" \
  "$(jq -cn --argjson version "$version" \
    '{observation:{x:"-1/4",y:"0",z:"0"},kind:"observation",source:"e2e-smoke",expected_case_version:$version}')")"
version="$(jq -r '.case_version' <<<"$observation")"

final_snapshot="$(api GET "/api/v1/cases/${case_id}")"
[[ "$(jq '[.branches[] | select(.status == "active")] | length' <<<"$final_snapshot")" == "2" ]]
[[ "$(jq '.evidence | length' <<<"$final_snapshot")" == "2" ]]
[[ "$(jq -r '.audit.valid' <<<"$final_snapshot")" == "true" ]]
[[ "$(jq -r '.case.version' <<<"$final_snapshot")" == "$version" ]]

audit="$(api GET "/api/v1/cases/${case_id}/audit")"
[[ "$(jq -r '.valid' <<<"$audit")" == "true" ]]
[[ "$(jq -r '.checked_events' <<<"$audit")" == "15" ]]
manual_semantic_audit="$(api GET "/api/v1/cases/${case_id}/audit/semantic/jacobian")"
[[ "$(jq -r '.valid' <<<"$manual_semantic_audit")" == "false" ]]
[[ "$(jq -r '.recorded_active_branches' <<<"$manual_semantic_audit")" == "2" ]]
[[ "$(jq -r '.recomputed_branches' <<<"$manual_semantic_audit")" == "3" ]]

# Certified automatic materialization, Bayesian evidence, KL-robust decisions,
# and globally matched sheet continuation.
deep_case="$(api POST "/api/v1/cases" \
  '{"name":"E2E certified continuation","observation":{"x":"-1/4","y":"0","z":"0"},"metadata":{"suite":"e2e","mode":"automatic-fiber"}}')"
deep_case_id="$(jq -r '.resource.id' <<<"$deep_case")"
deep_version="$(jq -r '.case_version' <<<"$deep_case")"

materialized="$(api POST "/api/v1/cases/${deep_case_id}/fiber/materialize/jacobian" \
  "$(jq -cn --argjson version "$deep_version" '{expected_case_version:$version}')")"
deep_version="$(jq -r '.case_version' <<<"$materialized")"
[[ "$(jq -r '.resource.complete' <<<"$materialized")" == "true" ]]
[[ "$(jq '.resource.branches | length' <<<"$materialized")" == "3" ]]
[[ "$(jq '[.resource.branches[] | select(.status == "active" and .validity.valid == true)] | length' <<<"$materialized")" == "3" ]]
[[ "$(jq '[.resource.branches[].weight] | add > 0.999999999999 and add < 1.000000000001' <<<"$materialized")" == "true" ]]

deep_branch_ids=(
  "$(jq -r '.resource.branches[0].id' <<<"$materialized")"
  "$(jq -r '.resource.branches[1].id' <<<"$materialized")"
  "$(jq -r '.resource.branches[2].id' <<<"$materialized")"
)
likelihoods="$(jq -cn \
  --arg first "${deep_branch_ids[0]}" \
  --arg second "${deep_branch_ids[1]}" \
  --arg third "${deep_branch_ids[2]}" \
  '{($first):0,($second):-4,($third):-4}')"
posterior="$(api POST "/api/v1/cases/${deep_case_id}/evidence/likelihood" \
  "$(jq -cn --argjson version "$deep_version" --argjson likelihoods "$likelihoods" \
    '{kind:"sheet-sensitive-measurement",payload:{outcome:"first-sheet-signature"},source:"e2e-calibrated-sensor",log_likelihood_by_branch:$likelihoods,model:{id:"e2e.sensor",version:"1.0.0",conditional_independence:"Conditionally independent of prior observations given the active algebraic sheet."},expected_case_version:$version}')")"
deep_version="$(jq -r '.case_version' <<<"$posterior")"
[[ "$(jq '[.resource.weights[].posterior] | add > 0.999999999999 and add < 1.000000000001' <<<"$posterior")" == "true" ]]
[[ "$(jq -r '.resource.weights[0].posterior > .resource.weights[1].posterior' <<<"$posterior")" == "true" ]]
[[ "$(jq -r '.resource.information_gain_bits > 0' <<<"$posterior")" == "true" ]]

utilities_aggressive="$(jq -cn \
  --arg first "${deep_branch_ids[0]}" \
  --arg second "${deep_branch_ids[1]}" \
  --arg third "${deep_branch_ids[2]}" \
  '{($first):10,($second):-20,($third):-20}')"
utilities_safe="$(jq -cn \
  --arg first "${deep_branch_ids[0]}" \
  --arg second "${deep_branch_ids[1]}" \
  --arg third "${deep_branch_ids[2]}" \
  '{($first):2,($second):2,($third):2}')"
kl_decision="$(api POST "/api/v1/cases/${deep_case_id}/decisions/evaluate" \
  "$(jq -cn --argjson aggressive "$utilities_aggressive" --argjson safe "$utilities_safe" \
    '{policy:"distributionally_robust",ambiguity_radius:0.5,actions:[
      {id:"aggressive",label:"Exploit dominant sheet",utility_by_branch:$aggressive},
      {id:"safe",label:"Safe across KL ambiguity set",utility_by_branch:$safe}
    ]}')")"
[[ "$(jq -r '.selected.id' <<<"$kl_decision")" == "safe" ]]
[[ "$(jq '[.scores[].adversarial_distribution_by_branch | to_entries[].value] | all(. >= 0)' <<<"$kl_decision")" == "true" ]]

# Second-order assumption fiber, exact proof/refutation, joint authorization,
# and transactional cascade revocation.
assumption="$(api POST "/api/v1/cases/${deep_case_id}/assumptions" \
  "$(jq -cn --argjson version "$deep_version" \
    '{label:"nominal arithmetic model",statement:{integer_domain:true,arithmetic:"exact"},weight:1,parent_ids:[],evidence_ids:[],proposal:{source:"e2e-assurance"},expected_case_version:$version}')")"
assumption_id="$(jq -r '.resource.id' <<<"$assumption")"
deep_version="$(jq -r '.case_version' <<<"$assumption")"

activated_assumption="$(api POST "/api/v1/assumptions/${assumption_id}/validate" \
  "$(jq -cn --argjson version "$deep_version" \
    '{valid:true,reason:"bounded integer model accepted for e2e",evidence_ids:[],certificate:{verifier:"e2e-assumption-attestation"},expected_case_version:$version}')")"
[[ "$(jq -r '.resource.status' <<<"$activated_assumption")" == "active" ]]
deep_version="$(jq -r '.case_version' <<<"$activated_assumption")"

true_spec='{
  "variables":[{"name":"x","minimum":-12,"maximum":12}],
  "premises":[],
  "claim":{
    "op":"greater_than_or_equal",
    "left":{"op":"power","base":{"op":"variable","name":"x"},"exponent":2},
    "right":{"op":"constant","value":"0"}
  }
}'
true_guarantee="$(api POST "/api/v1/cases/${deep_case_id}/guarantees" \
  "$(jq -cn --arg assumption "$assumption_id" --argjson specification "$true_spec" \
    --argjson version "$deep_version" \
    '{label:"integer squares are non-negative",description:"Exact bounded theorem for action gating.",premise_assumption_ids:[$assumption],parent_ids:[],specification:$specification,expected_case_version:$version}')")"
true_guarantee_id="$(jq -r '.resource.id' <<<"$true_guarantee")"
deep_version="$(jq -r '.case_version' <<<"$true_guarantee")"

true_search="$(api POST "/api/v1/guarantees/${true_guarantee_id}/search/exhaustive" \
  "$(jq -cn --argjson version "$deep_version" '{expected_case_version:$version}')")"
[[ "$(jq -r '.resource.guarantee.status' <<<"$true_search")" == "verified" ]]
[[ "$(jq -r '.resource.search.outcome' <<<"$true_search")" == "verified" ]]
[[ "$(jq -r '.resource.search.examined_assignments' <<<"$true_search")" == "25" ]]
deep_version="$(jq -r '.case_version' <<<"$true_search")"

safe_joint="$(jq -cn --arg assumption "$assumption_id" \
  --arg first "${deep_branch_ids[0]}" --arg second "${deep_branch_ids[1]}" \
  --arg third "${deep_branch_ids[2]}" \
  '[{branch_id:$first,assumption_id:$assumption,utility:2},
    {branch_id:$second,assumption_id:$assumption,utility:2},
    {branch_id:$third,assumption_id:$assumption,utility:2}]')"
risky_joint="$(jq -cn --arg assumption "$assumption_id" \
  --arg first "${deep_branch_ids[0]}" --arg second "${deep_branch_ids[1]}" \
  --arg third "${deep_branch_ids[2]}" \
  '[{branch_id:$first,assumption_id:$assumption,utility:8},
    {branch_id:$second,assumption_id:$assumption,utility:-4},
    {branch_id:$third,assumption_id:$assumption,utility:-9}]')"
authorization="$(api POST "/api/v1/cases/${deep_case_id}/actions/authorize" \
  "$(jq -cn --arg guarantee "$true_guarantee_id" --arg assumption "$assumption_id" \
    --argjson safe "$safe_joint" --argjson risky "$risky_joint" \
    --argjson version "$deep_version" \
    '{requested_action_id:"safe",actions:[
      {id:"safe",label:"Safe across product fiber",utilities:$safe},
      {id:"risky",label:"Risky tail exposure",utilities:$risky}
    ],required_guarantee_ids:[$guarantee],required_assumption_ids:[$assumption],expected_case_version:$version}')")"
authorization_id="$(jq -r '.resource.authorization.id' <<<"$authorization")"
[[ "$(jq -r '.resource.authorized' <<<"$authorization")" == "true" ]]
[[ "$(jq -r '.resource.authorization.status' <<<"$authorization")" == "authorized" ]]
[[ "$(jq -r '.resource.scenario_count' <<<"$authorization")" == "3" ]]
deep_version="$(jq -r '.case_version' <<<"$authorization")"

false_spec='{
  "variables":[{"name":"x","minimum":0,"maximum":10}],
  "premises":[],
  "claim":{
    "op":"less_than_or_equal",
    "left":{"op":"power","base":{"op":"variable","name":"x"},"exponent":2},
    "right":{"op":"add","arguments":[
      {"op":"multiply","arguments":[{"op":"constant","value":"2"},{"op":"variable","name":"x"}]},
      {"op":"constant","value":"3"}
    ]}
  }
}'
false_guarantee="$(api POST "/api/v1/cases/${deep_case_id}/guarantees" \
  "$(jq -cn --arg assumption "$assumption_id" --argjson specification "$false_spec" \
    --argjson version "$deep_version" \
    '{label:"false quadratic bound",description:"Known-false theorem used to exercise exact refutation.",premise_assumption_ids:[$assumption],parent_ids:[],specification:$specification,expected_case_version:$version}')")"
false_guarantee_id="$(jq -r '.resource.id' <<<"$false_guarantee")"
deep_version="$(jq -r '.case_version' <<<"$false_guarantee")"

false_search="$(api POST "/api/v1/guarantees/${false_guarantee_id}/search/exhaustive" \
  "$(jq -cn --argjson version "$deep_version" '{expected_case_version:$version}')")"
[[ "$(jq -r '.resource.guarantee.status' <<<"$false_search")" == "contradicted" ]]
[[ "$(jq -r '.resource.search.outcome' <<<"$false_search")" == "counterexample" ]]
[[ "$(jq -r '.resource.search.witness.x' <<<"$false_search")" == "4" ]]
deep_version="$(jq -r '.case_version' <<<"$false_search")"

contradicted_assumption="$(api POST "/api/v1/assumptions/${assumption_id}/validate" \
  "$(jq -cn --argjson version "$deep_version" \
    '{valid:false,reason:"e2e premise withdrawn",evidence_ids:[],certificate:{verifier:"e2e-contradiction"},expected_case_version:$version}')")"
[[ "$(jq -r '.resource.status' <<<"$contradicted_assumption")" == "contradicted" ]]
deep_version="$(jq -r '.case_version' <<<"$contradicted_assumption")"

assurance_snapshot="$(api GET "/api/v1/cases/${deep_case_id}")"
[[ "$(jq -r --arg id "$true_guarantee_id" '.guarantees[] | select(.id == $id) | .status' <<<"$assurance_snapshot")" == "suspended" ]]
[[ "$(jq -r --arg id "$false_guarantee_id" '.guarantees[] | select(.id == $id) | .status' <<<"$assurance_snapshot")" == "contradicted" ]]
[[ "$(jq -r --arg id "$authorization_id" '.authorizations[] | select(.id == $id) | .status' <<<"$assurance_snapshot")" == "revoked" ]]
[[ "$(jq '.counterexamples | length' <<<"$assurance_snapshot")" == "1" ]]
[[ "$(jq -r '.counterexamples[0].witness.x' <<<"$assurance_snapshot")" == "4" ]]

guarantee_audit="$(api GET "/api/v1/cases/${deep_case_id}/audit/semantic/guarantees")"
[[ "$(jq -r '.valid' <<<"$guarantee_audit")" == "true" ]]
[[ "$(jq -r '.checked_guarantees' <<<"$guarantee_audit")" == "2" ]]
[[ "$(jq -r '.suspended_guarantees' <<<"$guarantee_audit")" == "1" ]]
[[ "$(jq -r '.contradicted_guarantees' <<<"$guarantee_audit")" == "1" ]]

advanced="$(api POST "/api/v1/cases/${deep_case_id}/fiber/advance/jacobian" \
  "$(jq -cn --argjson version "$deep_version" \
    '{observation:{x:"-8/27",y:"0",z:"1"},kind:"continuation-target",source:"e2e-path",expected_case_version:$version}')")"
deep_version="$(jq -r '.case_version' <<<"$advanced")"
[[ "$(jq -r '.resource.complete' <<<"$advanced")" == "true" ]]
[[ "$(jq '.resource.branches | length' <<<"$advanced")" == "3" ]]
[[ "$(jq '.resource.superseded_branch_ids | length' <<<"$advanced")" == "3" ]]
[[ "$(jq '.resource.correspondence | length' <<<"$advanced")" == "3" ]]
[[ "$(jq '[.resource.branches[] | select(.status == "active" and (.parent_ids | length) == 1)] | length' <<<"$advanced")" == "3" ]]
[[ "$(jq '[.resource.branches[].validity.certificate.root_disc.root_count] | all(. == 1)' <<<"$advanced")" == "true" ]]
[[ "$(jq '[.resource.branches[].risk_score] | all(. >= 0)' <<<"$advanced")" == "true" ]]

deep_snapshot="$(api GET "/api/v1/cases/${deep_case_id}")"
[[ "$(jq '[.branches[] | select(.status == "active")] | length' <<<"$deep_snapshot")" == "3" ]]
[[ "$(jq '[.branches[] | select(.status == "superseded")] | length' <<<"$deep_snapshot")" == "3" ]]
[[ "$(jq -r '.case.observation.x' <<<"$deep_snapshot")" == "-8/27" ]]
[[ "$(jq -r '.audit.valid' <<<"$deep_snapshot")" == "true" ]]
[[ "$(jq -r '.case.version' <<<"$deep_snapshot")" == "$deep_version" ]]

semantic_audit="$(api GET "/api/v1/cases/${deep_case_id}/audit/semantic/jacobian")"
[[ "$(jq -r '.valid' <<<"$semantic_audit")" == "true" ]]
[[ "$(jq -r '.complete' <<<"$semantic_audit")" == "true" ]]
[[ "$(jq '.matches | length' <<<"$semantic_audit")" == "3" ]]
[[ "$(jq '[.matches[].valid] | all' <<<"$semantic_audit")" == "true" ]]
[[ "$(jq -r '.maximum_escape_score >= 0' <<<"$semantic_audit")" == "true" ]]

deep_audit="$(api GET "/api/v1/cases/${deep_case_id}/audit")"
[[ "$(jq -r '.valid' <<<"$deep_audit")" == "true" ]]
[[ "$(jq -r '.checked_events' <<<"$deep_audit")" == "12" ]]

printf 'case_id=%s\n' "$case_id"
printf 'active_branches=2\n'
printf 'case_version=%s\n' "$version"
printf 'audit_events=%s\n' "$(jq -r '.checked_events' <<<"$audit")"
printf 'audit_head=%s\n' "$(jq -r '.head_hash' <<<"$audit")"
printf 'deep_case_id=%s\n' "$deep_case_id"
printf 'deep_case_version=%s\n' "$deep_version"
printf 'certified_continuation_branches=3\n'
printf 'assurance_guarantees=2\n'
printf 'revoked_authorizations=1\n'
printf 'deep_audit_head=%s\n' "$(jq -r '.head_hash' <<<"$deep_audit")"
