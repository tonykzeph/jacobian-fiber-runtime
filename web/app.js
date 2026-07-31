const state = {
  token: sessionStorage.getItem("jfr_api_key"),
  session: null,
  cases: [],
  snapshot: null,
  selectedBranchId: null,
  selectedAssumptionId: null,
};

const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => [...document.querySelectorAll(selector)];

document.addEventListener("DOMContentLoaded", () => {
  bindEvents();
  if (state.token) connect();
});

function bindEvents() {
  $("#auth-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    state.token = $("#api-key").value;
    await connect();
  });
  $("#logout-button").addEventListener("click", logout);
  $("#refresh-button").addEventListener("click", refresh);
  $("#new-case-button").addEventListener("click", () => $("#case-dialog").showModal());
  $("#materialize-fiber-button").addEventListener("click", materializeFiber);
  $("#advance-fiber-button").addEventListener("click", () => $("#advance-dialog").showModal());
  $("#likelihood-button").addEventListener("click", openLikelihoodDialog);
  $("#add-evidence-button").addEventListener("click", () => $("#evidence-dialog").showModal());
  $("#add-assumption-button").addEventListener("click", openAssumptionDialog);
  $("#assumption-column-button").addEventListener("click", openAssumptionDialog);
  $("#new-guarantee-button").addEventListener("click", openGuaranteeDialog);
  $("#authorize-action-button").addEventListener("click", openAuthorizationDialog);
  $("#guarantee-audit-button").addEventListener("click", auditGuarantees);
  $("#propose-branch-button").addEventListener("click", () => $("#branch-dialog").showModal());
  $("#audit-button").addEventListener("click", audit);
  $$(".rail-tabs button").forEach((button) => {
    button.addEventListener("click", () => selectTab(button.dataset.tab));
  });
  $$("dialog form").forEach((form) => {
    form.addEventListener("submit", handleDialogSubmit);
  });
}

async function connect() {
  $("#auth-error").textContent = "";
  try {
    state.session = await api("/api/v1/session");
    sessionStorage.setItem("jfr_api_key", state.token);
    $("#tenant-label").textContent = `${state.session.key_name} · ${shortId(state.session.tenant_id)}`;
    $("#auth-gate").hidden = true;
    $("#app-shell").hidden = false;
    await loadCases();
  } catch (error) {
    $("#auth-error").textContent = error.message;
    sessionStorage.removeItem("jfr_api_key");
  }
}

function logout() {
  sessionStorage.removeItem("jfr_api_key");
  state.token = null;
  state.snapshot = null;
  $("#api-key").value = "";
  $("#app-shell").hidden = true;
  $("#auth-gate").hidden = false;
  $("#api-key").focus();
}

async function refresh() {
  if (state.snapshot) {
    await selectCase(state.snapshot.case.id);
  } else {
    await loadCases();
  }
  toast("Runtime state refreshed.");
}

async function loadCases(selectNewest = false) {
  state.cases = await api("/api/v1/cases?limit=100");
  renderCases();
  if (selectNewest && state.cases.length) {
    await selectCase(state.cases[0].id);
  }
}

function renderCases() {
  const list = $("#case-list");
  list.replaceChildren();
  for (const item of state.cases) {
    const button = document.createElement("button");
    button.className = "case-item";
    button.setAttribute("aria-current", String(state.snapshot?.case.id === item.id));
    const name = document.createElement("strong");
    name.textContent = item.name;
    const meta = document.createElement("span");
    meta.textContent = `v${item.version} · ${formatTime(item.updated_at)}`;
    button.append(name, meta);
    button.addEventListener("click", () => selectCase(item.id));
    list.append(button);
  }
  if (!state.cases.length) {
    const empty = document.createElement("p");
    empty.className = "empty-copy";
    empty.textContent = "Create the first state space.";
    list.append(empty);
  }
  $("#case-count").textContent = `${state.cases.length} ${state.cases.length === 1 ? "case" : "cases"}`;
}

async function selectCase(caseId) {
  try {
    state.snapshot = await api(`/api/v1/cases/${caseId}`);
    state.selectedBranchId = null;
    state.selectedAssumptionId = null;
    renderCases();
    renderSnapshot();
  } catch (error) {
    toast(error.message, true);
  }
}

function renderSnapshot() {
  const {
    case: current,
    branches,
    evidence,
    events,
    audit: report,
    assumptions = [],
    guarantees = [],
    counterexamples = [],
    authorizations = [],
  } = state.snapshot;
  $("#case-id-label").textContent = current.id;
  $("#case-name").textContent = current.name;
  $("#version-label").textContent = `Version ${current.version}`;
  $("#observation-value").textContent = pretty(current.observation);
  $("#materialize-fiber-button").disabled = false;
  $("#advance-fiber-button").disabled = false;
  $("#likelihood-button").disabled = !branches.some((branch) => branch.status === "active");
  $("#add-evidence-button").disabled = false;
  $("#add-assumption-button").disabled = false;
  $("#assumption-column-button").disabled = false;
  $("#new-guarantee-button").disabled = !assumptions.some((item) => item.status === "active");
  $("#authorize-action-button").disabled =
    !branches.some((item) => item.status === "active") ||
    !assumptions.some((item) => item.status === "active");
  $("#guarantee-audit-button").disabled = false;
  $("#propose-branch-button").disabled = false;
  $("#audit-button").disabled = false;
  const active = branches.filter((branch) => branch.status === "active");
  const mass = active.reduce((sum, branch) => sum + branch.weight, 0);
  $("#active-mass").textContent = `${active.length} active · mass ${formatNumber(mass)}`;
  renderFiber(branches);
  renderBranchTable(branches);
  renderEvidence(evidence);
  renderEvents(events, report);
  renderBranchDetail();
  renderAssurance(assumptions, guarantees, counterexamples, authorizations);
}

function renderAssurance(assumptions, guarantees, counterexamples, authorizations) {
  $("#assumption-count").textContent = `${assumptions.length} ${assumptions.length === 1 ? "branch" : "branches"}`;
  $("#guarantee-count").textContent = `${guarantees.length} ${guarantees.length === 1 ? "guarantee" : "guarantees"}`;
  $("#authorization-count").textContent = `${authorizations.length} ${authorizations.length === 1 ? "decision" : "decisions"}`;
  $("#guarantee-semantic-status").textContent = "Not audited";
  $("#guarantee-semantic-status").style.color = "var(--muted)";

  const assumptionList = $("#assumption-list");
  assumptionList.replaceChildren();
  for (const assumption of assumptions) {
    const card = assuranceCard(assumption.label, assumption.status, `M${assumption.generation} · w ${formatNumber(assumption.weight)}`);
    card.append(detailBlock("Statement", assumption.statement));
    if (["proposed", "active"].includes(assumption.status)) {
      card.append(actionButton(
        assumption.status === "active" ? "Revalidate premise" : "Validate premise",
        "secondary-action compact",
        () => {
          state.selectedAssumptionId = assumption.id;
          $("#assumption-validation-dialog").showModal();
        },
      ));
    }
    assumptionList.append(card);
  }
  if (!assumptions.length) assumptionList.append(emptyCopy("No assumptions declared."));

  const counterexampleByGuarantee = new Map();
  const activeAssumptionIds = new Set(
    assumptions.filter((item) => item.status === "active").map((item) => item.id),
  );
  for (const counterexample of counterexamples) {
    if (!counterexampleByGuarantee.has(counterexample.guarantee_id)) {
      counterexampleByGuarantee.set(counterexample.guarantee_id, counterexample);
    }
  }
  const guaranteeList = $("#guarantee-list");
  guaranteeList.replaceChildren();
  for (const guarantee of guarantees) {
    const assignments = guarantee.verification?.total_domain_assignments
      ?? guarantee.verification?.declared_search_assignments
      ?? "—";
    const card = assuranceCard(
      guarantee.label,
      guarantee.status,
      `${guarantee.verifier_id} · ${assignments} assignments`,
    );
    const lineage = selectElement("p", "assurance-lineage");
    lineage.textContent = guarantee.premise_assumption_ids.length
      ? `premises ${guarantee.premise_assumption_ids.map(shortId).join(", ")}`
      : "unconditional finite-domain gate";
    card.append(lineage);
    const witness = counterexampleByGuarantee.get(guarantee.id);
    if (witness) card.append(detailBlock("Counterexample", witness.witness));
    const premisesActive = guarantee.premise_assumption_ids.every((id) => activeAssumptionIds.has(id));
    if (guarantee.status === "proposed" || (guarantee.status === "suspended" && premisesActive)) {
      card.append(actionButton("Run exhaustive verifier", "primary-action compact", () => searchGuarantee(guarantee.id)));
    } else if (guarantee.status === "suspended") {
      card.append(selectElement("span", "gate-blocked", "Blocked until every premise is active"));
    }
    guaranteeList.append(card);
  }
  if (!guarantees.length) guaranteeList.append(emptyCopy("No guarantees declared."));

  const authorizationList = $("#authorization-list");
  authorizationList.replaceChildren();
  for (const authorization of [...authorizations].reverse()) {
    const card = assuranceCard(
      authorization.requested_action_id,
      authorization.status,
      `${authorization.policy} · selected ${authorization.selected_action_id}`,
    );
    const worst = authorization.result?.selected?.worst_case;
    if (worst) {
      const exposure = selectElement("p", "assurance-lineage");
      exposure.textContent = `floor ${formatNumber(worst.utility)} · ${shortId(worst.branch_id)} × ${shortId(worst.assumption_id)}`;
      card.append(exposure);
    }
    if (authorization.revocation) card.append(detailBlock("Revocation", authorization.revocation));
    authorizationList.append(card);
  }
  if (!authorizations.length) authorizationList.append(emptyCopy("No authorization evaluated."));
}

function assuranceCard(titleText, status, metaText) {
  const card = selectElement("section", "assurance-card");
  const heading = selectElement("header", "");
  const title = selectElement("strong", "", titleText);
  const pill = selectElement("span", `status-pill ${status}`, status);
  heading.append(title, pill);
  card.append(heading, selectElement("code", "assurance-meta", metaText));
  return card;
}

function renderFiber(branches) {
  const canvas = $("#fiber-canvas");
  canvas.replaceChildren();
  if (!branches.length) {
    canvas.append(emptyState("No branches have been proposed."));
    return;
  }
  const width = Math.max(canvas.clientWidth, 560);
  const height = 320;
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("viewBox", `0 0 ${width} ${height}`);
  svg.classList.add("fiber-svg");
  const observationX = width * 0.73;
  const observationY = height / 2;
  const visible = branches.slice(0, 14);
  const spacing = height / (visible.length + 1);
  visible.forEach((branch, index) => {
    const x = width * 0.17 + Math.min(branch.generation, 5) * 23;
    const y = spacing * (index + 1);
    const color = statusColor(branch.status);
    const path = svgNode("path", {
      d: `M ${x + 8} ${y} C ${width * .38} ${y}, ${width * .48} ${observationY}, ${observationX - 21} ${observationY}`,
      stroke: color,
      class: "fiber-line",
    });
    if (!["active", "proposed"].includes(branch.status)) path.setAttribute("stroke-dasharray", "4 6");
    const circle = svgNode("circle", { cx: x, cy: y, r: 7, stroke: color, class: "fiber-node" });
    circle.addEventListener("click", () => selectBranch(branch.id));
    const label = svgNode("text", { x: x + 14, y: y + 4, class: "fiber-label" });
    label.textContent = truncate(branch.label, 28);
    svg.append(path, circle, label);
  });
  const observation = svgNode("rect", {
    x: observationX - 18,
    y: observationY - 18,
    width: 36,
    height: 36,
    rx: 3,
    class: "fiber-observation",
  });
  const marker = svgNode("text", {
    x: observationX,
    y: observationY + 3,
    "text-anchor": "middle",
    class: "fiber-observation-label",
  });
  marker.textContent = "y";
  svg.append(observation, marker);
  canvas.append(svg);
}

function renderBranchTable(branches) {
  const body = $("#branch-table");
  body.replaceChildren();
  if (!branches.length) {
    body.append(tableEmpty("No branches yet."));
    return;
  }
  for (const branch of branches) {
    const row = document.createElement("tr");
    if (branch.id === state.selectedBranchId) row.classList.add("selected");
    row.append(
      tableCell(branch.label),
      statusCell(branch.status),
      tableCell(String(branch.generation)),
      tableCell(formatNumber(branch.weight)),
      tableCell(branch.risk_score == null ? "—" : formatNumber(branch.risk_score)),
    );
    row.addEventListener("click", () => selectBranch(branch.id));
    body.append(row);
  }
}

function renderEvidence(evidence) {
  $("#evidence-count").textContent = `${evidence.length} ${evidence.length === 1 ? "record" : "records"}`;
  const list = $("#evidence-list");
  list.replaceChildren();
  for (const item of [...evidence].reverse()) {
    const node = document.createElement("article");
    node.className = "timeline-item";
    const title = document.createElement("strong");
    title.textContent = item.kind;
    const time = document.createElement("time");
    time.textContent = `${item.source} · ${formatTime(item.observed_at)}`;
    const payload = document.createElement("pre");
    payload.textContent = pretty(item.payload);
    node.append(title, time, payload);
    list.append(node);
  }
  if (!evidence.length) list.append(emptyCopy("No evidence recorded."));
}

function renderEvents(events, report) {
  $("#audit-status").textContent = report.valid ? `Verified · ${report.checked_events} events` : "Verification failed";
  $("#audit-status").style.color = report.valid ? "var(--green)" : "var(--rose)";
  $("#semantic-status").textContent = "Run verification";
  $("#semantic-status").style.color = "var(--muted)";
  $("#escape-score").textContent = "escape —";
  $("#head-hash").textContent = report.head_hash || "—";
  const list = $("#event-list");
  list.replaceChildren();
  for (const event of [...events].reverse()) {
    const node = document.createElement("article");
    node.className = "timeline-item";
    const title = document.createElement("strong");
    title.textContent = event.event_type;
    const time = document.createElement("time");
    time.textContent = `#${event.sequence} · ${formatTime(event.created_at)}`;
    const hash = document.createElement("code");
    hash.textContent = event.event_hash.slice(0, 18);
    node.append(title, time, hash);
    list.append(node);
  }
}

function selectBranch(branchId) {
  state.selectedBranchId = branchId;
  renderBranchTable(state.snapshot.branches);
  renderBranchDetail();
  selectTab("branch");
}

function renderBranchDetail() {
  const panel = $("#branch-detail");
  panel.replaceChildren();
  const branch = state.snapshot?.branches.find((item) => item.id === state.selectedBranchId);
  if (!branch) {
    panel.append(emptyCopy("Choose a branch from the register."));
    return;
  }
  const title = document.createElement("h3");
  title.textContent = branch.label;
  const meta = document.createElement("div");
  meta.className = "detail-meta";
  meta.textContent = `${branch.status} · generation ${branch.generation} · ${shortId(branch.id)}`;
  panel.append(title, meta, detailBlock("Hidden state", branch.state), detailBlock("Validity", branch.validity));
  const actions = document.createElement("div");
  actions.className = "detail-actions";
  if (["proposed", "active"].includes(branch.status)) {
    const validate = actionButton("Validate branch", "primary-action", () => $("#validation-dialog").showModal());
    const jacobian = actionButton("Run exact Jacobian verifier", "secondary-action", verifySelectedJacobian);
    actions.append(validate, jacobian);
  }
  panel.append(actions);
}

function selectTab(tab) {
  $$(".rail-tabs button").forEach((button) => button.setAttribute("aria-selected", String(button.dataset.tab === tab)));
  ["evidence", "ledger", "branch"].forEach((name) => {
    $(`#${name}-panel`).hidden = name !== tab;
  });
}

async function audit() {
  try {
    const [report, semantic, guarantees] = await Promise.all([
      api(`/api/v1/cases/${state.snapshot.case.id}/audit`),
      api(`/api/v1/cases/${state.snapshot.case.id}/audit/semantic/jacobian`),
      api(`/api/v1/cases/${state.snapshot.case.id}/audit/semantic/guarantees`),
    ]);
    $("#audit-status").textContent = report.valid ? `Verified · ${report.checked_events} events` : report.reason;
    $("#audit-status").style.color = report.valid ? "var(--green)" : "var(--rose)";
    $("#semantic-status").textContent = semantic.valid
      ? `Complete · ${semantic.recomputed_branches} sheets`
      : semantic.reason;
    $("#semantic-status").style.color = semantic.valid ? "var(--green)" : "var(--rose)";
    $("#escape-score").textContent = `escape ${formatNumber(semantic.maximum_escape_score)}`;
    $("#head-hash").textContent = report.head_hash;
    setGuaranteeAuditStatus(guarantees);
    selectTab("ledger");
    const valid = report.valid && semantic.valid && guarantees.valid;
    toast(valid ? "Ledger, fiber, and guarantee semantics verified." : "Verification failed.", !valid);
  } catch (error) {
    toast(error.message, true);
  }
}

async function auditGuarantees() {
  if (!state.snapshot) return;
  const button = $("#guarantee-audit-button");
  button.disabled = true;
  button.textContent = "Recomputing…";
  try {
    const report = await api(`/api/v1/cases/${state.snapshot.case.id}/audit/semantic/guarantees`);
    setGuaranteeAuditStatus(report);
    toast(
      report.valid
        ? `Recomputed ${report.checked_guarantees} guarantee certificates over ${report.checked_assignments} assignments.`
        : report.reason,
      !report.valid,
    );
  } catch (error) {
    toast(error.message, true);
  } finally {
    button.textContent = "Recompute proofs";
    button.disabled = !state.snapshot;
  }
}

function setGuaranteeAuditStatus(report) {
  const node = $("#guarantee-semantic-status");
  node.textContent = report.valid
    ? `Exact · ${report.checked_guarantees} gates`
    : report.reason || "Audit failed";
  node.style.color = report.valid ? "var(--green)" : "var(--rose)";
}

function openAssumptionDialog() {
  if (state.snapshot) $("#assumption-dialog").showModal();
}

function fillMultiSelect(selector, records, selected = true) {
  const select = $(selector);
  select.replaceChildren();
  for (const record of records) {
    const option = document.createElement("option");
    option.value = record.id;
    option.textContent = `${record.label} · ${record.status}`;
    option.selected = selected;
    select.append(option);
  }
}

function openGuaranteeDialog() {
  const active = state.snapshot?.assumptions.filter((item) => item.status === "active") || [];
  if (!active.length) {
    toast("Activate at least one assumption before declaring a guarantee.", true);
    return;
  }
  fillMultiSelect("#guarantee-premises", active);
  $("#guarantee-dialog").showModal();
}

function openAuthorizationDialog() {
  const branches = state.snapshot?.branches.filter((item) => item.status === "active") || [];
  const assumptions = state.snapshot?.assumptions.filter((item) => item.status === "active") || [];
  if (!branches.length || !assumptions.length) {
    toast("Authorization requires active world and assumption fibers.", true);
    return;
  }
  const guarantees = state.snapshot.guarantees.filter((item) => item.status === "verified");
  fillMultiSelect("#authorization-guarantees", guarantees);
  fillMultiSelect("#authorization-assumptions", assumptions);
  const utilities = (value) => branches.flatMap((branch) =>
    assumptions.map((assumption) => ({
      branch_id: branch.id,
      assumption_id: assumption.id,
      utility: value,
    })));
  const actions = [
    { id: "safe", label: "Safe across the full product fiber", utilities: utilities(1) },
    {
      id: "fast",
      label: "Higher upside with a weak tail",
      utilities: utilities(4).map((scenario, index, values) => ({
        ...scenario,
        utility: index === values.length - 1 ? -5 : scenario.utility,
      })),
    },
  ];
  $("#authorization-dialog").querySelector("[name='actions']").value = pretty(actions);
  $("#authorization-dialog").showModal();
}

async function searchGuarantee(guaranteeId) {
  try {
    const result = await api(`/api/v1/guarantees/${guaranteeId}/search/exhaustive`, {
      method: "POST",
      body: { expected_case_version: state.snapshot.case.version },
    });
    const outcome = result.resource.search.outcome;
    toast(outcome === "verified"
      ? `Guarantee verified across ${result.resource.search.examined_assignments} exact assignments.`
      : `Guarantee refuted by ${pretty(result.resource.search.witness)}.`);
    await selectCase(state.snapshot.case.id);
  } catch (error) {
    toast(error.message, true);
  }
}

async function verifySelectedJacobian() {
  const branch = selectedBranch();
  if (!branch) return;
  try {
    await api(`/api/v1/branches/${branch.id}/verify/jacobian`, {
      method: "POST",
      body: { expected_case_version: state.snapshot.case.version },
    });
    toast("Exact Jacobian verification recorded.");
    await selectCase(state.snapshot.case.id);
  } catch (error) {
    toast(error.message, true);
  }
}

async function materializeFiber() {
  if (!state.snapshot) return;
  const button = $("#materialize-fiber-button");
  button.disabled = true;
  button.textContent = "Certifying…";
  try {
    const result = await api(`/api/v1/cases/${state.snapshot.case.id}/fiber/materialize/jacobian`, {
      method: "POST",
      body: { expected_case_version: state.snapshot.case.version },
    });
    toast(`Certified ${result.resource.branches.length} complete algebraic sheets.`);
    await selectCase(state.snapshot.case.id);
  } catch (error) {
    toast(error.message, true);
  } finally {
    button.textContent = "Certify fiber";
    button.disabled = !state.snapshot;
  }
}

function openLikelihoodDialog() {
  const active = state.snapshot?.branches.filter((branch) => branch.status === "active") || [];
  const likelihoods = Object.fromEntries(active.map((branch) => [branch.id, 0]));
  $("#likelihood-dialog").querySelector("[name='likelihoods']").value = pretty(likelihoods);
  $("#likelihood-dialog").showModal();
}

async function handleDialogSubmit(event) {
  event.preventDefault();
  const submitter = event.submitter;
  if (submitter?.value === "cancel") {
    event.currentTarget.closest("dialog").close();
    return;
  }
  const form = event.currentTarget;
  const error = form.querySelector("[data-error]");
  error.textContent = "";
  try {
    if (form.dataset.submit === "case") await submitCase(form);
    if (form.dataset.submit === "evidence") await submitEvidence(form);
    if (form.dataset.submit === "advance") await submitAdvance(form);
    if (form.dataset.submit === "likelihood") await submitLikelihood(form);
    if (form.dataset.submit === "branch") await submitBranch(form);
    if (form.dataset.submit === "validation") await submitValidation(form);
    if (form.dataset.submit === "assumption") await submitAssumption(form);
    if (form.dataset.submit === "assumption-validation") await submitAssumptionValidation(form);
    if (form.dataset.submit === "guarantee") await submitGuarantee(form);
    if (form.dataset.submit === "authorization") await submitAuthorization(form);
    form.closest("dialog").close();
  } catch (failure) {
    error.textContent = failure.message;
  }
}

async function submitAdvance(form) {
  const fields = new FormData(form);
  const result = await api(`/api/v1/cases/${state.snapshot.case.id}/fiber/advance/jacobian`, {
    method: "POST",
    body: {
      observation: parseJson(fields.get("observation"), "Next observation"),
      kind: fields.get("kind"),
      source: fields.get("source"),
      expected_case_version: state.snapshot.case.version,
    },
  });
  toast(`Advanced ${result.resource.branches.length} sheets with ${result.resource.correspondence.length} lineage matches.`);
  await selectCase(state.snapshot.case.id);
}

async function submitLikelihood(form) {
  const fields = new FormData(form);
  const result = await api(`/api/v1/cases/${state.snapshot.case.id}/evidence/likelihood`, {
    method: "POST",
    body: {
      kind: fields.get("kind"),
      source: fields.get("source"),
      payload: parseJson(fields.get("payload"), "Evidence payload"),
      log_likelihood_by_branch: parseJson(fields.get("likelihoods"), "Log likelihood map"),
      model: {
        id: fields.get("model_id"),
        version: fields.get("model_version"),
        conditional_independence: fields.get("independence"),
      },
      expected_case_version: state.snapshot.case.version,
    },
  });
  toast(`Posterior committed · ${formatNumber(result.resource.information_gain_bits)} bits gained.`);
  await selectCase(state.snapshot.case.id);
}

async function submitCase(form) {
  const fields = new FormData(form);
  const result = await api("/api/v1/cases", {
    method: "POST",
    body: {
      name: fields.get("name"),
      observation: parseJson(fields.get("observation"), "Initial observation"),
      metadata: parseJson(fields.get("metadata"), "Metadata"),
    },
  });
  toast(`Created ${result.resource.name}.`);
  form.reset();
  form.elements.observation.value = "{}";
  form.elements.metadata.value = "{}";
  await loadCases();
  await selectCase(result.resource.id);
}

async function submitEvidence(form) {
  const fields = new FormData(form);
  await api(`/api/v1/cases/${state.snapshot.case.id}/evidence`, {
    method: "POST",
    body: {
      kind: fields.get("kind"),
      source: fields.get("source"),
      payload: parseJson(fields.get("payload"), "Payload"),
      expected_case_version: state.snapshot.case.version,
    },
  });
  toast("Evidence added.");
  form.reset();
  form.elements.kind.value = "observation";
  form.elements.payload.value = "{}";
  await selectCase(state.snapshot.case.id);
}

async function submitBranch(form) {
  const fields = new FormData(form);
  await api(`/api/v1/cases/${state.snapshot.case.id}/branches`, {
    method: "POST",
    body: {
      label: fields.get("label"),
      state: parseJson(fields.get("state"), "State"),
      weight: Number(fields.get("weight")),
      parent_ids: [],
      evidence_ids: [],
      proposal: parseJson(fields.get("proposal"), "Proposal certificate"),
      expected_case_version: state.snapshot.case.version,
    },
  });
  toast("Branch proposed.");
  form.reset();
  form.elements.weight.value = "1";
  form.elements.state.value = "{}";
  form.elements.proposal.value = "{}";
  await selectCase(state.snapshot.case.id);
}

async function submitValidation(form) {
  const branch = selectedBranch();
  if (!branch) throw new Error("Choose a branch first.");
  const fields = new FormData(form);
  await api(`/api/v1/branches/${branch.id}/validate`, {
    method: "POST",
    body: {
      valid: fields.get("valid") === "true",
      reason: fields.get("reason"),
      evidence_ids: [],
      certificate: parseJson(fields.get("certificate"), "Certificate"),
      risk_score: null,
      expected_case_version: state.snapshot.case.version,
    },
  });
  toast("Validation recorded.");
  form.reset();
  form.elements.certificate.value = '{"verifier":"operator-attestation"}';
  await selectCase(state.snapshot.case.id);
}

async function submitAssumption(form) {
  const fields = new FormData(form);
  await api(`/api/v1/cases/${state.snapshot.case.id}/assumptions`, {
    method: "POST",
    body: {
      label: fields.get("label"),
      statement: parseJson(fields.get("statement"), "Statement"),
      weight: Number(fields.get("weight")),
      parent_ids: [],
      evidence_ids: [],
      proposal: parseJson(fields.get("proposal"), "Proposal certificate"),
      expected_case_version: state.snapshot.case.version,
    },
  });
  toast("Assumption branch proposed.");
  form.reset();
  form.elements.weight.value = "1";
  form.elements.statement.value = '{"model":"nominal"}';
  form.elements.proposal.value = '{"source":"operator"}';
  await selectCase(state.snapshot.case.id);
}

async function submitAssumptionValidation(form) {
  const assumption = state.snapshot?.assumptions.find((item) => item.id === state.selectedAssumptionId);
  if (!assumption) throw new Error("Choose an assumption first.");
  const fields = new FormData(form);
  const valid = fields.get("valid") === "true";
  const result = await api(`/api/v1/assumptions/${assumption.id}/validate`, {
    method: "POST",
    body: {
      valid,
      reason: fields.get("reason"),
      evidence_ids: [],
      certificate: parseJson(fields.get("certificate"), "Certificate"),
      expected_case_version: state.snapshot.case.version,
    },
  });
  toast(valid
    ? "Assumption activated."
    : `Assumption contradicted at case version ${result.case_version}; dependent permits were revoked.`);
  form.reset();
  form.elements.certificate.value = '{"verifier":"operator-attestation"}';
  await selectCase(state.snapshot.case.id);
}

async function submitGuarantee(form) {
  const fields = new FormData(form);
  const premiseIds = [...form.elements.premises.selectedOptions].map((option) => option.value);
  await api(`/api/v1/cases/${state.snapshot.case.id}/guarantees`, {
    method: "POST",
    body: {
      label: fields.get("label"),
      description: fields.get("description"),
      premise_assumption_ids: premiseIds,
      parent_ids: [],
      specification: parseJson(fields.get("specification"), "Finite-domain specification"),
      expected_case_version: state.snapshot.case.version,
    },
  });
  toast("Guarantee gate declared. Run the exact verifier to activate it.");
  await selectCase(state.snapshot.case.id);
}

async function submitAuthorization(form) {
  const fields = new FormData(form);
  const guaranteeIds = [...form.elements.guarantees.selectedOptions].map((option) => option.value);
  const assumptionIds = [...form.elements.assumptions.selectedOptions].map((option) => option.value);
  const result = await api(`/api/v1/cases/${state.snapshot.case.id}/actions/authorize`, {
    method: "POST",
    body: {
      requested_action_id: fields.get("requested_action_id"),
      actions: parseJson(fields.get("actions"), "Actions and utilities"),
      required_guarantee_ids: guaranteeIds,
      required_assumption_ids: assumptionIds,
      expected_case_version: state.snapshot.case.version,
    },
  });
  toast(
    result.resource.authorized
      ? `Action ${result.resource.selected.id} authorized across ${result.resource.scenario_count} joint scenarios.`
      : `Permit denied: ${result.resource.dependency_reasons.join("; ")}`,
    !result.resource.authorized,
  );
  await selectCase(state.snapshot.case.id);
}

async function api(path, options = {}) {
  const headers = { Accept: "application/json" };
  if (state.token) headers.Authorization = `Bearer ${state.token}`;
  if (options.body !== undefined) {
    headers["Content-Type"] = "application/json";
    headers["Idempotency-Key"] = crypto.randomUUID();
  }
  const response = await fetch(path, {
    method: options.method || "GET",
    headers,
    body: options.body === undefined ? undefined : JSON.stringify(options.body),
  });
  const type = response.headers.get("content-type") || "";
  const payload = type.includes("json") ? await response.json() : await response.text();
  if (!response.ok) {
    if (response.status === 401 && state.session) logout();
    const message = payload?.error?.message || payload || `Request failed with ${response.status}`;
    throw new Error(message);
  }
  return payload;
}

function selectedBranch() {
  return state.snapshot?.branches.find((branch) => branch.id === state.selectedBranchId);
}

function parseJson(raw, label) {
  try {
    return JSON.parse(raw);
  } catch (error) {
    throw new Error(`${label} is not valid JSON: ${error.message}`);
  }
}

function selectElement(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function emptyState(text) {
  const wrapper = selectElement("div", "empty-state");
  wrapper.append(selectElement("span", "empty-glyph", "∅"), selectElement("p", "", text));
  return wrapper;
}

function emptyCopy(text) { return selectElement("p", "empty-copy", text); }
function tableCell(text) { return selectElement("td", "", text); }

function statusCell(status) {
  const cell = document.createElement("td");
  cell.append(selectElement("span", `status-pill ${status}`, status));
  return cell;
}

function tableEmpty(text) {
  const row = document.createElement("tr");
  const cell = selectElement("td", "table-empty", text);
  cell.colSpan = 5;
  row.append(cell);
  return row;
}

function detailBlock(label, value) {
  const block = selectElement("div", "detail-block");
  block.append(selectElement("span", "", label), selectElement("pre", "", pretty(value)));
  return block;
}

function actionButton(label, className, handler) {
  const button = selectElement("button", className, label);
  button.type = "button";
  button.addEventListener("click", handler);
  return button;
}

function svgNode(name, attributes) {
  const node = document.createElementNS("http://www.w3.org/2000/svg", name);
  Object.entries(attributes).forEach(([key, value]) => node.setAttribute(key, value));
  return node;
}

function statusColor(status) {
  if (status === "active") return "var(--cyan)";
  if (status === "proposed") return "var(--amber)";
  if (status === "contradicted") return "var(--rose)";
  return "var(--rule-strong)";
}

function pretty(value) { return JSON.stringify(value, null, 2); }
function truncate(value, length) { return value.length > length ? `${value.slice(0, length - 1)}…` : value; }
function shortId(value) { return `${value.slice(0, 8)}…${value.slice(-4)}`; }
function formatNumber(value) { return new Intl.NumberFormat("en", { maximumFractionDigits: 4 }).format(value); }
function formatTime(value) { return new Intl.DateTimeFormat("en", { dateStyle: "medium", timeStyle: "short" }).format(new Date(value)); }

function toast(message, error = false) {
  const node = selectElement("div", `toast${error ? " error" : ""}`, message);
  $("#toast-region").append(node);
  window.setTimeout(() => node.remove(), 4200);
}
