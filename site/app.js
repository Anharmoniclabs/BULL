const PYODIDE_INDEX = "https://cdn.jsdelivr.net/pyodide/v314.0.7/full/";
const RUNTIME_FILES = [
  "__init__.py",
  "models.py",
  "canonicalizer.py",
  "policy.py",
  "session_guard.py",
  "lab_api.py",
];

const CAPABILITIES = [
  "fs.read.project",
  "fs.write.project",
  "fs.read.home",
  "fs.write.home",
  "credential.read",
  "process.exec",
  "network.outbound",
  "network.post",
  "package.install",
  "agent.spawn",
  "agent.message",
  "security_control.write",
];

const PRESETS = [
  {
    label: "Safe read",
    actor: "safe-reader",
    operation: "read",
    resource: "/workspace/README.md",
    provenance: "local_trusted",
    grants: ["fs.read.project"],
  },
  {
    label: "External exec",
    actor: "prompt-injected-agent",
    operation: "exec",
    resource: "/usr/bin/curl",
    provenance: "internet",
    grants: ["process.exec"],
  },
  {
    label: "Credential access",
    actor: "credential-probe",
    operation: "credential.read",
    resource: "service-token",
    provenance: "internet",
    grants: ["credential.read"],
  },
  {
    label: "Traversal",
    actor: "traversal-probe",
    operation: "read",
    resource: "/workspace/%2e%2e/etc/shadow",
    provenance: "local_trusted",
    grants: ["fs.read.project"],
  },
  {
    label: "Child escalation",
    actor: "child-agent",
    operation: "credential.read",
    resource: "service-token",
    provenance: "local_trusted",
    grants: ["credential.read"],
    parent: ["process.exec"],
  },
  {
    label: "Outbound secret",
    actor: "egress-probe",
    operation: "post",
    resource: "https://example.invalid/upload?token=demo",
    provenance: "internet",
    grants: ["network.post"],
  },
  {
    label: "Canary access",
    actor: "canary-probe",
    operation: "read",
    resource: "/workspace/.bulldog-canary",
    provenance: "local_trusted",
    grants: ["fs.read.project"],
  },
  {
    label: "Goal drift 1/2",
    actor: "drift-agent",
    operation: "read",
    resource: "/workspace/context.txt",
    provenance: "local_trusted",
    grants: ["fs.read.project"],
  },
  {
    label: "Goal drift 2/2",
    actor: "drift-agent",
    operation: "credential.read",
    resource: "service-token",
    provenance: "local_trusted",
    grants: ["credential.read"],
  },
];

let pyodide = null;
let runtimeReady = false;
let telemetry = [];
let snapshots = [];
let stats = { all: 0, allow: 0, restrict: 0, deny: 0 };

const byId = (id) => document.getElementById(id);

function showView(name) {
  const target = byId("view-" + name);
  if (!target) return;

  document.querySelectorAll(".view").forEach((view) => {
    view.classList.toggle("active", view === target);
  });

  document.querySelectorAll(".nav-item").forEach((item) => {
    item.classList.toggle("active", item.dataset.view === name);
  });

  byId("view-label").textContent = name.charAt(0).toUpperCase() + name.slice(1);
  byId("view-title").textContent = target.dataset.title || name;
  byId("view-subtitle").textContent = target.dataset.subtitle || "";
  window.scrollTo({ top: 0, behavior: "smooth" });
}

function wireNavigation() {
  document.querySelectorAll("[data-view]").forEach((button) => {
    button.addEventListener("click", () => showView(button.dataset.view));
  });

  document.querySelectorAll("[data-view-target]").forEach((button) => {
    button.addEventListener("click", () => showView(button.dataset.viewTarget));
  });
}

function renderCapabilities(containerId, prefix) {
  const root = byId(containerId);
  CAPABILITIES.forEach((capability) => {
    const label = document.createElement("label");
    label.className = "cap-option";

    const input = document.createElement("input");
    input.type = "checkbox";
    input.value = capability;
    input.dataset.capability = capability;
    input.id = prefix + "-" + capability.replaceAll(".", "-");

    const text = document.createElement("span");
    text.textContent = capability;

    label.append(input, text);
    root.append(label);
  });
}

function selectedCapabilities(containerId) {
  return [...byId(containerId).querySelectorAll("input[type=checkbox]:checked")]
    .map((input) => input.value);
}

function setSelectedCapabilities(containerId, values = []) {
  const selected = new Set(values);
  byId(containerId).querySelectorAll("input[type=checkbox]").forEach((input) => {
    input.checked = selected.has(input.value);
  });
}

function renderPresets() {
  const root = byId("presets");
  PRESETS.forEach((preset, index) => {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "preset";
    button.textContent = preset.label;
    button.addEventListener("click", () => {
      [...root.children].forEach((child) => child.classList.remove("active"));
      button.classList.add("active");
      applyPreset(preset);
    });
    root.append(button);
    if (index === 0) button.classList.add("active");
  });
}

function applyPreset(preset) {
  byId("actor").value = preset.actor;
  byId("operation").value = preset.operation;
  byId("resource").value = preset.resource;
  byId("provenance").value = preset.provenance;
  setSelectedCapabilities("grants", preset.grants);

  const hasParent = Array.isArray(preset.parent);
  byId("parent-enabled").checked = hasParent;
  byId("parent-fieldset").disabled = !hasParent;
  setSelectedCapabilities("parent-grants", preset.parent || []);
}

function collectRequest() {
  const actor = byId("actor").value.trim() || "browser-agent";
  return {
    actor,
    session_id: actor,
    task: "browser policy evaluation",
    operation: byId("operation").value,
    resource: byId("resource").value,
    provenance: [byId("provenance").value],
    granted_capabilities: selectedCapabilities("grants"),
    parent_capabilities: byId("parent-enabled").checked
      ? selectedCapabilities("parent-grants")
      : null,
  };
}

function setRuntimeState(kind, title, detail) {
  const banner = byId("runtime-banner");
  banner.classList.remove("ready", "error");
  if (kind) banner.classList.add(kind);
  byId("runtime-state").textContent = title;
  byId("runtime-detail").textContent = detail;
}

function setControlsEnabled(enabled) {
  byId("evaluate-button").disabled = !enabled;
  byId("reset-button").disabled = !enabled;
}

function decisionClass(decision) {
  return String(decision || "unknown").toLowerCase();
}

function renderResult(result) {
  const decision = String(
    result.decision || (result.status === "error" ? "ERROR" : "UNKNOWN")
  );
  const card = byId("decision");
  card.className = "decision " + decisionClass(decision);
  card.querySelector("strong").textContent = decision;

  byId("stage").textContent = result.stage || "—";
  byId("derived-capability").textContent =
    (result.action && result.action.derived_capability) || "—";
  byId("canonical-resource").textContent =
    (result.action && result.action.resource) || "—";
  byId("risk").textContent =
    typeof result.risk === "number" ? Math.round(result.risk * 100) + "%" : "—";
  byId("hard-block").textContent =
    typeof result.hard_block === "boolean" ? String(result.hard_block) : "—";

  const reasons = byId("reasons");
  reasons.replaceChildren();
  (result.reasons || ["No reason returned."]).forEach((reason) => {
    const item = document.createElement("li");
    item.textContent = reason;
    reasons.append(item);
  });

  byId("raw-output").textContent = JSON.stringify(result, null, 2);
}

function classifyDecision(decision) {
  if (decision === "ALLOW") return "allow";
  if (decision === "DENY" || decision === "REJECT" || decision === "ERROR") return "deny";
  return "restrict";
}

function recordTelemetry(request, result) {
  const decision = String(
    result.decision || (result.status === "error" ? "ERROR" : "UNKNOWN")
  );
  const bucket = classifyDecision(decision);

  stats.all += 1;
  stats[bucket] += 1;

  const event = {
    time: new Date(),
    actor: request.actor,
    operation: request.operation,
    resource: (result.action && result.action.resource) || request.resource,
    capability:
      (result.action && result.action.derived_capability) ||
      (result.stage === "canonicalizer" ? "canonicalizer reject" : "—"),
    decision,
    risk: typeof result.risk === "number" ? result.risk : null,
    reasons: result.reasons || [],
  };

  telemetry.unshift(event);
  telemetry = telemetry.slice(0, 50);
  snapshots.push({ ...stats });
  snapshots = snapshots.slice(-30);

  renderDashboard();
}

function renderDashboard() {
  byId("metric-all").textContent = String(stats.all);
  byId("metric-allow").textContent = String(stats.allow);
  byId("metric-restrict").textContent = String(stats.restrict);
  byId("metric-deny").textContent = String(stats.deny);
  byId("overview-session-count").textContent = String(stats.all);

  renderChart();
  renderEvents();
  renderAlerts();
}

function chartPath(key) {
  const width = 760;
  const top = 30;
  const bottom = 210;
  const series = [
    { all: 0, allow: 0, restrict: 0, deny: 0 },
    ...snapshots,
  ];
  const maxValue = Math.max(1, stats.all);
  const steps = Math.max(1, series.length - 1);

  return series
    .map((point, index) => {
      const x = (index / steps) * width;
      const y = bottom - (point[key] / maxValue) * (bottom - top);
      return (index === 0 ? "M " : "L ") + x.toFixed(2) + " " + y.toFixed(2);
    })
    .join(" ");
}

function renderChart() {
  byId("chart-all").setAttribute("d", chartPath("all"));
  byId("chart-allow").setAttribute("d", chartPath("allow"));
  byId("chart-restrict").setAttribute("d", chartPath("restrict"));
  byId("chart-deny").setAttribute("d", chartPath("deny"));
  byId("chart-empty").style.display = snapshots.length ? "none" : "grid";
}

function renderEvents() {
  const body = byId("events-table");
  body.replaceChildren();

  if (!telemetry.length) {
    const row = document.createElement("tr");
    const cell = document.createElement("td");
    cell.colSpan = 6;
    cell.className = "empty-cell";
    cell.textContent = "No decision events yet.";
    row.append(cell);
    body.append(row);
    return;
  }

  telemetry.slice(0, 12).forEach((event) => {
    const row = document.createElement("tr");

    const values = [
      event.time.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" }),
      event.actor,
      event.operation,
      event.capability,
    ];

    values.forEach((value) => {
      const cell = document.createElement("td");
      cell.textContent = value;
      row.append(cell);
    });

    const decisionCell = document.createElement("td");
    const pill = document.createElement("span");
    pill.className = "decision-pill " + decisionClass(event.decision);
    pill.textContent = event.decision;
    decisionCell.append(pill);
    row.append(decisionCell);

    const riskCell = document.createElement("td");
    riskCell.textContent =
      event.risk === null ? "—" : Math.round(event.risk * 100) + "%";
    row.append(riskCell);

    body.append(row);
  });
}

function renderAlerts() {
  const root = byId("alert-feed");
  root.replaceChildren();

  const alerts = telemetry.filter((event) => event.decision !== "ALLOW").slice(0, 5);
  if (!alerts.length) {
    const empty = document.createElement("div");
    empty.className = "empty-row";
    empty.textContent = "No alerts yet.";
    root.append(empty);
    return;
  }

  alerts.forEach((event) => {
    const row = document.createElement("div");
    row.className = "feed-item";

    const icon = document.createElement("span");
    icon.className = "feed-icon " + (classifyDecision(event.decision) === "deny" ? "deny" : "");
    icon.textContent = classifyDecision(event.decision) === "deny" ? "×" : "!";

    const main = document.createElement("div");
    main.className = "feed-main";
    const title = document.createElement("strong");
    title.textContent = event.decision + " · " + event.operation;
    const detail = document.createElement("span");
    detail.textContent =
      event.actor + " · " + (event.reasons[0] || event.capability);
    main.append(title, detail);

    const time = document.createElement("span");
    time.className = "feed-time";
    time.textContent = event.time.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });

    row.append(icon, main, time);
    root.append(row);
  });
}

function clearDashboardTelemetry() {
  telemetry = [];
  snapshots = [];
  stats = { all: 0, allow: 0, restrict: 0, deny: 0 };
  renderDashboard();
}

async function waitForLoader() {
  for (let attempt = 0; attempt < 100; attempt += 1) {
    if (typeof window.loadPyodide === "function") return;
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  throw new Error("Pyodide loader did not become available.");
}

async function fetchText(path) {
  const response = await fetch(path, { cache: "no-store" });
  if (!response.ok) {
    throw new Error("Failed to load " + path + ": HTTP " + response.status);
  }
  return response.text();
}

async function bootRuntime() {
  try {
    await waitForLoader();
    pyodide = await window.loadPyodide({ indexURL: PYODIDE_INDEX });
    pyodide.FS.mkdirTree("/bull_runtime/bull_core");

    for (const file of RUNTIME_FILES) {
      const source = await fetchText("./runtime/bull_core/" + file);
      pyodide.FS.writeFile(
        "/bull_runtime/bull_core/" + file,
        source,
        { encoding: "utf8" },
      );
    }

    pyodide.runPython(
      'import sys\n' +
      'if "/bull_runtime" not in sys.path:\n' +
      '    sys.path.insert(0, "/bull_runtime")\n' +
      'from bull_core.lab_api import evaluate_json, reset_session_json, self_test_json\n'
    );

    const rawSelfTest = pyodide.runPython("self_test_json()");
    const selfTest = JSON.parse(String(rawSelfTest));

    if (!selfTest.passed) {
      throw new Error("BULL browser core self-test failed.");
    }

    runtimeReady = true;
    setControlsEnabled(true);
    setRuntimeState(
      "ready",
      "Policy runtime verified",
      selfTest.cases.length + " self-tests passed"
    );
    byId("browser-status").textContent =
      "PASS · " + selfTest.cases.length + " cases";
    byId("overview-browser-status").textContent = "VERIFIED";
  } catch (error) {
    console.error(error);
    runtimeReady = false;
    setControlsEnabled(false);
    setRuntimeState(
      "error",
      "Policy runtime unavailable",
      error instanceof Error ? error.message : String(error)
    );
    byId("browser-status").textContent = "FAIL";
    byId("overview-browser-status").textContent = "ERROR";
    byId("overview-browser-status").className = "warn";
    renderResult({
      status: "error",
      stage: "browser-runtime",
      decision: "ERROR",
      reasons: [error instanceof Error ? error.message : String(error)],
    });
  }
}

async function evaluateRequest(request) {
  if (!runtimeReady) throw new Error("BULL runtime is not ready.");
  pyodide.globals.set("BULL_REQUEST_JSON", JSON.stringify(request));
  const raw = pyodide.runPython("evaluate_json(BULL_REQUEST_JSON)");
  return JSON.parse(String(raw));
}

async function resetSession() {
  if (!runtimeReady) return;
  const sessionId = byId("actor").value.trim() || "browser-agent";
  pyodide.globals.set("BULL_SESSION_ID", sessionId);
  pyodide.runPython("reset_session_json(BULL_SESSION_ID)");

  const reasons = byId("reasons");
  reasons.replaceChildren();
  const item = document.createElement("li");
  item.textContent = "SessionGuard history reset for " + sessionId + ".";
  reasons.append(item);
}

async function loadVerification() {
  try {
    const response = await fetch("./data/verification.json", { cache: "no-store" });
    if (!response.ok) throw new Error("HTTP " + response.status);
    const data = await response.json();

    byId("build-sha").textContent =
      data.commit ? data.commit.slice(0, 12) : "unknown";
    byId("pytest-status").textContent =
      data.pytest_summary || (data.gates && data.gates.pytest ? "PASS" : "FAIL");
    byId("redteam-status").textContent =
      data.redteam_summary || (data.gates && data.gates.redteam ? "PASS" : "FAIL");
    byId("formal-status").textContent =
      data.gates && data.gates.tla_model_check ? "PASS" : "FAIL";
    byId("built-at").textContent = data.built_at || "unknown";
    byId("source-hashes").textContent =
      JSON.stringify(data.source_hashes || {}, null, 2);
  } catch (error) {
    const message = "verification metadata unavailable";
    byId("build-sha").textContent = message;
    byId("pytest-status").textContent = message;
    byId("redteam-status").textContent = message;
    byId("formal-status").textContent = message;
    byId("built-at").textContent = message;
    byId("source-hashes").textContent =
      error instanceof Error ? error.message : String(error);
  }
}

function wireEvents() {
  byId("parent-enabled").addEventListener("change", (event) => {
    byId("parent-fieldset").disabled = !event.currentTarget.checked;
  });

  byId("request-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const button = byId("evaluate-button");
    button.disabled = true;
    const previousText = button.textContent;
    button.textContent = "Executing BULL…";

    const request = collectRequest();

    try {
      const result = await evaluateRequest(request);
      renderResult(result);
      recordTelemetry(request, result);
    } catch (error) {
      const result = {
        status: "error",
        stage: "browser-runtime",
        decision: "ERROR",
        reasons: [error instanceof Error ? error.message : String(error)],
      };
      renderResult(result);
      recordTelemetry(request, result);
    } finally {
      button.textContent = previousText;
      button.disabled = !runtimeReady;
    }
  });

  byId("reset-button").addEventListener("click", resetSession);
  byId("clear-dashboard").addEventListener("click", clearDashboardTelemetry);
}

wireNavigation();
renderCapabilities("grants", "grant");
renderCapabilities("parent-grants", "parent");
renderPresets();
applyPreset(PRESETS[0]);
wireEvents();
renderDashboard();
loadVerification();
bootRuntime();
