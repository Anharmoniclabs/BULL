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
    label: "Safe project read",
    actor: "safe-reader",
    operation: "read",
    resource: "/workspace/README.md",
    provenance: "local_trusted",
    grants: ["fs.read.project"],
  },
  {
    label: "External process exec",
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
    label: "Encoded traversal",
    actor: "traversal-probe",
    operation: "read",
    resource: "/workspace/%2e%2e/etc/shadow",
    provenance: "local_trusted",
    grants: ["fs.read.project"],
  },
  {
    label: "Child privilege escalation",
    actor: "child-agent",
    operation: "credential.read",
    resource: "service-token",
    provenance: "local_trusted",
    grants: ["credential.read"],
    parent: ["process.exec"],
  },
  {
    label: "Outbound secret hint",
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

const byId = (id) => document.getElementById(id);

function renderCapabilities(containerId, prefix) {
  const root = byId(containerId);
  CAPABILITIES.forEach((capability) => {
    const label = document.createElement("label");
    label.className = "cap-option";

    const input = document.createElement("input");
    input.type = "checkbox";
    input.value = capability;
    input.dataset.capability = capability;
    input.id = `${prefix}-${capability.replaceAll(".", "-")}`;

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

function renderResult(result) {
  const decision = String(result.decision || (result.status === "error" ? "ERROR" : "UNKNOWN"));
  const card = byId("decision");
  card.className = `decision ${decision.toLowerCase()}`;
  card.querySelector("strong").textContent = decision;

  byId("stage").textContent = result.stage || "—";
  byId("derived-capability").textContent = result.action?.derived_capability || "—";
  byId("canonical-resource").textContent = result.action?.resource || "—";
  byId("risk").textContent = typeof result.risk === "number"
    ? `${Math.round(result.risk * 100)}%`
    : "—";
  byId("hard-block").textContent = typeof result.hard_block === "boolean"
    ? String(result.hard_block)
    : "—";

  const reasons = byId("reasons");
  reasons.replaceChildren();
  (result.reasons || ["No reason returned."]).forEach((reason) => {
    const item = document.createElement("li");
    item.textContent = reason;
    reasons.append(item);
  });

  byId("raw-output").textContent = JSON.stringify(result, null, 2);
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
    throw new Error(`Failed to load ${path}: HTTP ${response.status}`);
  }
  return response.text();
}

async function bootRuntime() {
  try {
    await waitForLoader();
    pyodide = await window.loadPyodide({ indexURL: PYODIDE_INDEX });
    pyodide.FS.mkdirTree("/bull_runtime/bull_core");

    for (const file of RUNTIME_FILES) {
      const source = await fetchText(`./runtime/bull_core/${file}`);
      pyodide.FS.writeFile(
        `/bull_runtime/bull_core/${file}`,
        source,
        { encoding: "utf8" },
      );
    }

    pyodide.runPython(`
import sys
if "/bull_runtime" not in sys.path:
    sys.path.insert(0, "/bull_runtime")
from bull_core.lab_api import evaluate_json, reset_session_json, self_test_json
`);

    const rawSelfTest = pyodide.runPython("self_test_json()");
    const selfTest = JSON.parse(String(rawSelfTest));

    if (!selfTest.passed) {
      throw new Error("BULL browser core self-test failed.");
    }

    runtimeReady = true;
    setControlsEnabled(true);
    setRuntimeState(
      "ready",
      "BULL browser runtime: verified",
      `${selfTest.cases.length} self-tests passed using repository Python sources.`,
    );
    byId("browser-status").textContent = `PASS · ${selfTest.cases.length} cases`;
  } catch (error) {
    console.error(error);
    runtimeReady = false;
    setControlsEnabled(false);
    setRuntimeState(
      "error",
      "BULL browser runtime: unavailable",
      error instanceof Error ? error.message : String(error),
    );
    byId("browser-status").textContent = "FAIL";
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
  item.textContent = `Session history reset for ${sessionId}.`;
  reasons.append(item);
}

async function loadVerification() {
  try {
    const response = await fetch("./data/verification.json", { cache: "no-store" });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const data = await response.json();

    byId("build-sha").textContent = data.commit?.slice(0, 12) || "unknown";
    byId("pytest-status").textContent = data.pytest_summary || (data.gates?.pytest ? "PASS" : "FAIL");
    byId("redteam-status").textContent = data.redteam_summary || (data.gates?.redteam ? "PASS" : "FAIL");
    byId("formal-status").textContent = data.gates?.tla_model_check ? "PASS" : "FAIL";
    byId("built-at").textContent = data.built_at || "unknown";
    byId("source-hashes").textContent = JSON.stringify(data.source_hashes || {}, null, 2);
  } catch (error) {
    const message = "verification metadata unavailable";
    byId("build-sha").textContent = message;
    byId("pytest-status").textContent = message;
    byId("redteam-status").textContent = message;
    byId("formal-status").textContent = message;
    byId("built-at").textContent = message;
    byId("source-hashes").textContent = error instanceof Error ? error.message : String(error);
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

    try {
      const result = await evaluateRequest(collectRequest());
      renderResult(result);
    } catch (error) {
      renderResult({
        status: "error",
        stage: "browser-runtime",
        decision: "ERROR",
        reasons: [error instanceof Error ? error.message : String(error)],
      });
    } finally {
      button.textContent = previousText;
      button.disabled = !runtimeReady;
    }
  });

  byId("reset-button").addEventListener("click", resetSession);
}

renderCapabilities("grants", "grant");
renderCapabilities("parent-grants", "parent");
renderPresets();
applyPreset(PRESETS[0]);
wireEvents();
loadVerification();
bootRuntime();
