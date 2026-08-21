/**
 * Deterministic release-gate policy engine.
 * Pure function: same input -> same output, no I/O, no randomness.
 */

const REQUIRED_PERMISSIONS = {
  contents: "read",
  packages: "write",
  "id-token": "none",
};

const SHA40 = /^[0-9a-f]{40}$/;
const SAFE_SECRET_MODES = new Set(["none", "buildkit"]);

function evaluate(payload) {
  const violations = new Set();

  const body = isObject(payload) ? payload : {};
  const workflow = isObject(body.workflow) ? body.workflow : {};
  const image = isObject(body.image) ? body.image : {};

  const target = str(body.target);
  const event = str(body.event);
  const ref = str(body.ref);
  const trigger = str(workflow.trigger);

  // ---- 1. Permissions must be EXACTLY least privilege -----------------------
  const permissions = isObject(workflow.permissions) ? workflow.permissions : {};
  const keys = Object.keys(permissions);
  const required = Object.keys(REQUIRED_PERMISSIONS);

  const hasExtraScope = keys.some((k) => !(k in REQUIRED_PERMISSIONS));
  const missingScope = required.some((k) => !(k in permissions));
  const wrongValue = required.some(
    (k) => k in permissions && str(permissions[k]) !== REQUIRED_PERMISSIONS[k]
  );

  if (hasExtraScope || missingScope || wrongValue) {
    violations.add("EXCESS_PERMISSION");
  }

  // ---- 2. Pull-request trigger safety --------------------------------------
  if (trigger === "pull_request_target") {
    violations.add("UNSAFE_PR_TRIGGER");
  } else if (event === "pull_request" && trigger !== "pull_request") {
    violations.add("UNSAFE_PR_TRIGGER");
  }

  // ---- 3. Test completeness -------------------------------------------------
  if (
    workflow.testsPassed !== true ||
    workflow.matrixComplete !== true ||
    workflow.failFast !== false
  ) {
    violations.add("TESTS_INCOMPLETE");
  }

  // ---- 4. Action pinning ----------------------------------------------------
  const actions = Array.isArray(workflow.actions) ? workflow.actions : [];
  for (const action of actions) {
    const a = isObject(action) ? action : {};
    const owner = str(a.owner).toLowerCase();
    const actionRef = str(a.ref);

    // First-party `actions/*` may use a version tag; everyone else needs a SHA.
    if (owner === "actions") continue;
    if (!SHA40.test(actionRef)) {
      violations.add("MUTABLE_ACTION");
      break;
    }
  }

  // ---- 5. Image hardening ---------------------------------------------------
  if (image.multiStage !== true) violations.add("SINGLE_STAGE_IMAGE");
  if (image.runsAsRoot !== false) violations.add("ROOT_RUNTIME");
  if (!SAFE_SECRET_MODES.has(str(image.secretMode))) {
    violations.add("SECRET_IN_LAYER");
  }
  if (!(Number(image.criticalVulnerabilities) === 0)) {
    violations.add("CRITICAL_CVE");
  }
  if (image.digestPinned !== true) violations.add("UNPINNED_IMAGE");

  // ---- 6. Production-only requirements --------------------------------------
  if (target === "production") {
    if (event !== "push" || ref !== "refs/heads/main") {
      violations.add("INVALID_PRODUCTION_REF");
    }
    if (workflow.environmentApproval !== true) {
      violations.add("APPROVAL_REQUIRED");
    }
  }

  const list = [...violations];
  return {
    decision: list.length === 0 ? "promote" : "block",
    violations: list,
  };
}

function isObject(v) {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function str(v) {
  return typeof v === "string" ? v : "";
}

export { evaluate };
