import { evaluate } from "../src/policy.js";
import assert from "node:assert/strict";

const SHA = "a".repeat(40);

const safePreview = () => ({
  target: "preview",
  event: "pull_request",
  ref: "refs/heads/feature/x",
  workflow: {
    trigger: "pull_request",
    permissions: { contents: "read", packages: "write", "id-token": "none" },
    testsPassed: true,
    matrixComplete: true,
    failFast: false,
    actions: [
      { owner: "actions", name: "checkout", ref: "v4" },
      { owner: "docker", name: "build-push-action", ref: SHA },
    ],
  },
  image: {
    multiStage: true,
    runsAsRoot: false,
    secretMode: "buildkit",
    criticalVulnerabilities: 0,
    digestPinned: true,
  },
});

const safeProduction = () => {
  const p = safePreview();
  p.target = "production";
  p.event = "push";
  p.ref = "refs/heads/main";
  p.workflow.trigger = "push";
  p.workflow.environmentApproval = true;
  return p;
};

const set = (arr) => [...arr].sort().join(",");

let passed = 0;
function check(name, payload, expectedDecision, expectedViolations) {
  const got = evaluate(payload);
  assert.equal(got.decision, expectedDecision, `${name}: decision`);
  assert.equal(
    set(got.violations),
    set(expectedViolations),
    `${name}: expected [${expectedViolations}] got [${got.violations}]`
  );
  passed++;
  console.log(`  ok  ${name}`);
}

// --- safe paths --------------------------------------------------------------
check("safe preview", safePreview(), "promote", []);
check("safe production", safeProduction(), "promote", []);
check("secretMode none is safe", mutate(safePreview(), (p) => {
  p.image.secretMode = "none";
}), "promote", []);

// --- single failures ---------------------------------------------------------
check("extra scope", mutate(safePreview(), (p) => {
  p.workflow.permissions.issues = "write";
}), "block", ["EXCESS_PERMISSION"]);

check("escalated contents", mutate(safePreview(), (p) => {
  p.workflow.permissions.contents = "write";
}), "block", ["EXCESS_PERMISSION"]);

check("missing scope", mutate(safePreview(), (p) => {
  delete p.workflow.permissions["id-token"];
}), "block", ["EXCESS_PERMISSION"]);

check("pull_request_target", mutate(safePreview(), (p) => {
  p.workflow.trigger = "pull_request_target";
}), "block", ["UNSAFE_PR_TRIGGER"]);

check("tests failed", mutate(safePreview(), (p) => {
  p.workflow.testsPassed = false;
}), "block", ["TESTS_INCOMPLETE"]);

check("matrix incomplete", mutate(safePreview(), (p) => {
  p.workflow.matrixComplete = false;
}), "block", ["TESTS_INCOMPLETE"]);

check("failFast true", mutate(safePreview(), (p) => {
  p.workflow.failFast = true;
}), "block", ["TESTS_INCOMPLETE"]);

check("third-party tag", mutate(safePreview(), (p) => {
  p.workflow.actions[1].ref = "v5";
}), "block", ["MUTABLE_ACTION"]);

check("uppercase sha rejected", mutate(safePreview(), (p) => {
  p.workflow.actions[1].ref = "A".repeat(40);
}), "block", ["MUTABLE_ACTION"]);

check("short sha rejected", mutate(safePreview(), (p) => {
  p.workflow.actions[1].ref = "a".repeat(39);
}), "block", ["MUTABLE_ACTION"]);

check("single stage", mutate(safePreview(), (p) => {
  p.image.multiStage = false;
}), "block", ["SINGLE_STAGE_IMAGE"]);

check("root runtime", mutate(safePreview(), (p) => {
  p.image.runsAsRoot = true;
}), "block", ["ROOT_RUNTIME"]);

check("arg secret", mutate(safePreview(), (p) => {
  p.image.secretMode = "arg";
}), "block", ["SECRET_IN_LAYER"]);

check("copy secret", mutate(safePreview(), (p) => {
  p.image.secretMode = "copy";
}), "block", ["SECRET_IN_LAYER"]);

check("critical cve", mutate(safePreview(), (p) => {
  p.image.criticalVulnerabilities = 3;
}), "block", ["CRITICAL_CVE"]);

check("unpinned image", mutate(safePreview(), (p) => {
  p.image.digestPinned = false;
}), "block", ["UNPINNED_IMAGE"]);

check("production off main", mutate(safeProduction(), (p) => {
  p.ref = "refs/heads/release";
}), "block", ["INVALID_PRODUCTION_REF"]);

check("production on tag", mutate(safeProduction(), (p) => {
  p.ref = "refs/tags/v1.0.0";
}), "block", ["INVALID_PRODUCTION_REF"]);

check("production missing approval", mutate(safeProduction(), (p) => {
  delete p.workflow.environmentApproval;
}), "block", ["APPROVAL_REQUIRED"]);

check("preview needs no approval", mutate(safePreview(), () => {}), "promote", []);

// --- combined failures -------------------------------------------------------
check("multi failure", mutate(safeProduction(), (p) => {
  p.event = "pull_request";
  p.ref = "refs/heads/feature";
  p.workflow.trigger = "pull_request_target";
  p.workflow.permissions["id-token"] = "write";
  p.workflow.failFast = true;
  p.workflow.actions[1].ref = "main";
  delete p.workflow.environmentApproval;
  p.image.multiStage = false;
  p.image.runsAsRoot = true;
  p.image.secretMode = "arg";
  p.image.criticalVulnerabilities = 1;
  p.image.digestPinned = false;
}), "block", [
  "EXCESS_PERMISSION",
  "UNSAFE_PR_TRIGGER",
  "TESTS_INCOMPLETE",
  "MUTABLE_ACTION",
  "SINGLE_STAGE_IMAGE",
  "ROOT_RUNTIME",
  "SECRET_IN_LAYER",
  "CRITICAL_CVE",
  "UNPINNED_IMAGE",
  "INVALID_PRODUCTION_REF",
  "APPROVAL_REQUIRED",
]);

check("no duplicate codes", mutate(safePreview(), (p) => {
  p.workflow.actions = [
    { owner: "docker", name: "a", ref: "v1" },
    { owner: "hashicorp", name: "b", ref: "latest" },
  ];
}), "block", ["MUTABLE_ACTION"]);

// --- determinism -------------------------------------------------------------
const a = evaluate(safeProduction());
const b = evaluate(safeProduction());
assert.deepEqual(a, b, "engine must be deterministic");
passed++;
console.log("  ok  deterministic across calls");

function mutate(obj, fn) {
  fn(obj);
  return obj;
}

console.log(`\n${passed} checks passed`);
