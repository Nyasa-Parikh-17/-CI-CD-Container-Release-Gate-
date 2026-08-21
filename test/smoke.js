import worker from "../src/index.js";
import assert from "node:assert/strict";

const SHA = "b".repeat(40);

async function post(body) {
  const req = new Request("https://local/release-gate", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  const res = await worker.fetch(req);
  assert.equal(res.status, 200);
  return res.json();
}

const promoted = await post({
  target: "production",
  event: "push",
  ref: "refs/heads/main",
  workflow: {
    trigger: "push",
    permissions: { contents: "read", packages: "write", "id-token": "none" },
    testsPassed: true,
    matrixComplete: true,
    failFast: false,
    environmentApproval: true,
    actions: [
      { owner: "actions", name: "checkout", ref: "v4" },
      { owner: "docker", name: "login-action", ref: SHA },
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
assert.deepEqual(promoted, { decision: "promote", violations: [] });
console.log("  ok  safe production payload promotes over HTTP");

const blocked = await post({
  target: "preview",
  event: "pull_request",
  ref: "refs/heads/topic",
  workflow: {
    trigger: "pull_request_target",
    permissions: { contents: "write", packages: "write", "id-token": "none" },
    testsPassed: true,
    matrixComplete: false,
    failFast: false,
    actions: [{ owner: "third-party", name: "scan", ref: "v2" }],
  },
  image: {
    multiStage: true,
    runsAsRoot: true,
    secretMode: "arg",
    criticalVulnerabilities: 2,
    digestPinned: true,
  },
});
assert.equal(blocked.decision, "block");
assert.deepEqual(
  [...blocked.violations].sort(),
  [
    "CRITICAL_CVE",
    "EXCESS_PERMISSION",
    "MUTABLE_ACTION",
    "ROOT_RUNTIME",
    "SECRET_IN_LAYER",
    "TESTS_INCOMPLETE",
    "UNSAFE_PR_TRIGGER",
  ]
);
console.log("  ok  multi-failure payload blocks with exact codes");

const notFound = await worker.fetch(new Request("https://local/nope"));
assert.equal(notFound.status, 404);
console.log("  ok  unknown route returns 404");

console.log("\nsmoke tests passed");
