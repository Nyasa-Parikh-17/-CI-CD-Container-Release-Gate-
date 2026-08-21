# TDS GA7 — CI/CD Container Release Gate

Deterministic policy endpoint: `POST /release-gate` → `{"decision":"promote|block","violations":[...]}`.

## Run

```bash
npm test          # policy unit tests (26 checks)
node test/smoke.js
npx wrangler dev  # local endpoint at http://127.0.0.1:8787/release-gate
npx wrangler deploy
```

## Rule → code mapping

| Condition | Code |
|---|---|
| `permissions` is not exactly `{contents:read, packages:write, id-token:none}` (extra scope, missing scope, or wrong value) | `EXCESS_PERMISSION` |
| `trigger` is `pull_request_target`, or `event=pull_request` with a non-`pull_request` trigger | `UNSAFE_PR_TRIGGER` |
| `testsPassed !== true` or `matrixComplete !== true` or `failFast !== false` | `TESTS_INCOMPLETE` |
| any action with `owner !== "actions"` whose `ref` is not `^[0-9a-f]{40}$` | `MUTABLE_ACTION` |
| `multiStage !== true` | `SINGLE_STAGE_IMAGE` |
| `runsAsRoot !== false` | `ROOT_RUNTIME` |
| `secretMode` not in `{none, buildkit}` | `SECRET_IN_LAYER` |
| `criticalVulnerabilities !== 0` | `CRITICAL_CVE` |
| `digestPinned !== true` | `UNPINNED_IMAGE` |
| production and not (`event=push` and `ref=refs/heads/main`) | `INVALID_PRODUCTION_REF` |
| production and `environmentApproval !== true` | `APPROVAL_REQUIRED` |

Codes are de-duplicated via a `Set`; `promote` only when the array is empty.

## Submission

```json
{"serviceUrl":"https://release-gate.<subdomain>.workers.dev","workflowUrl":"https://github.com/<OWNER>/<REPO>/actions/workflows/release-gate.yml"}
```

`serviceUrl` is the worker origin (the grader appends `/release-gate`). `workflowUrl` is the
workflow *page*, not a run URL.
