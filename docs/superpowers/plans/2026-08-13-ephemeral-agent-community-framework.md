# Ephemeral Agent Community Framework Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Publish a vendor-portable Ephemeral Agent Community Protocol and implementation, prove it with two isolated AWS Fargate agents completing the production Clockchain handshake, and ship reproducible adapters, conformance tests, evidence, documentation, and demonstration assets.

**Architecture:** Preserve the current Handshake mechanics proof long enough to produce one verified baseline, then create a standalone Apache-2.0 EACF repository whose core imports no cloud, harness, identity, or workflow provider. Portable JSON schemas and small JavaScript contracts govern lifecycle, capabilities, authority, state, evidence, budgets, and teardown; Codex, Claude Code, Hermes, Bedrock Converse, AWS Fargate, and Clockchain are replaceable adapters or profiles. Every implementation step is test-first, every live run is budget- and teardown-gated, and no evidence is retained until its offline verifier passes after cloud destruction.

**Tech Stack:** Node.js 24 ESM, JSON Schema 2020-12, ACP, MCP Streamable HTTP, A2A HTTP/SSE, CloudEvents 1.0, W3C Trace Context, OpenTelemetry, in-toto/SLSA provenance, OCI images, AWS ECS Fargate, IAM, SQS, CloudWatch, Secrets Manager, ECR, CloudFormation, Bedrock Converse, GitHub Actions.

**Repositories:**

- Baseline mechanics proof: `/private/tmp/clockchain-mechanics-proof`
- New standalone repository: `/private/tmp/ephemeral-agent-community`
- Production MCP worktree: `/private/tmp/clockchain-mcp-checkpoint-binding`
- Research-site presenter: `/Users/Kailor/.config/superpowers/worktrees/clockchain-research/hermes-turnkey-demo`

**Existing detailed plans incorporated by this master sequence:**

- `docs/superpowers/plans/2026-08-12-phase6c1-live-party-production-mcp.md`
- `docs/superpowers/plans/2026-08-12-phase6c2-live-fargate-isolation.md`
- `docs/superpowers/plans/2026-08-12-phase6c3-three-harness-live-matrix.md`
- `docs/superpowers/plans/2026-08-12-phase6c4-verified-monitor-and-presenter.md`
- `docs/superpowers/plans/2026-08-12-phase6c5-verified-product-demo-video.md`

---

## Program gates

1. The baseline Fargate run must pass before extraction changes the executable mechanics.
2. The standalone core must pass offline conformance before any provider profile is accepted.
3. Provider, harness, identity, and workflow packages may import core contracts; core packages may not import any profile package.
4. A live result is publishable only after offline verification succeeds against the retained bundle after teardown.
5. Production mutations require the already-approved account `570035913370`, region `us-west-2`, immutable image digest, maximum two tasks, TTL no greater than 3600 seconds, maximum budget USD 25, and exact teardown checks.
6. Temporary secrets are never printed, committed, copied into evidence, or retained after the run.
7. The demo page and video consume verified evidence but never control the protocol or prove success by themselves.

---

## Phase 1: Establish the current verified baseline

### Task 1: Freeze the post-adapter-boundary baseline

**Files:**
- Modify: `/private/tmp/clockchain-mechanics-proof/docs/evidence/ephemeral-agent-community/baseline-source.json`
- Test: `/private/tmp/clockchain-mechanics-proof/test/harness-agent-handshake-mcp-client.test.mjs`
- Test: `/private/tmp/clockchain-mechanics-proof/test/harness-direct-a2a-party-bridge.test.mjs`
- Test: `/private/tmp/clockchain-mechanics-proof/test/harness-acp-process-transport.test.mjs`
- Test: `/private/tmp/clockchain-mechanics-proof/test/mechanics-proof-party-runtime.test.mjs`

- [ ] **Step 1: Run the exact adapter-boundary regressions**

```bash
cd /private/tmp/clockchain-mechanics-proof
PATH=/opt/homebrew/opt/node@24/bin:$PATH node --test \
  test/harness-agent-handshake-mcp-client.test.mjs \
  test/harness-direct-a2a-party-bridge.test.mjs \
  test/harness-acp-process-transport.test.mjs \
  test/mechanics-proof-party-runtime.test.mjs
```

Expected: all tests pass; authorized identity, proposal, acceptance, and evidence signatures are submitted by the deterministic adapter rather than copied by the model.

- [ ] **Step 2: Run the complete baseline verification**

```bash
cd /private/tmp/clockchain-mechanics-proof
PATH=/opt/homebrew/opt/node@24/bin:$PATH npm run verify
```

Expected: all Node tests and repository invariants pass.

- [ ] **Step 3: Record only immutable public source facts**

Create `docs/evidence/ephemeral-agent-community/baseline-source.json` with this exact shape, filling values from local Git and the already-pushed ECR digest:

```json
{
  "schema": "clockchain.eacf-baseline-source/v1",
  "sourceCommit": "7c697314f0b1fb78956988e5a8ca02b5de4b8396",
  "designCommit": "c303802",
  "imageDigest": "sha256:66fec05bd3ede0640bb8df3a76466607fc6a27af08d537a11ebcccd6388b7c85",
  "accountId": "570035913370",
  "region": "us-west-2",
  "maxTasks": 2,
  "maxTtlSeconds": 3600,
  "maxBudgetUsd": 25,
  "liveResult": null
}
```

Do not add a secret ARN, queue URL, task ARN, raw log, token, prompt, signature, or private path.

- [ ] **Step 4: Validate and commit the baseline record**

```bash
cd /private/tmp/clockchain-mechanics-proof
node -e 'const v=require("./docs/evidence/ephemeral-agent-community/baseline-source.json"); if(v.liveResult!==null||v.maxTasks!==2||v.maxBudgetUsd!==25) process.exit(1)'
git diff --check
git add docs/evidence/ephemeral-agent-community/baseline-source.json
git commit -m "Bind the portable extraction to a verified source baseline" \
  -m "Constraint: Extraction cannot move the live proof target while the baseline run is pending.
Rejected: Treat prior partial canaries as the baseline | none reached a verified two-party certificate and teardown bundle.
Confidence: high
Scope-risk: narrow
Directive: Populate liveResult only from the offline-verified post-teardown bundle.
Tested: Full repository verification and exact public baseline record validation.
Not-tested: Live AWS behavior remains the next gate."
```

### Task 2: Run the isolated production Clockchain proof

**Files:**
- Read: `/private/tmp/clockchain-mechanics-proof/docs/mechanics-proof-fargate-runbook.md`
- Execute: `/private/tmp/clockchain-mechanics-proof/scripts/run-mechanics-proof-fargate.mjs`
- Modify: `/private/tmp/clockchain-mechanics-proof/docs/evidence/ephemeral-agent-community/baseline-source.json`
- Create: `/private/tmp/clockchain-mechanics-proof/docs/evidence/ephemeral-agent-community/runs/<run-id>/`

- [ ] **Step 1: Run read-only preflight and enumerate exact inputs**

```bash
cd /private/tmp/clockchain-mechanics-proof
PATH=/opt/homebrew/opt/node@24/bin:$PATH npm run mechanics-proof:fargate -- --dry-run
PATH=/opt/homebrew/opt/node@24/bin:$PATH node --test \
  test/mechanics-proof-fargate-runner.test.mjs \
  test/aws-fargate-runtime-adapter.test.mjs
```

Expected: account, region, immutable image, VPC/subnets, secret reference, task count, TTL, budget, MCP health/tool surface, and teardown targets are explicit; no AWS resource is created.

- [ ] **Step 2: Verify the temporary Codex secret without printing it**

Resolve the secret ARN only from the operator-owned 0600 reference file. Use `aws secretsmanager describe-secret`, never `get-secret-value`, to prove the secret exists in the approved account/region and is tagged for the approved proof. Abort if the file is absent, permissions are wider than 0600, the secret is pending deletion, or its tags do not bind the run.

```bash
stat -f '%Lp' /private/tmp/clockchain-proof-secret-arn-ttl5m.txt
aws sts get-caller-identity --output json
aws configure get region
```

Expected: mode `600`, account `570035913370`, and region `us-west-2`. Command output retained for the user must not contain the ARN.

- [ ] **Step 3: Launch one exact bounded run**

Invoke the runner with `--run`, exact account/region, image digest, networking inputs, secret reference file, TTL at most 3600, concurrency 2, and budget 25. Do not reconstruct flags from memory; use only the dry-run plan's accepted argument names.

Expected live progression:

```text
stack-created
tasks-registered
two-tasks-running
two-distinct-workload-identities
peer-descriptors-exchanged
identity-claims-submitted
erc8004-identities-ready
mandate-and-request-accepted
proposal-acceptance-acknowledgment-recorded
two-party-evidence-submitted
certificate-verified-by-both-parties
tasks-stopped
task-definitions-deregistered
queues-and-stack-deleted
temporary-secret-permanently-deleted
offline-bundle-verified
```

- [ ] **Step 4: Classify any failure before changing code**

The runner must return one typed public stage. Do not patch prompts on a generic failure. Map failure into exactly one category: `preflight`, `provision`, `attestation`, `bootstrap`, `harness-start`, `workflow-state`, `local-authorization`, `deterministic-submit`, `a2a`, `mcp`, `certificate`, `evidence`, `budget`, or `teardown`. Retain digest/length/counter facts only; never retain raw credentials or payloads.

- [ ] **Step 5: Verify teardown independently**

Use exact run/stack identifiers from the runner's safe result to query CloudFormation, ECS tasks/task definitions, SQS queues, IAM roles, CloudWatch log groups, ENIs/security groups, and Secrets Manager. Every in-scope temporary resource must be absent. If any absence check fails, outcome is cleanup `UNCONFIRMED` and the run is not publishable.

- [ ] **Step 6: Revalidate retained evidence and commit the clean result**

The live adapter calls `buildFargatePublicProofEvidence` only after `collectFargateCleanupProofInputs` proves exact resource absence, and `retainFargateSuccessEvidence` writes only the controller evidence and public proof after that finalizer succeeds. Re-parse those retained files through the same exported strict builders and validators in a new `test/eacf-baseline-evidence.test.mjs`; reject any mutation, extra key, cross-run value, missing cleanup response, failed certificate binding, or unsafe field. Then update `baseline-source.json.liveResult` with only `{runId, bundleDigest, certificateDigest, verifiedAt}` and commit the safe bundle.

```bash
cd /private/tmp/clockchain-mechanics-proof
PATH=/opt/homebrew/opt/node@24/bin:$PATH node --test \
  test/eacf-baseline-evidence.test.mjs \
  test/mechanics-proof-cloud-evidence.test.mjs \
  test/aws-fargate-live-adapter.test.mjs \
  test/mechanics-proof-fargate-runner.test.mjs
git diff --check
git add docs/evidence/ephemeral-agent-community
git commit -m "Prove the two-party handshake survives isolated teardown" \
  -m "Constraint: A live success is publishable only after certificate, evidence, and resource absence checks pass.
Rejected: Retain the interrupted run as proof | it produced no terminal evidence bundle.
Confidence: high
Scope-risk: moderate
Directive: Never weaken teardown or offline verification to rescue a live run.
Tested: Production handshake, distinct workload identities, certificate verification, offline evidence verification, and exact AWS absence checks.
Not-tested: Cross-harness matrix runs remain later gates."
```

---

## Phase 2: Create the standalone normative repository

### Task 3: Scaffold only repository governance and package boundaries

**Files:**
- Create: `/private/tmp/ephemeral-agent-community/package.json`
- Create: `/private/tmp/ephemeral-agent-community/LICENSE`
- Create: `/private/tmp/ephemeral-agent-community/README.md`
- Create: `/private/tmp/ephemeral-agent-community/SPEC.md`
- Create: `/private/tmp/ephemeral-agent-community/SECURITY.md`
- Create: `/private/tmp/ephemeral-agent-community/GOVERNANCE.md`
- Create: `/private/tmp/ephemeral-agent-community/CONTRIBUTING.md`
- Create: `/private/tmp/ephemeral-agent-community/.gitignore`
- Create: `/private/tmp/ephemeral-agent-community/test/repository-boundaries.test.mjs`

- [ ] **Step 1: Create an empty Git repository and RED boundary test**

```javascript
import assert from "node:assert/strict";
import { readdir, readFile } from "node:fs/promises";
import test from "node:test";

test("normative packages never import profiles or adapters", async () => {
  const roots = ["packages/core", "packages/runtime-contract", "packages/harness-contract", "packages/workflow-contract"];
  for (const root of roots) {
    for (const name of await readdir(root, { recursive: true })) {
      if (!name.endsWith(".mjs")) continue;
      const source = await readFile(`${root}/${name}`, "utf8");
      assert.doesNotMatch(source, /(?:from|import\()\s*["'][^"']*(?:adapters|profiles)\//);
      assert.doesNotMatch(source, /@aws-sdk|clockchain|erc-8004|agent_handshake_/i);
    }
  }
});
```

- [ ] **Step 2: Run RED**

```bash
cd /private/tmp/ephemeral-agent-community
node --test test/repository-boundaries.test.mjs
```

Expected: FAIL because the package directories do not exist.

- [ ] **Step 3: Create the exact package tree and governance documents**

Create empty source directories for `packages/core`, `runtime-contract`, `harness-contract`, `workflow-contract`, `conformance`, and `evidence-verifier`; adapter directories for `codex-acp`, `claude-code-acp`, `hermes`, and `bedrock-converse`; profile directories for `aws-fargate` and `clockchain-handshake`. Root `package.json` uses private npm workspaces, Node `>=24`, `type:module`, and scripts `test`, `verify`, `schemas:check`, `conformance`, and `evidence:verify`. Copy the approved design's normative sections into `SPEC.md`; link rather than duplicate detail in `README.md`.

- [ ] **Step 4: Run GREEN and commit**

```bash
cd /private/tmp/ephemeral-agent-community
node --test test/repository-boundaries.test.mjs
git diff --check
git add .
git commit -m "Establish a provider-neutral protocol repository" \
  -m "Constraint: Core packages must remain independent of every cloud, harness, identity, and workflow profile.
Rejected: Convert the Handshake repository in place | its public contracts already encode Clockchain-specific assumptions.
Confidence: high
Scope-risk: moderate
Directive: Dependency direction is contracts outward to profiles, never profiles inward to core.
Tested: Repository-boundary import and vocabulary test.
Not-tested: Protocol behavior is added in subsequent tasks."
```

### Task 4: Define normative JSON schemas

**Files:**
- Create: `/private/tmp/ephemeral-agent-community/schemas/run-manifest/v0.1.0.schema.json`
- Create: `/private/tmp/ephemeral-agent-community/schemas/lifecycle-event/v0.1.0.schema.json`
- Create: `/private/tmp/ephemeral-agent-community/schemas/capability/v0.1.0.schema.json`
- Create: `/private/tmp/ephemeral-agent-community/schemas/admission/v0.1.0.schema.json`
- Create: `/private/tmp/ephemeral-agent-community/schemas/authorized-action/v0.1.0.schema.json`
- Create: `/private/tmp/ephemeral-agent-community/schemas/evidence-bundle/v0.1.0.schema.json`
- Create: `/private/tmp/ephemeral-agent-community/schemas/teardown/v0.1.0.schema.json`
- Create: `/private/tmp/ephemeral-agent-community/test/schema-conformance.test.mjs`

- [ ] **Step 1: Write RED tests for exact valid and invalid fixtures**

The test must assert stable `$id`, `additionalProperties:false` on security-sensitive objects, opaque profile-owned role/action identifiers, secret-free manifest values, unique parties, immutable profile digests, exact lifecycle/outcome/cleanup enums, previous-event digests, three identity bindings, state digests, idempotency keys, cost limits, evidence references, and teardown inventory.

```javascript
test("a manifest cannot contain secret material", () => {
  const value = structuredClone(validManifest);
  value.parties[0].runtime.extensions = { apiKey: "secret" };
  assert.equal(validate("run-manifest", value).valid, false);
});

test("roles are profile-owned rather than fixed to two parties", () => {
  const value = structuredClone(validManifest);
  value.parties.push({ ...validManifest.parties[0], partyId: "auditor", role: "observer" });
  assert.equal(validate("run-manifest", value).valid, true);
});
```

- [ ] **Step 2: Run RED**

```bash
npm test -- test/schema-conformance.test.mjs
```

Expected: missing schemas or validator failures.

- [ ] **Step 3: Implement schemas with local deterministic validation**

Use JSON Schema 2020-12. Add one exact-pinned validator dependency only after license and vulnerability checks. Extension objects accept keys only when the manifest declares the extension profile identifier, version, and schema digest; the core validator otherwise rejects them.

- [ ] **Step 4: Run GREEN, audit, and commit**

```bash
npm test -- test/schema-conformance.test.mjs
npm audit --omit=dev
npm run schemas:check
git diff --check
git add schemas package.json package-lock.json test/schema-conformance.test.mjs
git commit -m "Make ephemeral agent runs independently describable" \
  -m "Constraint: Normative objects must be exact while profile extensions remain explicitly negotiated.
Rejected: Reuse clockchain.* schemas | their roles and evidence fields are workflow-specific.
Confidence: high
Scope-risk: broad
Directive: Unknown security-sensitive fields remain fail-closed.
Tested: Valid, malformed, replay-shaped, secret-bearing, multiparty, and extension-profile schema fixtures.
Not-tested: Provider implementations are not yet connected."
```

### Task 5: Implement the lifecycle and failure-state model

**Files:**
- Create: `/private/tmp/ephemeral-agent-community/packages/core/src/lifecycle.mjs`
- Create: `/private/tmp/ephemeral-agent-community/packages/core/src/errors.mjs`
- Create: `/private/tmp/ephemeral-agent-community/packages/core/src/digest-chain.mjs`
- Create: `/private/tmp/ephemeral-agent-community/packages/core/test/lifecycle.test.mjs`

- [ ] **Step 1: Write RED table tests**

Prove `PLANNED -> PROVISIONING -> ATTESTING -> ADMITTING -> EXECUTING -> COLLECTING_EVIDENCE -> VERIFYING -> DESTROYING -> TERMINAL`. From every nonterminal phase, failure may enter `DESTROYING`; no failure skips it. Prove workflow and cleanup outcomes are orthogonal and overall success requires `SUCCEEDED + evidenceVerified + VERIFIED`.

- [ ] **Step 2: Run RED**

```bash
npm test -- packages/core/test/lifecycle.test.mjs
```

- [ ] **Step 3: Implement pure transition functions**

Export `createRunState`, `advanceRun`, `failRun`, `beginDestroy`, `finishRun`, and `publicRunStatus`. Every operation returns a new frozen object, increments sequence, binds the previous digest, and emits the lifecycle-event schema. Invalid transitions throw a generic `EacfProtocolError` with a stable public reason code.

- [ ] **Step 4: Run GREEN and commit**

```bash
npm test -- packages/core/test/lifecycle.test.mjs
git add packages/core
git commit -m "Require every agent community to end through teardown" \
  -m "Constraint: Business outcome and cleanup outcome answer different operational questions.
Rejected: A single success/failure enum | it hides clean failures and leaked successful runs.
Confidence: high
Scope-risk: moderate
Directive: No new failure path may bypass DESTROYING.
Tested: Complete transition matrix, digest chain, invalid transitions, and all terminal combinations.
Not-tested: Cloud cleanup is implemented by provider profiles."
```

### Task 6: Implement capability negotiation and admission

**Files:**
- Create: `/private/tmp/ephemeral-agent-community/packages/core/src/capability.mjs`
- Create: `/private/tmp/ephemeral-agent-community/packages/core/src/admission.mjs`
- Create: `/private/tmp/ephemeral-agent-community/packages/core/test/admission.test.mjs`

- [ ] **Step 1: Write RED tests**

Require exact runtime, harness, workflow, identity, communication, evidence, cancellation, and teardown capabilities. Bind workload, party, and harness identities to one run/party/role. Reject missing requirements, silent fallback, reused identities, shared writable-state identifiers, shared signer identifiers, stale descriptors, digest mismatch, and undeclared extension profiles.

- [ ] **Step 2: Run RED**

```bash
npm test -- packages/core/test/admission.test.mjs
```

- [ ] **Step 3: Implement deterministic negotiation**

Export `satisfiesCapabilities(requirements, offered)` and `admitParty({manifest, party, runtime, harness, workflow, identities})`. Return a signed-or-attested admission payload only; signing is supplied by a profile callback. Never choose a lower capability automatically.

- [ ] **Step 4: Run GREEN and commit**

```bash
npm test -- packages/core/test/admission.test.mjs
git add packages/core
git commit -m "Fail admission before agents silently lose safeguards" \
  -m "Constraint: Portability cannot mean best-effort degradation.
Rejected: Adapter-specific fallback logic | it creates unprovable differences between harnesses.
Confidence: high
Scope-risk: moderate
Directive: Capability mismatches remain explicit pre-execution failures.
Tested: Three-identity binding, multiparty admission, downgrade, reuse, freshness, and extension-profile negatives.
Not-tested: Workload attestations are provider-profile responsibilities."
```

---

## Phase 3: Portable execution contracts

### Task 7: Implement the runtime adapter contract

**Files:**
- Create: `/private/tmp/ephemeral-agent-community/packages/runtime-contract/src/index.mjs`
- Create: `/private/tmp/ephemeral-agent-community/packages/runtime-contract/test/contract.test.mjs`

- [ ] Write RED contract-fixture tests requiring `plan`, `provision`, `attest`, `start`, `observe`, `cancel`, `collectEvidence`, `destroy`, and `verifyDestroyed`; prove idempotent cancellation/destruction and generic failures.
- [ ] Run `npm test -- packages/runtime-contract/test/contract.test.mjs`; expect missing exports.
- [ ] Implement `defineRuntimeAdapter` as a validating wrapper around injected functions, AbortSignals, monotonic deadlines, and normalized evidence. Provider extensions remain under a declared extension profile.
- [ ] Run focused tests and commit with Lore intent `Make runtime isolation replaceable without weakening proof`.

### Task 8: Implement the harness adapter contract

**Files:**
- Create: `/private/tmp/ephemeral-agent-community/packages/harness-contract/src/index.mjs`
- Create: `/private/tmp/ephemeral-agent-community/packages/harness-contract/src/events.mjs`
- Create: `/private/tmp/ephemeral-agent-community/packages/harness-contract/test/contract.test.mjs`

- [ ] Write RED fixtures requiring `inspect`, `createFreshSession`, `configureWorkflowClient`, `promptForDecision`, `requestAuthorization`, `executeAuthorizedAction`, `cancel`, `collectEvidence`, and `destroy`; assert context freshness, event order, permission correlation, and no transcript-as-success. In deterministic workflow mode, assert the model receives an empty workflow-tool surface and never receives MCP credentials, role capabilities, invitation tokens, helper commands, signing payloads, or signatures.
- [ ] Run focused RED.
- [ ] Implement `defineHarnessAdapter`, CloudEvents-compatible normalization, and strict terminal result validation. The adapter owns workflow bootstrap, state reads, bounded waits/retries, idempotent submission, and certificate retrieval through an injected typed client. An authorized action contains mandate, local-policy, workflow-state, and request-byte digests; the model returns only an exact authorization or denial and never sees signer output.
- [ ] Run GREEN and commit with Lore intent `Put deterministic action execution behind every harness`.

### Task 9: Implement workflow-state and authority contracts

**Files:**
- Create: `/private/tmp/ephemeral-agent-community/packages/workflow-contract/src/state-client.mjs`
- Create: `/private/tmp/ephemeral-agent-community/packages/workflow-contract/src/authorized-action.mjs`
- Create: `/private/tmp/ephemeral-agent-community/packages/workflow-contract/src/party-signer.mjs`
- Create: `/private/tmp/ephemeral-agent-community/packages/workflow-contract/test/state-client.test.mjs`
- Create: `/private/tmp/ephemeral-agent-community/packages/workflow-contract/test/authority.test.mjs`

- [ ] Write RED tests for bootstrap/admission, read-state, allowed-action selection, policy denial, mandate/local-policy/state/request-digest binding, local authorization, exclusive party signing, deterministic submission, idempotency, stale/replay rejection, direct model tool-call rejection, and controller/coordinator impersonation negatives.
- [ ] Run focused RED.
- [ ] Implement the six-step state loop from the design. The state client accepts injected bootstrap/read/submit/certificate functions; the signer accepts injected `signExactBytes`; the adapter submits the returned artifact directly. The model-facing decision port is separate from the transport port and cannot receive private capabilities or execute workflow calls.
- [ ] Run GREEN and commit with Lore intent `Keep decisions probabilistic and protocol actions deterministic`.

### Task 10: Implement portable bootstrap, A2A, and MCP bindings

**Files:**
- Create: `/private/tmp/ephemeral-agent-community/packages/core/src/bootstrap.mjs`
- Create: `/private/tmp/ephemeral-agent-community/packages/core/src/a2a-binding.mjs`
- Create: `/private/tmp/ephemeral-agent-community/packages/core/src/mcp-binding.mjs`
- Create: `/private/tmp/ephemeral-agent-community/packages/core/test/communication.test.mjs`

- [ ] Write RED tests proving bootstrap carries public descriptors only; A2A messages are peer/run/state bound and signed; MCP credentials are distinct and resource-bound; private negotiation does not transit the controller; public commitments can be profile-required.
- [ ] Run focused RED.
- [ ] Extract the current digest, canonicalization, signed-envelope, deadline, and peer-binding algorithms while replacing fixed role/artifact enums with profile definitions. Use MCP SDK clients behind injected credentials; do not invent public per-tool REST routes.
- [ ] Run GREEN and commit with Lore intent `Let parties communicate directly without losing public accountability`.

### Task 11: Implement evidence, observability, budget, and teardown contracts

**Files:**
- Create: `/private/tmp/ephemeral-agent-community/packages/core/src/public-events.mjs`
- Create: `/private/tmp/ephemeral-agent-community/packages/core/src/budget.mjs`
- Create: `/private/tmp/ephemeral-agent-community/packages/core/src/teardown.mjs`
- Create: `/private/tmp/ephemeral-agent-community/packages/evidence-verifier/src/index.mjs`
- Create: `/private/tmp/ephemeral-agent-community/packages/evidence-verifier/test/verifier.test.mjs`

- [ ] Write RED tests for CloudEvents fields, trace context, secret-free event payloads, warning/hard budget thresholds, teardown ordering, evidence-before-source-deletion, exact absence inventory, tamper detection, mixed-run rejection, missing provenance, cleanup unconfirmed, and transcript-only claims.
- [ ] Run focused RED.
- [ ] Implement append-only digest events, budget guard, ordered teardown executor, evidence manifest builder, canary secret scanner, and offline verifier. The verifier must operate with network disabled.
- [ ] Run GREEN and commit with Lore intent `Make evidence and destruction independently verifiable`.

---

## Phase 4: Harness adapters and local conformance

### Task 12: Port the Codex and Claude Code ACP adapters

**Files:**
- Create: `/private/tmp/ephemeral-agent-community/adapters/codex-acp/src/index.mjs`
- Create: `/private/tmp/ephemeral-agent-community/adapters/claude-code-acp/src/index.mjs`
- Create: `/private/tmp/ephemeral-agent-community/adapters/acp-common/src/process-transport.mjs`
- Create: `/private/tmp/ephemeral-agent-community/adapters/acp-common/test/process-transport.test.mjs`
- Create: `/private/tmp/ephemeral-agent-community/adapters/codex-acp/test/conformance.test.mjs`
- Create: `/private/tmp/ephemeral-agent-community/adapters/claude-code-acp/test/conformance.test.mjs`

- [ ] Copy only the pinned ACP process-control and normalized-event logic from the current repository; first write black-box fixtures for concurrent session-update/permission delivery, MCP result association, exact action digest, cancellation, usage, and no natural-language success.
- [ ] Run RED against empty adapters.
- [ ] Generalize Clockchain operation names into workflow-provided authorized-action descriptors; preserve the bounded late-registration waiter that handles ACP callback concurrency.
- [ ] Run both adapters through the shared harness conformance suite and commit with Lore intent `Control Codex and Claude through one deterministic authority boundary`.

### Task 13: Port the Hermes adapter

**Files:**
- Create: `/private/tmp/ephemeral-agent-community/adapters/hermes/src/index.mjs`
- Create: `/private/tmp/ephemeral-agent-community/adapters/hermes/src/clean-room.mjs`
- Create: `/private/tmp/ephemeral-agent-community/adapters/hermes/test/conformance.test.mjs`

- [ ] Write RED tests for isolated `HOME`/`HERMES_HOME`, empty sessions/memory/contacts/skills, no global auth fallback, exact MCP allowlist, explicit model/provider, normalized events, cancellation, evidence redaction, and disposable cleanup.
- [ ] Run RED.
- [ ] Port the audited clean-room and native transport behavior behind `defineHarnessAdapter`; replace Clockchain tool constants with manifest requirements.
- [ ] Run shared harness conformance and commit with Lore intent `Prove harness portability without requiring ACP`.

### Task 14: Implement the minimal Bedrock Converse adapter

**Files:**
- Create: `/private/tmp/ephemeral-agent-community/adapters/bedrock-converse/src/index.mjs`
- Create: `/private/tmp/ephemeral-agent-community/adapters/bedrock-converse/src/tool-loop.mjs`
- Create: `/private/tmp/ephemeral-agent-community/adapters/bedrock-converse/test/conformance.test.mjs`

- [ ] Write RED fixtures for a bounded Converse request/tool-use/result loop, task-role credentials, declared model ID, exact MCP tool set, local policy decision, adapter-side signed-action submission, max turns, deadline, cancellation, token usage, and malformed tool requests.
- [ ] Run RED without AWS by injecting a fake Converse client.
- [ ] Implement the minimal loop using exact-pinned AWS SDK v3 packages; no memory service, shared database, browser, or human approval path.
- [ ] Run shared harness conformance, `npm audit --omit=dev`, and commit with Lore intent `Offer an AWS-native agent without changing the protocol`.

### Task 15: Build the reusable conformance runner

**Files:**
- Create: `/private/tmp/ephemeral-agent-community/packages/conformance/src/index.mjs`
- Create: `/private/tmp/ephemeral-agent-community/packages/conformance/src/runtime-suite.mjs`
- Create: `/private/tmp/ephemeral-agent-community/packages/conformance/src/harness-suite.mjs`
- Create: `/private/tmp/ephemeral-agent-community/packages/conformance/src/workflow-suite.mjs`
- Create: `/private/tmp/ephemeral-agent-community/packages/conformance/src/live-suite.mjs`
- Create: `/private/tmp/ephemeral-agent-community/packages/conformance/test/conformance.test.mjs`

- [ ] Write RED meta-tests proving a deliberately broken adapter fails each required capability and a fixture adapter passes Core conformance.
- [ ] Run RED.
- [ ] Implement programmatic and CLI suites with `Core`, `Isolated`, and `Verifiable` levels. Emit JUnit plus exact EACF JSON results; never emit injected credentials or payload bodies.
- [ ] Run every local adapter through Core conformance and commit with Lore intent `Turn best practices into executable compatibility tests`.

---

## Phase 5: Reference profiles

### Task 16: Extract the AWS Fargate runtime profile

**Files:**
- Create: `/private/tmp/ephemeral-agent-community/profiles/aws-fargate/infra/runtime.yaml`
- Create: `/private/tmp/ephemeral-agent-community/profiles/aws-fargate/src/runtime-adapter.mjs`
- Create: `/private/tmp/ephemeral-agent-community/profiles/aws-fargate/src/task-attestation.mjs`
- Create: `/private/tmp/ephemeral-agent-community/profiles/aws-fargate/src/sqs-bootstrap.mjs`
- Create: `/private/tmp/ephemeral-agent-community/profiles/aws-fargate/src/evidence.mjs`
- Create: `/private/tmp/ephemeral-agent-community/profiles/aws-fargate/test/profile.test.mjs`

- [ ] Write RED tests using the current Fargate fixtures: two distinct task/execution roles, separate subnets/security groups/logs/writable state, disabled public IP, no EFS/shared secret/signer, task metadata plus STS attestation, exact SQS role policy, immutable image, budget/TTL gate, and complete resource absence envelope.
- [ ] Run RED.
- [ ] Port the current live plan, control-plane normalizers, task bootstrap, SQS exchange, evidence, and teardown into the runtime contract. AWS-only fields live under `eacf.aws-fargate/v0.1.0` extensions.
- [ ] Run runtime `Isolated` conformance, CloudFormation local lint/validation, and commit with Lore intent `Make Fargate the first replaceable isolation profile`.

### Task 17: Extract the Clockchain workflow profile

**Files:**
- Create: `/private/tmp/ephemeral-agent-community/profiles/clockchain-handshake/src/profile.mjs`
- Create: `/private/tmp/ephemeral-agent-community/profiles/clockchain-handshake/src/mcp-client.mjs`
- Create: `/private/tmp/ephemeral-agent-community/profiles/clockchain-handshake/src/erc8004-identity.mjs`
- Create: `/private/tmp/ephemeral-agent-community/profiles/clockchain-handshake/src/verifier.mjs`
- Create: `/private/tmp/ephemeral-agent-community/profiles/clockchain-handshake/test/profile.test.mjs`

- [ ] Write RED tests for Payer/Requestor roles, mandate-controlled optional ERC-8004 requirement, direct invitation/negotiation, MCP state/action mapping, proposal/acceptance/acknowledgment, two party evidence packages, certificate verification, no-money-moved, and host non-authority.
- [ ] Run RED.
- [ ] Port only workflow-specific code and bind it to the generic workflow-state client. The profile supplies allowed actions and artifact schemas; the adapter supplies execution; the host remains coordinator/checker.
- [ ] Run workflow conformance and commit with Lore intent `Prove Clockchain as a profile rather than a framework dependency`.

### Task 18: Build the two-party reference example

**Files:**
- Create: `/private/tmp/ephemeral-agent-community/examples/two-party-clockchain-handshake/run-manifest.json`
- Create: `/private/tmp/ephemeral-agent-community/examples/two-party-clockchain-handshake/policies/payer.json`
- Create: `/private/tmp/ephemeral-agent-community/examples/two-party-clockchain-handshake/policies/requestor.json`
- Create: `/private/tmp/ephemeral-agent-community/examples/two-party-clockchain-handshake/run-local.mjs`
- Create: `/private/tmp/ephemeral-agent-community/examples/two-party-clockchain-handshake/run-aws.mjs`
- Create: `/private/tmp/ephemeral-agent-community/examples/two-party-clockchain-handshake/README.md`
- Create: `/private/tmp/ephemeral-agent-community/examples/two-party-clockchain-handshake/test/example.test.mjs`

- [ ] Write RED tests proving prompts contain only business scenario, invitation/mandate, MCP endpoint, role, and checked-in local policy—not clone commands, opaque payloads, signatures, or procedural MCP loops.
- [ ] Run RED.
- [ ] Compose profiles and adapters through the manifest. Provide local fixture mode and live AWS mode with identical workflow inputs and evidence contract.
- [ ] Run local two-container proof and commit with Lore intent `Make the reference handshake runnable without hidden choreography`.

---

## Phase 6: Live matrix, hardening, and publication

### Task 19: Reproduce the live AWS proof from EACF

**Files:**
- Modify: `/private/tmp/ephemeral-agent-community/evidence/verified-runs/index.json`
- Create: `/private/tmp/ephemeral-agent-community/evidence/verified-runs/<run-id>/`

- [ ] Run exact read-only preflight and compare the generated Fargate plan with the current baseline invariants.
- [ ] Run one Codex/Claude production Clockchain proof under the same account, region, TTL, concurrency, and USD 25 gate.
- [ ] Verify certificate, evidence, and teardown offline.
- [ ] Compare normalized EACF claims with baseline claims; provider-specific identifiers may differ but authority, identity, workflow, and cleanup claims must match.
- [ ] Commit only the redacted verified bundle with Lore intent `Reproduce the Clockchain proof through the portable framework`.

### Task 20: Execute the four-harness live conformance matrix

**Files:**
- Create: `/private/tmp/ephemeral-agent-community/evidence/verified-runs/matrix.json`
- Create: `/private/tmp/ephemeral-agent-community/evidence/verified-runs/<matrix-run-id>/`

- [ ] Define a minimal matrix that covers every adapter at least once as a party and includes both ACP and non-ACP control: `codex:claude-code`, `claude-code:hermes`, `hermes:codex`, and `bedrock-converse:codex`.
- [ ] Give every row new runtimes, workload identities, signers, MCP credentials, run identifiers, optional ERC-8004 identities when mandated, and evidence bundles. Never reuse a certificate.
- [ ] Run rows sequentially under an aggregate declared budget; verify and tear down each row before starting the next.
- [ ] Run the conformance aggregator; a single failed/unverified row makes the matrix fail.
- [ ] Commit the redacted matrix proof with Lore intent `Demonstrate one protocol across four agent harnesses`.

### Task 21: Run security, privacy, supply-chain, cost, and teardown review

**Files:**
- Create: `/private/tmp/ephemeral-agent-community/docs/threat-model.md`
- Create: `/private/tmp/ephemeral-agent-community/docs/cost-and-teardown.md`
- Create: `/private/tmp/ephemeral-agent-community/docs/security-review.md`
- Create: `/private/tmp/ephemeral-agent-community/test/release-invariants.test.mjs`

- [ ] Add adversarial tests for controller impersonation, adapter overreach, peer prompt injection, cross-run replay, stale state, credential terminal leakage, evidence canaries, image substitution, profile digest mismatch, budget exhaustion, cancellation races, and partial teardown.
- [ ] Run full tests, dependency audit, secret scan, license scan, image scan, and offline verifier with network disabled.
- [ ] Generate SLSA-compatible source/image provenance and in-toto run attestations; verify signatures and subject digests.
- [ ] Confirm no temporary proof secrets or run-tagged AWS resources remain.
- [ ] Commit findings and fixes with Lore intent `Publish only evidence that survives adversarial review`.

### Task 22: Write operator and extension documentation

**Files:**
- Create: `/private/tmp/ephemeral-agent-community/docs/architecture.md`
- Create: `/private/tmp/ephemeral-agent-community/docs/authority-model.md`
- Create: `/private/tmp/ephemeral-agent-community/docs/operator-runbook.md`
- Create: `/private/tmp/ephemeral-agent-community/docs/adapter-authoring.md`
- Create: `/private/tmp/ephemeral-agent-community/docs/workflow-profile-authoring.md`
- Create: `/private/tmp/ephemeral-agent-community/docs/portability-guide.md`
- Create: `/private/tmp/ephemeral-agent-community/docs/aws-reference.md`
- Create: `/private/tmp/ephemeral-agent-community/test/documentation.test.mjs`

- [ ] Write RED link, command, schema-reference, and forbidden-secret tests for every documented path.
- [ ] Write one quickstart that reaches local conformance without AWS and one AWS runbook with explicit account, budget, region, credentials, image, network, and teardown prerequisites.
- [ ] Document how to author a runtime adapter, harness adapter, workflow profile, and identity profile without importing Clockchain or AWS.
- [ ] Run every non-live command from a clean checkout and commit with Lore intent `Make the protocol reproducible without project lore`.

### Task 23: Update the verified presenter and create the demo video

**Files:**
- Execute detailed plan: `/private/tmp/clockchain-mechanics-proof/docs/superpowers/plans/2026-08-12-phase6c4-verified-monitor-and-presenter.md`
- Execute detailed plan: `/private/tmp/clockchain-mechanics-proof/docs/superpowers/plans/2026-08-12-phase6c5-verified-product-demo-video.md`

- [ ] Publish a strict redacted mechanics-proof document joined to the live monitor only by exact session and certificate digest.
- [ ] Preserve the existing `/handshake/claude-v6` layout while showing two independent agents, full ERC-8004 identity detail when applicable, direct A2A, receipts, certificate, runtime isolation, and teardown proof.
- [ ] Ensure the page is read-only and never controls a protocol run.
- [ ] Produce the evidence-backed two-minute video, technical/business reviews, captions, poster, MP4, and WebM.
- [ ] Verify every on-screen factual claim resolves to an evidence JSON pointer.

### Task 24: Publish the GitHub release

**Files:**
- Create: `/private/tmp/ephemeral-agent-community/.github/workflows/ci.yml`
- Create: `/private/tmp/ephemeral-agent-community/.github/workflows/release.yml`
- Create: `/private/tmp/ephemeral-agent-community/CHANGELOG.md`
- Modify: `/private/tmp/ephemeral-agent-community/package.json`
- Modify: `/private/tmp/ephemeral-agent-community/README.md`

- [ ] Configure CI for Node 24, schema checks, unit/conformance tests, offline evidence verification, dependency/license/secret scans, package boundary checks, and documentation commands. Live AWS tests remain an explicitly approved protected workflow.
- [ ] Run the release candidate from a clean clone with no untracked files.
- [ ] Create the public GitHub repository, push the reviewed default branch, enable required checks and secret scanning, and publish signed `v0.1.0` source artifacts plus checksums/provenance.
- [ ] Publish only verified redacted evidence and demo assets; exclude credentials, private paths, raw transcripts, unrestricted logs, and confidential negotiation bodies.
- [ ] Verify the public clone, links, package checksums, OCI digests, evidence verifier, and quickstart.
- [ ] Commit/tag with Lore intent `Publish an executable protocol for disposable agent communities` and record the final release URL and digest in `CHANGELOG.md`.

---

## Final completion audit

- [ ] The current mechanics branch has one verified post-teardown production Fargate proof.
- [ ] The standalone EACF core imports no AWS, harness, Clockchain, or ERC-8004 implementation.
- [ ] Normative schemas, lifecycle, authority, identity, state, communication, evidence, observability, budget, and teardown contracts pass Core conformance.
- [ ] Codex, Claude Code, Hermes, and Bedrock Converse adapters pass the shared harness suite.
- [ ] AWS Fargate passes Isolated and Verifiable conformance.
- [ ] Clockchain remains a workflow profile and completes a fresh live run through EACF.
- [ ] The complete live matrix passes with new identities and verified cleanup for every row.
- [ ] Security, privacy, supply-chain, cost, and teardown audits have no unresolved release blocker.
- [ ] Documentation commands reproduce from a clean checkout.
- [ ] Presenter and video claims are evidence-bound.
- [ ] Public GitHub `v0.1.0` is reachable, signed, independently verifiable, and contains no secrets.
