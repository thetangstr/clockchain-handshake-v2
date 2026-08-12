# Phase 6C2 Live Fargate Isolation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Keep production mutation behind the explicit live gate; use TDD for every behavior change.

**Goal:** Run one Codex Initiator and one Claude/Bedrock Responder in two disposable Fargate tasks with distinct workload identities, no shared writable state, direct peer traffic, live ERC-8004 registration, one closing Clockchain certificate, and independently collected teardown evidence.

**Architecture:** Preserve the existing portable `RuntimeAdapter` and harness adapters. Add one provider-neutral public bootstrap-exchange port. Local Docker keeps its stdin descriptor exchange; Fargate uses two run-scoped SQS queues only to exchange each task's task-role-authenticated public bootstrap descriptor. SQS IAM and message binding authenticate publication; the exchanged public key verifies later signed A2A envelopes. All invitations, Agent Cards, mandates, proposal/acceptance artifacts, commitment checkpoints, helper commands, private MCP access, and certificate verification stay inside the two runtimes or flow directly over peer-only HTTPS port 8443. A Clockchain-owned Fargate controller provisions and observes infrastructure but never signs, decides, or routes private protocol content.

**Tech Stack:** Node.js 24 ESM, exact-pinned `@aws-sdk/client-sqs` and `@aws-sdk/client-sts` inside the party image for task-role-authenticated bootstrap exchange and caller-identity proof, AWS CLI v2 through an injected exact-command executor for controller-side CloudFormation/ECR/ECS/EC2/Logs/CloudTrail inspection, ECS task metadata v4, ECS Fargate `awsvpc`, CloudWatch Logs, Secrets Manager, SQS, direct HTTPS/TLS-pinned A2A, existing ACP Codex/Claude adapters.

**Repository:** `/private/tmp/clockchain-mechanics-proof`

**Hard gates:**

- No live AWS mutation until `--run`, an exact account/region allowlist, immutable ECR image digest, production MCP health/checkpoint-tool smoke, explicit VPC/public-subnet/private-CIDR inputs, a Codex auth secret ARN, TTL <= 3600 seconds, max concurrency 2, and budget <= USD 25 all pass.
- The controller may create/delete queues and infrastructure and may retain public descriptor digests. It must not read or persist raw queue messages, invitations, terms, access capabilities, signatures, prompts, transcripts, party keys, or model reasoning.
- Party signer, delegated A2A key, bootstrap Ed25519 key, and TLS private key are generated inside each task and destroyed with it. There are no signer/state secret references and no EFS/shared volume.
- Initiator receives only its Codex auth secret. Responder receives no Anthropic secret and uses its distinct task role for Bedrock. MCP role capability remains runtime-private.
- Evidence is written only after both tasks are stopped, task definitions are deregistered, run-scoped queues/stacks are deleted, and absence checks succeed.

---

### Task 1: Introduce the provider-neutral bootstrap-exchange port

**Files:**
- Create: `src/runtime/bootstrap-exchange-contract.mjs`
- Create: `src/runtime/stdin-bootstrap-exchange.mjs`
- Modify: `bin/mechanics-proof-party.mjs`
- Modify: `src/testing/mechanics-proof-party-runtime.mjs`
- Test: `test/bootstrap-exchange-contract.test.mjs`
- Test: `test/mechanics-proof-party-entrypoint.test.mjs`
- Test: `test/mechanics-proof-party-runtime.test.mjs`

- [ ] **Step 1: Write RED contract tests**

Require `publishOwnDescriptor`, `awaitPeerDescriptor`, and `destroy`. Accept only the frozen `clockchain.mechanics-proof-party-bootstrap/v1` public descriptor, exact run/role, one publication, one opposite-role response, a bounded wait, and idempotent secret-free cleanup. Reject replay, same-role/self descriptor, different run, accessor/proxy input, oversized payload, ambiguous publish, or a controller-provided private field.

- [ ] **Step 2: Run RED**

```bash
PATH=/opt/homebrew/opt/node@24/bin:$PATH node --test \
  test/bootstrap-exchange-contract.test.mjs \
  test/mechanics-proof-party-entrypoint.test.mjs \
  test/mechanics-proof-party-runtime.test.mjs
```

- [ ] **Step 3: Implement and preserve local behavior**

Move stdin/stdout descriptor exchange behind `createStdinBootstrapExchange`. `mechanics-proof-party --run` remains byte-compatible for the local container proof. `createMechanicsProofPartyRuntime.run` receives the already validated peer descriptor and remains unaware of AWS.

- [ ] **Step 4: Run GREEN and Phase 6C1 regressions**

Run the three focused files plus `test/mechanics-proof-two-container.test.mjs` and the direct-A2A bridge/transport tests.

- [ ] **Step 5: Commit**

Commit with Lore intent `Separate public rendezvous from private party traffic`.

### Task 2: Add task-role-authenticated SQS descriptor exchange

**Files:**
- Create: `src/runtime/aws-sqs-bootstrap-exchange.mjs`
- Modify: `bin/mechanics-proof-party.mjs`
- Modify: `infra/mechanics-proof/Dockerfile`
- Modify: `package.json`
- Modify: `package-lock.json`
- Test: `test/aws-sqs-bootstrap-exchange.test.mjs`
- Test: `test/mechanics-proof-party-entrypoint.test.mjs`
- Test: `test/mechanics-proof-container.test.mjs`

- [ ] **Step 1: Write RED SQS tests**

With an injected fake `SQSClient`, prove each role sends its descriptor exactly once to its own queue and long-polls only the peer queue. Bind message attributes to schema/run/role and require an exact SHA-256 body digest. Delete only the validated peer message after parsing. Reject mixed regions/accounts, duplicate messages, wrong attributes/body digest, stale run, self descriptor, malformed/oversized body, timeout, abort, and any queue URL or error text leaking into public output.

- [ ] **Step 2: Run RED**

```bash
PATH=/opt/homebrew/opt/node@24/bin:$PATH node --test \
  test/aws-sqs-bootstrap-exchange.test.mjs \
  test/mechanics-proof-party-entrypoint.test.mjs \
  test/mechanics-proof-container.test.mjs
```

- [ ] **Step 3: Implement managed exchange mode**

Add the managed exchange selection used by `--run-managed`, consuming exact nonsecret queue URLs and region. Let the AWS SDK default credential chain use the ECS task role; reject static AWS credentials and controller-supplied web-identity overrides. Emit only descriptor/event/evidence records already permitted by the party runtime. Pin `@aws-sdk/client-sqs` to one exact version. Task runtime identity and endpoint derivation remain Task 2B; do not accept controller-invented values as a substitute.

- [ ] **Step 4: Run GREEN, dependency audit, and image verification**

Run focused tests, `npm audit --omit=dev`, Dockerfile tests, and `npm run verify`.

- [ ] **Step 5: Commit**

Commit with Lore intent `Exchange only public peer bootstraps through workload identity`.

### Task 2B: Derive runtime identity inside each Fargate task

**Files:**
- Create: `src/runtime/aws-ecs-task-bootstrap.mjs`
- Modify: `bin/mechanics-proof-party.mjs`
- Modify: `package.json`
- Modify: `package-lock.json`
- Test: `test/aws-ecs-task-bootstrap.test.mjs`
- Test: `test/mechanics-proof-party-entrypoint.test.mjs`

- [ ] **Step 1: Write RED ECS metadata and STS tests**

With injected `fetch` and `STSClient`, require an exact ECS metadata v4 task envelope, one non-loopback private IPv4 address, task ARN, family, revision, availability zone, container ARN/name, and the task-role `GetCallerIdentity` response. Derive `publicEndpoint`, `runtimeId`, `taskId`, and `workloadAttestationDigest` inside the task. Reject missing/non-v4 metadata URI, link-local/public/loopback IP, multiple ambiguous task networks, wrong account/region, controller-supplied runtime/task/workload/public-endpoint fields, static AWS credentials, controller web-identity fields, metadata timeout/oversize, or STS identity that is not an assumed task role for the same account.

- [ ] **Step 2: Run RED**

```bash
PATH=/opt/homebrew/opt/node@24/bin:$PATH node --test \
  test/aws-ecs-task-bootstrap.test.mjs \
  test/mechanics-proof-party-entrypoint.test.mjs
```

- [ ] **Step 3: Implement fail-closed managed entrypoint bootstrap**

`mechanics-proof-party --run-managed` reads only the platform-injected `ECS_CONTAINER_METADATA_URI_V4`, fetches `${URI}/task` with a bounded response, calls STS through the ECS default credential chain, derives `https://<private-ip>:8443`, and constructs the existing party-runtime options plus SQS exchange. The resulting public task-attestation log record is exact-schema and may contain the STS caller identity for later corroboration; no credentials or metadata endpoint are retained. Pin `@aws-sdk/client-sts` to the same exact SDK release family as SQS.

- [ ] **Step 4: Run GREEN and managed-mode regressions**

Run focused tests, SQS tests, party runtime/entrypoint tests, `npm audit --omit=dev`, and `npm run verify`.

- [ ] **Step 5: Commit**

Commit with Lore intent `Derive cloud identity inside each party runtime`.

### Task 3: Replace dry fixtures with a live-safe run-scoped stack template

**Files:**
- Create: `infra/mechanics-proof/fargate-live-runtime.yaml`
- Create: `src/runtime/aws-fargate-live-plan.mjs`
- Modify: `src/runtime/aws-fargate-runtime-adapter.mjs`
- Modify: `docs/mechanics-proof-fargate-runbook.md`
- Test: `test/aws-fargate-live-plan.test.mjs`
- Test: `test/aws-fargate-runtime-adapter.test.mjs`

- [ ] **Step 1: Write RED infrastructure contract tests**

Require one run-scoped cluster, two queues with SSE-SQS and 15-minute retention, two run-scoped private subnets in distinct AZs, one temporary NAT gateway in an explicitly supplied existing public subnet, private route tables, two peer-only security groups, two log groups, distinct task and execution roles, responder-only Bedrock permissions, initiator-only Codex secret retrieval, and task-role queue permissions limited to own-send/peer-receive-delete. Require `assignPublicIp: DISABLED`, 8443 peer-group traffic, HTTPS egress through the run-scoped NAT, no EFS, no signer/state/MCP credential secrets, and mandatory run/phase/expiry/cost tags. Reject overlapping CIDRs, a public subnet outside the selected VPC, `MapPublicIpOnLaunch` on either new subnet, or a preexisting route selected by inference.

- [ ] **Step 2: Run RED**

```bash
PATH=/opt/homebrew/opt/node@24/bin:$PATH node --test \
  test/aws-fargate-live-plan.test.mjs \
  test/aws-fargate-runtime-adapter.test.mjs
```

- [ ] **Step 3: Implement the live plan builder**

Keep the existing dry fixture and validator for historical regression. Build the live stack/task definitions from validated inputs and CloudFormation outputs, not hard-coded account `123456789012` fixtures. The stack creates `10.0.16.0/24` and `10.0.17.0/24` only when those explicit CIDRs are revalidated as unused inside the selected VPC at execution time; callers may supply different validated unused `/24` CIDRs. Task definitions use one immutable ECR image, ephemeral `/workspace`, read-only root, nonroot user, exact managed-mode env, per-role log stream, and no shared writable resource. The Responder task role receives `bedrock:InvokeModel`; the Initiator execution role receives only its Codex secret. Both task roles receive only their role-scoped SQS actions.

- [ ] **Step 4: Validate templates without mutation**

Run focused tests and `aws cloudformation validate-template` against the generated template in the allowed account/region. The command executor must be exact-command allowlisted and redact all returned identifiers before printable summaries.

- [ ] **Step 5: Commit**

Commit with Lore intent `Define disposable peer-isolated Fargate runtimes`.

### Task 4: Implement the live Fargate runtime adapter and controller

**Files:**
- Create: `src/runtime/aws-cli-control-plane.mjs`
- Create: `src/runtime/aws-fargate-live-adapter.mjs`
- Create: `scripts/run-mechanics-proof-fargate.mjs`
- Modify: `src/runtime/runtime-adapter-contract.mjs`
- Modify: `package.json`
- Test: `test/aws-cli-control-plane.test.mjs`
- Test: `test/aws-fargate-live-adapter.test.mjs`
- Test: `test/mechanics-proof-fargate-runner.test.mjs`

- [ ] **Step 1: Write RED lifecycle tests**

Prove exact order: identity/account check -> MCP health/tool gate -> template validation -> stack create/wait -> task-definition register -> two `RunTask` calls issued before waiting -> public event polling -> terminal evidence match -> stop/wait -> deregister definitions -> delete/wait stack -> absence checks -> retained evidence. Any partial failure must enter the same bounded cleanup path. Reject an existing same-run stack, more than two tasks, unpinned image, public subnet/public IP, unexpected command/JSON shape, cross-role secret, expired TTL, budget overflow, or production endpoint drift.

- [ ] **Step 2: Run RED**

```bash
PATH=/opt/homebrew/opt/node@24/bin:$PATH node --test \
  test/aws-cli-control-plane.test.mjs \
  test/aws-fargate-live-adapter.test.mjs \
  test/mechanics-proof-fargate-runner.test.mjs
```

- [ ] **Step 3: Implement the exact AWS CLI boundary**

Use `execFile("aws", argv)` only through an injected executor. Allowlist every service/action and require JSON output. Never use shell interpolation. Treat nonzero/timeout/parse/shape ambiguity as failure. Public controller events contain run ID, role, state, timestamp, and digests only. `--dry-run` prints the safe mutation plan; `--run` requires explicit account, region, VPC, existing public subnet ID, two unused private CIDRs, Codex secret ARN, immutable image, evidence directory, TTL, budget, and production MCP URL. The preflight must prove the supplied public subnet has the selected VPC, an Internet Gateway route, and public-address capability; it must prove the private CIDRs are inside the VPC and do not overlap any existing subnet.

- [ ] **Step 4: Run GREEN and failure-injection sweep**

Run the focused tests with injected failures after every mutation boundary. Verify cleanup succeeds or the runner returns a typed `CLEANUP_UNCONFIRMED` result and writes no success evidence.

- [ ] **Step 5: Commit**

Commit with Lore intent `Run and tear down two isolated Fargate parties`.

### Task 5: Derive proof only from AWS control-plane and protocol evidence

**Files:**
- Modify: `src/runtime/aws-fargate-evidence.mjs`
- Create: `src/testing/mechanics-proof-cloud-evidence.mjs`
- Modify: `scripts/run-mechanics-proof-fargate.mjs`
- Test: `test/aws-fargate-runtime-adapter.test.mjs`
- Test: `test/mechanics-proof-cloud-evidence.test.mjs`

- [ ] **Step 1: Write RED evidence tests**

Require two stopped ECS tasks with distinct task ARNs, task roles, execution roles, ENIs, security groups, writable-root digests, signer addresses, A2A card addresses, and ERC-8004 agent IDs. Require identical certificate/session/result digests, both direct-delivery/checkpoint acknowledgments, three Clockchain receipt IDs, `certificateVerified:true`, `externalBusinessActionPerformed:false`, and cleanup/absence proof. Reject self-reported workload identity, missing CloudTrail `RunTask`/`StopTask`, mismatched image digest, shared credential/volume, absent queue cleanup, sanitized-log failure, or any terminal success inferred from model prose.

- [ ] **Step 2: Run RED**

```bash
PATH=/opt/homebrew/opt/node@24/bin:$PATH node --test \
  test/aws-fargate-runtime-adapter.test.mjs \
  test/mechanics-proof-cloud-evidence.test.mjs
```

- [ ] **Step 3: Implement the evidence reducer**

Collect exact AWS API responses and log records in memory, validate them, and persist only canonical public evidence plus SHA-256 digests of the raw control-plane envelopes. Include the task-role STS caller identity emitted inside each task, but corroborate it with the ECS task definition and task ARN. Public proof must state that SQS carried only task-role-authenticated public bootstrap descriptors, with SQS IAM/message binding authenticating publication and the exchanged public key verifying later signed A2A envelopes, and that private workflow content used peer HTTPS.

- [ ] **Step 4: Run GREEN and secret/path scans**

Run focused tests, `assertSecretFree` against real-shaped canaries, repo invariant checks, and `git diff --check`.

- [ ] **Step 5: Commit**

Commit with Lore intent `Accept cloud proof only from corroborated runtime evidence`.

### Task 6: Execute the live Fargate proof and close Phase 6C2

**Files:**
- Modify: `docs/mechanics-proof-fargate-runbook.md`
- Create: `evidence/mechanics-proof-fargate/<run-id>/public-proof.json` (generated, sanitized)
- Create: `evidence/mechanics-proof-fargate/<run-id>/verification.md` (generated, no secrets)

- [ ] **Step 1: Reconfirm prerequisites**

Require the production MCP to expose `agent_handshake_submit_checkpoint`, production health to pass, the app image to be built from a clean immutable source commit and pushed by digest to the approved ECR account, and AWS caller identity to match the explicit allowlist. If the production checkpoint tool is still absent, stop before cloud mutation and report that exact prerequisite; do not weaken the protocol or use the old seven-tool server.

- [ ] **Step 2: Run the live proof**

Execute exactly one `codex:claude` pair with Codex Terra and Claude Sonnet through Bedrock. Require fresh on-run ERC-8004 registration, direct A2A proposal/acceptance, two accepted MCP checkpoint digests, three anchor receipts, and one independently verified closing certificate.

- [ ] **Step 3: Tear down before retaining success**

Stop both tasks, deregister both task definitions, delete the run stack/queues/log groups according to retention policy, and confirm exact absence. Retain no raw queue messages, credentials, private keys, helper payloads, prompts, transcripts, or reasoning.

- [ ] **Step 4: Verify and review**

Run `npm run verify`, an independent spec review, an independent code/security review, and a fresh read-only AWS absence audit. The final Phase 6C2 claim must cite the run ID, two ERC-8004 IDs, task-role identity digests, receipt IDs, certificate digest, source commit, image digest, and cleanup evidence digest.

- [ ] **Step 5: Commit**

Commit with Lore intent `Prove the handshake across two disposable cloud identities`.

---

Phase 6C2 ends only after Task 6. A local mock, CloudFormation validation, successful task startup, model-auth success, or an MCP-only interaction is not a cloud mechanics proof. The subsequent three-harness matrix, monitoring presentation, and demo video remain separate evidence-gated plans.
