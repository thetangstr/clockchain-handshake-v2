# Phase 6C1 Live Party and Production MCP Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make two isolated real harness processes complete the production v2 handshake through direct party-to-party delivery, additive checkpoint binding, and one verified Clockchain certificate.

**Architecture:** Extend the deployed role-scoped MCP with one additive checkpoint-submission tool and make proposal/acceptance submission fail closed without its exact checkpoint. Inside each party runtime, bind the live protocol session from the authoritative invitation response, deliver the signed business artifact and checkpoint directly to the peer, submit the checkpoint through a private MCP client, and only then release the helper signature to Codex or Claude. Compose those pieces in `mechanics-proof-party --run`; the Test Director exchanges only public bootstrap descriptors and retains digest-only evidence.

**Tech Stack:** Node.js 24 ESM, TypeScript, MCP Streamable HTTP, ACP Codex/Claude adapters, viem EIP-191, HTTPS/TLS-pinned A2A, Unix-domain completion socket, Docker, production AWS EC2 Compose deployment.

**Repositories:**
- Mechanics proof: `/private/tmp/clockchain-mechanics-proof`
- Production MCP worktree: `/private/tmp/clockchain-mcp-checkpoint-binding`

---

### Task 1: Add an additive checkpoint tool to the production MCP

**Files:**
- Create: `/private/tmp/clockchain-mcp-checkpoint-binding/packages/mcp-server/src/agent-handshake/v2/commitment-checkpoint.ts`
- Modify: `/private/tmp/clockchain-mcp-checkpoint-binding/packages/mcp-server/src/agent-handshake/v2/coordinator.ts`
- Modify: `/private/tmp/clockchain-mcp-checkpoint-binding/packages/mcp-server/src/agent-handshake/v2/access.ts`
- Modify: `/private/tmp/clockchain-mcp-checkpoint-binding/packages/mcp-server/src/agent-handshake/v2/public-server.ts`
- Modify: `/private/tmp/clockchain-mcp-checkpoint-binding/packages/mcp-server/src/agent-handshake/v2/public-tools.ts`
- Test: `/private/tmp/clockchain-mcp-checkpoint-binding/packages/mcp-server/test/agent-handshake-v2-checkpoint.test.mjs`
- Test: `/private/tmp/clockchain-mcp-checkpoint-binding/packages/mcp-server/test/agent-handshake-v2-coordinator.test.mjs`
- Test: `/private/tmp/clockchain-mcp-checkpoint-binding/packages/mcp-server/test/agent-handshake-v2-public-server.test.mjs`

- [ ] **Step 1: Write RED protocol and coordinator tests**

Prove the new exact tool name is `agent_handshake_submit_checkpoint` with input `{access, checkpoint}`. A proposal checkpoint must be role `initiator`, sequence `"1"`, previous digest `null`, signed by the joined Initiator address, and bind the eventual exact proposal-envelope digest. An acceptance checkpoint must be role `responder`, sequence `"2"`, point to the stored proposal-checkpoint digest, and bind the eventual exact acceptance-envelope digest. Reject missing, replayed, expired, foreign, wrong-role, wrong-session, wrong-artifact, wrong-sequence, and wrong-predecessor checkpoints. Prove ordinary `agent_handshake_submit` cannot publish proposal or acceptance without its matching checkpoint.

- [ ] **Step 2: Run RED**

```bash
PATH=/opt/homebrew/opt/node@24/bin:$PATH npm test -- \
  packages/mcp-server/test/agent-handshake-v2-checkpoint.test.mjs \
  packages/mcp-server/test/agent-handshake-v2-coordinator.test.mjs \
  packages/mcp-server/test/agent-handshake-v2-public-server.test.mjs
```

Expected: missing-module/tool and checkpoint-gate failures.

- [ ] **Step 3: Port the frozen checkpoint verifier and add the bounded tool**

Port the mechanics-proof checkpoint schema byte-for-byte except TypeScript import suffixes. Add `submitCheckpoint({access, checkpoint})` to the coordinator. It authorizes only `agent_handshake_submit_checkpoint`, verifies against the currently pending proposal/acceptance, stores/posts `agent_v2_commitment_checkpoint`, rejects a second value, and returns only `{role, sessionId, stage, checkpointDigest}`. In `submit`, construct the signed proposal/acceptance envelope first, require `checkpoint.artifactDigest === digestHex(envelope)`, then publish the existing artifact. Do not modify identity/evidence submission, proposal/acceptance wire schemas, acknowledgment authority, helper `2.1.2`, or certificate shape.

- [ ] **Step 4: Run GREEN and package verification**

```bash
PATH=/opt/homebrew/opt/node@24/bin:$PATH npm test -- \
  packages/mcp-server/test/agent-handshake-v2-checkpoint.test.mjs \
  packages/mcp-server/test/agent-handshake-v2-coordinator.test.mjs \
  packages/mcp-server/test/agent-handshake-v2-public-server.test.mjs
PATH=/opt/homebrew/opt/node@24/bin:$PATH npm test
```

Expected: focused tests and the complete MCP package pass.

- [ ] **Step 5: Commit**

Commit with Lore intent `Bind direct-party checkpoints before accepting stakeholder artifacts`.

### Task 2: Submit checkpoints privately from the party bridge

**Files:**
- Create: `src/harness/agent-handshake-mcp-client.mjs`
- Modify: `src/harness/direct-a2a-party-bridge.mjs`
- Test: `test/harness-agent-handshake-mcp-client.test.mjs`
- Test: `test/harness-direct-a2a-party-bridge.test.mjs`

- [ ] **Step 1: Write RED private-submission tests**

Add a stateless MCP client test for an exact JSON-RPC `tools/call` to `agent_handshake_submit_checkpoint`, bounded response bytes/time, JSON and SSE response parsing, no retry after an ambiguous write, and generic errors without access/checkpoint leakage. Extend bridge tests so it retains one authoritative `roleAccess` privately, sends artifact then checkpoint directly, calls `submitCheckpoint({access, checkpoint})` only after both peer acknowledgments, and releases the helper completion only after MCP returns the matching digest. Public bridge evidence must contain neither access nor checkpoint bytes/signature.

- [ ] **Step 2: Run RED**

```bash
PATH=/opt/homebrew/opt/node@24/bin:$PATH node --test \
  test/harness-agent-handshake-mcp-client.test.mjs \
  test/harness-direct-a2a-party-bridge.test.mjs
```

Expected: missing client and missing bridge callback failures.

- [ ] **Step 3: Implement the private client and causal bridge order**

Export `createAgentHandshakeCheckpointClient({endpoint, fetchImpl, timeoutMs})` with one method `submitCheckpoint({access, checkpoint})`. Add exact bridge option `submitCheckpoint`. Capture exactly one stable `roleAccess` from authoritative role-scoped results. The business completion order is fixed:

```text
verify helper result -> sign checkpoint -> direct artifact ack -> direct checkpoint ack
-> private MCP checkpoint ack -> release helper result -> model calls existing signature submit
```

Any failure leaves the retained action unreleased and records no completed delivery.

- [ ] **Step 4: Run GREEN and regressions**

```bash
PATH=/opt/homebrew/opt/node@24/bin:$PATH node --test \
  test/harness-agent-handshake-mcp-client.test.mjs \
  test/harness-direct-a2a-party-bridge.test.mjs \
  test/harness-acp-process-transport.test.mjs \
  test/agent-handshake-v2-checkpoint-compatibility.test.mjs
```

Expected: all pass.

- [ ] **Step 5: Commit**

Commit with Lore intent `Submit direct-party checkpoints before releasing model-visible signatures`.

### Task 3: Bind the live protocol session from authoritative MCP results

**Files:**
- Modify: `src/harness/direct-a2a-party-bridge.mjs`
- Modify: `src/harness/acp-process-transport.mjs`
- Test: `test/harness-direct-a2a-party-bridge.test.mjs`
- Test: `test/harness-acp-process-transport.test.mjs`

- [ ] **Step 1: Write RED dynamic-binding tests**

Start each transport with a controller run UUID but no protocol session. Prove the Initiator binds from the exact `agent_handshake_invite` result; the Responder first binds its invitation transport from the direct request, then requires `agent_handshake_accept_invitation` to return the same session. Prove retained helper actions are accepted only after this binding and only for that protocol session. Reject a second session, a mismatched accepted session, helper action before binding, and any attempt to expose role access or raw invitation in events.

- [ ] **Step 2: Run RED**

```bash
PATH=/opt/homebrew/opt/node@24/bin:$PATH node --test \
  test/harness-direct-a2a-party-bridge.test.mjs \
  test/harness-acp-process-transport.test.mjs
```

Expected: current construction-time session requirement fails the new cases.

- [ ] **Step 3: Implement one-use protocol-session binding**

Allow bridge construction with `sessionId: null`; internally expose only the actual bound session in `publicEvidence()`. Return `{observed:true, protocolSessionId}` from authoritative observations. ACP keeps the existing controller UUID for process/event correlation but validates every retained action against the one bridge-returned protocol session. It never trusts session text from the model, title, raw terminal output, or controller.

- [ ] **Step 4: Run GREEN**

Run the two focused files above, followed by the Phase 6C0 120-test gate. Expected: all pass.

- [ ] **Step 5: Commit**

Commit with Lore intent `Bind live Clockchain sessions inside each party runtime`.

### Task 4: Compose the real party process

**Files:**
- Create: `src/testing/mechanics-proof-party-runtime.mjs`
- Create: `src/testing/ephemeral-tls-identity.mjs`
- Modify: `bin/mechanics-proof-party.mjs`
- Modify: `infra/mechanics-proof/Dockerfile`
- Test: `test/mechanics-proof-party-runtime.test.mjs`
- Test: `test/mechanics-proof-party-entrypoint.test.mjs`
- Test: `test/mechanics-proof-container.test.mjs`

- [ ] **Step 1: Write RED composition tests**

With fake ACP spawn and fake production MCP, prove `--run` generates party wallet, delegated A2A key, Ed25519 bootstrap key, and self-signed TLS key inside the runtime; emits one sanitized public bootstrap descriptor; reads exactly one peer public descriptor from stdin; starts Responder listener before the Responder agent; wires verified release recorder, dynamic bridge, signed channel bootstrap, private checkpoint client, and pinned Codex/Claude ACP adapter; verifies a terminal certificate; emits digest-only terminal evidence; and destroys every private key/state/listener/process. Reject controller signer material, peer descriptor drift, shared workload/credential/state roots, preexisting state, unsupported harness, and incomplete teardown.

- [ ] **Step 2: Run RED**

```bash
PATH=/opt/homebrew/opt/node@24/bin:$PATH node --test \
  test/mechanics-proof-party-runtime.test.mjs \
  test/mechanics-proof-party-entrypoint.test.mjs \
  test/mechanics-proof-container.test.mjs
```

Expected: `--run` remains fail closed and runtime module is missing.

- [ ] **Step 3: Implement the party runtime**

Use OpenSSL only as an image-provided executable to generate an ephemeral P-256 self-signed TLS certificate and key under the mode-0700 party root; never accept a controller TLS key. Keep stdin/stdout as the portable public-control adapter: stdout line 1 is `clockchain.mechanics-proof-party-bootstrap/v1`; stdin line 1 is the exact peer descriptor; later stdout contains normalized digest-only events and one terminal `clockchain.mechanics-proof-party-evidence/v1`. Raw invitation, role access, MCP bodies, signer files, prompts, transcripts, and reasoning never cross that interface.

- [ ] **Step 4: Run GREEN and full verification**

Run the three focused tests, the Phase 6C0 gate, and `npm run verify`. Expected: all pass.

- [ ] **Step 5: Commit**

Commit with Lore intent `Run one complete stakeholder entirely inside its ephemeral runtime`.

### Task 5: Prove the path in two local containers against an MCP candidate

**Files:**
- Create: `scripts/run-mechanics-proof-containers.mjs`
- Create: `infra/mechanics-proof/compose.local.yml`
- Modify: `docs/mechanics-proof-fargate-runbook.md`
- Test: `test/mechanics-proof-two-container.test.mjs`

- [ ] **Step 1: Write RED orchestration tests**

Prove the controller creates two containers with distinct read-only roots, writable tmpfs/state/workspace mounts, no shared volume, separate provider/MCP credentials, and one private bridge network. It reads only each public bootstrap line, swaps descriptors, starts both harness loops, requires one identical verified certificate digest plus distinct party/agent/workload identities, captures digest-only evidence, observes container exit, and removes the exact run resources. A simulated success claim without certificate, direct delivery, checkpoint acknowledgments, or teardown must fail.

- [ ] **Step 2: Run RED**

```bash
PATH=/opt/homebrew/opt/node@24/bin:$PATH node --test test/mechanics-proof-two-container.test.mjs
```

- [ ] **Step 3: Implement the two-container runner**

Add `--dry-run` and `--run`. `--run` requires an immutable app-image digest, exact MCP endpoint, two private credential-file references, explicit evidence directory, 10-minute TTL, and max concurrency two. It must not put credential values in argv, Compose YAML, labels, logs, or retained evidence.

- [ ] **Step 4: Run local candidate canary**

Run with Codex Initiator and Claude Responder against a locally built MCP candidate plus the production host/relay dependencies. Require live fresh ERC-8004 identities, direct proposal/acceptance delivery, two accepted checkpoint digests, three Clockchain receipts, identical locally verified certificate digest, no external business action, and complete container cleanup.

- [ ] **Step 5: Commit**

Commit with Lore intent `Prove the production path in two disposable containers`.

### Task 6: Deploy the checkpoint gate to production and rerun the container proof

**Files:**
- Modify: `/private/tmp/clockchain-mcp-checkpoint-binding/infra/clockchain-mcp/RUNBOOK.md`
- Create: `docs/evidence/supervised-fresh-agent-mechanics-proof/phase6c1-production-two-container.json`
- Modify: `docs/mechanics-proof-fargate-runbook.md`

- [ ] **Step 1: Production release gate**

Require clean MCP and mechanics-proof commits, complete tests, unchanged helper manifest digest/version `2.1.2`, current AWS caller identity, read-only host inspection, rollback SHA, and canary budget. Push the MCP branch and deploy through the existing EC2/SSM Compose runbook; do not mutate helper or host roots.

- [ ] **Step 2: Smoke and negative tests**

Verify `/health`, the public agent-handshake manifest, unauthenticated handshake initialize, authenticated general MCP behavior, old v1 surfaces, checkpoint tool listing, and negative proposal/acceptance submission without checkpoints. Ensure failures are generic and prior sessions remain readable.

- [ ] **Step 3: Production two-container proof**

Run the exact Task 5 containers against `https://mcp.clockchain.network/handshake/mcp`. Retain only canonical public evidence: source/image/MCP commits, runtime and workload identities/digests, fresh ERC-8004 agent IDs and registration receipts, direct invitation/card/artifact/checkpoint digests, three Clockchain receipts, one certificate digest verified by both parties, token usage, no-external-action invariant, and observed teardown.

- [ ] **Step 4: Independent reviews**

Require specification and security/quality reviewers to approve the evidence and authority boundary. Any missing direct acknowledgment, checkpoint binding, live registration, closing certificate, or teardown keeps Phase 6C1 open.

- [ ] **Step 5: Commit**

Commit with Lore intent `Record the first isolated production direct-party handshake`.

## Phase boundary

Phase 6C1 ends only after Task 6. Fargate runtime mutation, the Codex/Claude/Hermes matrix, monitoring presentation, and demo video remain subsequent implementation plans; no local-container result may be relabeled as cloud isolation or final marketing proof.
