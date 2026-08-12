# Direct A2A Bootstrap Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the first invitation, Agent Card exchange, and additive checkpoint signatures work directly between two isolated party runtimes without making Clockchain or the Test Director a content router.

**Architecture:** Add a one-use TLS-pinned bootstrap transport before the existing party-signed A2A channel. Reuse the existing runtime-private wallet through a narrowly bounded party-authority module for Agent Card and derived checkpoint signatures, leaving the deployed helper `2.1.2` and existing v2 authority chain unchanged.

**Tech Stack:** Node.js 24 ESM, `node:https`, `node:crypto`, viem, existing Clockchain wallet bridge, v2 proposal/acceptance/checkpoint modules, existing A2A HTTP task transport, Node test runner.

---

### Task 1: One-use direct invitation transport

**Files:**
- Create: `src/a2a/invitation-bootstrap-transport.mjs`
- Create: `test/a2a-invitation-bootstrap-transport.test.mjs`

- [ ] **Step 1: Write failing transport tests**

Cover exact HTTPS path/method/content type, private endpoint validation, sender-side peer certificate pinning, receiver-side bootstrap-signature authentication, one bounded invitation, digest acknowledgment, replay rejection, one-time `takeInvitation()`, timeout, oversized/malformed requests, no raw value in `publicEvidence()`, and send-before-public-evidence behavior on ambiguous network failure. Prove missing/wrong bootstrap key, swapped role/run/session/runtime/workload, wrong endpoint/certificate, duplicate nonce/jti, expired signature, body-length/digest mismatch, and attempted session rebinding all fail closed.

- [ ] **Step 2: Run RED**

Run:

```bash
PATH=/opt/homebrew/opt/node@24/bin:$PATH node --test test/a2a-invitation-bootstrap-transport.test.mjs
```

Expected: fail because `src/a2a/invitation-bootstrap-transport.mjs` does not exist.

- [ ] **Step 3: Implement the minimal transport**

Export:

```js
export async function createInvitationBootstrapTransport({
  allowLoopbackForTests = false,
  bootstrapSigner,
  initialSessionId = null,
  listenHost = "0.0.0.0",
  localRuntime,
  maxBytes = 64 * 1024,
  nowMs = () => Date.now(),
  peerBootstrapPublicKey,
  peerRole,
  peerRuntime,
  peerUrl = null,
  port = 8443,
  publicEndpoint,
  role,
  runId,
  tls,
})
```

Required immutable shapes:

```js
bootstrapSigner = {
  publicKey,             // Ed25519 SPKI PEM
  signCanonicalBytes,    // private callback; key is never passed in
}
localRuntime = {
  runtimeId,
  workloadAttestationDigest,
}
peerRuntime = {
  runtimeId,
  workloadAttestationDigest,
}
tls = {
  certificate,
  privateKey,
  ownCertificateSha256,
  peerCertificateSha256,
}
```

The listener starts with the mechanics-proof `runId` but, for the Responder only, `initialSessionId:null` because the live Clockchain session does not exist before invitation receipt. The Initiator binds its result's `sessionId` in `sendInvitation`. The first valid signed invitation atomically binds the Responder; `takeInvitation()` returns that bound public `sessionId` with the private invitation, and the later accept result must match it. No second bind is allowed.

Return only:

```js
{
  publicUrl,
  sendInvitation({ invitation, sessionId, expiresAtMs }),
  takeInvitation(),
  publicEvidence(),
  close(),
}
```

Use `POST /a2a/v1/bootstrap/invitations`, SHA-256 acknowledgment, and private/loopback endpoint rules matching `http-task-transport.mjs`. The sender pins `tls.peerCertificateSha256` before sending a body. The receiver authenticates `peerBootstrapPublicKey` against one exact canonical unsigned request payload containing: schema/version, artifact kind, method, path, run and bound session, sender/receiver roles, runtime IDs and workload digests, sender/receiver bootstrap keys, receiver endpoint and certificate fingerprint, body SHA-256 and byte length, issued/expiry times, nonce, and jti. Append `{algorithm:"ed25519", value}` outside the signed payload. Reject extra/missing keys. Keep raw invitation storage in memory and erase it after one take. Public evidence records only certificate/bootstrap-key fingerprints, public run/session identifiers, invitation digest, direction, and timestamps.

- [ ] **Step 4: Run GREEN and regression tests**

```bash
PATH=/opt/homebrew/opt/node@24/bin:$PATH node --test \
  test/a2a-invitation-bootstrap-transport.test.mjs \
  test/a2a-http-task-transport.test.mjs
```

Expected: all pass.

- [ ] **Step 5: Commit**

Commit with Lore intent `Deliver the first invitation without a content router` and record focused test evidence.

### Task 2: Deterministic party-signed card bootstrap

**Files:**
- Create: `src/a2a/card-bootstrap.mjs`
- Create: `test/a2a-card-bootstrap.test.mjs`
- Modify: `src/a2a/invitation-bootstrap-transport.mjs`

- [ ] **Step 1: Write failing card-order tests**

Prove Responder card must be signed first with `peerCardDigest:null`; Initiator card must pin the exact Responder digest; the returned pair passes `createDirectTaskChannel()`; wrong session/role/signer/runtime/workload/endpoint/pin/order/replay/expiry/bootstrap request signature fails; public evidence contains card digests only; bootstrap key use fails after pair finalization.

- [ ] **Step 2: Run RED**

```bash
PATH=/opt/homebrew/opt/node@24/bin:$PATH node --test test/a2a-card-bootstrap.test.mjs
```

Expected: module-not-found failure.

- [ ] **Step 3: Implement card bootstrap**

Export `createA2ACardBootstrap()` with role-specific `publishResponderCard`, `takeResponderCard`, `publishInitiatorCard`, `takeInitiatorCard`, `verifiedPair`, and `publicEvidence` methods. Reuse the bootstrap HTTPS peer/pin code; do not add a second listener or a mutual card-digest cycle.

- [ ] **Step 4: Run GREEN**

```bash
PATH=/opt/homebrew/opt/node@24/bin:$PATH node --test \
  test/a2a-card-bootstrap.test.mjs \
  test/a2a-agent-card.test.mjs \
  test/a2a-direct-task-channel.test.mjs \
  test/a2a-http-task-transport.test.mjs
```

Expected: all pass.

- [ ] **Step 5: Commit**

Commit with Lore intent `Bind the signed channel after direct invitation receipt`.

### Task 3: Bounded party A2A authority

**Files:**
- Create: `src/harness/party-a2a-authority.mjs`
- Create: `test/harness-party-a2a-authority.test.mjs`
- Modify: `src/core/wallet-bridge.mjs`
- Modify: `test/wallet-bridge.test.mjs`

- [ ] **Step 1: Write failing signer-boundary tests**

Prove the module returns public key/signatures only; signs an exact Agent Card for its own session/role/address/runtime/workload/endpoint; signs a checkpoint only after verifying the same party's existing v2 proposal or acceptance; rejects arbitrary bytes, foreign signer, wrong role/session/policy/artifact/digest/window, collapsed A2A key, proxy/accessor input, and any request for private key material.

- [ ] **Step 2: Run RED**

```bash
PATH=/opt/homebrew/opt/node@24/bin:$PATH node --test \
  test/harness-party-a2a-authority.test.mjs \
  test/wallet-bridge.test.mjs
```

Expected: module-not-found or missing public-key inspection failure.

- [ ] **Step 3: Add public-key inspection without changing CLI output**

Add an internal wallet-bridge export that returns only the lowercase address and uncompressed secp256k1 public key for a validated private state path. Do not add the field to agent CLI `init`, `inspect`, or release `2.1.2` output.

- [ ] **Step 4: Implement the bounded authority**

Create the party authority with a private state path, immutable session/role/policy/runtime/workload/task/HTTPS-endpoint bindings, and one separately generated delegated A2A account. Its public binding's exact nested `runtime` and `peerRuntime` objects each include `tlsCertificateSha256`. The unchanged v1 Agent Card binds the endpoint but has no certificate field; certificate identity remains enforced by the signed bootstrap envelope and sender pin. Expose only `publicBinding()`, `signResponderCard()`, `signInitiatorCard({responderCard})`, `signProposalCheckpoint({proposalEnvelope,...})`, `signAcceptanceCheckpoint({proposalEnvelope,acceptanceEnvelope,...})`, and `destroy()`.

Use existing `verifyAgentHandshakeV2Proposal`, `verifyAgentHandshakeV2Acceptance`, `signA2AAgentCard`, and `signAgentHandshakeV2CommitmentCheckpoint`. Every party-key signature must call `walletBridge.signExactBytes`; arbitrary bytes are never caller-controlled.

- [ ] **Step 5: Run GREEN and unchanged helper tests**

```bash
PATH=/opt/homebrew/opt/node@24/bin:$PATH node --test \
  test/harness-party-a2a-authority.test.mjs \
  test/wallet-bridge.test.mjs \
  test/agent-cli.test.mjs \
  test/agent-cli-security.test.mjs \
  test/commitment-checkpoint.test.mjs \
  test/agent-handshake-v2-checkpoint-compatibility.test.mjs
```

Expected: all pass; helper version/output fixtures remain `2.1.2`.

- [ ] **Step 6: Commit**

Commit with Lore intent `Derive A2A proof from the party's existing authority`.

### Task 4: Reuse the existing retained-action recorder

**Files:**
- Create: `src/harness/verified-release-action-recorder.mjs`
- Create: `test/harness-verified-release-action-recorder.test.mjs`
- Modify: `src/testing/fresh-agent-client.mjs`
- Modify: `test/fresh-agent-client.test.mjs`
- Modify: `src/harness/acp-process-transport.mjs`
- Modify: `test/harness-acp-process-transport.test.mjs`

- [ ] **Step 1: Write extraction compatibility tests**

Lock the existing Phase 1 release download, manifest/helper digest checks, state-path rewrite, signed bound-action file, one-use authorization, and diagnostics before moving code. Add a test that the new recorder returns an exact `clockchain.retained-local-action/v1` accepted by `createAcpProcessTransport()` while the old fresh-agent client behavior remains byte-compatible. Add a private Unix-socket completion test proving a verified signing request and the bounded helper JSON result correlate by action/command/request digest plus a one-use action nonce, while arbitrary terminal output cannot create a completion. Phase 6C0 supports Linux/macOS only and rejects any other platform. Test mode-`0700` root validation, `lstat`/no-follow path checks, platform-safe socket path bounds, symlink/non-socket/stale collision handling, bounded one-line JSON framing, connect/read/write deadlines, one-connection/one-action behavior, replay rejection, generic failures, deterministic `close()`, and cleanup limited to the exact owned socket path.

- [ ] **Step 2: Run RED**

```bash
PATH=/opt/homebrew/opt/node@24/bin:$PATH node --test \
  test/harness-verified-release-action-recorder.test.mjs \
  test/fresh-agent-client.test.mjs \
  test/harness-acp-process-transport.test.mjs
```

Expected: new recorder module missing.

- [ ] **Step 3: Extract, do not duplicate**

Move `preloadVerifiedReleaseAssets`, adapter executable/shim creation, helper-step validation, and signed pending-action recording from `src/testing/fresh-agent-client.mjs` into the production harness module. Keep compatibility wrappers in `fresh-agent-client.mjs`. Add `recordRetainedAction(helperStep)`, `trustedAdapterPublicKey`, and `setCompletionHandler(handler)`. The recorder creates a private Unix-domain socket under its validated mode-`0700` root and fails closed outside Linux/macOS. The executable captures only the helper's bounded public JSON result, sends one bounded JSON line with action/command/request digests plus its one-use nonce, waits under deadline for one acknowledgment, and forwards the exact helper bytes to the agent only on success. The recorder performs no broad recursive cleanup and unlinks only its exact owned socket after no-follow validation. Never expose the recorder private key, raw shell command, state path, verified signing request, socket path, completion JSON, or pending action body to ACP evidence.

- [ ] **Step 4: Run GREEN and full relevant suites**

```bash
PATH=/opt/homebrew/opt/node@24/bin:$PATH node --test \
  test/harness-verified-release-action-recorder.test.mjs \
  test/fresh-agent-client.test.mjs \
  test/harness-acp-process-transport.test.mjs \
  test/harness-conformance.test.mjs
```

Expected: all pass.

- [ ] **Step 5: Commit**

Commit with Lore intent `Reuse the proven helper recorder in real ACP sessions`.

### Task 5: Party-local bridge and truthful public evidence

**Files:**
- Create: `src/harness/direct-a2a-party-bridge.mjs`
- Create: `test/harness-direct-a2a-party-bridge.test.mjs`
- Modify: `src/harness/acp-process-transport.mjs`
- Modify: `test/harness-acp-process-transport.test.mjs`

- [ ] **Step 1: Write failing bridge tests**

Use installed Codex and Claude ACP event shapes. Prove only authoritative Clockchain MCP results can trigger invitation/card/proposal/acceptance handling; a non-MCP title/raw output cannot; the bridge remains party-local; public evidence contains digests and delivery acknowledgments only; raw invitation/tool output/A2A body cannot reach events or `collectEvidence()`.

- [ ] **Step 2: Run RED**

```bash
PATH=/opt/homebrew/opt/node@24/bin:$PATH node --test test/harness-direct-a2a-party-bridge.test.mjs
```

Expected: module-not-found failure.

- [ ] **Step 3: Implement the bridge and ACP callback**

The bridge receives exact authoritative MCP tool results and signed retained-action completions inside the party process. It sends the one-time invitation, advances card bootstrap after signer readiness, reconstructs and verifies proposal/acceptance envelopes from the retained signing request plus helper result, sends them over existing `createHttpTaskTransport()`, and signs/stores additive checkpoints through `party-a2a-authority`. The completion socket acknowledges only after the peer acknowledges direct delivery. The bridge returns only a public digest summary to ACP transport.

Add one exact `partyBridge` option to `createAcpProcessTransport()`. Snapshot it as `{observeToolResult}` and call it only after the same exact Codex/Claude provenance checks used for retained actions. Bind the recorder's private completion handler directly to the bridge inside the party process; do not route completion data through ACP events. Never pass the bridge through the Test Director/controller interface.

- [ ] **Step 4: Run GREEN and direct-channel regressions**

```bash
PATH=/opt/homebrew/opt/node@24/bin:$PATH node --test \
  test/harness-direct-a2a-party-bridge.test.mjs \
  test/harness-acp-process-transport.test.mjs \
  test/a2a-*.test.mjs \
  test/agent-handshake-v2-checkpoint-compatibility.test.mjs
```

Expected: all pass.

- [ ] **Step 5: Commit**

Commit with Lore intent `Keep direct party artifacts inside each harness runtime`.

### Task 6: Gate Phase 6C1

**Files:**
- Modify: `docs/superpowers/specs/2026-08-12-direct-a2a-bootstrap-design.md`
- Modify: `docs/superpowers/plans/2026-08-12-direct-a2a-bootstrap.md`

- [ ] **Step 1: Run the complete local gate**

```bash
PATH=/opt/homebrew/opt/node@24/bin:$PATH node --test \
  test/a2a-invitation-bootstrap-transport.test.mjs \
  test/a2a-card-bootstrap.test.mjs \
  test/harness-party-a2a-authority.test.mjs \
  test/harness-verified-release-action-recorder.test.mjs \
  test/harness-direct-a2a-party-bridge.test.mjs \
  test/harness-acp-process-transport.test.mjs \
  test/a2a-*.test.mjs \
  test/agent-handshake-v2-*.test.mjs
```

Expected: all pass.

- [ ] **Step 2: Run full verification**

```bash
PATH=/opt/homebrew/opt/node@24/bin:$PATH npm run verify
```

Expected: all repository tests and structural invariants pass.

- [ ] **Step 3: Security/spec review**

Required reviewer findings: Test Director sees no invitation/body/card bytes; bootstrap sender proof is exact; no arbitrary party-sign API; helper `2.1.2` unchanged; card ordering deterministic; exact MCP and retained-completion provenance; direct acknowledgment precedes MCP submit; teardown remains evidence-gated.

- [ ] **Step 4: Mark Phase 6C0 complete**

Only after both reviews approve may work begin on `bin/mechanics-proof-party.mjs --run` and the two-container production-MCP rehearsal.
