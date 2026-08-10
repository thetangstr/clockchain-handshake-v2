# Generic Two-Stakeholder Handshake Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add and production-verify a non-payment Initiator/Responder Handshake, one-time Responder invitation exchange, fresh Codex/Claude Code operating path, and preserved-layout stakeholder presentation without changing the existing payment-authorization protocol.

**Architecture:** The Handshake repository owns the canonical generic protocol, host, verifier, local signing kit, evidence, and snapshots. The MCP repository ports the canonical generic wire validators, adds six `agent_handshake_*` tools, and adds a persisted single-use invitation-capability exchange that yields a role/session-scoped MCP principal. The Research repository presents the two-person runbook and adapts generic snapshots while retaining the existing two-column layout.

**Tech Stack:** Node.js ESM, TypeScript, Zod, MCP Streamable HTTP, EIP-191/viem, ERC-8004 on Sepolia, Clockchain ledger receipts, Next.js/React/Vitest, Node test runner, Docker Compose/Caddy on AWS, Vercel.

---

## Repository worktrees

- Handshake: `/Users/Kailor/.config/superpowers/worktrees/handshake/generic-stakeholder-handshake`
- MCP: `/Users/Kailor/.config/superpowers/worktrees/clockchain-developer-tools/generic-stakeholder-handshake`
- Research: `/Users/Kailor/.config/superpowers/worktrees/clockchain-research/generic-stakeholder-handshake`

The Handshake branch starts at `435cc0e`, MCP at `8c68f35`, and Research at
`13a6ee3`. Baselines are green: Handshake 1,063 tests plus invariants, MCP package
and 18 infrastructure tests, and Research 128 tests plus typecheck.

## File responsibility map

### Handshake repository

- Create `src/agent-handshake/constants.mjs`: frozen generic schema/protocol ids,
  role names, outcomes, bounds, and exact public vocabulary.
- Create `src/agent-handshake/statement.mjs`: canonical generic terms, proposal,
  and acceptance validation/signature envelopes.
- Create `src/agent-handshake/protocol.mjs`: generic proposal/acceptance/
  acknowledgment transition construction and validation.
- Create `src/agent-handshake/descriptor.mjs`: host-signed descriptor binding the
  two identities, statement, repository, session, and expiry.
- Create `src/agent-handshake/evidence.mjs`: generic role-result and evidence
  package validation.
- Create `src/agent-handshake/result.mjs`: generic signed result construction and
  local certificate verification.
- Create `src/agent-handshake/verdict.mjs`: independent checker with one
  `VERIFIED` emission site and fixed fail-closed outcomes.
- Create `src/agent-handshake/host.mjs`: generic relay intake, funding, evidence
  download, and monitor mapping helpers.
- Create `bin/agent-handshake-host.mjs`: production generic host loop selected by
  deployment configuration, with no party signing authority.
- Create `src/monitor/agent-snapshot.mjs` and update relay snapshot routing:
  generic snapshot v1 without payment fields.
- Create `prompts/codex-initiator.md`, `prompts/codex-responder.md`,
  `prompts/claude-initiator.md`, and `prompts/claude-responder.md`: exact fresh
  stakeholder operating prompts using the existing wallet bridge.
- Create focused tests under `test/agent-handshake-*.test.mjs` and extend host,
  relay, prompt, and invariant tests.

### MCP repository

- Create `packages/mcp-server/src/agent-handshake/protocol.ts`: byte-faithful
  TypeScript port of canonical generic schemas.
- Create `packages/mcp-server/src/agent-handshake/coordinator.ts`: generic
  principal state machine and six-tool implementation.
- Create `packages/mcp-server/src/agent-handshake/invitation-store.ts`: atomic,
  mode-0600, restart-safe capability consumption.
- Modify `packages/mcp-server/src/token.ts`: v3 invitation and scoped-session
  token mint/verify functions with exact shapes.
- Modify `packages/mcp-server/src/http.ts`: capability exchange endpoint, v3 auth
  outcome, scoped principal derivation, and fixed no-leak errors.
- Modify `packages/mcp-server/src/server.ts` and `tools.ts`: pass auth scope,
  register generic tools, and refuse unrelated tools for scoped principals.
- Modify `packages/mcp-server/src/landing.ts`: advertise the generic stakeholder
  flow and exact canonical endpoint without exposing credentials.
- Modify `infra/clockchain-mcp/docker-compose.yml` and its infrastructure tests to
  persist the invitation store on the existing MCP state volume.

### Research repository

- Create `src/lib/agent-handshake-snapshot.ts`: exact generic snapshot parser.
- Modify `src/app/api/handshake/monitor/route.ts`: accept and hold either legacy
  payment snapshot or generic snapshot without coercing one into the other.
- Rewrite `src/components/ClaudeV6Runbook.tsx`: approved two-stakeholder narrative,
  connection preflight, invitation flow, and four role/client prompt cards.
- Modify `src/components/ClaudeV6Live.tsx` and
  `ClaudeV6LiveMonitor.tsx`: Initiator/Responder fact-derived generic timeline,
  full ERC-8004 identity detail, and generic certificate language.
- Add `src/components/StakeholderPromptCard.tsx`: reusable copy surface with no
  credential fields.
- Preserve `src/app/handshake/claude-v6/page.tsx` layout classes exactly; update
  metadata only.
- Extend presenter, live, monitor route, and prompt copy tests.

---

### Task 1: Canonical generic terms and party signatures

**Files:**
- Create: `src/agent-handshake/constants.mjs`
- Create: `src/agent-handshake/statement.mjs`
- Test: `test/agent-handshake-statement.test.mjs`

- [ ] **Step 1: Write failing canonical-shape tests**

```js
test("generic terms contain only reference, statement, and validity", () => {
  assert.deepEqual(validateAgentHandshakeTerms({
    reference: "NS-1847",
    statement: STATEMENT,
    validForMinutes: "45",
  }), { reference: "NS-1847", statement: STATEMENT, validForMinutes: "45" });
});

test("generic signed bytes contain no payment vocabulary", async () => {
  const envelope = await signAgentHandshakeProposal(validProposal, signMessage);
  const text = Buffer.from(envelope.payload, "base64url").toString("utf8");
  for (const word of ["amount", "currency", "invoice", "payer", "payee", "payment"]) {
    assert.equal(text.toLowerCase().includes(word), false);
  }
});
```

- [ ] **Step 2: Run RED**

Run: `node --test test/agent-handshake-statement.test.mjs`  
Expected: FAIL because the generic statement module does not exist.

- [ ] **Step 3: Implement exact generic constants and envelopes**

```js
export const AGENT_HANDSHAKE_PROTOCOL = "clockchain.agent-handshake/v1";
export const AGENT_HANDSHAKE_PROPOSAL_SCHEMA = "clockchain.agent-handshake-proposal/v1";
export const AGENT_HANDSHAKE_ACCEPTANCE_SCHEMA = "clockchain.agent-handshake-acceptance/v1";
export const AGENT_HANDSHAKE_ROLES = Object.freeze(["initiator", "responder"]);
export const AGENT_HANDSHAKE_STATEMENT_MAX = 512;
export const AGENT_HANDSHAKE_REFERENCE_MAX = 128;
```

Use `canonicalBytes` and the existing EIP-191 envelope conventions. Proposal and
acceptance validators must enforce exact keys, printable ASCII, decimal-string
times, lowercase EVM addresses, distinct parties, exact role values, repository
SHA, session UUID, and `externalActionPerformed:false`.

- [ ] **Step 4: Run GREEN and legacy regressions**

Run: `node --test test/agent-handshake-statement.test.mjs test/payer-mandate.test.mjs test/payment-request.test.mjs`  
Expected: PASS with legacy fixtures unchanged.

- [ ] **Step 5: Commit**

```bash
git add src/agent-handshake/constants.mjs src/agent-handshake/statement.mjs test/agent-handshake-statement.test.mjs
git commit -m "Give generic stakeholders their own signed intent" -m "Constraint: Generic public bytes may contain no payment vocabulary.\nRejected: Mapping statements into zero-value payment mandates | it would preserve the wrong semantics.\nConfidence: high\nScope-risk: moderate\nDirective: Keep the generic and payment schemas separate.\nTested: agent-handshake statement tests plus legacy mandate/request regressions.\nNot-tested: Ledger transitions and host verification land in later tasks."
```

### Task 2: Generic ordered transitions and descriptor

**Files:**
- Create: `src/agent-handshake/protocol.mjs`
- Create: `src/agent-handshake/descriptor.mjs`
- Test: `test/agent-handshake-protocol.test.mjs`
- Test: `test/agent-handshake-descriptor.test.mjs`

- [ ] **Step 1: Write failing transition-chain tests**

```js
test("generic transitions bind one statement in strict order", () => {
  const proposed = createAgentProposal(input);
  const accepted = createAgentAcceptance({ ...input, predecessor: digestHex(proposed) });
  const acknowledged = createAgentAcknowledgment({ ...input, predecessor: digestHex(accepted) });
  assert.deepEqual([proposed.sequence, accepted.sequence, acknowledged.sequence], ["1", "2", "3"]);
  assert.equal(accepted.statementDigest, proposed.statementDigest);
  assert.equal(acknowledged.predecessor, digestHex(accepted));
});
```

Add mutation cases for wrong predecessor, role, statement digest, session digest,
expiry, sequence, identity, and `externalActionPerformed:true`.

- [ ] **Step 2: Run RED**

Run: `node --test test/agent-handshake-protocol.test.mjs test/agent-handshake-descriptor.test.mjs`  
Expected: FAIL on missing modules.

- [ ] **Step 3: Implement transitions and host descriptor**

The descriptor exact keys are:

```js
[
  "chainId", "expiresAtMs", "externalActionPerformed", "initiator",
  "operatorPublicKey", "protocol", "reference", "registryAddress",
  "repositorySha", "responder", "schema", "sessionId", "statementDigest"
]
```

The host signs the descriptor with its existing Ed25519 session key. Party
transition creation remains outside the host.

- [ ] **Step 4: Run GREEN and payment-protocol regressions**

Run: `node --test test/agent-handshake-protocol.test.mjs test/agent-handshake-descriptor.test.mjs test/protocol.test.mjs test/descriptor.test.mjs`  
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/agent-handshake/protocol.mjs src/agent-handshake/descriptor.mjs test/agent-handshake-protocol.test.mjs test/agent-handshake-descriptor.test.mjs
git commit -m "Bind generic agreement to one ordered receipt chain" -m "Constraint: The three receipts must bind one statement without importing payment fields.\nRejected: Reusing the bilateral transition schema | its amount and party vocabulary are semantically wrong.\nConfidence: high\nScope-risk: moderate\nDirective: Preserve exact predecessor and statement-digest binding.\nTested: generic protocol and descriptor tests plus legacy protocol regressions.\nNot-tested: Host and live ledger integration land in later tasks."
```

### Task 3: Generic evidence, checker, result, and certificate proof

**Files:**
- Create: `src/agent-handshake/evidence.mjs`
- Create: `src/agent-handshake/verdict.mjs`
- Create: `src/agent-handshake/result.mjs`
- Create: `bin/agent-certificate-proof.mjs`
- Test: `test/agent-handshake-evidence.test.mjs`
- Test: `test/agent-handshake-verdict.test.mjs`
- Test: `test/agent-handshake-result.test.mjs`

- [ ] **Step 1: Write failing independent-checker tests**

```js
test("only complete, distinct, statement-bound evidence verifies", async () => {
  const verdict = await verifyAgentHandshakeAuthorization(validFixture());
  assert.equal(verdict.outcome, "VERIFIED");
  assert.equal(verdict.externalActionPerformed, false);
});

test("a validly signed certificate from another host or session is rejected", () => {
  assert.throws(() => verifyAgentHandshakeResult(foreignEnvelope, {
    expectedPublicKey,
    expectedSessionId,
  }));
});
```

Cover mutated party signatures, same owner, ERC-8004 owner mismatch, reordered or
wrong-height anchors, missing evidence, statement/reference drift, late bounds,
repository mismatch, negative outcome, and foreign signer.

- [ ] **Step 2: Run RED** with the three focused files.

- [ ] **Step 3: Implement one generic `VERIFIED` emission site**

`verdict.mjs` returns fixed failure codes everywhere else. `result.mjs` signs
`clockchain.agent-handshake-result/v1`; it has `parties.initiator` and
`parties.responder` and no legacy payment keys. The proof CLI accepts exact
`--file`, `--role`, `--expected-public-key`, and `--session-id` flags and emits a
small public JSON object only after full verification.

- [ ] **Step 4: Run GREEN plus result/verdict regressions**

Run: `node --test test/agent-handshake-{evidence,verdict,result}.test.mjs test/verdict.test.mjs test/result.test.mjs test/certificate-proof.test.mjs`  
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/agent-handshake/evidence.mjs src/agent-handshake/verdict.mjs src/agent-handshake/result.mjs bin/agent-certificate-proof.mjs test/agent-handshake-evidence.test.mjs test/agent-handshake-verdict.test.mjs test/agent-handshake-result.test.mjs
git commit -m "Let an independent checker certify generic handshakes" -m "Constraint: Only the checker may emit VERIFIED and both local agents must re-verify the signed result.\nRejected: Treating receipt presence as success | identity, signature, timing, and statement binding must also pass.\nConfidence: high\nScope-risk: broad\nDirective: Keep one VERIFIED emission site and pin every proof to discovery key plus session.\nTested: generic evidence, verdict, result, and legacy result regressions.\nNot-tested: Production chain reads land in the live gate."
```

### Task 4: Generic host and snapshot

**Files:**
- Create: `src/agent-handshake/host.mjs`
- Create: `bin/agent-handshake-host.mjs`
- Create: `src/monitor/agent-snapshot.mjs`
- Modify: `bin/clockchain-host.mjs`
- Modify: `infra` deployment selection only where the host command is chosen
- Test: `test/agent-handshake-host.test.mjs`
- Test: `test/agent-handshake-snapshot.test.mjs`
- Modify: `test/container-contract.test.mjs`

- [ ] **Step 1: Write failing host-boundary tests**

Assert the generic host:

```js
assert.equal(source.includes("signAgentHandshakeProposal"), false);
assert.equal(source.includes("signAgentHandshakeAcceptance"), false);
assert.match(source, /roles:\s*\["initiator",\s*"responder"\]/);
assert.match(source, /verifyAgentHandshakeAuthorization/);
```

Snapshot tests require exact generic keys, full identities, fact-derived anchors,
generic verdict, and absence of all payment keys/vocabulary.

- [ ] **Step 2: Run RED**.

- [ ] **Step 3: Implement the generic host loop**

Reuse relay discovery, funding journal, ERC-8004 funding, mailbox intake,
evidence persistence, Clockchain client, and host Ed25519 key handling. Do not
reuse payment mandate/request/descriptor/verdict modules. Select the loop with
`HANDSHAKE_PROTOCOL=agent-handshake-v1`; preserve the current default and binary.

- [ ] **Step 4: Run focused GREEN, monitor regressions, and container contract**.

- [ ] **Step 5: Commit**

```bash
git add src/agent-handshake/host.mjs bin/agent-handshake-host.mjs src/monitor/agent-snapshot.mjs bin/clockchain-host.mjs test/agent-handshake-host.test.mjs test/agent-handshake-snapshot.test.mjs test/container-contract.test.mjs
git commit -m "Host generic sessions without becoming a party" -m "Constraint: The host may fund, observe, verify, and certify but must never sign a stakeholder artifact.\nRejected: Running the Initiator on the host | it would collapse the two-stakeholder boundary.\nConfidence: high\nScope-risk: broad\nDirective: Keep bilateral-payment-v1 as the deployment default.\nTested: host boundary, generic snapshot, monitor, and container contract tests.\nNot-tested: MCP-driven live execution lands after the coordinator port."
```

### Task 5: Port generic protocol and build MCP coordinator

**Repository:** MCP

**Files:**
- Create: `packages/mcp-server/src/agent-handshake/protocol.ts`
- Create: `packages/mcp-server/src/agent-handshake/coordinator.ts`
- Create: `packages/mcp-server/test/agent-handshake-protocol.test.mjs`
- Create: `packages/mcp-server/test/agent-handshake-coordinator.test.mjs`
- Modify: `packages/mcp-server/src/tools.ts`
- Modify: `packages/mcp-server/test/handshake-tools.test.mjs`

- [ ] **Step 1: Add failing parity and state-machine tests**

The parity test loads shared JSON fixtures generated by the Handshake canonical
module and requires byte-identical canonical JSON and digests. Coordinator tests
cover identity signing, registration wait, proposal, acceptance, three anchors,
two evidence submissions, and result verification for distinct principals.

- [ ] **Step 2: Run RED**

Run: `npm test --workspace packages/mcp-server -- agent-handshake-protocol.test.mjs agent-handshake-coordinator.test.mjs`  
Expected: FAIL on missing modules and tools.

- [ ] **Step 3: Implement the port and six tools**

Use exact Zod inputs:

```ts
const agentTermsSchema = z.object({
  reference: z.string().min(1).max(128),
  statement: z.string().min(1).max(512),
  validForMinutes: z.number().int().min(1).max(60),
}).strict();
```

`agent_handshake_join` requires terms from both roles. A Responder mismatch fails
before signing acceptance. `agent_handshake_next` uses existing exact-byte and
gzip-base64url signing encodings plus the existing wallet registration response.

- [ ] **Step 4: Run GREEN, existing five-tool regressions, and full MCP package tests**.

- [ ] **Step 5: Commit**

```bash
git add packages/mcp-server/src/agent-handshake/protocol.ts packages/mcp-server/src/agent-handshake/coordinator.ts packages/mcp-server/src/tools.ts packages/mcp-server/test/agent-handshake-protocol.test.mjs packages/mcp-server/test/agent-handshake-coordinator.test.mjs packages/mcp-server/test/handshake-tools.test.mjs
git commit -m "Expose a generic handshake without weakening the payment tools" -m "Constraint: Fresh agents must discover generic roles and bytes without changing the existing five payment tools.\nRejected: Overloading handshake_join with a mode flag | it would create cross-protocol coercion risk.\nConfidence: high\nScope-risk: broad\nDirective: Keep agent_handshake tools in a separate namespace and preserve canonical-byte parity.\nTested: generic protocol/coordinator/tool tests and full MCP package suite.\nNot-tested: Invitation exchange and scoped auth land next."
```

### Task 6: One-time invitation capability and scoped MCP principal

**Repository:** MCP

**Files:**
- Modify: `packages/mcp-server/src/token.ts`
- Create: `packages/mcp-server/src/agent-handshake/invitation-store.ts`
- Modify: `packages/mcp-server/src/http.ts`
- Modify: `packages/mcp-server/src/server.ts`
- Modify: `packages/mcp-server/src/tools.ts`
- Create: `packages/mcp-server/test/agent-handshake-invitation.test.mjs`
- Modify: `packages/mcp-server/test/http.test.mjs`
- Modify: `packages/mcp-server/test/tools.test.mjs`
- Modify: `infra/clockchain-mcp/docker-compose.yml`
- Modify: `infra/clockchain-mcp/test/infra.test.mjs`

- [ ] **Step 1: Write failing token, replay, scope, and restart tests**

```js
test("an invitation exchanges once for a responder-only principal", async () => {
  const capability = mintHandshakeInvitation(secret, invite);
  const first = await exchange(capability.token);
  assert.equal(first.scope.role, "responder");
  await assert.rejects(exchange(capability.token), { code: "INVITATION_UNAVAILABLE" });
});

test("scoped principals cannot call unrelated or legacy tools", async () => {
  for (const name of ["get_time", "handshake_join", "agent_handshake_invite"]) {
    await assert.rejects(callAsResponder(name), { code: "TOOL_NOT_ALLOWED" });
  }
});
```

Add tamper, expiry, wrong discovery session, wrong statement digest, wrong role,
concurrent exchange, store symlink/mode, restart reload, no raw token persistence,
no-store response, and fixed-error tests.

- [ ] **Step 2: Run RED**.

- [ ] **Step 3: Implement v3 tokens, atomic store, exchange route, and scope gate**

The server must mark the capability hash consumed before minting a scoped token.
Tool registration may remain global, but dispatch must reject every tool outside
the scoped allowlist before handler execution. Principal hashing uses the verified
scoped token `jti`, never the capability or subject label.

- [ ] **Step 4: Run GREEN, all token/http/tool tests, compose resolution, and full MCP tests**.

- [ ] **Step 5: Commit**

```bash
git add packages/mcp-server/src/token.ts packages/mcp-server/src/agent-handshake/invitation-store.ts packages/mcp-server/src/http.ts packages/mcp-server/src/server.ts packages/mcp-server/src/tools.ts packages/mcp-server/test/agent-handshake-invitation.test.mjs packages/mcp-server/test/http.test.mjs packages/mcp-server/test/tools.test.mjs infra/clockchain-mcp/docker-compose.yml infra/clockchain-mcp/test/infra.test.mjs
git commit -m "Let an Initiator invite one independently authenticated Responder" -m "Constraint: The shared invitation may bootstrap one Responder but may never become a shared MCP principal.\nRejected: Returning an ordinary unrestricted demo token | the invitation must be role, session, and tool scoped.\nConfidence: high\nScope-risk: broad\nDirective: Persist only capability hashes and consume before minting the scoped credential.\nTested: tamper, expiry, replay, scope, concurrency, restart, HTTP, tools, and infrastructure suites.\nNot-tested: Public-browser exchange is verified after Research integration."
```

### Task 7: Fresh Codex and Claude Code stakeholder runbooks

**Repository:** Handshake

**Files:**
- Create: `prompts/codex-initiator.md`
- Create: `prompts/codex-responder.md`
- Create: `prompts/claude-initiator.md`
- Create: `prompts/claude-responder.md`
- Create: `docs/agent-handshake-demo.md`
- Create: `test/agent-handshake-prompts.test.mjs`

- [ ] **Step 1: Consult official Codex and Claude Code MCP configuration docs**

Use official primary documentation only. Record the exact current commands and
configuration keys in `docs/agent-handshake-demo.md`; do not infer syntax from
memory.

- [ ] **Step 2: Write failing prompt-contract tests**

Require each prompt to contain the canonical endpoint, role, invitation marker,
live discovery repository/commit checks, exact generic tools, wallet bridge
commands, live ERC-8004 registration, human review before party signatures,
certificate proof, and bans on payment language, shared tokens, private-key
output, JSON handoff files, and invented signer products.

- [ ] **Step 3: Run RED**.

- [ ] **Step 4: Write minimal prompts and runbooks on existing kit primitives**

Keep the pasted role prompt under 180 words. Put deterministic installation and
command detail in the MCP tool descriptions and runbook rather than relying on
agent improvisation. Codex and Claude Code variants may differ only where their
MCP configuration syntax differs.

- [ ] **Step 5: Run GREEN, wallet regressions, and full Handshake verify**.

- [ ] **Step 6: Commit**

```bash
git add prompts/codex-initiator.md prompts/codex-responder.md prompts/claude-initiator.md prompts/claude-responder.md docs/agent-handshake-demo.md test/agent-handshake-prompts.test.mjs
git commit -m "Make two fresh stakeholder agents reproducible from the real kit" -m "Constraint: A fresh Codex or Claude Code agent must use only the hosted MCP and existing open-source wallet bridge.\nRejected: Inventing a signer companion | no such product exists.\nConfidence: high\nScope-risk: moderate\nDirective: Keep pasted prompts concise and deterministic installation detail in the runbook/tool guidance.\nTested: exact prompt contracts, official-client configuration checks, and full Handshake verify.\nNot-tested: Human usability is covered by the production two-person rehearsal."
```

### Task 8: Generic research monitor adapter

**Repository:** Research

**Files:**
- Create: `src/lib/agent-handshake-snapshot.ts`
- Modify: `src/app/api/handshake/monitor/route.ts`
- Modify: `src/app/api/handshake/monitor/route.test.ts`
- Modify: `src/components/ClaudeV6Live.tsx`
- Modify: `src/components/ClaudeV6LiveMonitor.tsx`
- Modify: `src/lib/claude-v6-live.test.ts`

- [ ] **Step 1: Write failing exact-schema and fact-derived timeline tests**

Generic snapshots must reject extra keys, legacy payment fields, invalid roles,
partial identities, malformed receipts, verdict/stage inconsistencies, and
terminal session mismatch. The timeline derives completion only from actual
identity, statement, receipt, evidence, and verdict facts.

- [ ] **Step 2: Run RED** with route and live tests.

- [ ] **Step 3: Implement the generic parser and dual-schema route**

Return a discriminated union. Never normalize generic roles into payment roles or
vice versa. Terminal hold selection requires a canonical generic snapshot with
three receipts and a generic verdict.

- [ ] **Step 4: Run GREEN and legacy monitor regressions**.

- [ ] **Step 5: Commit**

```bash
git add src/lib/agent-handshake-snapshot.ts src/app/api/handshake/monitor/route.ts src/app/api/handshake/monitor/route.test.ts src/components/ClaudeV6Live.tsx src/components/ClaudeV6LiveMonitor.tsx src/lib/claude-v6-live.test.ts
git commit -m "Let the existing monitor tell a generic handshake truthfully" -m "Constraint: Generic and payment snapshots must coexist without vocabulary or field coercion.\nRejected: Renaming payer/payee only in JSX | the source snapshot would remain misleading.\nConfidence: high\nScope-risk: moderate\nDirective: Keep timeline completion fact-derived from generic artifacts.\nTested: exact parser, terminal hold, timeline, and legacy monitor regressions.\nNot-tested: Final copy and browser hierarchy land next."
```

### Task 9: Rewrite the existing stakeholder page

**Repository:** Research

**Files:**
- Create: `src/components/StakeholderPromptCard.tsx`
- Modify: `src/components/ClaudeV6Runbook.tsx`
- Modify: `src/components/ClaudeV6LiveMonitor.tsx`
- Modify: `src/app/handshake/claude-v6/page.tsx`
- Modify: `src/lib/claude-v6-presenter.test.tsx`
- Create: `src/lib/stakeholder-prompt-card.test.tsx`

- [ ] **Step 1: Lock the existing layout and write failing narrative tests**

Keep exact shell classes:

```ts
expect(markup).toContain("max-w-6xl flex-col-reverse");
expect(markup).toContain("xl:sticky xl:top-8");
expect(markup).toContain("xl:w-[380px]");
```

Require “Two stakeholders. Two computers. One verifiable handshake,” canonical
endpoint, Initiator and Responder prompts, one-time invitation explanation, local
kit and ERC-8004 registration, full identity details, three receipts, independent
checker, and certificate. Ban invoice, amount, currency, payer, payee, requestor,
payment, settlement, accounts payable, IT/security onboarding, and signer
companion wording from rendered markup.

- [ ] **Step 2: Run RED**.

- [ ] **Step 3: Rewrite copy and add safe copy cards**

Prompt cards receive public invitation id, statement, reference, repository URL,
and SHA only. They must structurally reject keys matching token, secret,
capability, signature, private, or credential before rendering/copying.

- [ ] **Step 4: Run GREEN, typecheck, full Research tests, and production build**.

- [ ] **Step 5: Perform browser visual verification at desktop and mobile widths**

Check hierarchy, copy wrapping, sticky monitor, copy buttons, invitations, full
identity cards, receipt expansion, terminal certificate, and absence of stale
payment language. Persist screenshots and the visual verdict.

- [ ] **Step 6: Commit**

```bash
git add src/components/StakeholderPromptCard.tsx src/components/ClaudeV6Runbook.tsx src/components/ClaudeV6LiveMonitor.tsx src/app/handshake/claude-v6/page.tsx src/lib/claude-v6-presenter.test.tsx src/lib/stakeholder-prompt-card.test.tsx
git commit -m "Center the demo on two stakeholder-controlled agents" -m "Constraint: Preserve the accepted layout while making the two-person MCP operation the primary story.\nRejected: Adding another experimental page | stakeholders already know the canonical route.\nConfidence: high\nScope-risk: moderate\nDirective: Keep credentials and capabilities out of rendered markup and copy payloads.\nTested: presenter, prompt-card, live-monitor, typecheck, build, and browser visual verification.\nNot-tested: Production data binding lands in the deployment gate."
```

### Task 10: Cross-repository security and compatibility gate

**Files:**
- Modify only tests or implementation required by failures found here.

- [ ] **Step 1: Run Handshake full verification**

Run: `npm run verify`  
Expected: all tests and structural invariants pass; generic vocabulary invariant
and legacy byte-fidelity checks pass.

- [ ] **Step 2: Run MCP full verification**

Run: `npm test`  
Expected: package build/tests and 18+ infrastructure tests pass.

- [ ] **Step 3: Run Research full verification**

Run: `npm test -- --run && npm run typecheck && npm run build`  
Expected: all tests pass, typecheck exit 0, production build exit 0.

- [ ] **Step 4: Run secret/capability and payment-vocabulary scans**

Scan retained evidence and rendered page output for raw tokens, capabilities,
private keys, authorization headers, signatures, private paths, and banned
payment vocabulary. Expected: no secret or banned public copy.

- [ ] **Step 5: Run a code review focused on invitation replay, confused-deputy scope, cross-protocol coercion, signer trust roots, and result binding**.

- [ ] **Step 6: Fix every confirmed blocker with a RED/GREEN regression before proceeding**.

### Task 11: Deploy and prove the live two-stakeholder flow

**Files:**
- Update: `HANDOFF.md` after evidence exists
- Update deployment records only with public commit ids and results

- [ ] **Step 1: Push all three branches and record immutable commits**.

- [ ] **Step 2: Deploy the generic-capable Handshake host checkout to AWS without changing the legacy default**.

- [ ] **Step 3: Deploy MCP and verify health, manifest, six generic tools, legacy tools, invitation exchange, state mount, and scoped-tool refusal**.

- [ ] **Step 4: Switch only the demonstration host to `HANDSHAKE_PROTOCOL=agent-handshake-v1` in a no-demo window and confirm new generic discovery**.

- [ ] **Step 5: Run two fresh stakeholder agents from separate work directories**

The Initiator uses an ordinary distinct MCP principal and creates the invitation.
The Responder enters only through the one-time exchange. Both clone the exact live
SHA, install independently, generate separate keys, register fresh ERC-8004
identities, sign only their role artifacts, and verify the same certificate.

- [ ] **Step 6: Verify production evidence**

Require two identity references, distinct owners and principals, statement and
reference match, three ordered receipts, `VERIFIED`, identical certificate
digests, `externalActionPerformed:false`, consumed invitation replay refusal,
disposable cleanup, and no payment vocabulary in the research page.

- [ ] **Step 7: Deploy Research and perform browser verification on the production URL**.

- [ ] **Step 8: Record sanitized evidence in `HANDOFF.md`, rerun Handshake `npm run verify`, commit, and push**.

---

## Plan self-review checklist

- Every design requirement maps to Tasks 1–11.
- Generic schemas and presentation contain no payment fields or vocabulary.
- Legacy payment modules, tools, token types, host default, and evidence remain.
- The invitation is single-use, restart-safe, role/session scoped, and keyless.
- The Responder gets a distinct principal without manually minting a general token.
- Fresh ERC-8004 registration uses the existing wallet bridge and happens live.
- Codex and Claude Code configuration is verified against official documentation.
- The accepted page layout is locked by characterization tests.
- Production deployment is ordered and reversible.
- No task contains a deferred placeholder.
