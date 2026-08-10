# Realistic Invoice-Authorization Demo Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the existing Payer and Requestor complete a production Clockchain Handshake for an invitation-bound, configurable invoice authorization, then present that exact business story in the existing research-site demo.

**Architecture:** Extend only `handshake_join`: it resolves either current discovery or a named existing relay session and stores validated business expectations inside the existing principal/session/role coordinator record. Existing mandate and payment-request preparation consume those stored terms; every downstream signature, anchor, evidence, verifier, and certificate path is unchanged. The existing Hermes launcher injects the preflight session invitation and scenario into its current role prompts, and the existing research page receives narrative-only changes without a new layout or state model.

**Tech Stack:** TypeScript, Zod, MCP Streamable HTTP, Node.js ESM, `node:test`, Hermes clean rooms, Next.js, React, Vitest.

---

## Repository and file map

### Clockchain developer tools

Worktree: `/Users/Kailor/.config/superpowers/worktrees/clockchain-developer-tools/handshake-payload-digest`

- Modify `packages/mcp-server/src/handshake/relay.ts`: fetch current or exact-session discovery through the existing relay routes.
- Modify `packages/mcp-server/src/handshake/coordinator.ts`: validate/store business terms, bind join to an invitation, construct the existing mandate/request from those terms, and fail before Requestor signing on mismatch.
- Modify `packages/mcp-server/src/tools.ts`: expose optional invitation and terms fields on the existing `handshake_join` tool only.
- Modify `packages/mcp-server/test/handshake-relay.test.mjs`: exact-session discovery tests.
- Modify `packages/mcp-server/test/handshake-coordinator.test.mjs`: coordinator state and artifact tests.
- Modify `packages/mcp-server/test/handshake-tools.test.mjs`: public tool-schema and wiring tests.

### Handshake

Worktree: `/Users/Kailor/.config/superpowers/worktrees/handshake/hermes-turnkey-demo`

- Modify `src/core/hermes-launcher.mjs`: retain the exact preflight invitation id, render scenario-specific existing role prompts, and require both agents to join that invitation.
- Modify `prompts/hermes-payer.md` and `prompts/hermes-requestor.md`: keep checked-in prompt examples synchronized with generated prompts.
- Modify `test/hermes-launcher.test.mjs` and `test/prompts.test.mjs`: prompt, invitation, and retained-evidence contracts.
- Keep `src/core/wallet-bridge.mjs`, `bin/wallet-bridge.mjs`, Payer/Requestor CLIs, verifier, and certificate code unchanged unless a regression proves a required compatibility adjustment.

### Clockchain research

Worktree: `/Users/Kailor/.config/superpowers/worktrees/clockchain-research/hermes-turnkey-demo`

- Modify `src/components/ClaudeV6Runbook.tsx`: realistic Northstar/Harbor invoice story using the existing components and layout.
- Modify `src/app/handshake/claude-v6/page.tsx`: matching metadata only.
- Modify `src/lib/claude-v6-presenter.test.tsx`: scenario-copy and layout-preservation assertions.
- Keep `ClaudeV6Live.tsx`, `ClaudeV6LiveMonitor.tsx`, the monitor route, receipt UI, and snapshot contract unchanged.

## Task 1: Bind existing MCP joins to an exact relay invitation

**Files:**

- Modify: `packages/mcp-server/src/handshake/relay.ts`
- Modify: `packages/mcp-server/src/handshake/coordinator.ts`
- Modify: `packages/mcp-server/test/handshake-relay.test.mjs`
- Modify: `packages/mcp-server/test/handshake-coordinator.test.mjs`

- [ ] **Step 1: Write failing relay tests for current and named discovery**

Add tests that create a relay client with a recording fetch implementation and assert:

```js
await client.fetchDiscovery();
assert.equal(requests[0], `${relayUrl}/v1/discovery/current`);

await client.fetchDiscovery("11111111-1111-4111-8111-111111111111");
assert.equal(requests[1], `${relayUrl}/v1/discovery/11111111-1111-4111-8111-111111111111`);
```

Also assert malformed invitation ids are rejected before `fetch` and a named discovery document whose `sessionId` differs from the requested id fails with `DISCOVERY_SESSION_MISMATCH`.

- [ ] **Step 2: Run the relay test and confirm RED**

Run:

```bash
node --test packages/mcp-server/test/handshake-relay.test.mjs
```

Expected: failure because `fetchDiscovery` accepts no session id and always requests `/current`.

- [ ] **Step 3: Implement exact-session discovery using the existing route**

Change the relay client contract to:

```ts
fetchDiscovery(sessionId?: string): Promise<JsonObject>;
```

When `sessionId` is undefined, request `/v1/discovery/current`. Otherwise validate the UUID, request `/v1/discovery/${encodeURIComponent(sessionId)}`, validate the returned discovery, and require `discovery.sessionId === sessionId`.

- [ ] **Step 4: Write failing coordinator tests for invitation binding**

Cover:

```js
const joined = await coordinator.join("requestor", INVITATION_ID, EXPECTED_TERMS);
assert.equal(joined.invitationId, INVITATION_ID);
assert.equal(joined.sessionId, INVITATION_ID);
assert.equal(relay.discoveryRequests.at(-1), INVITATION_ID);
```

Also prove `join("payer")` still fetches current discovery, `join("requestor", unknownId)` does not fall through to current, and retrying the same role/session preserves its existing relay key and state.

- [ ] **Step 5: Implement invitation-aware join in the existing coordinator**

Extend the runtime and coordinator signatures without creating a second join path:

```ts
join(role: string, invitationId?: string, termsInput?: unknown): Promise<JsonObject>
```

Resolve discovery with `options.relay.fetchDiscovery(invitationId)`, keep the existing role-seat checks and `ensureRecord`, and return:

```ts
{
  invitationId: sessionId,
  invitationUrl: `${discovery.relayUrl}/v1/discovery/${encodeURIComponent(sessionId)}`,
  operatorPublicKey,
  relayUrl: discovery.relayUrl,
  repositorySha: discovery.repositorySha,
  sessionId,
  stage
}
```

- [ ] **Step 6: Run focused invitation tests GREEN**

```bash
node --test packages/mcp-server/test/handshake-relay.test.mjs packages/mcp-server/test/handshake-coordinator.test.mjs
```

Expected: all focused tests pass.

- [ ] **Step 7: Commit the invitation slice**

Commit with Lore intent `Make every external party join the Payer's exact rendezvous` and record that a new short-code service was rejected in favor of the existing relay session id.

## Task 2: Put realistic terms into the existing mandate and request

**Files:**

- Modify: `packages/mcp-server/src/handshake/coordinator.ts`
- Modify: `packages/mcp-server/test/handshake-coordinator.test.mjs`

- [ ] **Step 1: Add failing validation and principal-isolation tests**

Use this canonical fixture:

```js
const TERMS = {
  amount: { currency: "USD", value: "18750" },
  invoiceReference: "HS-8842",
  purpose: "Invoice HS-8842 against PO NS-1847",
  validForMinutes: 45,
};
```

Assert canonical decimal and printable limits, `validForMinutes` 30–240, immutable normalized storage, and different Payer/Requestor principals retaining distinct expectations for the same relay session.

- [ ] **Step 2: Run coordinator tests RED**

```bash
node --test packages/mcp-server/test/handshake-coordinator.test.mjs
```

Expected: terms are currently ignored and generated artifacts still contain `$100 / INV-0001`.

- [ ] **Step 3: Add one bounded business-terms validator**

Add a private normalized shape in `coordinator.ts`:

```ts
type HandshakeBusinessTerms = {
  amount: { currency: "USD"; value: string };
  invoiceReference: string;
  purpose: string;
  validForMinutes?: number;
};
```

Copy validated primitives into a frozen plain object. Do not store caller objects or add fields to signed wire schemas.

- [ ] **Step 4: Feed Payer terms into the existing mandate preparation**

Use stored terms when present:

```ts
const terms = data.businessTerms ?? LEGACY_BUSINESS_TERMS;
const mandate = preparePayerMandate({
  amount: terms.amount,
  expiresAtMs: String(BigInt(issuedAtMs) + BigInt(terms.validForMinutes ?? 45) * 60n * 1000n),
  invoiceReferencePrefix: terms.invoiceReference,
  purpose: terms.purpose,
  // every existing party, repository, session, and schema field remains unchanged
});
```

- [ ] **Step 5: Fail closed before returning Requestor signing bytes on mismatch**

Before `prepareRequest`, compare the verified mandate with the Requestor's stored expectations:

```ts
if (
  mandate.amount.currency !== expected.amount.currency ||
  mandate.amount.value !== expected.amount.value ||
  mandate.invoiceReferencePrefix !== expected.invoiceReference ||
  mandate.purpose !== expected.purpose
) {
  throw new HandshakeCoordinatorError(
    "The signed payer mandate does not match the Requestor's expected invoice terms.",
    "BUSINESS_TERMS_MISMATCH",
  );
}
```

Then set the existing payment request's `invoiceReference` to the stored exact reference. Assert that no pending Requestor signing artifact or relay write is created on mismatch.

- [ ] **Step 6: Prove existing defaults and full downstream flow remain compatible**

Keep one legacy test calling `join(role)` without terms and expecting `$100`, `INV-0001`, and `Invoice settlement`. Add one realistic success test that reaches sealed mandate and payment request with the new values.

- [ ] **Step 7: Run coordinator and protocol regression tests GREEN**

```bash
node --test packages/mcp-server/test/handshake-coordinator.test.mjs packages/mcp-server/test/handshake-protocol.test.mjs
```

Expected: all tests pass and no protocol fixture changes are required.

- [ ] **Step 8: Commit the business-contract slice**

Commit with Lore intent `Make the signed artifacts carry the business terms both companies saw`.

## Task 3: Extend the same five-tool MCP surface

**Files:**

- Modify: `packages/mcp-server/src/tools.ts`
- Modify: `packages/mcp-server/test/handshake-tools.test.mjs`

- [ ] **Step 1: Write failing public-schema tests**

Assert the MCP catalog still contains exactly the existing five handshake tools and `handshake_join` now accepts:

```js
{
  role: "payer" | "requestor",
  invitationId?: "uuid",
  terms?: {
    amount: { currency: "USD", value: "18750" },
    invoiceReference: "HS-8842",
    purpose: "Invoice HS-8842 against PO NS-1847",
    validForMinutes?: 45
  }
}
```

Reject extra keys, non-USD currency, noncanonical values, overlong strings, and out-of-range duration.

- [ ] **Step 2: Run tool tests RED**

```bash
node --test packages/mcp-server/test/handshake-tools.test.mjs
```

- [ ] **Step 3: Add strict Zod schemas and forward values to the existing coordinator**

Use `.strict()` for nested objects and wire:

```ts
handshakeCoordinator().join(
  handshakeRoleSchema.parse(role),
  invitationId,
  terms,
)
```

Do not register a sixth tool or expose private signing material.

- [ ] **Step 4: Run the complete MCP package test suite**

```bash
npm test
```

Expected: TypeScript build succeeds and every MCP package test passes.

- [ ] **Step 5: Commit the tool-contract slice**

Commit with Lore intent `Keep a short business instruction sufficient at the existing MCP endpoint`.

## Task 4: Drive the existing fresh-Hermes harness with one shared invitation and scenario

**Files:**

- Modify: `src/core/hermes-launcher.mjs`
- Modify: `prompts/hermes-payer.md`
- Modify: `prompts/hermes-requestor.md`
- Modify: `test/hermes-launcher.test.mjs`
- Modify: `test/prompts.test.mjs`

- [ ] **Step 1: Write failing preflight and prompt tests**

Change the validated public-service summary to retain a public `invitationId` equal to current discovery's UUID. Assert generated prompts include the same invitation id and exact terms but retain asymmetric roles, the exact five MCP tools, local wallet bridge, and certificate proof.

- [ ] **Step 2: Run focused Handshake tests RED**

```bash
node --test test/hermes-launcher.test.mjs test/prompts.test.mjs
```

- [ ] **Step 3: Preserve invitation id from existing preflight**

Return this exact safe summary:

```js
{
  discoveryRepositoryMatches: true,
  invitationId: discovery.sessionId,
  mcpAwsHealth: true,
  mcpHealth: true,
  relayDiscovery: true,
  relayHealth: true,
}
```

Validate the UUID and persist it only as public run evidence.

- [ ] **Step 4: Render the existing role prompts with the realistic scenario**

Payer join instruction:

```text
Call handshake_join with role payer, invitationId <INVITATION_ID>, and terms for USD 18750, invoice HS-8842, purpose "Invoice HS-8842 against PO NS-1847", validForMinutes 45.
```

Requestor uses the same invitation id and independently supplies the same expected terms. Keep the current retry, exact-byte signing, registration, evidence, and certificate loops byte-for-byte where possible.

- [ ] **Step 5: Keep checked-in prompt examples synchronized**

Update only their business/join instructions. Do not remove wallet or certificate safety requirements and do not claim the host is a party.

- [ ] **Step 6: Run focused and regression tests GREEN**

```bash
node --test test/hermes-launcher.test.mjs test/prompts.test.mjs test/wallet-bridge.test.mjs test/hermes-cleanroom.test.mjs test/certificate-proof.test.mjs
```

Expected: all tests pass.

- [ ] **Step 7: Commit the client slice**

Commit with Lore intent `Make two blank agents meet on one explicit business invitation`.

## Task 5: Put the realistic story into the existing research presenter

**Files:**

- Modify: `src/components/ClaudeV6Runbook.tsx`
- Modify: `src/app/handshake/claude-v6/page.tsx`
- Modify: `src/lib/claude-v6-presenter.test.tsx`

- [ ] **Step 1: Add failing copy and layout-preservation tests**

Require rendered output to include `Northstar Logistics`, `Harbor Supply`, `HS-8842`, `NS-1847`, `USD 18,750`, invitation-as-rendezvous copy, later-AP/certificate copy, and `No funds move`. Preserve the existing `max-w-6xl`, two-column, and sticky-monitor classes. Ban any claim that the invitation is authorization, Clockchain signs as a party, or the certificate is payment.

- [ ] **Step 2: Run presenter tests RED**

```bash
npx vitest run src/lib/claude-v6-presenter.test.tsx --reporter=verbose
```

- [ ] **Step 3: Rewrite narrative content inside existing components**

Keep `Section`, `Drawer`, `Step`, page composition, and live monitor component untouched. Explain the invoice workflow and retain the testnet, fresh-agent, independent-checker, ERC-8004, and no-money boundaries.

- [ ] **Step 4: Update page metadata only**

Set the page title and description to the Northstar/Harbor invoice authorization while retaining the same route and JSX layout.

- [ ] **Step 5: Run research verification GREEN**

```bash
npx vitest run src/lib/claude-v6-presenter.test.tsx src/lib/claude-v6-live.test.ts src/app/api/handshake/monitor/route.test.ts --reporter=verbose
npm run typecheck
```

Expected: all focused tests and typecheck pass.

- [ ] **Step 6: Commit the presenter slice**

Commit with Lore intent `Let stakeholders see the business authorization behind the receipts`.

## Task 6: Integrated verification and production gate

**Files:**

- Modify only if evidence requires: `HANDOFF.md`
- Retain evidence under the existing Hermes run evidence directory; never commit secrets or raw wallets.

- [ ] **Step 1: Verify all three worktrees are free of unintended changes**

```bash
git status --short
git diff --check
```

Inspect each repository independently and preserve the research worktree's pre-existing untracked `.omx/` directory.

- [ ] **Step 2: Run full local verification**

MCP:

```bash
npm test
```

Handshake:

```bash
npm run verify
```

Research:

```bash
npm test
npm run typecheck
npm run build
```

- [ ] **Step 3: Deploy in dependency order**

Deploy MCP first, then update the immutable Handshake kit commit used by the host and Hermes launcher, then deploy the research site. Do not rotate party, host, funding, or certificate keys as part of this feature.

- [ ] **Step 4: Run one production fresh-agent gate**

Use two distinct MCP principals and disposable wallets. Require the same invitation id, distinct ERC-8004 agent ids, realistic signed terms in both artifacts, three anchors, two evidence packages, one certificate digest, `certificateVerified:true` for both roles, and `paymentMoved:false`.

- [ ] **Step 5: Record evidence and remaining limitations**

Record public session id, agent ids, addresses, blocks, certificate digest, test counts, deployed commits, and presenter URL. State explicitly that the invitation is presently a UUID, identity registration and anchors are on Sepolia/testnet infrastructure, and actual payment remains outside Clockchain.

## Plan self-review

- Every design requirement maps to one task.
- The same five MCP tools, existing party roles, wire schemas, verifier, wallet bridge, clean-room launcher, and research layout remain authoritative.
- Invitation binding precedes business terms; backend precedes prompts; prompts precede presenter; all precede deployment.
- No placeholder step, new dependency, new agent runtime, new relay store, new cryptographic envelope, or sixth MCP tool is introduced.
