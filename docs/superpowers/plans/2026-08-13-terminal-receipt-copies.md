# Terminal Receipt Copies Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** End every successful live Codex-and-Claude tmux run with detailed, role-specific receipt copies derived only from the verified public evidence object.

**Architecture:** Add one pure formatter for validated public evidence and one standalone event presenter that owns terminal narration. The shell runner pipes JSON events into that presenter; the presenter appends the Payer copy only to the Codex log and the Requestor copy only to the Claude log.

**Tech Stack:** Node.js 24 ESM, `node:test`, zsh, existing fresh-agent evidence schema.

---

### Task 1: Pure receipt-copy formatter

**Files:**
- Create: `src/testing/terminal-receipt-copy.mjs`
- Create: `test/terminal-receipt-copy.test.mjs`

- [ ] **Step 1: Write the failing formatter tests**

Create a complete public-evidence fixture with distinct Initiator and Responder
identity facts, one shared certificate, and proposal/acceptance/acknowledgment
receipts. Assert:

```js
const payer = formatTerminalReceiptCopy(evidence, "initiator");
const requestor = formatTerminalReceiptCopy(evidence, "responder");

assert.match(payer, /HANDSHAKE COMPLETE — PAYER COPY/);
assert.match(requestor, /HANDSHAKE COMPLETE — REQUESTOR COPY/);
assert.match(payer, /ERC-8004 agent: #9621/);
assert.doesNotMatch(payer, /#9622/);
assert.match(requestor, /ERC-8004 agent: #9622/);
assert.doesNotMatch(requestor, /#9621/);
assert.match(payer, /Certificate digest: [0-9a-f]{64}/);
assert.match(payer, /Issued: 2026-08-13 20:52:36 UTC/);
assert.ok(payer.indexOf("Receipt 1 — Proposal") < payer.indexOf("Receipt 2 — Acceptance"));
assert.ok(payer.indexOf("Receipt 2 — Acceptance") < payer.indexOf("Receipt 3 — Acknowledgment"));
assert.match(payer, /No external business action occurred\./);
```

Add table-driven negative tests for an unknown role, missing party, malformed
certificate digest, malformed issue time, missing receipt, wrong receipt kind,
missing ledger ID, malformed receipt digest, and malformed block height. Every
case must throw `TerminalReceiptCopyError` without returning partial text.

- [ ] **Step 2: Run the formatter test and verify RED**

Run:

```sh
PATH=/opt/homebrew/opt/node@24/bin:$PATH node --test test/terminal-receipt-copy.test.mjs
```

Expected: FAIL because `src/testing/terminal-receipt-copy.mjs` does not exist.

- [ ] **Step 3: Implement the minimal pure formatter**

Export:

```js
export class TerminalReceiptCopyError extends Error {}
export function formatTerminalReceiptCopy(evidence, role) {}
```

Validate exact public values before formatting:

- role is `initiator` or `responder`;
- session ID and ledger IDs are nonempty printable strings;
- agent ID and block heights are canonical unsigned decimals;
- address, registration transaction, certificate digest, and receipt digests
  use their exact hexadecimal forms;
- certificate outcome is `VERIFIED`;
- `certificateVerified` is true;
- `externalBusinessActionPerformed` is false;
- receipt objects exist in the frozen order and their `kind` fields match.

Format `issuedAtMs` using `new Date(value).toISOString()`, replacing `T` with a
space and `.000Z` with ` UTC`. Return one newline-terminated string.

- [ ] **Step 4: Run the formatter test and verify GREEN**

Run the Task 1 command. Expected: all formatter tests PASS.

- [ ] **Step 5: Commit the formatter**

Commit only the formatter and its tests with a Lore-format message describing
the verified-evidence boundary.

### Task 2: Extract and extend the tmux event presenter

**Files:**
- Create: `scripts/present-live-tmux-events.mjs`
- Modify: `scripts/run-live-tmux-demo.zsh`
- Modify: `test/live-tmux-demo.test.mjs`

- [ ] **Step 1: Write the failing presenter contract**

Update `test/live-tmux-demo.test.mjs` to require:

```js
assert.match(runnerSource, /present-live-tmux-events\.mjs/);
assert.doesNotMatch(runnerSource, /--input-type=commonjs --eval/);
assert.match(presenterSource, /formatTerminalReceiptCopy/);
assert.match(presenterSource, /clockchain\.fresh-agent-canary-evidence\/v1/);
assert.match(presenterSource, /HANDSHAKE COMPLETE/);
```

Add a subprocess test that sends one verified success event to the presenter
with temporary Codex and Claude log paths. Assert both processes exit zero;
the Codex log contains the Payer copy and not the Requestor identity; the
Claude log contains the Requestor copy and not the Payer identity; both contain
the identical certificate digest and three ledger IDs.

- [ ] **Step 2: Run the presenter test and verify RED**

Run:

```sh
PATH=/opt/homebrew/opt/node@24/bin:$PATH node --test test/live-tmux-demo.test.mjs
```

Expected: FAIL because the standalone presenter does not exist and the runner
still embeds the presenter in `--eval`.

- [ ] **Step 3: Extract current narration without behavior changes**

Move the existing readline, safe narration filter, event-to-sentence mapping,
deduplication, and role-log routing from the zsh inline evaluation into
`scripts/present-live-tmux-events.mjs`. Preserve all existing public sentences.
Replace the inline evaluator in `run-live-tmux-demo.zsh` with:

```sh
"$NODE_BIN" scripts/run-fresh-agent-handshake.mjs 2>&1 \
  | tee "$TRACE_LOG" \
  | "$NODE_BIN" scripts/present-live-tmux-events.mjs \
  | tee "$COMBINED_LOG"
```

- [ ] **Step 4: Append deterministic role copies on success**

When the presenter receives the verified success schema, call:

```js
say(formatTerminalReceiptCopy(event, "initiator"), "initiator", "payer-receipt-copy");
say(formatTerminalReceiptCopy(event, "responder"), "responder", "requestor-receipt-copy");
```

Catch only `TerminalReceiptCopyError`. Append the exact safe fallback line to
both role logs, set `process.exitCode = 1`, and do not print partial receipt
text. Re-throw unexpected errors.

- [ ] **Step 5: Run presenter tests and shell validation**

Run:

```sh
PATH=/opt/homebrew/opt/node@24/bin:$PATH node --test test/terminal-receipt-copy.test.mjs test/live-tmux-demo.test.mjs
zsh -n scripts/run-live-tmux-demo.zsh
git diff --check
```

Expected: all tests PASS, shell syntax PASS, patch check clean.

- [ ] **Step 6: Commit the presenter integration**

Commit only the presenter, runner, and presenter tests with a Lore-format
message preserving the model-narration boundary.

### Task 3: Regression and visible proof

**Files:**
- Modify: `docs/live-tmux-demo-runbook.md`
- Test: `test/agent-handshake-prompts.test.mjs`
- Test: `test/fresh-agent-client.test.mjs`
- Test: `test/live-tmux-demo.test.mjs`
- Test: `test/monitor-agent-snapshot-v2.test.mjs`

- [ ] **Step 1: Document the final terminal receipt copies**

Add one paragraph to the facilitator runbook stating that each stable terminal
ends with its own identity proof and the shared certificate plus three receipt
references; neither terminal displays private material.

- [ ] **Step 2: Run the focused regression suite**

Run:

```sh
PATH=/opt/homebrew/opt/node@24/bin:$PATH node --test \
  test/terminal-receipt-copy.test.mjs \
  test/live-tmux-demo.test.mjs \
  test/agent-handshake-prompts.test.mjs \
  test/fresh-agent-client.test.mjs \
  test/monitor-agent-snapshot-v2.test.mjs
zsh -n scripts/start-live-tmux-demo.zsh scripts/wait-for-live-demo-funding.zsh scripts/run-live-tmux-demo.zsh
git diff --check
```

Expected: all focused tests PASS; all scripts parse; patch check clean.

- [ ] **Step 3: Replay the latest retained success event through the presenter**

Pipe the `result` object from the newest
`clockchain.fresh-agent-canary-attempt/v1` evidence file into the presenter with
temporary role logs. Confirm both logs contain their own identity facts, the
same certificate digest, and blocks `3560023`, `3560033`, and `3560037`.

- [ ] **Step 4: Commit documentation and finish the branch**

Commit the runbook change with a Lore-format message, then use the
finishing-development-branch workflow to run final verification and report the
branch state without touching unrelated Hermes or `.omc` changes.
