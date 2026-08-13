# Human-Readable Agent Narration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make live Codex and Claude handshake agents give slightly more detailed stakeholder-facing progress updates and closing summaries.

**Architecture:** Add narration requirements only to existing prompts. Preserve strict machine outputs and all protocol boundaries; tests enforce meaningful milestones, quiet polling, safe public fields, and certificate-gated success.

**Tech Stack:** Markdown prompts, JSON prompt fixture, Node.js built-in test runner.

---

### Task 1: Lock the narration contract

**Files:**
- Modify: `test/agent-handshake-prompts.test.mjs`
- Modify: `test/fresh-agent-client.test.mjs`

- [x] **Step 1: Write failing assertions**

Assert that every stakeholder prompt requests one-to-three-sentence milestone updates, suppresses routine polling and sensitive/raw payload narration, and requires a closing summary with role, ERC-8004 identity, agreement status, local certificate verification, and no external business action.

- [x] **Step 2: Verify RED**

Run:

```bash
/opt/homebrew/opt/node@24/bin/node --test test/agent-handshake-prompts.test.mjs test/fresh-agent-client.test.mjs
```

Expected: failure because the current prompts do not define the narration contract.

### Task 2: Update all live and copyable prompts

**Files:**
- Modify: `test/fixtures/fresh-agent/prompts.json`
- Modify: `prompts/codex-initiator.md`
- Modify: `prompts/codex-responder.md`
- Modify: `prompts/claude-initiator.md`
- Modify: `prompts/claude-responder.md`

- [x] **Step 1: Add minimal narration instructions**

Require short plain-language updates only at meaningful milestones, including the completed check and next wait. Prohibit raw JSON, private material, full hashes, and poll-by-poll chatter.

- [x] **Step 2: Add the certificate-gated closing summary**

Require role, ERC-8004 identity, agreement status, local certificate verification, and no external business action. Preserve the existing rule that no success is announced before local certificate verification.

- [x] **Step 3: Verify GREEN**

Run:

```bash
/opt/homebrew/opt/node@24/bin/node --test test/agent-handshake-prompts.test.mjs test/fresh-agent-client.test.mjs
```

Expected: all tests pass.

### Task 3: Verify the live execution seams

**Files:**
- Test: `test/live-tmux-demo.test.mjs`
- Test: `test/monitor-agent-snapshot-v2.test.mjs`

- [x] **Step 1: Run the focused live-path suite**

```bash
/opt/homebrew/opt/node@24/bin/node --test test/agent-handshake-prompts.test.mjs test/fresh-agent-client.test.mjs test/live-tmux-demo.test.mjs test/monitor-agent-snapshot-v2.test.mjs
```

Expected: all tests pass.

- [x] **Step 2: Check patch integrity**

```bash
git diff --check
```

Expected: no output and exit code 0.

- [x] **Step 3: Commit only narration files**

Use a Lore-format commit. Do not stage the unrelated Hermes edits or prior evidence directory.

### Task 4: Surface safe model narration in tmux

**Files:**
- Modify: `scripts/run-live-tmux-demo.zsh`
- Modify: `test/live-tmux-demo.test.mjs`

- [x] **Step 1: Write the failing presenter assertion**

Require the runner to consume both Codex `agent_message` text and Claude assistant text through one bounded filter.

- [x] **Step 2: Verify RED**

Run `node --test test/live-tmux-demo.test.mjs` and confirm the missing narration filter fails.

- [x] **Step 3: Add the bounded narration filter**

Normalize whitespace, cap output at 600 characters, and suppress URLs, role-access or secret markers, raw JSON, long opaque strings, and full hashes before writing model narration to a role pane.

- [x] **Step 4: Verify GREEN**

Run `node --test test/live-tmux-demo.test.mjs`, `zsh -n scripts/run-live-tmux-demo.zsh`, and `git diff --check`.

### Task 5: Correct checkpoint ownership in continuation prompts

**Files:**
- Modify: `src/testing/fresh-agent-client.mjs`
- Modify: `test/fixtures/fresh-agent/prompts.json`
- Modify: `test/fresh-agent-client.test.mjs`

- [x] **Step 1: Reproduce from retained live evidence**

The production run reached fresh identities 9607/9608 and the adapter submitted the proposal checkpoint, but Codex refused to proceed because the continuation prompt incorrectly assigned checkpoint submission to the model.

- [x] **Step 2: Write the failing ownership assertions**

Require both the initial action boundary and continuation prompt to say that the adapter automatically submits the checkpoint before releasing the signature, and that the agent must submit the exact signature rather than create or call a checkpoint.

- [x] **Step 3: Correct only the prompt boundary**

Do not change adapter execution or protocol code. Replace the ambiguous model-owned checkpoint instruction with the verified adapter-owned sequence.

- [x] **Step 4: Verify the focused live path**

Run the 110-test prompt, fresh-client, tmux, and monitor suite plus shell syntax and patch-integrity checks.
