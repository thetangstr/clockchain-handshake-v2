import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const launcherUrl = new URL("../scripts/start-live-tmux-demo.zsh", import.meta.url);
const runnerUrl = new URL("../scripts/run-live-tmux-demo.zsh", import.meta.url);
const watcherUrl = new URL("../scripts/wait-for-live-demo-funding.zsh", import.meta.url);
const runbookUrl = new URL("../docs/live-tmux-demo-runbook.md", import.meta.url);

test("live tmux launcher keeps stable human-readable Codex and Claude panes", async () => {
  const source = await readFile(launcherUrl, "utf8");

  assert.match(source, /TMUX_SERVER=.*clockchain-demo/);
  assert.match(source, /CODEX_SESSION=.*codex/);
  assert.match(source, /CLAUDE_SESSION=.*claude/);
  assert.match(source, /CONTROLLER_SESSION=.*clockchain-controller/);
  assert.match(source, /tail -n \+1 -F/);
  assert.match(source, /tmux -L \"\$TMUX_SERVER\" new-session/);
  assert.match(source, /tmux -L \"\$TMUX_SERVER\" respawn-pane -k -t \"\$CODEX_SESSION:0\.0\"/);
  assert.match(source, /tmux -L \"\$TMUX_SERVER\" respawn-pane -k -t \"\$CLAUDE_SESSION:0\.0\"/);
  assert.match(source, /tmux -L \"\$TMUX_SERVER\" respawn-pane -k -t \"\$CONTROLLER_SESSION:0\.0\"/);
  assert.match(source, /tmux -L \"\$TMUX_SERVER\" clear-history -t \"\$CODEX_SESSION:0\.0\"/);
  assert.match(source, /tmux -L \"\$TMUX_SERVER\" clear-history -t \"\$CLAUDE_SESSION:0\.0\"/);
  assert.match(source, /wait-for-live-demo-funding\.zsh/);
});

test("live runner pins the production clients and retains public evidence", async () => {
  const source = await readFile(runnerUrl, "utf8");

  assert.match(source, /Codex \/ Payer — Terra/);
  assert.match(source, /Claude Code \/ Requestor — Sonnet/);
  assert.match(source, /CLOCKCHAIN_INITIATOR_MODEL=.*gpt-5\.6-terra/);
  assert.match(source, /CLOCKCHAIN_RESPONDER_MODEL=.*sonnet/);
  assert.match(source, /CLOCKCHAIN_FRESH_AGENT_RESULT_DIR/);
  assert.match(source, /run-fresh-agent-handshake\.mjs/);
  assert.match(source, /adapter-checkpoint-submitted/);
  assert.match(source, /verified its closing certificate/);
});

test("funding watcher never creates an invitation before the two-seat threshold", async () => {
  const source = await readFile(watcherUrl, "utf8");

  assert.match(source, /REQUIRED_WEI=.*25000000000000000/);
  assert.match(source, /eth_getBalance/);
  assert.match(source, /if \(\( current_wei >= REQUIRED_WEI \)\)/);
  assert.match(source, /RUNNER=.*run-live-tmux-demo\.zsh/);
  assert.match(source, /exec "\$RUNNER"/);
});

test("facilitator runbook describes the exact visible production proof", async () => {
  const text = await readFile(runbookUrl, "utf8");

  for (const expected of [
    "Codex / Payer",
    "Claude Code / Requestor",
    "Node 24",
    "one-time invitation",
    "fresh ERC-8004",
    "proposal",
    "acceptance",
    "closing certificate",
    "https://clockchain-research.vercel.app/handshake/claude-v6",
    "TMUX_TMPDIR=/tmp tmux -L clockchain-demo attach -t codex",
    "TMUX_TMPDIR=/tmp tmux -L clockchain-demo attach -t claude",
  ]) assert.match(text, new RegExp(expected.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));

  assert.doesNotMatch(text, /Hermes/i);
});
