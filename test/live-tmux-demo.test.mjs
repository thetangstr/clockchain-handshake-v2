import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

const launcherUrl = new URL("../scripts/start-live-tmux-demo.zsh", import.meta.url);
const presenterUrl = new URL("../scripts/present-live-tmux-events.mjs", import.meta.url);
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
  assert.match(source, /tmux -L \"\$TMUX_SERVER\" new-session -d -s \"\$CONTROLLER_SESSION\"/);
  assert.doesNotMatch(source, /respawn-pane -k -t \"\$CONTROLLER_SESSION/);
  assert.match(source, /tmux -L \"\$TMUX_SERVER\" clear-history -t \"\$CODEX_SESSION:0\.0\"/);
  assert.match(source, /tmux -L \"\$TMUX_SERVER\" clear-history -t \"\$CLAUDE_SESSION:0\.0\"/);
  assert.match(source, /wait-for-live-demo-funding\.zsh/);
});

test("live runner pins the production clients and retains public evidence", async () => {
  const source = await readFile(runnerUrl, "utf8");
  const presenter = await readFile(presenterUrl, "utf8");

  assert.match(source, /Codex \/ Payer — Terra/);
  assert.match(source, /Claude Code \/ Requestor — Sonnet/);
  assert.match(source, /CLOCKCHAIN_INITIATOR_MODEL=.*gpt-5\.6-terra/);
  assert.match(source, /CLOCKCHAIN_RESPONDER_MODEL=.*sonnet/);
  assert.match(source, /ANTHROPIC_BASE_URL/);
  assert.match(source, /ANTHROPIC_AUTH_TOKEN/);
  assert.match(source, /\.claude\/settings\.json/);
  assert.match(source, /CLOCKCHAIN_FRESH_AGENT_RESULT_DIR/);
  assert.match(source, /CLOCKCHAIN_TRACE_LOG/);
  assert.match(source, /tee "\$TRACE_LOG"/);
  assert.match(source, /export CLOCKCHAIN_RESEARCH_MONITOR_URL="http:\/\/44\.249\.47\.220:8080\/v1\/sessions\/\{sessionId\}\/snapshot"/);
  assert.match(source, /run-fresh-agent-handshake\.mjs/);
  assert.match(presenter, /adapter-checkpoint-submitted/);
  assert.match(presenter, /verified its closing certificate/);
  assert.match(source, /present-live-tmux-events\.mjs/);
  assert.doesNotMatch(source, /--input-type=commonjs --eval/);
  assert.match(presenter, /function safeAgentNarration/);
  assert.match(presenter, /event\.codexItem\?\.type === "agent_message"/);
  assert.match(presenter, /Array\.isArray\(event\.texts\)/);
  assert.match(presenter, /\[ROLE_ACCESS\].*\[SECRET\].*\[HEX_32\]/s);
  assert.match(presenter, /https\?:/);
  assert.match(presenter, /slice\(0, 600\)/);
  assert.match(presenter, /Agent says:/);
  assert.match(presenter, /formatTerminalReceiptCopy/);
  assert.match(presenter, /clockchain\.fresh-agent-canary-evidence\/v1/);
  const relaxedErrors = source.indexOf("set +e");
  const pipeline = source.indexOf('"$NODE_BIN" scripts/run-fresh-agent-handshake.mjs');
  const capturedStatus = source.indexOf("exit_status=${pipestatus[1]:-1}");
  assert.ok(relaxedErrors >= 0 && relaxedErrors < pipeline);
  assert.ok(source.indexOf("set -e", capturedStatus) > capturedStatus);
  assert.ok(source.indexOf("Live acceptance test finished with status") > source.indexOf("exit_status=${pipestatus[1]:-1}"));
});

test("verified success appends separate detailed receipt copies to both stable panes", () => {
  const parent = mkdtempSync(join(tmpdir(), "clockchain-terminal-receipts-"));
  try {
    const codexLog = join(parent, "codex.log");
    const claudeLog = join(parent, "claude.log");
    const certificateDigest = "d".repeat(64);
    const event = {
      schema: "clockchain.fresh-agent-canary-evidence/v1",
      monitor: {
        certificate: {
          digest: certificateDigest,
          issuedAtMs: Date.UTC(2026, 7, 13, 20, 52, 36),
          outcome: "VERIFIED",
        },
        receipts: {
          proposal: { blockHeight: "3560023", digest: "a".repeat(64), kind: "proposal", ledgerId: "1cd46000-2a55-4d25-bf14-7e2e2109aca0" },
          acceptance: { blockHeight: "3560033", digest: "b".repeat(64), kind: "acceptance", ledgerId: "62beab92-703c-4eed-87f2-6b8bba29aa46" },
          acknowledgment: { blockHeight: "3560037", digest: "c".repeat(64), kind: "acknowledgment", ledgerId: "b3c16c4d-f5fd-4f27-8861-556b7ff69b17" },
        },
        sessionId: "c3681923-e837-4774-9ea4-38a6d9736532",
        terms: {
          reference: "NS-1847",
          statement: "Northstar Logistics and Harbor Supply authorize these two independently controlled agents to communicate about shipment reference NS-1847 for 90 seconds.",
          statementDigest: "9".repeat(64),
          validForSeconds: "90",
        },
      },
      roles: {
        initiator: {
          address: "0x1111111111111111111111111111111111111111",
          certificateDigest,
          certificateVerified: true,
          erc8004: { agentId: "9621", registrationBlock: "11482629", registrationTx: `0x${"1".repeat(64)}` },
          externalBusinessActionPerformed: false,
        },
        responder: {
          address: "0x2222222222222222222222222222222222222222",
          certificateDigest,
          certificateVerified: true,
          erc8004: { agentId: "9622", registrationBlock: "11482630", registrationTx: `0x${"2".repeat(64)}` },
          externalBusinessActionPerformed: false,
        },
      },
    };
    const result = spawnSync(process.execPath, [presenterUrl.pathname], {
      encoding: "utf8",
      env: {
        ...process.env,
        CLOCKCHAIN_CLAUDE_LIVE_LOG: claudeLog,
        CLOCKCHAIN_CODEX_LIVE_LOG: codexLog,
      },
      input: `${JSON.stringify(event)}\n`,
    });
    assert.equal(result.status, 0, result.stderr);

    const codex = readFileSync(codexLog, "utf8");
    const claude = readFileSync(claudeLog, "utf8");
    assert.match(codex, /HANDSHAKE COMPLETE — PAYER COPY/);
    assert.match(codex, /ERC-8004 agent: #9621/);
    assert.match(codex, /Network: Ethereum Sepolia \(eip155:11155111\)/);
    assert.match(codex, /Registry contract: 0x8004A818BFB912233c491871b3d84c89A494BD9e/);
    assert.doesNotMatch(codex, /#9622/);
    assert.match(claude, /HANDSHAKE COMPLETE — REQUESTOR COPY/);
    assert.match(claude, /ERC-8004 agent: #9622/);
    assert.doesNotMatch(claude, /#9621/);
    assert.match(codex, /Accepted contract terms/);
    assert.match(codex, /Statement digest: 9{64}/);
    assert.match(claude, /Accepted contract terms/);
    for (const value of [
      certificateDigest,
      "1cd46000-2a55-4d25-bf14-7e2e2109aca0",
      "62beab92-703c-4eed-87f2-6b8bba29aa46",
      "b3c16c4d-f5fd-4f27-8861-556b7ff69b17",
    ]) {
      assert.ok(codex.includes(value));
      assert.ok(claude.includes(value));
    }
  } finally {
    rmSync(parent, { force: true, recursive: true });
  }
});

test("stable panes explain the mandate and ERC-8004 registration without exposing signing material", () => {
  const parent = mkdtempSync(join(tmpdir(), "clockchain-terminal-mechanics-"));
  try {
    const codexLog = join(parent, "codex.log");
    const claudeLog = join(parent, "claude.log");
    const input = [
      { phase: "configure", role: "initiator", status: "started" },
      { phase: "configure", role: "responder", status: "started" },
      { phase: "continuation-needed", role: "initiator", pendingHelperOperation: "register" },
      { phase: "continuation-needed", role: "responder", pendingHelperOperation: "register" },
    ].map((event) => JSON.stringify(event)).join("\n");
    const result = spawnSync(process.execPath, [presenterUrl.pathname], {
      encoding: "utf8",
      env: {
        ...process.env,
        CLOCKCHAIN_CLAUDE_LIVE_LOG: claudeLog,
        CLOCKCHAIN_CODEX_LIVE_LOG: codexLog,
      },
      input: `${input}\n`,
    });
    assert.equal(result.status, 0, result.stderr);

    for (const log of [readFileSync(codexLog, "utf8"), readFileSync(claudeLog, "utf8")]) {
      for (const fact of [
        "DEMO MANDATE · NS-1847",
        "Northstar Logistics and Harbor Supply authorize these two independently controlled agents to communicate about shipment reference NS-1847 for 90 seconds.",
        "Local policy: exact terms only · fresh ERC-8004 required · no external business action",
        "Ethereum Sepolia",
        "0x8004A818BFB912233c491871b3d84c89A494BD9e",
        "Clockchain-funded Sepolia test gas",
        "private key stays inside this isolated agent session",
      ]) assert.match(log, new RegExp(fact.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
      assert.doesNotMatch(log, /privateKey|roleAccess|payload-base64url/);
    }
  } finally {
    rmSync(parent, { force: true, recursive: true });
  }
});

test("funding watcher never creates an invitation before the two-seat threshold", async () => {
  const source = await readFile(watcherUrl, "utf8");

  assert.match(source, /REQUIRED_WEI=.*25000000000000000/);
  assert.match(source, /eth_getBalance/);
  assert.match(source, /if \(\( current_wei >= REQUIRED_WEI \)\)/);
  assert.match(source, /wait-for-live-invitation-window\.mjs/);
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
    "scripts/start-facilitator-demo-controller.zsh",
    "Start fresh demo",
  ]) assert.match(text, new RegExp(expected.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));

  assert.doesNotMatch(text, /Hermes/i);
});
