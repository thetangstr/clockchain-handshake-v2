import fs from "node:fs";
import readline from "node:readline";

import {
  TerminalReceiptCopyError,
  formatTerminalReceiptCopy,
} from "../src/testing/terminal-receipt-copy.mjs";

const names = Object.freeze({
  initiator: "Codex / Payer",
  responder: "Claude Code / Requestor",
});
const logs = Object.freeze({
  initiator: process.env.CLOCKCHAIN_CODEX_LIVE_LOG || "/tmp/clockchain-codex-live.log",
  responder: process.env.CLOCKCHAIN_CLAUDE_LIVE_LOG || "/tmp/clockchain-claude-live.log",
});
const seen = new Set();
const DEMO_REFERENCE = "NS-1847";
const DEMO_STATEMENT = "Northstar Logistics and Harbor Supply authorize these two independently controlled agents to communicate about shipment reference NS-1847 for 90 seconds.";
const ERC8004_REGISTRY = "0x8004A818BFB912233c491871b3d84c89A494BD9e";

function say(text, role = null, key = text) {
  const identity = `${role || "both"}:${key}`;
  if (seen.has(identity)) return;
  seen.add(identity);
  console.log(text);
  const targets = role === null ? Object.values(logs) : [logs[role]];
  for (const target of targets) fs.appendFileSync(target, `${text}\n`);
}

function safeAgentNarration(value) {
  if (typeof value !== "string") return null;
  const text = value.replace(/\s+/gu, " ").trim();
  if (text.length === 0) return null;
  if (["[ROLE_ACCESS]", "[SECRET]", "[HEX_32]"].some((marker) => text.includes(marker))) return null;
  if (/https?:/iu.test(text) || /\b[0-9a-f]{64}\b/iu.test(text) || /[A-Za-z0-9_-]{80,}/u.test(text)) return null;
  if (/^[\[{]/u.test(text) || /"schema"\s*:/iu.test(text)) return null;
  return text.slice(0, 600);
}

function showAgentNarration(event, role, name) {
  const values = [];
  if (event.codexItem?.type === "agent_message") values.push(event.codexItem.text);
  if (Array.isArray(event.texts)) values.push(...event.texts);
  for (const value of values) {
    const narration = safeAgentNarration(value);
    if (narration !== null) say(`${name} — Agent says: ${narration}`, role, `agent-narration-${narration}`);
  }
}

function showDemoContext(role) {
  say([
    `DEMO MANDATE · ${DEMO_REFERENCE}`,
    DEMO_STATEMENT,
    "Local policy: exact terms only · fresh ERC-8004 required · no external business action",
  ].join("\n"), role, "demo-context");
}

function showLocalOperation(role, operation) {
  const name = names[role] || "Agent";
  const explanations = {
    init: `${name} — Behind the scenes: creating a new local signing key; the private key stays inside this isolated agent session.`,
    policy: `${name} — Decision: comparing the exact mandate, 90-second limit, identity requirement, and no-action rule with local policy.`,
    inspect: `${name} — Behind the scenes: checking the local identity state before requesting another action.`,
    register: `${name} — Decision: fresh ERC-8004 registration is allowed. The local helper will submit to ${ERC8004_REGISTRY} on Ethereum Sepolia using Clockchain-funded Sepolia test gas; the private key stays inside this isolated agent session.`,
    sign: `${name} — Decision: the exact Clockchain-bound bytes match local policy, so this signature is allowed.`,
    "verify-certificate": `${name} — Behind the scenes: verifying the signed closing certificate and all three receipt references locally.`,
  };
  const explanation = explanations[operation];
  if (explanation !== undefined) say(explanation, role, `operation-${operation}`);
}

function toolMessages(event, role) {
  const blocks = Array.isArray(event.blocks) ? event.blocks : [event.codexItem];
  for (const block of blocks) {
    const tool = String(block?.tool || "");
    if (tool.endsWith("agent_handshake_invite")) say("Codex / Payer: opening the handshake and creating a one-time invitation.", "initiator", "invite");
    if (tool.endsWith("agent_handshake_accept_invitation")) say("Claude Code / Requestor: accepting the one-time invitation.", "responder", "accept-invitation");
    if (tool.endsWith("agent_handshake_join")) say(`${names[role]}: creating a fresh local identity.`, role, "join");
    if (tool.endsWith("agent_handshake_next")) say(`${names[role]}: asking Clockchain for its next permitted action.`, role, `next-${event.type || "event"}`);
    if (tool.endsWith("agent_handshake_submit_checkpoint")) say(`${names[role]}: recording the approved ${role === "initiator" ? "proposal" : "acceptance"} checkpoint.`, role, "checkpoint-tool");
    if (tool.endsWith("agent_handshake_submit")) say(`${names[role]}: submitting its independently approved proof.`, role, `submit-${event.type || "event"}`);
    if (tool.endsWith("agent_handshake_get_certificate")) say(`${names[role]}: retrieving the signed closing certificate.`, role, "certificate-get");
  }
}

function showReceiptCopies(event) {
  try {
    say(
      formatTerminalReceiptCopy(event, "initiator"),
      "initiator",
      "payer-receipt-copy",
    );
    say(
      formatTerminalReceiptCopy(event, "responder"),
      "responder",
      "requestor-receipt-copy",
    );
  } catch (error) {
    if (!(error instanceof TerminalReceiptCopyError)) throw error;
    say(
      "Receipt copy unavailable — verified evidence was incomplete.",
      null,
      "receipt-copy-unavailable",
    );
    process.exitCode = 1;
  }
}

function present(event) {
  const role = event?.role;
  const name = names[role] || "Agent";
  if (event?.schema === "clockchain.fresh-agent-canary-evidence/v1") {
    say("✓ Both fresh agents verified the same signed closing certificate.", null, "success-certificate");
    say(`✓ Session ${event.monitor.sessionId} completed on the original monitor.`, null, "success-monitor");
    say(`✓ Codex identity: ERC-8004 #${event.roles.initiator.erc8004.agentId}.`, "initiator", "identity-final");
    say(`✓ Claude identity: ERC-8004 #${event.roles.responder.erc8004.agentId}.`, "responder", "identity-final");
    showReceiptCopies(event);
    return;
  }
  if (event?.phase === "configure" && event.status === "started") {
    showDemoContext(role);
    say(`${name}: connecting only to Clockchain MCP…`, role, "configure-start");
  }
  if (event?.phase === "configure" && event.status === "completed") say(`${name}: connection ready.`, role, "configure-complete");
  if (event?.phase === "prepare" && event.status === "completed") say("Claude Code / Requestor: clean isolated session confirmed.", "responder", "prepare-complete");
  if (event?.phase === "spawn") say(`${name}: fresh agent started.`, role, "spawn");
  if (event?.phase === "continuation-spawn") say(`${name}: continuing the same isolated session (step ${event.turn}).`, role, `continue-${event.turn}`);
  if (event?.phase === "continuation-needed" && event.pendingHelperOperation) {
    say(`${name}: reviewing the exact ${event.pendingHelperOperation} request against local policy.`, role, `review-${event.pendingHelperOperation}`);
    showLocalOperation(role, event.pendingHelperOperation);
  }
  if (event?.phase === "adapter-checkpoint-submitted") say(`${name}: deterministic ${event.artifactType} checkpoint submitted after agent approval.`, role, `adapter-checkpoint-${event.artifactType}`);
  if (event?.phase === "event") {
    showAgentNarration(event, role, name);
    if (event.invitationObserved) say("Codex / Payer: invitation ready for Claude Code / Requestor.", "initiator", "invitation-ready");
    if (event.terminalObserved) say(`${name}: verified its closing certificate locally.`, role, "certificate-verified");
    toolMessages(event, role);
  }
  if (event?.phase === "observer-reject") say(`${name}: stopped safely (${event?.diagnostic?.code || "typed diagnostic"}).`, role, "observer-reject");
}

const input = readline.createInterface({ input: process.stdin });
input.on("line", (line) => {
  let event;
  try {
    event = JSON.parse(line);
  } catch {
    return;
  }
  present(event);
});
