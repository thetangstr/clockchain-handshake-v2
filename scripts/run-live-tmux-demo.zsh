#!/bin/zsh
set -euo pipefail

readonly SCRIPT_DIR="${0:A:h}"
readonly REPO_ROOT="${SCRIPT_DIR:h}"
readonly NODE_BIN="${CLOCKCHAIN_NODE_BIN:-/opt/homebrew/opt/node@24/bin/node}"
readonly CODEX_LOG="${CLOCKCHAIN_CODEX_LIVE_LOG:-/tmp/clockchain-codex-live.log}"
readonly CLAUDE_LOG="${CLOCKCHAIN_CLAUDE_LIVE_LOG:-/tmp/clockchain-claude-live.log}"
readonly COMBINED_LOG="${CLOCKCHAIN_COMBINED_LIVE_LOG:-/tmp/clockchain-codex-claude-live.log}"
readonly CLOCKCHAIN_INITIATOR_MODEL="${CLOCKCHAIN_INITIATOR_MODEL:-gpt-5.6-terra}"
readonly CLOCKCHAIN_RESPONDER_MODEL="${CLOCKCHAIN_RESPONDER_MODEL:-sonnet}"

if [[ ! -x "$NODE_BIN" ]] || [[ "$($NODE_BIN -p 'process.versions.node.split(".")[0]')" != 24 ]]; then
  print -u2 'Node 24 is required for the pinned local signing helper.'
  exit 24
fi

export PATH="${NODE_BIN:h}:/Applications/ChatGPT.app/Contents/Resources:/Users/Kailor/.local/bin:$PATH"
export CLOCKCHAIN_INITIATOR_CLIENT=codex
export CLOCKCHAIN_RESPONDER_CLIENT=claude
export CLOCKCHAIN_INITIATOR_MODEL
export CLOCKCHAIN_RESPONDER_MODEL
export CLOCKCHAIN_CLAUDE_EXISTING_LOGIN="${CLOCKCHAIN_CLAUDE_EXISTING_LOGIN:-1}"
export CLOCKCHAIN_MCP_RELEASE_MANIFEST_DIGEST="${CLOCKCHAIN_MCP_RELEASE_MANIFEST_DIGEST:-fa3c408a3739227b5bdb71486b4d291b8f4dffdb0d1f2fa79dd59644ba5e09ad}"
export CLOCKCHAIN_RESEARCH_RELEASE_MANIFEST_DIGEST="${CLOCKCHAIN_RESEARCH_RELEASE_MANIFEST_DIGEST:-fa3c408a3739227b5bdb71486b4d291b8f4dffdb0d1f2fa79dd59644ba5e09ad}"
export CLOCKCHAIN_MCP_HOST_ROOT_FINGERPRINTS="${CLOCKCHAIN_MCP_HOST_ROOT_FINGERPRINTS:-da2771c36bf2298525d2bbd8351b6122bb67115e9979624e8bb56537bcf71ed8}"
export CLOCKCHAIN_RESEARCH_HOST_ROOT_FINGERPRINTS="${CLOCKCHAIN_RESEARCH_HOST_ROOT_FINGERPRINTS:-da2771c36bf2298525d2bbd8351b6122bb67115e9979624e8bb56537bcf71ed8}"
export CLOCKCHAIN_RESEARCH_MONITOR_URL="${CLOCKCHAIN_RESEARCH_MONITOR_URL:-http://44.249.47.220:8080/v1/sessions/{sessionId}/snapshot}"
export CLOCKCHAIN_FRESH_AGENT_TRACE=1

if [[ -z "${CLOCKCHAIN_FRESH_AGENT_RESULT_DIR:-}" ]]; then
  export CLOCKCHAIN_FRESH_AGENT_RESULT_DIR="$REPO_ROOT/docs/evidence/live-tmux/$(date -u '+%Y-%m-%dT%H%M%SZ')"
fi
mkdir -p -m 700 "$CLOCKCHAIN_FRESH_AGENT_RESULT_DIR"

print 'Codex / Payer — Terra' >| "$CODEX_LOG"
print 'Waiting for the live run to start…' >> "$CODEX_LOG"
print >> "$CODEX_LOG"
chmod 600 "$CODEX_LOG"
print 'Claude Code / Requestor — Sonnet' >| "$CLAUDE_LOG"
print 'Waiting for the one-time invitation…' >> "$CLAUDE_LOG"
print >> "$CLAUDE_LOG"
chmod 600 "$CLAUDE_LOG"

clear
print 'Clockchain live production handshake'
print 'Two fresh clients: Codex (Terra) and Claude Code (Sonnet).'
print 'Original monitor: https://clockchain-research.vercel.app/handshake/claude-v6'
print

cd "$REPO_ROOT"
"$NODE_BIN" scripts/run-fresh-agent-handshake.mjs 2>&1 | "$NODE_BIN" --input-type=commonjs --eval '
const fs = require("node:fs");
const readline = require("node:readline");
const rl = readline.createInterface({ input: process.stdin });
const names = { initiator: "Codex / Payer", responder: "Claude Code / Requestor" };
const logs = {
  initiator: process.env.CLOCKCHAIN_CODEX_LIVE_LOG || "/tmp/clockchain-codex-live.log",
  responder: process.env.CLOCKCHAIN_CLAUDE_LIVE_LOG || "/tmp/clockchain-claude-live.log",
};
const seen = new Set();
function say(text, role = null, key = text) {
  const identity = `${role || "both"}:${key}`;
  if (seen.has(identity)) return;
  seen.add(identity);
  console.log(text);
  const targets = role === null ? Object.values(logs) : [logs[role]];
  for (const target of targets) fs.appendFileSync(target, `${text}\n`);
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
rl.on("line", (line) => {
  let event;
  try { event = JSON.parse(line); } catch { return; }
  const role = event?.role;
  const name = names[role] || "Agent";
  if (event?.schema === "clockchain.fresh-agent-canary-evidence/v1") {
    say("✓ Both fresh agents verified the same signed closing certificate.", null, "success-certificate");
    say(`✓ Session ${event.monitor.sessionId} completed on the original monitor.`, null, "success-monitor");
    say(`✓ Codex identity: ERC-8004 #${event.roles.initiator.erc8004.agentId}.`, "initiator", "identity-final");
    say(`✓ Claude identity: ERC-8004 #${event.roles.responder.erc8004.agentId}.`, "responder", "identity-final");
    return;
  }
  if (event?.phase === "configure" && event.status === "started") say(`${name}: connecting only to Clockchain MCP…`, role, "configure-start");
  if (event?.phase === "configure" && event.status === "completed") say(`${name}: connection ready.`, role, "configure-complete");
  if (event?.phase === "prepare" && event.status === "completed") say("Claude Code / Requestor: clean isolated session confirmed.", "responder", "prepare-complete");
  if (event?.phase === "spawn") say(`${name}: fresh agent started.`, role, "spawn");
  if (event?.phase === "continuation-spawn") say(`${name}: continuing the same isolated session (step ${event.turn}).`, role, `continue-${event.turn}`);
  if (event?.phase === "continuation-needed" && event.pendingHelperOperation) say(`${name}: reviewing the exact ${event.pendingHelperOperation} request against local policy.`, role, `review-${event.pendingHelperOperation}`);
  if (event?.phase === "adapter-checkpoint-submitted") say(`${name}: deterministic ${event.artifactType} checkpoint submitted after agent approval.`, role, `adapter-checkpoint-${event.artifactType}`);
  if (event?.phase === "event") {
    if (event.invitationObserved) say("Codex / Payer: invitation ready for Claude Code / Requestor.", "initiator", "invitation-ready");
    if (event.terminalObserved) say(`${name}: verified its closing certificate locally.`, role, "certificate-verified");
    toolMessages(event, role);
  }
  if (event?.phase === "observer-reject") say(`${name}: stopped safely (${event?.diagnostic?.code || "typed diagnostic"}).`, role, "observer-reject");
});
' | tee "$COMBINED_LOG"
exit_status=${pipestatus[1]:-1}
print
print "Live acceptance test finished with status ${exit_status}."
print "Redacted evidence directory: ${CLOCKCHAIN_FRESH_AGENT_RESULT_DIR}"
exit "$exit_status"
