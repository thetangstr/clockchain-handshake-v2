#!/bin/zsh
set -euo pipefail

readonly SCRIPT_DIR="${0:A:h}"
readonly REPO_ROOT="${SCRIPT_DIR:h}"
readonly NODE_BIN="${CLOCKCHAIN_NODE_BIN:-/opt/homebrew/opt/node@24/bin/node}"
readonly CODEX_LOG="${CLOCKCHAIN_CODEX_LIVE_LOG:-/tmp/clockchain-codex-live.log}"
readonly CLAUDE_LOG="${CLOCKCHAIN_CLAUDE_LIVE_LOG:-/tmp/clockchain-claude-live.log}"
readonly COMBINED_LOG="${CLOCKCHAIN_COMBINED_LIVE_LOG:-/tmp/clockchain-codex-claude-live.log}"
readonly TRACE_LOG="${CLOCKCHAIN_TRACE_LOG:-/tmp/clockchain-fresh-agent-trace.jsonl}"
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

# Import only the local Claude gateway credential, never user prompts, plugins, or agent state.
readonly CLAUDE_SETTINGS="${CLOCKCHAIN_CLAUDE_SETTINGS:-$HOME/.claude/settings.json}"
if [[ -z "${ANTHROPIC_BASE_URL:-}" && -z "${ANTHROPIC_AUTH_TOKEN:-}" && -r "$CLAUDE_SETTINGS" ]]; then
  export ANTHROPIC_BASE_URL="$($NODE_BIN -e 'const s=JSON.parse(require("node:fs").readFileSync(process.argv.at(-1),"utf8"));process.stdout.write(s?.env?.ANTHROPIC_BASE_URL??"")' "$CLAUDE_SETTINGS")"
  export ANTHROPIC_AUTH_TOKEN="$($NODE_BIN -e 'const s=JSON.parse(require("node:fs").readFileSync(process.argv.at(-1),"utf8"));process.stdout.write(s?.env?.ANTHROPIC_AUTH_TOKEN??"")' "$CLAUDE_SETTINGS")"
fi
export CLOCKCHAIN_MCP_RELEASE_MANIFEST_DIGEST="${CLOCKCHAIN_MCP_RELEASE_MANIFEST_DIGEST:-cc744e287f2f1dfc4b4b67ed460611543fc44c00c2385120cac1b37e28a56342}"
export CLOCKCHAIN_RESEARCH_RELEASE_MANIFEST_DIGEST="${CLOCKCHAIN_RESEARCH_RELEASE_MANIFEST_DIGEST:-cc744e287f2f1dfc4b4b67ed460611543fc44c00c2385120cac1b37e28a56342}"
export CLOCKCHAIN_MCP_HOST_ROOT_FINGERPRINTS="${CLOCKCHAIN_MCP_HOST_ROOT_FINGERPRINTS:-da2771c36bf2298525d2bbd8351b6122bb67115e9979624e8bb56537bcf71ed8}"
export CLOCKCHAIN_RESEARCH_HOST_ROOT_FINGERPRINTS="${CLOCKCHAIN_RESEARCH_HOST_ROOT_FINGERPRINTS:-da2771c36bf2298525d2bbd8351b6122bb67115e9979624e8bb56537bcf71ed8}"
export CLOCKCHAIN_RESEARCH_MONITOR_URL="http://44.249.47.220:8080/v1/sessions/{sessionId}/snapshot"
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
: >| "$TRACE_LOG"
chmod 600 "$TRACE_LOG"

clear
print 'Clockchain live production handshake'
print 'Two fresh clients: Codex (Terra) and Claude Code (Sonnet).'
print 'Original monitor: https://clockchain-research.vercel.app/handshake/claude-v6'
print

cd "$REPO_ROOT"
set +e
"$NODE_BIN" scripts/run-fresh-agent-handshake.mjs 2>&1 \
  | tee "$TRACE_LOG" \
  | "$NODE_BIN" scripts/present-live-tmux-events.mjs \
  | tee "$COMBINED_LOG"
exit_status=${pipestatus[1]:-1}
set -e
print
print "Live acceptance test finished with status ${exit_status}."
print "Redacted evidence directory: ${CLOCKCHAIN_FRESH_AGENT_RESULT_DIR}"
exit "$exit_status"
