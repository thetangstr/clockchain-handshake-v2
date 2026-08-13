#!/bin/zsh
set -euo pipefail

readonly SCRIPT_DIR="${0:A:h}"
readonly TMUX_SERVER="${CLOCKCHAIN_TMUX_SERVER:-clockchain-demo}"
readonly CODEX_SESSION="${CLOCKCHAIN_CODEX_TMUX_SESSION:-codex}"
readonly CLAUDE_SESSION="${CLOCKCHAIN_CLAUDE_TMUX_SESSION:-claude}"
readonly CONTROLLER_SESSION="${CLOCKCHAIN_CONTROLLER_TMUX_SESSION:-clockchain-controller}"
readonly CODEX_LOG="${CLOCKCHAIN_CODEX_LIVE_LOG:-/tmp/clockchain-codex-live.log}"
readonly CLAUDE_LOG="${CLOCKCHAIN_CLAUDE_LIVE_LOG:-/tmp/clockchain-claude-live.log}"
export TMUX_TMPDIR="${TMUX_TMPDIR:-/tmp}"

command -v tmux >/dev/null
[[ -x "${CLOCKCHAIN_NODE_BIN:-/opt/homebrew/opt/node@24/bin/node}" ]]
command -v codex >/dev/null
command -v claude >/dev/null

print 'Codex / Payer — Terra' >| "$CODEX_LOG"
print 'READY. Waiting for the controller to start the production run.' >> "$CODEX_LOG"
print 'Claude Code / Requestor — Sonnet' >| "$CLAUDE_LOG"
print 'READY. Waiting for the one-time invitation.' >> "$CLAUDE_LOG"
chmod 600 "$CODEX_LOG" "$CLAUDE_LOG"

if tmux -L "$TMUX_SERVER" has-session -t "$CODEX_SESSION" 2>/dev/null; then
  tmux -L "$TMUX_SERVER" respawn-pane -k -t "$CODEX_SESSION:0.0" "tail -n +1 -F '$CODEX_LOG'"
else
  tmux -L "$TMUX_SERVER" new-session -d -s "$CODEX_SESSION" "tail -n +1 -F '$CODEX_LOG'"
fi
if tmux -L "$TMUX_SERVER" has-session -t "$CLAUDE_SESSION" 2>/dev/null; then
  tmux -L "$TMUX_SERVER" respawn-pane -k -t "$CLAUDE_SESSION:0.0" "tail -n +1 -F '$CLAUDE_LOG'"
else
  tmux -L "$TMUX_SERVER" new-session -d -s "$CLAUDE_SESSION" "tail -n +1 -F '$CLAUDE_LOG'"
fi
if tmux -L "$TMUX_SERVER" has-session -t "$CONTROLLER_SESSION" 2>/dev/null; then
  tmux -L "$TMUX_SERVER" respawn-pane -k -t "$CONTROLLER_SESSION:0.0" "$SCRIPT_DIR/wait-for-live-demo-funding.zsh"
else
  tmux -L "$TMUX_SERVER" new-session -d -s "$CONTROLLER_SESSION" "$SCRIPT_DIR/wait-for-live-demo-funding.zsh"
fi
tmux -L "$TMUX_SERVER" clear-history -t "$CODEX_SESSION:0.0"
tmux -L "$TMUX_SERVER" clear-history -t "$CLAUDE_SESSION:0.0"
tmux -L "$TMUX_SERVER" clear-history -t "$CONTROLLER_SESSION:0.0"

print 'Clockchain live tmux demo is ready.'
print
print "Codex / Payer:       TMUX_TMPDIR=$TMUX_TMPDIR tmux -L $TMUX_SERVER attach -t $CODEX_SESSION"
print "Claude / Requestor:  TMUX_TMPDIR=$TMUX_TMPDIR tmux -L $TMUX_SERVER attach -t $CLAUDE_SESSION"
print "Controller:          TMUX_TMPDIR=$TMUX_TMPDIR tmux -L $TMUX_SERVER attach -t $CONTROLLER_SESSION"
print
print 'Original monitor: https://clockchain-research.vercel.app/handshake/claude-v6'
