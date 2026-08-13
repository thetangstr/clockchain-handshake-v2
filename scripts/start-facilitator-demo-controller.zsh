#!/bin/zsh
set -euo pipefail

readonly SCRIPT_DIR="${0:A:h}"
readonly PROJECT_DIR="${SCRIPT_DIR:h}"
readonly NODE_BIN="${CLOCKCHAIN_NODE_BIN:-/opt/homebrew/opt/node@24/bin/node}"
readonly TMUX_SERVER="${CLOCKCHAIN_TMUX_SERVER:-clockchain-demo}"
readonly CONTROL_SESSION="${CLOCKCHAIN_CONTROL_TMUX_SESSION:-clockchain-facilitator-control}"
readonly CONTROL_LOG="${CLOCKCHAIN_CONTROL_LOG:-/tmp/clockchain-facilitator-control.log}"
readonly CONTROL_ENTRY="$PROJECT_DIR/bin/facilitator-demo-control.mjs"
export TMUX_TMPDIR="${TMUX_TMPDIR:-/tmp}"

command -v tmux >/dev/null
[[ -x "$NODE_BIN" ]]
[[ -f "$CONTROL_ENTRY" ]]

: >| "$CONTROL_LOG"
chmod 600 "$CONTROL_LOG"

readonly CONTROL_COMMAND="exec '$NODE_BIN' '$CONTROL_ENTRY' >> '$CONTROL_LOG' 2>&1"
if tmux -L "$TMUX_SERVER" has-session -t "$CONTROL_SESSION" 2>/dev/null; then
  tmux -L "$TMUX_SERVER" respawn-pane -k -t "$CONTROL_SESSION:0.0" "$CONTROL_COMMAND"
else
  tmux -L "$TMUX_SERVER" new-session -d -s "$CONTROL_SESSION" "$CONTROL_COMMAND"
fi
tmux -L "$TMUX_SERVER" clear-history -t "$CONTROL_SESSION:0.0"

print 'Facilitator Start control is ready.'
print 'Local endpoint: http://127.0.0.1:43181/control/status'
print "Controller log: $CONTROL_LOG"
