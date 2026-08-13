#!/bin/zsh
set -euo pipefail

readonly SCRIPT_DIR="${0:A:h}"
readonly RUNNER="$SCRIPT_DIR/run-live-tmux-demo.zsh"
readonly RPC_URL="${CLOCKCHAIN_SEPOLIA_RPC_URL:-https://ethereum-sepolia-rpc.publicnode.com}"
readonly HOST_ADDRESS="${CLOCKCHAIN_HOST_WALLET_ADDRESS:-0x157a377e4181f3f87c7f6eFED5ddC340cCc00DcE}"
readonly REQUIRED_WEI="${CLOCKCHAIN_LIVE_REQUIRED_WEI:-25000000000000000}"
readonly NODE_BIN="${CLOCKCHAIN_NODE_BIN:-/opt/homebrew/opt/node@24/bin/node}"

balance_wei() {
  local response
  response="$(curl -fsS "$RPC_URL" -H 'content-type: application/json' \
    --data "{\"jsonrpc\":\"2.0\",\"method\":\"eth_getBalance\",\"params\":[\"$HOST_ADDRESS\",\"latest\"],\"id\":1}")"
  "$NODE_BIN" -e 'const r=JSON.parse(process.argv[1]); if (!r.result) process.exit(1); process.stdout.write(BigInt(r.result).toString())' "$response"
}

format_eth() {
  "$NODE_BIN" -e 'const n=BigInt(process.argv[1]); const w=n/10n**18n; const f=(n%10n**18n).toString().padStart(18,"0").replace(/0+$/,""); process.stdout.write(`${w}.${f || "0"}`)' "$1"
}

clear
print 'Clockchain live demo controller'
print
print 'READY. No invitation has been created yet.'
print 'Waiting for enough Sepolia ETH to register two fresh ERC-8004 identities.'
print "Host wallet: $HOST_ADDRESS"
print 'Required balance: 0.025 Sepolia ETH'
print
print 'The visible Codex and Claude panes start automatically when funding is ready.'

while true; do
  if ! current_wei="$(balance_wei)"; then
    print "$(date '+%H:%M:%S')  Balance check unavailable; retrying safely."
    sleep 15
    continue
  fi
  print "$(date '+%H:%M:%S')  Current balance: $(format_eth "$current_wei") Sepolia ETH"
  if (( current_wei >= REQUIRED_WEI )); then
    print
    print 'Funding ready. Waiting for a fresh Clockchain session.'
    "$NODE_BIN" "$SCRIPT_DIR/wait-for-live-invitation-window.mjs"
    print 'Invitation window ready. Starting both fresh agents now.'
    exec "$RUNNER"
  fi
  sleep 15
done
