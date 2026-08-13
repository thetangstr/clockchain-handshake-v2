# Live two-stakeholder tmux demo

This is the facilitator runbook for the real production acceptance test. It
uses two genuinely fresh local agents: **Codex / Payer** with Terra and
**Claude Code / Requestor** with Sonnet. The agents remain separately visible
from the one-time invitation through the shared closing certificate.

## Before the stakeholders arrive

The Mac Studio needs authenticated Codex and Claude Code CLIs, tmux, Internet
access, and the pinned **Node 24** runtime at
`/opt/homebrew/opt/node@24/bin/node`. The stakeholder does not clone this
repository, install a plugin, manage a wallet, or copy a long signing command.
The harness creates an isolated workspace and wallet for each party, while the
agent independently decides whether each exact Clockchain request matches its
local policy.

The production host wallet must have at least 0.025 Sepolia ETH. The launcher
checks this before creating a session, so an invitation cannot expire while the
demo waits for testnet funding.

## Prepare the facilitator control

Before the audience arrives, start the loopback-only controller once from the
repository root:

```sh
scripts/start-facilitator-demo-controller.zsh
```

Then open the original research monitor:

https://clockchain-research.vercel.app/handshake/claude-v6?live=1

Only this Mac Studio sees **Facilitator controller ready**. Every other viewer
gets the same read-only monitor but cannot launch production.

## Start the fresh run

Open or keep these two stable terminal sessions visible for the stakeholders:

```sh
TMUX_TMPDIR=/tmp tmux -L clockchain-demo attach -t codex
TMUX_TMPDIR=/tmp tmux -L clockchain-demo attach -t claude
```

The first pane is **Codex / Payer**. The second is **Claude Code / Requestor**.
Click **Start fresh demo** at the top of the monitor. That one click clears the
old board, resets the two stable panes, checks the two-seat Sepolia balance,
and starts the existing production Codex and Claude Code runner. There is no
second start command and no stale invitation to paste. If the panes do not yet
exist on a newly prepared machine, click Start first, then attach to them as
soon as the button reports **Demo started**.

While a controller run is active, the button stays locked across page reloads.
If a local run stops while its server session is still open, the page says
**Previous run stopped** and **Waiting for session to close** instead of
pretending the run is live. The button unlocks automatically after that
time-bounded session closes. Never click around the lock or restart the tmux
controller manually; doing so would replace the evidence-producing process.

## What the audience should see

1. Codex opens the handshake and creates the one-time invitation.
2. Claude Code accepts that invitation as the independent Requestor.
3. Each isolated agent creates a different local key and a fresh ERC-8004
   registration. The host funds only the two exact registration seats.
4. Codex approves the proposal only if it matches the Payer policy.
5. Claude Code independently approves the acceptance only if it matches the
   Requestor policy.
6. The harness transports each approved action exactly and records the ordered
   proposal and acceptance checkpoints; the model never rewrites signing bytes.
7. Clockchain observes the anchors, receives both evidence packages, runs the
   independent checker, and publishes one signed closing certificate.
8. Both agents locally verify that same certificate. The original monitor must
   show the same session, identities, receipts, checker result, and certificate.

The run is not successful merely because both identities registered. It is
successful only after both panes say that the closing certificate was verified
and the runner saves a redacted public evidence artifact under
`docs/evidence/live-tmux/`.

At completion, each stable terminal also prints a detailed stakeholder receipt
copy. The Codex pane shows the Payer's ERC-8004 registration proof; the Claude
pane shows the Requestor's. Both copies show the same signed certificate and
the proposal, acceptance, and acknowledgment ledger references. These copies
come from the verified public evidence object and never include private keys,
role access, provider credentials, or local state paths.

## Record the tutorial master

For the tutorial recording, use one 16:9 macOS screen recording with the
research monitor and both stable terminal windows visible. Start recording
before clicking **Start fresh demo** and keep recording until both terminals
show their complete stakeholder receipt copies. The editor can crop and zoom
this one synchronized master into monitor, Codex, and Claude Code close-ups
without asking the protocol to run again.

## If the run stops

Do not reuse an invitation or a disposed identity. The runner saves a typed,
redacted diagnostic and removes both private clean rooms. Fix the causal defect,
then start a new run with two new identities. Never substitute another harness,
a shared wallet, or a host-authored party action for this acceptance test.
