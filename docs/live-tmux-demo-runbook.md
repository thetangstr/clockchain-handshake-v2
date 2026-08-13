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

## Start the stable panes

From the repository root, run:

```sh
scripts/start-live-tmux-demo.zsh
```

The command creates or reuses three stable tmux sessions. Open these two for
the stakeholders:

```sh
TMUX_TMPDIR=/tmp tmux -L clockchain-demo attach -t codex
TMUX_TMPDIR=/tmp tmux -L clockchain-demo attach -t claude
```

The first pane is **Codex / Payer**. The second is **Claude Code / Requestor**.
The controller waits offstage. As soon as funding is sufficient it starts both
fresh agents automatically; there is no separate “start the demo” command and
no stale invitation to paste.

Keep the original research monitor open:

https://clockchain-research.vercel.app/handshake/claude-v6

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

## If the run stops

Do not reuse an invitation or a disposed identity. The runner saves a typed,
redacted diagnostic and removes both private clean rooms. Fix the causal defect,
then start a new run with two new identities. Never substitute another harness,
a shared wallet, or a host-authored party action for this acceptance test.
