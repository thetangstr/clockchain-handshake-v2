# Live Two-Agent Handshake and Facilitated Proposal

This runbook launches two genuinely fresh local agents—**Codex / Payer** as the buyer-side Initiator and **Claude Code / Requestor** as the provider-side Responder—and keeps the same independently controlled sessions alive for one Agent Contract-facilitated proposal exchange.

## What is live

1. Each agent creates a distinct fresh ERC-8004 identity backed by its own wallet.
2. The buyer creates a one-time invitation, and both agents use the live Clockchain Handshake MCP to independently approve their exact handshake actions.
3. Both verify the same Clockchain closing certificate.
4. Agent Contract validates the fresh certificate, within the 90-second Clockchain window, and creates a separate narrowly scoped proposal session.
5. The same Claude session resumes as provider and sends one signed proposal through its role-local A2A adapter.
6. The same Codex session resumes as buyer and sends one signed, nonbinding `received_for_review` acknowledgment.

The resumed Codex buyer uses automatic approval inside the existing workspace-write sandbox so its bounded role-local MCP calls can run noninteractively. The demo never uses the combined approvals-and-sandbox bypass.

Clockchain remains the trust path for identity and the direct handshake. Agent Contract is the separate communication and verification path for the commercial messages. The proposal and acknowledgment are not represented as authorized or anchored by Clockchain.

## Timing model

- Clockchain handshake and certificate-freshness boundary: 90 seconds.
- Agent Contract proposal session: no more than 10 minutes from activation.
- Proposal-session scope: provider discovery, exactly one provider proposal, and exactly one nonbinding buyer acknowledgment.
- Excluded: negotiation, agreement, payment, escrow, execution, work verification, settlement, and external business action.

## Before stakeholders arrive

The machine needs authenticated Codex and Claude Code CLIs, tmux, Internet access, and Node 24 at `/opt/homebrew/opt/node@24/bin/node`. The production host wallet must have at least 0.025 Sepolia ETH.

Start Agent Contract first at `http://127.0.0.1:3017` with a fresh absolute `DEMO_ROOT`, a local operator token, and a different read-only observer token.

Then export these values in the shell that launches the Continuum controller:

```sh
AGENT_CONTRACT_A2A_ENABLED=1
AGENT_CONTRACT_A2A_BASE_URL=http://127.0.0.1:3017
AGENT_CONTRACT_A2A_OPERATOR_TOKEN=<Agent Contract operator token>
```

The controller may use the operator token only to activate and export the session. The token must not enter prompts, role environments, traces, or retained evidence. Each role receives only its own ephemeral A2A capability and the public continuation digest.

## Start the facilitator controller

From this worktree:

```sh
scripts/start-facilitator-demo-controller.zsh
```

Open the public monitor:

`https://clockchain-research.vercel.app/handshake/claude-v6?live=1`

Keep the stable panes visible:

```sh
TMUX_TMPDIR=/tmp tmux -L clockchain-demo attach -t codex
TMUX_TMPDIR=/tmp tmux -L clockchain-demo attach -t claude
```

Preflight the controller:

```sh
curl -sS -H 'Origin: https://clockchain-research.vercel.app' http://127.0.0.1:43181/control/status
```

Proceed only when it reports `ready:true`.

## Start one fresh combined run

Use the monitor's **Start fresh demo** button or the loopback control endpoint once. The run must visibly proceed through:

1. fresh identities and registrations;
2. proposal, acceptance, and acknowledgment anchors;
3. one shared certificate verified by both agents;
4. Agent Contract activation before the certificate deadline;
5. provider card discovery and one provider-authored proposal;
6. buyer inbox review and one nonbinding acknowledgment; and
7. sanitized Agent Contract export verification.

The models choose and sign their own messages through role-local adapters. The harness transports exact requests and enforces the lifecycle; it does not generate the commercial terms or act for a party.

## Success evidence

Success requires both terminal panes to report the same verified certificate and the combined runner to return a `result.facilitatedA2A` object with:

- `provenance: live_a2a_facilitator`;
- the same Codex buyer and Claude provider identities used during the handshake;
- the exact Clockchain certificate digest;
- one continuation digest bound to both commercial signatures;
- one proposal task and one acknowledgment task; and
- all six verification checks true.

The redacted attempt is written under `docs/evidence/live-tmux/<UTC timestamp>/`. No raw role capability, invitation, signing key, operator token, model credential, or clean-room path may be retained.

## Failure and retry

If activation misses the 90-second deadline, the proposal session expires, either agent fails to resume, a signature or digest does not match, or more than the allowed messages appear, fail closed. Do not extend Clockchain's policy, backdate an event, reuse the invitation, or replay the identities. Fix the cause and start a new run.

## Verification

Run the complete suite with the required runtime:

```sh
/opt/homebrew/opt/node@24/bin/node --test --test-concurrency=4 test/*.test.mjs
```

The test claim is valid only when all tests pass on Node 24. Node 22 is intentionally rejected by the pinned release bootstrap.

## Cleanup

After the run, Continuum removes both private clean rooms. Stop or respawn the local controller before changing A2A configuration, clear the operator token from the environment, and preserve only the redacted public attempt artifact. A completed artifact is historical evidence; it cannot authorize another proposal.
