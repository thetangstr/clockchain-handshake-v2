# Turnkey two-agent Hermes Handshake demo

This is the current operator path for demonstrating a bilateral Clockchain
Handshake with two newly created Hermes agents. The existing
`/handshake/claude-v6` presenter remains read-only and keeps its established
visual flow. The Mac mini launches the agents; it is not a Handshake party.
Clockchain is the host, funder, and independent checker; neither service holds a
party wallet or authors a party decision.

## What the command creates

Each run creates two disposable, disjoint clean rooms:

- one Payer Hermes process;
- one Requestor Hermes process;
- a new `HOME`, `HERMES_HOME`, workspace, package cache, MCP principal, EVM
  wallet, and ERC-8004 identity for each role;
- no inherited sessions, messages, contacts, memories, skills, shell startup,
  auth store, repository, dependencies, or wallet state.

The launcher records a secret-free pre-provision manifest before it reads the
inference credential or mints MCP tokens. It then proves that Hermes discovers
only the five Clockchain Handshake tools. Both agents clone the same pushed
40-character commit and run `npm ci` independently inside their empty
workspaces.

This is a measured application-state boundary, not a separate macOS account,
VM, container, or kernel sandbox.

## Public endpoints

| Endpoint | Method | Purpose | Expected unauthenticated result |
|---|---:|---|---|
| `https://mcp.clockchain.network/health` | GET | Canonical MCP health | `200` JSON |
| `https://mcp.clockchain.network/healthz` | GET | Health compatibility alias | `200` JSON |
| `https://mcp.clockchain.network/llms.txt` | GET | Agent connection guide | `200` text |
| `https://mcp.clockchain.network/install.txt` | GET | Install-guide alias | `200` text |
| `https://mcp.clockchain.network/.well-known/mcp.json` | GET | Machine-readable MCP manifest | `200` JSON |
| `https://mcp.clockchain.network/` | GET + `Accept: text/html` | Human landing page | `200` HTML |
| `https://mcp.clockchain.network/token` | POST | Mint a short-lived self-serve demo principal | `200` JSON, rate-limited |
| `https://mcp.clockchain.network/mcp` | POST / GET / DELETE | Canonical Streamable HTTP MCP transport | unauthenticated initialize returns `401` |
| `https://mcp-aws.clockchain.network/health` | GET | AWS hostname compatibility check | `200` JSON |

The MCP transport exposes exactly these Handshake tools to each demo agent:

1. `handshake_status`
2. `handshake_join`
3. `handshake_next`
4. `handshake_submit`
5. `handshake_get_certificate`

The relay is a separate protocol service, not an MCP REST surface:

| Endpoint | Purpose |
|---|---|
| `http://44.249.47.220:8080/healthz` | Relay/monitor health |
| `http://44.249.47.220:8080/v1/discovery/current` | Current hosted invitation |
| `http://44.249.47.220:8080/monitor/current` | Read-only stakeholder board |
| `https://clockchain-research.vercel.app/handshake/claude-v6` | Reused public demo presenter |

Read-only preflight checks (safe before a demo window):

```bash
curl --fail --silent --show-error https://mcp.clockchain.network/health
curl --fail --silent --show-error http://44.249.47.220:8080/healthz
curl --fail --silent --show-error http://44.249.47.220:8080/v1/discovery/current
curl --fail --silent --show-error https://clockchain-research.vercel.app/api/handshake/monitor
```

## Mac mini installation

Requirements:

- Node.js 22 or newer;
- the pinned Hermes 0.19.1 Mac build at
  `/Users/maxiaoer/.local/bin/hermes`;
- a reusable MiniMax China inference key stored as raw text in the mode-`0600`
  operator file `/Users/maxiaoer/.clockchain/hermes-demo/minimax-cn.key`;
- a clean checkout whose current branch HEAD exactly matches its live GitHub
  remote branch.

From the clean Mac-mini checkout:

```bash
npm ci
npm run demo:hermes
```

The second line is the single launch command. Operators reach this control
surface only through the authenticated Mac-mini account (normally over SSH);
the public presenter and relay board have no launch or signing authority.
Both disposable agents are pinned to provider `minimax-cn` and model
`MiniMax-M3`; no fallback provider is enabled.

The production wrapper derives a UUID run id, uses the canonical repository and
relay, verifies that the current commit is pushed, and retains sanitized public
evidence below `/Users/maxiaoer/.clockchain/hermes-demo/runs/<run-id>/evidence`.
`--dry-run` checks the pushed kit, both MCP origins, relay health, the current
host invitation/commit binding, and the secret-free pre-provision freshness
gate. It mints no MCP tokens and starts no agent. Run it before the first live
attempt:

```bash
npm run demo:hermes -- --dry-run
```

The launcher removes both disposable role roots after every success or
failure. It retains only sanitized evidence under the run's `evidence`
directory. To abandon a failed run, leave that evidence in place for diagnosis
and start a new command; never reuse a role root, MCP principal, wallet, or
Hermes session. Application rollback is the previous pushed Handshake commit,
previous AWS host image, and previous exact Vercel deployment; DNS does not
change for a demo run.

## What success means

Success is accepted only when all of the following agree:

- distinct Payer and Requestor MCP principal fingerprints;
- distinct locally generated EVM addresses and decimal ERC-8004 agent ids;
- one shared UUID session id;
- a real payer mandate and requestor payment request;
- proposal, acceptance, and acknowledgement Clockchain receipts;
- both party-result evidence packages;
- the host/checker's signed result envelope verifies against the discovery
  key;
- both agents report the same independently recomputed certificate digest;
- the verifier-derived outcome is authorized and `paymentMoved:false`;
- post-run manifests prove that each blank workspace cloned the pinned kit,
  installed dependencies, and created only its own mode-`0600` wallet;
- both disposable role roots are absent after cleanup.

The presenter never starts agents and never decides the result. It only renders
relay facts. The same page can be used to watch the two-agent run, while the
authenticated command stays on the Mac mini.

This is a single-validator testnet demonstration, not court-grade finality. No
payment moves; the verifier and retained certificate must both report
`paymentMoved:false`.

## Test record

On 2026-08-08, read-only probes verified both MCP hostnames, all documented
unauthenticated guide/manifest/health routes, relay health/discovery/monitor,
and the public presenter. An unauthenticated MCP initialize request returned the
expected `401`. A Vercel preview of the two-agent presenter passed its production
build, browser-rendered with Payer/Requestor/host-checker copy, excluded the
legacy party names, loaded snapshot schema `clockchain.handshake-snapshot/v1`,
and reported `paymentMoved:false`.

The production two-fresh-agent run record is appended here only after the
launcher, host deployment, both agent processes, certificate verification,
usage accounting, and cleanup all pass.
