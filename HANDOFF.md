# Handoff — two-agent build + AWS migration

**As of:** 2026-08-07 · **Branch:** `main` · **872 tests pass, all 10 structural
invariants hold.** The previous handoff (still valid for context, landmines §4, known
gaps §5, and the stakeholder-prompt lesson §6) is archived at
[docs/handoff-2026-08-04.md](docs/handoff-2026-08-04.md).

## What you are executing

**[docs/two-agent-execution-plan.md](docs/two-agent-execution-plan.md).** That document
is the work. Every design decision in it is already made and validated; your job is to
execute it task by task, in order, passing each Verify block before moving on. Its §0
executor contract binds you; its §6 pitfall register is fifteen ways this exact system
has already failed. Do not redesign. When a STOP trigger fires, write it into §Blockers
below and stop.

Context behind the plan, if you need it: [docs/two-agent-build.md](docs/two-agent-build.md)
(locked decisions D1–D5, verified infrastructure map, phase rationale).

## State of play

| Piece | Status |
|---|---|
| Closing certificate (`src/core/result.mjs`, relay result endpoint, both parties fetch+verify) | ✅ shipped `4d096f1`, live-verified (blocks 3057376/3057397/3057399, agents 9427/9428) |
| Role-aware seating (`roleAlreadySeated`, unblocks two kits per session) | ✅ shipped `f80aa7a` |
| Track A (A1–A8): host severance + payer kit + gates G0/G1 | ⬜ next — start at A1 |
| Track B (B0–B6): MCP → AWS migration, gate GM | ⬜ parallel — start at B0 |
| P2 / P3 / P4 | ⬜ gated on both tracks |

Both tracks are independent until P2. Work them in parallel if you can; if you must pick
one, Track B's first steps (B0–B2) have the longest external waits — start them first,
then do Track A while AWS/DNS steps settle.

## Environment facts you'll need on day one

- Run everything from `/Users/Kailor/Documents/Projects/handshake`. `npm run verify`
  = tests + invariants; it gates every commit.
- `keys/` is gitignored and exists only on this laptop: funding wallet keystore +
  password file + Clockchain token. Treasury `0x157a377e…dce` had ~2.09 testnet ETH on
  08-04; **the new host funds two seats per run (~0.02 + gas)** — check balance in
  `npm run preflight` before gate runs.
- Relay box: `ssh -i ~/.ssh/handshake-relay.pem ubuntu@44.249.47.220`, code at
  `/opt/handshake/app`, service `handshake-relay`. Deploy = rsync + restart (exact
  commands in plan §A7).
- AWS: account `570035913370`, IAM user `Yang`, CLI signed in, region us-west-2.
- Clockchain MCP source: `github.com/thetangstr/clockchain-developer-tools` — clone it
  (plan §B0); it is not on this machine yet.
- Token mints: 10/hour/IP. Budget them around gates.

## Waiting on Yang (the only external dependencies)

1. **GoDaddy visit #1** (plan §B3): add `mcp-aws.clockchain.network` A-record → the new
   Elastic IP, and lower TTL on `mcp.clockchain.network` to 600. Ask once B2 yields the IP.
2. **GoDaddy visit #2** (plan §B5): flip `mcp.clockchain.network` → Elastic IP, in an
   agreed no-demo window.
3. **GCP stays billed/warm** through cutover and until a separate decommission decision.

## Blockers

*(append dated entries here; format: what you ran, what you expected, what you saw)*

- 2026-08-07 — A3 legacy live verification initially appeared blocked before
  session creation, but both earlier failures shared the same unsupported
  environment-variable mistake: `HANDSHAKE_KEYSTORE` is ignored by
  `bin/operator.mjs`; the operator needs `--keystore`. The corrected local-relay
  run used `HANDSHAKE_RELAY=http://127.0.0.1:18788
  CLOCKCHAIN_FUNDING_PASSWORD_FILE=/Volumes/mac_studio_ssd/Projects/handshake/keys/funding.password
  npm run demo -- --keystore
  /Volumes/mac_studio_ssd/Projects/handshake/keys/funding-wallet.json`, then
  `bin/requestor.mjs` against the local discovery URL. The legacy operator's
  untagged funding record was accepted, the requestor registered identity
  `9430`, and the verifier completed `AUTHORIZED` for session
  `4408a633-55f2-438a-8824-7c46bc4db255`. Blocks: proposal `3080317`,
  acceptance `3080337`, acknowledgment `3080339`.

## Evidence

*(gate results land here: gate id, date, session id, block heights, anything a skeptic
would ask for)*

- 2026-08-07 — certificate path (pre-G0 live run): session verified end-to-end, operator
  published certificate, requestor + independent third read both verified it against the
  descriptor key. Blocks 3057376 / 3057397 / 3057399, agents 9427 / 9428.

## Migration inventory

*(plan §B0's table gets filled in here — every row, even when the answer is "none")*

Inventory source: `clockchain-developer-tools` commit
`bef177bdf93f1d36fbbe0a2a787121518eb3d3eb` (2026-08-07).

| Question | Answer |
|---|---|
| Language/runtime + listen port | TypeScript / Node ESM. The container runs Node 20 and `packages/mcp-server/dist/index.js`. HTTP listens on `PORT`, then `MCP_PORT`, then `3000`; Cloud Run and the Dockerfile use `8080`. |
| How does it reach the chain node (`node.clockchain.network`)? Pull or push? | Outbound request/response from MCP to `CLOCKCHAIN_ENDPOINT` (default `https://node.clockchain.network`): GETs for reads and POSTs for writes. The node does not push inbound to MCP. |
| Where do token quotas live (memory / file / external store)? | Static tokens are configuration; self-serve tokens are stateless HMAC tokens. Mint quotas and log-credit budgets are in-memory, per-process maps. |
| Where do receipts/ledger ids live? | The caller receives receipt payloads; ledger records and ids live on Clockchain and are read through its `/ledger` / chain APIs. The MCP has no receipt database. |
| Env vars + secrets the container needs (names, where GCP stores them) | Required core values: `CLOCKCHAIN_API_KEY`, `CLOCKCHAIN_CLIENT_ID`, `CLOCKCHAIN_WALLET_ID`; hosted configuration also sets `MCP_TRANSPORT`, `MCP_REQUIRE_AUTH`, `MCP_RATE_PER_MIN`, `MCP_LOG_BUDGET`, `MCP_TOKEN_MINT_PER_HOUR`, `MCP_TOKEN_TTL_DAYS`, and `CLOCKCHAIN_ENDPOINT`. Optional chain settings: `EVM_RPC_URL`, `ERC8004_CHAIN`, `ERC8004_REGISTRY_ADDRESS`. GCP Secret Manager supplies `clockchain-api-key`, `mcp-auth-tokens`, and `mcp-token-signing-secret`; B1 replaces those with SSM SecureStrings. |
| Does it use ANY GCP-managed service (Firestore, GCS, Cloud SQL, Memorystore, Pub/Sub)? | Deployment uses Cloud Run, Cloud Build, Artifact Registry, Secret Manager, Cloud Armor, and Cloud Logging/Monitoring. It uses none of Firestore, GCS, Cloud SQL, Memorystore, Pub/Sub, or any other application datastore. Default session/account state is memory; optional `MCP_SESSION_FILE` is local JSON; the documented DynamoDB store is not implemented. The B0 stateful-data STOP trigger did not fire. |
| Does it stream (SSE/websocket) on the MCP endpoint? | Streamable HTTP can return SSE and clients advertise `application/json, text/event-stream`. No websocket server was found. |
| Health endpoint | Unauthenticated `GET /health` and `GET /healthz`, returning `{"status":"ok"}` before auth or gateway access. |

### B2 provisioned host (2026-08-07)

| Resource | ID / value |
|---|---|
| AWS account / region | `570035913370` / `us-west-2` |
| EC2 instance | `i-0d6765d143da7e1ea` — `t3.small`, running, status checks green |
| Ubuntu AMI | `ami-0ac74609c6396bed3` — Canonical Ubuntu 24.04 LTS amd64 gp3 |
| VPC / subnet / AZ | `vpc-0aa12e33b416f8a90` / `subnet-0098c0ad31cc55dab` / `us-west-2d` |
| Private / Elastic IP | `172.31.50.64` / `34.209.199.138` |
| EIP allocation / association | `eipalloc-01233aceb0e395e04` / `eipassoc-04b63a9427c4addfb` |
| Security group | `sg-019cf9e090977a49f` (`clockchain-mcp-sg`): 80/443 public; 22 from `172.12.143.34/32` only |
| Root volume | `vol-0d84c8180aa7d2dff` — 20 GiB encrypted gp3, delete on termination |
| EC2 key pair | `clockchain-mcp` / `key-0cf030c5ba260d457`; private key at `~/.ssh/clockchain-mcp.pem` mode 0600 |
| IAM role | `arn:aws:iam::570035913370:role/clockchain-mcp-ec2-role` |
| Instance profile | `arn:aws:iam::570035913370:instance-profile/clockchain-mcp-instance-profile` |
| Inline role policy | `clockchain-mcp-ssm-parameter-read`: `ssm:GetParameter` on `arn:aws:ssm:us-west-2:570035913370:parameter/clockchain/mcp/*` only |
| SSM verification parameter | `/clockchain/mcp/PING` (`SecureString`, `alias/aws/ssm`) |

Bootstrap evidence: cloud-init completed; Docker, Compose, AWS CLI v2, git, and jq are
installed; `docker run --rm hello-world` passed; the instance read the PING parameter
through its role; `/home/ubuntu/.aws` is absent; IMDSv2 is required with hop limit 2.
Provisioning source is `clockchain-developer-tools` commit `6da3fc9`.
