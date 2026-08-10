# Zero-Plugin Live ERC-8004 Agent Handshake Design

**Date:** 2026-08-10  
**Status:** Reviewed and locked; awaiting stakeholder implementation approval
**Primary owner:** Clockchain Handshake  
**Dependent repositories:** `clockchain-developer-tools`, `clockchain-research`  
**Authoritative baselines:** Handshake `63401f2`, MCP `bef6066`, Research `f81ea0f`

## 2026-08-10 Apple demo release override

For today's two-person Apple-device demonstration, the functional release gate is
one portable Node 24 bundle, not five native executables. Clockchain publishes the
exact canonical `manifest.json` bytes and `clockchain-agent-handshake.cjs`; MCP and
Research independently pin the SHA-256 of the manifest bytes and the manifest pins
the helper SHA-256. Each fresh Codex or Claude Code client verifies both hashes with
macOS `shasum` before running the bundle with `node`. No Apple Developer, Windows
signing, or npm publishing credential is required. Native signed desktop artifacts
remain an optional later distribution improvement; they are not a protocol or
production-agent requirement.

## Objective

Two people use separate, newly started Codex or Claude Code agents to establish
one generic Clockchain Handshake. The Initiator gives the Responder one
copy-and-paste invitation. From that point, both agents operate autonomously:
they create separate local identities and policies, register fresh ERC-8004
identities on Sepolia, sign only their own exact protocol bytes, and verify the
same host-signed certificate.

The stakeholder experience has no Clockchain plugin, repository checkout,
browser invitation flow, wallet interface, stakeholder MCP token, JSON handoff,
or per-signature human approval. The demonstration establishes identity and
agreement only. It performs no business action and contains no payment terms.

## Product statement

> Two people. Two local agents. One independently verifiable agreement.

Northstar Logistics wants its agent and Harbor Supply's agent to communicate
about shipment reference `NS-1847`. Northstar's Initiator asks Clockchain for a
90-second handshake and requires both agents to register fresh ERC-8004
identities. The Initiator copies the returned invitation into Harbor's separate
agent. Harbor's Responder applies its own local policy, accepts only the exact
statement, and completes the handshake without either stakeholder sharing a
key, account, workspace, agent memory, or MCP credential.

The demonstration statement is exactly:

> Northstar Logistics and Harbor Supply authorize these two independently
> controlled agents to communicate about shipment reference NS-1847 for 90
> seconds.

## Selected approach

Use a dedicated public, rate-limited, handshake-only Streamable HTTP MCP
endpoint plus a version-pinned, one-shot local CLI bundle for Node 24:

```text
https://mcp.clockchain.network/handshake/mcp
clockchain-agent-handshake 2.1.0
```

Codex and Claude Code connect directly to the remote MCP server. MCP server
instructions explain the cross-tool workflow. When local cryptography is
required, the agent downloads the checksum-pinned release asset to its private
working directory, verifies the pinned release manifest and asset digest, and
runs the CLI with Node 24 through its existing terminal tool. The CLI is assembled from the
current tested wallet bridge, registration recovery, canonical protocol
validators, and certificate verifier. It bundles its JavaScript dependencies and is not a
plugin, daemon, browser extension, repository clone, remote signer, or global
dependency installation.

### Rejected alternatives

- **Persistent Clockchain plugin:** rejected because it makes first use client-
  and installation-specific.
- **Repository checkout plus `node bin/wallet-bridge.mjs`:** retained as an
  engineering fallback, rejected as the stakeholder path because it exposes
  internal packaging and repository state.
- **Clockchain-held party signer:** rejected because Clockchain could impersonate
  either stakeholder.
- **Browser invitation exchange:** retained only for historical compatibility,
  rejected from the demonstration because the Responder uses an agent client.
- **OAuth or wallet sign-in:** rejected because it introduces a browser and a
  human authentication step.
- **Opening the existing full MCP surface without authentication:** rejected
  because the delegated Clockchain credential would expose unrelated tools.

## Locked constraints

1. The two roles are exactly `initiator` and `responder`.
2. Codex and Claude Code are equally supported first-class clients.
3. Both clients connect to the same hosted Streamable HTTP MCP endpoint.
4. A client must configure the endpoint before starting its fresh handshake
   session; a prompt cannot reliably add a new MCP server to an already-running
   client.
5. The endpoint exposes only the generic handshake tools.
6. Neither stakeholder obtains, stores, or shares a general-purpose MCP token.
7. The Initiator shares only the one-time Responder invitation.
8. Role access values are created and carried by the agents internally. They are
   role-, session-, statement-, tool-, and expiry-scoped and are never presented
   as user credentials.
9. Both local private keys remain on their originating computers.
10. The remote MCP never signs a stakeholder artifact.
11. Every signature is preceded by local schema, digest, session, role, terms,
    identity-requirement, and policy validation.
12. The demonstration requires a fresh live ERC-8004 registration for each role.
13. The protocol also supports an Initiator mandate in which ERC-8004 is not
    required; the demonstration does not exercise that branch.
14. The only human handoff after launch is copying the invitation from the
    Initiator client to the Responder client. There are no signing, registration,
    policy, or certificate approvals.
15. The invitation can be claimed for 120 seconds. The host session remains open
    for at most 10 minutes to accommodate testnet funding and registration. The
    signed business agreement is valid for exactly 90 seconds beginning when the
    proposal is issued.
16. The existing bilateral payment protocol and generic v1 production evidence
    remain byte-compatible and renderable.
17. The accepted `/handshake/claude-v6` two-column layout, sticky monitor, and
    evidence presentation remain intact.
18. No generic v2 public schema contains amount, currency, invoice,
    `payment_request`, `payer`, `payee`, `requestor`, or `paymentMoved`.
19. Both role access values expire at the immutable host session deadline, never
    later. Invitation claim still expires after 120 seconds; proposal terms still
    expire 90 seconds after proposal creation.
20. A per-session host key is trusted only through a root-signed session-key
    certificate whose root key is already pinned in the verified local helper.
    The MCP response alone is never a certificate trust root.

## Stakeholder run

### One-time client connection

Codex:

```bash
codex mcp add clockchain-handshake \
  --url https://mcp.clockchain.network/handshake/mcp
codex mcp list
```

Claude Code:

```bash
claude mcp add --transport http --scope user \
  clockchain-handshake https://mcp.clockchain.network/handshake/mcp
claude mcp list
```

Each person starts a new client session after the connection exists. The live
runbook supplies version-tested launch settings. Claude Code uses
`--strict-mcp-config`, `--permission-mode dontAsk`, an exact MCP tool allowlist,
and literal Bash patterns for the pinned manifest download, two fail-closed
`shasum -c` checks, asset download, `--version`, and six helper
operations. Codex uses a strict inline MCP profile, `workspace-write`, an empty
working directory, network enabled only for the agent run, MCP auto approval,
and `approval_policy=never` so failures stop rather than ask a person.

Codex does not currently expose Claude Code's literal per-command Bash-pattern
allowlist. The runbook says this plainly: the Codex no-human demonstration is
contained by the empty workspace/sandbox and the helper's cryptographic policy,
not by a claimed shell-command firewall. Production client fixtures pin the
exact supported client versions and fail if a launch setting is unknown.

Official client behavior is pinned to:

- [OpenAI Codex MCP documentation](https://learn.chatgpt.com/docs/extend/mcp?surface=cli)
- [Anthropic Claude Code MCP documentation](https://code.claude.com/docs/en/mcp)
- [Anthropic Claude Code permissions](https://code.claude.com/docs/en/permissions)

### Initiator prompt

```text
Use Clockchain to establish a handshake with Harbor Supply about shipment
NS-1847. The exact statement is: "Northstar Logistics and Harbor Supply
authorize these two independently controlled agents to communicate about
shipment reference NS-1847 for 90 seconds."

Require both agents to register fresh ERC-8004 identities. Create and enforce a
local policy that permits only this statement, reference, identity requirement,
90-second validity, and no external business action. Show me only the Responder
invitation; keep your role access private. Continue autonomously until you have
locally verified the final Clockchain certificate or a check fails.
```

### Responder prompt

```text
Use the configured Clockchain Handshake MCP to consume this invitation:
<PASTE THE INITIATOR INVITATION>

Create and enforce a local policy that allows only reference NS-1847, the exact
invited statement, at most 90 seconds of validity, fresh ERC-8004 registration,
and no external business action. If every check passes, accept and complete the
handshake autonomously. Otherwise refuse. Keep your role access private and
finish only after locally verifying the final Clockchain certificate.
```

The prompts describe business intent and local policy. They do not enumerate the
tool loop, mention repository files, embed JSON, or instruct the agent to invent
cryptographic behavior.

## Public handshake MCP boundary

### Dedicated endpoint

`/handshake/mcp` is handled before the existing `/mcp` authentication branch. It
constructs a separate MCP server named `clockchain-agent-handshake` and exposes
only the seven tools below. The existing authenticated `/mcp`, token minting,
BYO credentials, trial entitlements, payment tools, and other Clockchain tools
remain unchanged.

The public endpoint has independent limits:

- invitation creation: 5 per source IP per hour;
- tool calls: 120 per source IP per minute;
- one active role binding per capability;
- existing host session-capacity limits;
- no caller-controlled gateway endpoint or delegated credential override.

### Server instructions

The initialization `instructions` field is client-neutral and puts the complete
safety-critical workflow in its first 512 characters. It tells the agent to:

1. create or accept exactly one invitation;
2. keep role access values out of user-visible output;
3. fetch the release manifest, require its pinned digest, download only the
   matching platform asset, require the asset digest, and create a local
   identity and policy with that CLI;
4. call `join`, then loop over `next` and `submit`;
5. run live ERC-8004 registration only when the signed identity policy requires
   it;
6. give every signing request to the local CLI rather than signing or rewriting
   bytes itself;
7. fetch and locally verify the certificate;
8. stop on any mismatch, timeout, replay, unexpected tool, helper version, or
   schema.

### Tool surface

The public endpoint preserves the existing generic tool names and adds one
agent-native invitation exchange. Its v2 input contracts are intentionally
smaller than the existing authenticated v1 contracts.

| Tool | Input | Result |
|---|---|---|
| `agent_handshake_invite` | exact terms and identity policy | public Responder invitation, private Initiator role access, session facts |
| `agent_handshake_accept_invitation` | full copied invitation | private Responder role access and exact invited terms |
| `agent_handshake_join` | role access and local policy digest | root-signed host session-key certificate, session facts, first identity-signing stage |
| `agent_handshake_status` | role access | only that role's public progress |
| `agent_handshake_next` | role access and `gzip-base64url` | a wait state, registration requirement, or one exact local signing request |
| `agent_handshake_submit` | role access, signature, policy digest | the next committed role stage |
| `agent_handshake_get_certificate` | role access | closing certificate after server-side verification |

The role access encoding is
`base64url(canonical-json).base64url(hmac-sha256)`, without padding. Its exact
canonical payload contains `v`, `alg:"HS256"`,
`typ:"clockchain-agent-handshake-role-access"`,
`iss:"https://mcp.clockchain.network"`,
`aud:"clockchain-agent-handshake"`, `kid`, UUID `jti`, `sessionId`, `role`,
`statementDigest`, the exact allowed-tool array, decimal-string `nbfMs`, and
decimal-string `expMs`. `expMs` equals the host session deadline. Verification
uses a timing-safe comparison and accepts only the configured active or previous
`kid`; the SSM-backed secret for each key is at least 32 uniformly random bytes.
The server derives the coordinator principal from a SHA-256 digest of the
verified role access value and persists only digests and public binding facts.
Raw invitations and role access values are not written to disk or server logs.

The Initiator receives its role access when it creates the invitation. The
Responder receives a different role access only after
`agent_handshake_accept_invitation` atomically consumes the invitation. The
Responder cannot claim the Initiator role, and neither role access can operate
another session or the general MCP endpoint.

### Host trust chain

The production host still creates a fresh Ed25519 session key. Before publishing
discovery, it uses the configured Clockchain host-root key to sign an exact
`clockchain.host-session-key/v1` certificate containing the root `kid`, session
id, session public key, repository SHA, `validFromMs`, and `validUntilMs`. The
certificate validity cannot exceed the host session.

`clockchain-agent-handshake 2.1.0` embeds the accepted current and previous root
public keys and their SHA-256 fingerprints. It verifies the root signature and
certificate fields before accepting the per-session key returned by MCP, and it
uses that exact session key for descriptor and closing-certificate checks. Root
rotation deploys a new helper release and Research pin first, then MCP and host;
only current and previous keys are accepted during the bounded overlap. Unknown,
stale, not-yet-valid, or MCP-substituted keys fail before party signing.

## Generic v2 protocol

Generic v1 remains supported for existing production evidence. New sessions use
`clockchain.agent-handshake/v2`.

### Terms and identity mandate

```json
{
  "reference": "NS-1847",
  "statement": "Northstar Logistics and Harbor Supply authorize these two independently controlled agents to communicate about shipment reference NS-1847 for 90 seconds.",
  "validForSeconds": "90",
  "identityPolicy": {
    "erc8004": "required_fresh",
    "chainId": "eip155:11155111",
    "registryAddress": "0x8004a818bfb912233c491871b3d84c89a494bd9e"
  }
}
```

The protocol accepts three exact ERC-8004 policy values:

- `required_fresh`: each role must register a newly created local address during
  this session;
- `required_existing_or_fresh`: a role may prove ownership of an existing
  identity or register a new one;
- `not_required`: the EIP-191 session-key address is sufficient and ERC-8004
  fields are null.

The two required modes require the exact chain and registry strings.
`not_required` keeps the same exact-key identity-policy object but requires
`chainId:null` and `registryAddress:null`; it cannot carry a dormant registry
mandate.

The demonstration accepts only `required_fresh` on Sepolia. A fresh registration
means the registry transfer establishing ownership must occur after the session
opens and must resolve to the exact locally generated address.

### Party identity

Each signed v2 party object contains:

```json
{
  "sessionKeyAddress": "0x...",
  "policyDigest": "<sha256>",
  "erc8004": {
    "agentId": "9452",
    "chainId": "eip155:11155111",
    "registryAddress": "0x8004a818bfb912233c491871b3d84c89a494bd9e",
    "reference": "eip155:11155111:0x8004a818bfb912233c491871b3d84c89a494bd9e:9452",
    "registrationTx": "0x...",
    "registrationBlock": "..."
  }
}
```

`erc8004` is null only when the Initiator selected `not_required`. The session
key signs the identity claim, proposal or acceptance, and party evidence. The
host verifies ERC-8004 ownership but never controls the key.

### Policy binding

Before joining, each client creates an exact local policy:

```json
{
  "schema": "clockchain.agent-handshake-policy/v1",
  "protocol": "clockchain.agent-handshake/v2",
  "role": "initiator",
  "mcpOrigin": "https://mcp.clockchain.network",
  "reference": "NS-1847",
  "statementDigest": "<sha256>",
  "maxValidForSeconds": "90",
  "identityPolicy": {
    "erc8004": "required_fresh",
    "chainId": "eip155:11155111",
    "registryAddress": "0x8004a818bfb912233c491871b3d84c89a494bd9e"
  },
  "externalBusinessActionsAllowed": false
}
```

The Responder policy differs only in `role`. Its digest is bound into the role's
identity claim and every later signed party artifact. The certificate includes
both policy digests. This proves which policy each agent committed to; it does
not claim that an external hardware policy engine enforced it.

### Existing protocol reuse

Generic v2 reuses the current proposal, acceptance, acknowledgment, descriptor,
three ordered anchors, two evidence packages, independent checker, and
host-signed result structure. V2 adds the identity mandate, session-key-first
party shape, policy digests, and second-based validity. It does not create a new
business action or a third stakeholder signature.

## One-shot local CLI

`clockchain-agent-handshake 2.1.0` is published as one audited portable CommonJS
bundle for Node 24. CI builds and executes that bundle on a pinned Node 24 Linux
runner, attests its provenance, and publishes it with an exact-key canonical
manifest containing version, source commit, build runtime, asset URL, byte length,
SHA-256, and public execution evidence. The manifest explicitly records
`nativeSignature.type:"none"`; this release makes no native code-signing or
notarization claim. Signed native packages and npm distribution are future
convenience work, not part of today's stakeholder or production gate.

The release lifecycle is intentionally non-circular. A reviewed helper source
commit is created first without naming its future artifact digest. CI builds an
asset whose manifest names that source commit. A separate post-release pin
commit then records the final manifest digest, asset-host allowlist, helper
version, and host-root fingerprints in the Handshake release record, MCP
instructions/well-known manifest, and Research prompt data. The helper artifact
never claims its own future manifest digest.

The Research runbook is the stakeholder's independent manifest-digest source;
MCP supplies the same value as a cross-check, not as local-code authority. An
agent must reject any disagreement before downloading or executing an asset. The
portable asset's digest must then match the sole manifest entry. Stakeholder Macs
must have Node 24 available; no npm login, repository checkout, native-signing
credential, or global Clockchain installation is required.

The release contains only the tested local identity, registration, policy,
signing-request, and certificate-verification code. It has no updater, plugin
loader, telemetry, network destination override, or general command-execution
surface.

The release build first produces one auditable JavaScript bundle and rejects any
unexpected dynamic import, filesystem module lookup, or dependency outside that
bundle. This is required because the portable entry script cannot treat an arbitrary
stakeholder filesystem as its package tree.

The CLI operations are:

- `init`: create a new EVM-compatible session identity in a mode-0700 directory
  and mode-0600 state file;
- `policy`: canonicalize the prompt-derived local policy and return its digest;
- `inspect`: return only the public address, policy digest, and public
  registration checkpoint;
- `register`: execute or recover the existing ERC-8004 registration for the
  exact local address;
- `sign`: validate the complete MCP signing request against local state and
  policy, then sign the exact decompressed bytes with EIP-191;
- `verify-certificate`: pin the host key, session, role, party, policy digest,
  outcome, and external-action invariant before returning terminal proof.

The agent chooses a fresh state directory inside its empty working directory.
The CLI never prints the private key, raw role access, or private paths. Every
failure emits one generic code and exits nonzero. Registration checkpoints are
durable so a process interruption cannot cause an ambiguous duplicate
registration.

MCP returns structured signing requests, never arbitrary shell. The client
instructions allow only the exact release manifest, asset, digest, executable
version, and operation. If the MCP requests another executable, version,
registry, chain, state path, signature encoding, or operation, the agent stops.

## Host and checker

The existing AWS generic host remains the session host and independent checker.
For `required_fresh`, it funds only the exact two newly claimed session-key
addresses with testnet registration gas, posts role-tagged funding records, and
requires registration receipts later than session creation. For
`required_existing_or_fresh`, it funds only when the exact address lacks an
owned identity. For `not_required`, it performs no identity funding or registry
lookup.

Funding is reserved atomically before the first transfer: at most 0.01 Sepolia
ETH per address, once per session address; at most 0.02 per `required_fresh`
session; at most 0.20 per rolling hour and 1.00 per UTC day across the public v2
surface. Exhaustion or queue backpressure fails the session before either role is
funded. The restart-safe budget ledger stores only public address, session,
amount, and transaction facts. Production alerts fire before the hourly or daily
ceiling.

The host still never creates a party key, signs a party artifact, chooses a
Responder decision, or operates role access. It verifies both local signatures,
policies, identity requirements, registration ownership and timing, exact terms,
ordered receipts, evidence packages, and external-action invariant before
issuing one certificate.

## Research page and preserved demo

`/handshake/claude-v6` keeps its existing page composition, two-column layout,
sticky monitor, typography, evidence drawers, detailed ERC-8004 identity links,
and certified-run fallback. Only the setup and business narrative change.

The page shows:

1. the exact Codex and Claude Code connection commands;
2. a statement that a new client session is required after connection;
3. the two short prompts above;
4. a copy/paste invitation handoff, with no browser-open instruction;
5. live state for local policy committed, key created, ERC-8004 registration,
   proposal, acceptance, three anchors, independent verification, and
   certificate;
6. complete ERC-8004 agent id, owner address, chain, registry, reference,
   registration transaction, and block for both roles;
7. a clear statement that the handshake performs no external business action.

The current browser join route and authenticated generic v1 setup remain
reachable for historical evidence but are no longer linked as the primary demo
path. A static version marker identifies the preserved v1 runbook so the prior
demonstration remains reproducible.

### Monitoring contract

The monitor is a read-only witness of relay and verifier facts. Generic v2 adds
`clockchain.agent-handshake-snapshot/v2`; the Research monitor proxy and parser
accept both generic v1 and v2 without coercing either into the bilateral payment
snapshot.

The v2 snapshot exposes only public facts:

- session id, protocol version, immutable repository revision, host session key,
  host-root `kid` and fingerprint, session-key certificate digest, creation time,
  invitation expiry, session deadline, and signed agreement window;
- invitation-created and Responder-claimed timestamps, never invitation or role
  access values;
- each role's policy digest and policy-committed timestamp;
- each role's session-key address and full optional ERC-8004 object;
- registration transaction and block for each required fresh identity;
- proposal and acceptance envelope digests;
- the proposal, acceptance, and acknowledgment receipts independently;
- evidence receipt for each role, checker stage, verdict, certificate digest,
  and certificate issue time;
- `externalBusinessActionPerformed:false`.

Every visible completion state is derived from its exact artifact. A later
status, anchor, verdict, or certificate must not fabricate a missing earlier
artifact. In particular, funding does not imply registration, registration does
not imply policy acceptance, and a certificate does not backfill a missing
receipt card. `FAILED` marks the first unresolved fact and displays only its
public reason code.

The same-origin monitor route continues polling the relay server-side so browser
CORS and the relay's HTTP origin remain hidden from stakeholders. It strictly
validates complete v1 and v2 snapshots, never forwards browser cookies or
headers, and returns the current live run unless that run is pristine and the
newest completed compatible run is available. That certified-run fallback must
continue to hold the last demonstration after the host opens the next session.

The page shows connectivity and freshness separately for Initiator, Responder,
host, and checker. A stale heartbeat is labeled stale; it does not change a
cryptographic artifact's completed state. Monitor rendering, polling, drawers,
copy buttons, registry links, and receipt links are tested independently from
the protocol producer.

The page also consumes a same-origin readiness route. Until the deployed public
endpoint passes initialization, exact seven-tool inventory, pinned manifest/root
metadata, rate-limit, and invitation canaries, the page keeps the accepted layout
but labels the live path unavailable and disables copyable live prompts. Enabling
the page is a distinct deployment action after those canaries pass.

## Failure behavior

The system fails closed when:

- the public endpoint receives a non-handshake tool request;
- invitation or call rate limits are exceeded;
- an invitation is malformed, expired, replayed, or bound to other terms;
- a role access value has the wrong signature, role, session, tool, terms, or
  expiry;
- a role access value has an unknown algorithm, type, issuer, audience, `kid`,
  non-canonical encoding, weak signing configuration, or session-later expiry;
- two roles resolve to the same local address or ERC-8004 identity;
- a local policy, helper version, package, action, schema, byte digest, host key,
  role, session, statement, validity, identity mandate, or external-action flag
  differs;
- the Research and MCP release pins differ, the asset leaves the allowed release
  origin, or the host session key does not verify under an embedded current or
  previous root;
- fresh ERC-8004 ownership was established before session creation or resolves
  to another address;
- funding, proposal, acceptance, descriptor, transition, evidence, or
  certificate records are missing, duplicated, reordered, malformed, or late;
- an atomic funding reservation, queue, hourly ceiling, or daily ceiling cannot
  be satisfied before either role is funded;
- either client cannot verify the identical final certificate locally.

Failure responses do not echo private keys, role access, invitation
capabilities, signatures, private paths, package-cache paths, or provider
credentials.

## Verification gates

### Contract gates

- Generic v1 and bilateral payment fixtures remain byte-identical.
- Generic v2 canonical bytes contain no payment vocabulary.
- All v2 schemas are exact-key and mutation-tested.
- `required_fresh`, `required_existing_or_fresh`, and `not_required` take the
  correct funding, ownership, and certificate branches.
- The public endpoint lists exactly seven tools and rejects every full-surface
  tool.
- Invitation and role access values reject tamper, replay, wrong role, wrong
  session, wrong tool, wrong statement, and expiry.
- Role access rejects every non-canonical/unknown algorithm, type, issuer,
  audience, key id, timing, rotation, or weak-secret case and expires exactly at
  the host session deadline.
- The local helper verifies a root-signed host session-key certificate against
  its embedded current/previous key ring before any party signature.
- MCP initialization returns the complete pinned server instructions.
- The portable release bundle executes under Node 24 in a clean environment
  without npm installation, a repository checkout, or a global Clockchain installation.
- Local policy tests prove that a validly signed but disallowed statement,
  duration, identity mode, external action, host, session, role, or helper
  version never reaches the signing function.
- Codex and Claude Code prompt contracts contain the same endpoint, terms,
  helper version, autonomy boundary, and certificate requirement.
- Client launch tests enforce Claude's literal tool/command patterns and Codex's
  strict empty-workspace sandbox while clearly retaining the documented Codex
  command-pattern limitation.
- Public funding tests atomically enforce address/session/hour/day ceilings and
  stop before a partial two-seat funding state.
- Research rendering preserves the accepted layout and contains no clone,
  plugin, browser-open, wallet-sign-in, token-mint, JSON-handoff, payment, or
  per-signature approval instruction.
- Monitor producer, strict proxy parser, view-model, and rendered-page tests prove
  v1/v2 coexistence, exact-artifact progression, independent role freshness,
  full ERC-8004 registration detail, receipt-by-receipt display, public failure
  behavior, and newest-certified-run fallback.
- Research readiness tests keep live prompts disabled until independent release
  pin, host-root, public-tool, rate-limit, invitation, and cross-client canaries
  pass.

### Local integration gate

Run the real generic v2 coordinator against a local relay, host, registry/RPC
fixtures, and two isolated client homes. Drive only the public handshake MCP
endpoint and the packed one-shot CLI. Require distinct role access, local keys,
policy digests, addresses, ERC-8004 ids, three anchors, evidence packages, and
one certificate. Require the two terminal certificate digests to match. Poll the
same Research monitor route during the run and assert each artifact becomes
visible only after the corresponding relay or verifier record exists.

### Fresh-client compatibility gate

Run two production-facing rehearsals from clean disposable client homes:

1. Codex Initiator with Claude Code Responder.
2. Claude Code Initiator with Codex Responder.

Each client has an empty working directory, no project instructions, no plugin,
no Clockchain repository, no prior Clockchain state, and only the handshake MCP
connection. Model-provider authentication may be supplied externally but is not
copied into retained evidence. Each run must create two new ERC-8004 identities
and complete from the exact stakeholder prompts without a signing approval.

### Production gate

Deploy in order: one-shot CLI release, Handshake host, MCP server, Research
site. Verify health and tool inventory before the public endpoint is announced.
Run both cross-client rehearsals against production. Retain only public session,
identity, policy-digest, registration, anchor, certificate, version, and test
evidence. Roll back Research first, MCP second, and host last; the authenticated
generic v1 and bilateral paths remain available throughout rollback.

## Non-goals

- Payment, settlement, invoicing, or accounts-payable behavior.
- Browser, email, SMS, Slack, or Teams invitation delivery.
- A persistent Clockchain plugin, daemon, extension, or wallet interface.
- Legal-entity verification or company IT/security onboarding.
- Mainnet deployment.
- Multi-validator expansion.
- Hardware-backed key custody in this iteration.
- Concurrent unbounded public sessions; the existing host capacity remains the
  production ceiling for this demonstration.
