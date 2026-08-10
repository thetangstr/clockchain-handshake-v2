# Generic Two-Stakeholder Handshake Design

**Date:** 2026-08-09  
**Status:** Approved for implementation  
**Primary owner:** Clockchain Handshake  
**Dependent repositories:** `clockchain-developer-tools`, `clockchain-research`

## Objective

Build a production demonstration in which two people, on two separate computers,
use independently configured Codex or Claude Code agents to establish a generic
Clockchain Handshake. The Initiator shares one invitation with the Responder.
Each agent creates a local signing key, registers a fresh ERC-8004 identity during
the run, signs only its own generic handshake artifact, and verifies the same
closing certificate.

The demonstration establishes a verified agent-to-agent relationship. It does
not present, authorize, settle, or discuss a payment.

## Product statement

> Two stakeholders. Two computers. One verifiable handshake.

Northstar Logistics and Harbor Supply want independently controlled agents to
establish a verified working relationship. Northstar's Initiator creates an
invitation and sends it to Harbor. Harbor's Responder joins from a separate
computer. The agents register fresh ERC-8004 identities, approve the same shared
statement, and independently verify the certificate Clockchain issues after
checking the ordered record.

The first demonstration statement is:

> Northstar Logistics and Harbor Supply confirm that these two registered agents
> are authorized to communicate about shipment reference NS-1847 for the next
> 45 minutes.

## Locked constraints

1. Two people operate two separate computers.
2. Each computer runs its own Codex or Claude Code installation.
3. Each stakeholder has a distinct MCP principal and local signing key.
4. The Initiator shares an invitation, never an MCP token or signing key.
5. The Responder does not manually mint a general-purpose token. It exchanges a
   one-time invitation capability for a distinct, role- and session-scoped MCP
   credential.
6. ERC-8004 registration happens visibly during the demonstration.
7. The local key never crosses the stakeholder's computer boundary.
8. Clockchain MCP remains keyless and returns exact signing work to the agent.
9. No company IT or security-team onboarding is part of the demonstration.
10. The open-source Handshake kit supplies the already-built wallet bridge and
    registration code. No invented local companion product is introduced.
11. The current bilateral payment-authorization protocol remains available and
    byte-compatible. Generic mode is additive.
12. The accepted `/handshake/claude-v6` two-column layout and live-monitor
    placement remain intact.
13. Clockchain does not send email, SMS, or chat messages. The Initiator copies
    and sends the invitation through an existing channel.
14. The new generic public schemas contain no amount, currency, invoice,
    `payment_request`, `payer`, `payee`, or `paymentMoved` fields.

## Values and trust boundaries

The demonstration uses three different values. The page and prompts must name
them precisely.

| Value | Purpose | Shared? |
|---|---|---|
| MCP credential | Authenticates one agent to Clockchain MCP | Never |
| Invitation capability | Lets one Responder claim one role in one session | Initiator sends it to Responder |
| Local signing key | Owns the stakeholder's ERC-8004 identity and signs exact protocol bytes | Never |

The invitation capability is not a signing key. It cannot authorize a statement,
operate another session, claim the Initiator role, or call unrelated Clockchain
tools.

## Stakeholder journey

### Reproducible preflight

Each stakeholder has Git, Node.js, Codex or Claude Code, and internet access.
The research page shows separate, tested connection instructions for Codex and
Claude Code using the canonical MCP endpoint:

```text
https://mcp.clockchain.network/mcp
```

The Initiator uses a distinct self-serve testnet MCP credential. The Responder
receives a one-time invitation link after the Initiator starts the handshake and
exchanges it for a scoped credential. Neither stakeholder needs an existing
wallet, ERC-8004 identity, AWS access, cryptocurrency, JSON handoff files, or the
other stakeholder's filesystem.

### Timed demonstration

1. Northstar's stakeholder asks its configured agent to start a generic
   handshake for the locked statement and reference.
2. Clockchain binds the current live session and statement to the Initiator's
   principal and returns a one-time Responder link.
3. Northstar sends the link to Harbor through an existing communication channel.
4. Harbor opens the link and receives exact MCP configuration for a distinct,
   scoped Responder credential.
5. Each stakeholder pastes the role prompt shown on the research page.
6. Each agent checks out the exact Handshake repository commit advertised by the
   live discovery document and installs the pinned dependencies in its own clean
   work directory.
7. Each agent uses the existing wallet bridge to create a fresh local key.
8. Each signs its identity claim, receives testnet registration funding from the
   session host, and registers its own ERC-8004 identity.
9. The Initiator reviews and signs the shared statement proposal.
10. The Responder independently checks the exact statement, reference, parties,
    and validity window before signing acceptance.
11. Clockchain records proposal, acceptance, and acknowledgment in order.
12. Both agents sign and upload their own result evidence.
13. The independent checker verifies the identities, signatures, statement,
    timing, predecessor chain, receipts, and role separation.
14. Both agents fetch and locally verify the same signed generic certificate.

## Public MCP surface

Generic mode uses an additive tool namespace so a fresh agent cannot confuse it
with the existing payment-authorization workflow.

| Tool | Responsibility |
|---|---|
| `agent_handshake_invite` | Initiator binds a generic statement to the current session and receives a Responder invitation link |
| `agent_handshake_status` | Reads generic handshake progress for the authenticated principal |
| `agent_handshake_join` | Joins as `initiator` or `responder`; exact invitation and expected statement are mandatory |
| `agent_handshake_next` | Returns the next generic action or exact byte payload to sign |
| `agent_handshake_submit` | Accepts the caller-produced public EIP-191 signature for the pending action |
| `agent_handshake_get_certificate` | Returns the signed generic result envelope after terminal verification |

The existing five `handshake_*` payment-authorization tools and their schemas are
unchanged.

## Generic protocol schemas

### Terms

```json
{
  "reference": "NS-1847",
  "statement": "Northstar Logistics and Harbor Supply confirm that these two registered agents are authorized to communicate about shipment reference NS-1847 for the next 45 minutes.",
  "validForMinutes": 45
}
```

The fields are printable bounded strings (reference 128 characters, statement
256 characters to match the frozen canonical-string profile). `validForMinutes` is a decimal integer
string on the signed wire and a bounded integer only at the MCP input boundary.

### Roles

The public and signed role values are exactly `initiator` and `responder`.
Generic artifacts never use `payer`, `payee`, or `requestor` aliases.

### Party intent artifacts

The Initiator signs `clockchain.agent-handshake-proposal/v1`. It contains the
session id, repository SHA, Initiator and Responder ERC-8004 references, exact
reference, exact statement, issued-at time, expiry, and a false-by-construction
`externalActionPerformed` field.

The Responder signs `clockchain.agent-handshake-acceptance/v1`. It binds the same
session, parties, reference, statement digest, proposal digest, issued-at time,
and expiry. Its decision is exactly `ACCEPTED`.

`externalActionPerformed` exists only to state the generic invariant that the
handshake records authorization and performs no external business action. No
payment-specific invariant appears in generic schemas.

### Ordered anchors

The ledger transition schemas are:

- `clockchain.agent-handshake-transition/v1` / `PROPOSED`, sequence `1`, no
  predecessor.
- `clockchain.agent-handshake-transition/v1` / `ACCEPTED`, sequence `2`,
  predecessor equal to the proposal digest.
- `clockchain.agent-handshake-transition/v1` / `ACKNOWLEDGED`, sequence `3`,
  predecessor equal to the acceptance digest.

Every transition binds the protocol id, session digest, statement digest,
reference, two party references, expiry, and exact sequence. The acknowledgment
does not invent a third party signature; it records that hosted coordination
observed a valid acceptance.

### Result

The generic closing envelope contains
`clockchain.agent-handshake-result/v1` with:

- `outcome`: `VERIFIED` or a fixed fail-closed outcome.
- `sessionId` and `sessionDigest`.
- `reference` and `statementDigest`.
- `parties.initiator` and `parties.responder`, including address, ERC-8004 agent
  id, chain, registry, and full reference.
- the three ordered anchor receipts.
- `issuedAtMs`, `subjectRun`, and `externalActionPerformed:false`.

Both agents verify the host Ed25519 signature, exact discovery key, exact session,
their own party binding, `VERIFIED`, and `externalActionPerformed:false` before
displaying terminal success.

## Invitation capability and token exchange

### Creation

`agent_handshake_invite` requires an authenticated ordinary MCP principal and the
exact generic terms. It can bind only the current unclaimed generic session. It
returns:

- `invitationId` equal to the live session UUID.
- a human-safe join URL whose URL fragment contains a signed capability.
- expiry.
- a statement digest and public terms for comparison.

The capability payload is HMAC signed and contains exact keys:

```json
{
  "v": 3,
  "kind": "handshake_invitation",
  "invitationId": "<uuid>",
  "role": "responder",
  "statementDigest": "<sha256>",
  "iat": 0,
  "exp": 0,
  "jti": "<uuid>"
}
```

### Exchange

`POST /handshake/invitations/exchange` accepts the capability in a JSON body.
The server verifies signature, exact shape, expiry, current discovery session,
statement digest, role, and unused `jti`. It atomically marks the capability used
before returning a `kind:"handshake_session"` transport token scoped to the
same invitation and `responder` role.

The exchange response is `Cache-Control: no-store` and never echoes the original
capability. Failures use fixed error codes and do not reveal whether another
principal won a race.

### Scope enforcement

The scoped token:

- authenticates as its own principal through a unique signed `jti`;
- can call only the six `agent_handshake_*` tools;
- can join only its embedded invitation as `responder`;
- cannot use legacy payment tools or any non-handshake Clockchain tool;
- expires with the invitation;
- remains useless without a local signing key.

Single-use state is persisted in a mode-0600 file on the existing MCP state
volume so restart cannot make an exchanged capability reusable. Stored records
contain only capability hashes, invitation ids, roles, expiry, and consumed
timestamps; raw capabilities and transport tokens are never stored.

The capability is carried in the URL fragment so browsers do not send it in the
HTTP request line, referrer, proxy logs, or server access logs. Client-side code
posts it to the exchange endpoint and immediately removes it from browser history.

## Local signer and registration boundary

There is no new signer product. Fresh agents use the existing open-source
Handshake kit:

- `bin/wallet-bridge.mjs`
- `src/core/wallet-bridge.mjs`
- the existing ERC-8004 registration implementation and recovery checkpoints.

Generic mode adds no private-key handling to MCP or the research page. The wallet
bridge remains responsible only for initializing/inspecting the local wallet,
signing exact bytes, and registering the fresh ERC-8004 identity. The page and
prompts call this the "open-source Handshake kit," not a companion, wallet
product, or enterprise custody system.

The exact repository URL and immutable commit come from live discovery. Agents
must reject a checkout whose HEAD differs from discovery before creating a key or
joining a role.

## Host and independent checker

The AWS host supports an additive `HANDSHAKE_PROTOCOL` configuration:

- default `bilateral-payment-v1` preserves current production behavior;
- `agent-handshake-v1` runs the generic flow.

Generic host responsibilities are limited to opening discovery, funding the two
fresh identity registrations, receiving signed party artifacts, publishing the
descriptor, observing ordered anchors, receiving two evidence packages,
independently verifying them, signing one result, and opening the next session.

The host never creates a party key, signs a party artifact, decides acceptance
for the Responder, or exchanges the invitation on the Responder's behalf.

## Monitor and research presentation

Generic sessions publish `clockchain.agent-handshake-snapshot/v1`. It contains:

- `identities.initiator` and `identities.responder`;
- exact statement reference and digest;
- proposal, acceptance, and acknowledgment receipts;
- independent checker state and generic verdict;
- no payment-specific field or vocabulary.

The research route retains the current two-column shell and sticky live monitor.
The narrative is rewritten around:

1. Two stakeholders and two computers.
2. Reproducible Codex/Claude Code connection preflight.
3. One Initiator action that returns a copyable Responder invitation.
4. Two concise role prompts populated from the current generic snapshot.
5. Live ERC-8004 registration details for both agents.
6. Exact proposal, acceptance, acknowledgment, checker, and certificate evidence.
7. A clear statement that this demonstration establishes a handshake and does
   not initiate any later business action.

The page never embeds MCP credentials, invitation capabilities, private keys, or
raw evidence packages in HTML, analytics, logs, or static assets.

## Backward compatibility

The following remain unchanged:

- all existing bilateral payment schemas and pure modules;
- the five `handshake_*` payment tools;
- existing self-serve v1 and trial v2 token verification;
- existing payment host default;
- existing result and snapshot validators for payment sessions;
- historical evidence and routes.

Generic schemas, tools, host paths, token v3 types, and monitor adapters are new
modules or explicit protocol branches. No generic value is silently coerced into
a payment field.

## Failure behavior

The generic workflow fails closed when:

- the invitation is expired, malformed, already exchanged, for another session,
  or has a mismatched statement digest;
- a scoped token attempts another role, invitation, or tool;
- a role is already bound to another principal;
- the two stakeholder addresses are equal;
- identity ownership cannot be resolved on ERC-8004;
- statements, references, windows, signatures, predecessor digests, receipts, or
  repository pins differ;
- either evidence package is missing, duplicated, reordered, malformed, or late;
- the result signer, session, parties, outcome, or external-action invariant does
  not match local expectations.

No failure response echoes a raw token, capability, signature, private path, or
private key material.

## Verification gates

### Unit and contract gates

- Generic canonical bytes are deterministic and contain no payment vocabulary.
- Generic proposal, acceptance, transitions, descriptor, evidence, verdict, and
  result fail closed under mutation.
- Legacy payment fixtures remain byte-identical.
- Invitation capabilities reject tamper, expiry, replay, wrong session, wrong
  role, and digest mismatch.
- Scoped tokens cannot access unrelated tools or roles.
- Capability-consumption persistence survives process restart.
- Codex and Claude Code instructions contain the canonical endpoint, immutable
  repository pin, exact generic tools, and no secrets.
- Research static rendering contains the approved narrative and preserves the
  existing layout contract.

### Integrated local gate

Run a local relay, generic host, two distinct MCP principals, two fresh wallet
directories, and the generic MCP loop. Require two new ERC-8004 identities,
three anchors, a `VERIFIED` result, identical certificate digests, and both local
proofs. Delete disposable private state only after sanitized evidence is retained.

### Production gate

Deploy Handshake host first, MCP second, and Research last. Run two separately
configured fresh agents from separate work directories against production. The
Initiator must create the invitation and the Responder must enter through the
one-time exchange. The final page must hold the terminal generic snapshot and
show two full identities, three receipts, one verified certificate, and no
payment vocabulary.

## Non-goals

- Email, SMS, Slack, or Teams delivery.
- Legal-entity verification or durable company identity.
- Reusing identities across sessions.
- Mainnet deployment.
- Multi-validator rollout.
- Money movement, invoice authorization, settlement, or accounts-payable
  integration.
- Replacing the existing payment-authorization protocol.
