# Direct A2A Bootstrap Design

## Status

Approved amendment to the supervised fresh-agent mechanics proof. This design corrects a bootstrap contradiction discovered after Phase 6B without weakening the locked authority boundary.

## Problem

The existing signed A2A channel cannot carry the first Responder invitation in a live run:

1. the Initiator creates a one-time, host-signed Clockchain invitation;
2. the Responder needs that invitation before it can accept the session and create its session-bound party identity;
3. the current A2A channel requires both party-signed Agent Cards before it will carry any artifact;
4. a party-signed Responder card therefore cannot exist early enough to carry the invitation that creates its session context.

The same live path also lacks a bounded way for the party's existing local signer to sign the Agent Card and additive commitment checkpoint. The Test Director must not solve either problem by forwarding the invitation, holding a party key, or signing an artifact.

## Decision

Use a two-stage direct party channel.

### Stage 1: TLS-pinned invitation bootstrap

Each party runtime creates its own ephemeral TLS key/certificate and a separate ephemeral Ed25519 bootstrap key inside the runtime boundary. The Test Director may exchange only the two public endpoints, certificate fingerprints, bootstrap public keys, runtime identifiers, and workload-attestation digests. It never receives either private key.

The Initiator's party-local adapter observes the authoritative `agent_handshake_invite` MCP result and sends the exact opaque invitation directly to the Responder's private bootstrap endpoint. The Test Director and Clockchain do not receive or route that HTTP body. The Responder consumes the invitation once and passes it unchanged to `agent_handshake_accept_invitation`.

Every bootstrap transport instance is immutably bound to the mechanics-proof `runId`, local and peer roles, runtime identifiers, workload-attestation digests, public endpoints, TLS certificate fingerprints, the local bootstrap public key plus a private sign callback, and the expected peer bootstrap public key. The callback accepts canonical request bytes only; the transport never receives or exports the bootstrap private key.

The live Clockchain `sessionId` does not exist when the Responder listener starts. The transport therefore uses a fail-closed one-time session bind instead of asking the Test Director to learn or forward the invitation:

- the Initiator binds its transport to the `sessionId` returned with its authoritative invitation result;
- the first otherwise-valid signed invitation request atomically binds the Responder transport to that same `sessionId`;
- `agent_handshake_accept_invitation` must return the identical `sessionId` before card bootstrap can begin;
- every later bootstrap request must carry the already-bound value, and rebinding is forbidden.

Each HTTP request carries a canonical signed envelope with exactly these unsigned fields:

```text
schema, version, artifactKind, method, path,
runId, sessionId,
senderRole, receiverRole,
senderRuntimeId, receiverRuntimeId,
senderWorkloadAttestationDigest, receiverWorkloadAttestationDigest,
senderBootstrapPublicKey, receiverBootstrapPublicKey,
receiverPublicEndpoint, receiverCertificateSha256,
bodySha256, bodyLength,
issuedAtMs, expiresAtMs, nonce, jti
```

The Ed25519 signature and algorithm are appended outside the canonical unsigned payload so a signature never signs itself. The receiver verifies the exact key set and values, method/path, its own endpoint and certificate pin, sender and receiver identities, body digest and byte length, bounded time window, unique nonce/jti, configured sender bootstrap public key, and signature before reading the body as an invitation or card. Cross-run, cross-session, swapped-role, swapped-runtime, swapped-workload, endpoint, certificate, and key substitution all fail closed.

The bootstrap endpoint:

- accepts only `POST /a2a/v1/bootstrap/invitations` over HTTPS;
- requires the sender/client to pin the configured receiver TLS certificate fingerprint before transmitting a body;
- requires the receiver/server to authenticate the canonical request with the configured sender bootstrap public key;
- accepts one bounded invitation and rejects replay;
- returns only its SHA-256 digest as acknowledgment;
- retains the raw invitation in party-private memory only until one `takeInvitation()` call;
- exposes public evidence containing digests, timestamps, peer pin, and delivery direction, never the invitation.

Local Docker isolation supplies the network boundary for rehearsal. Fargate uses private subnets, `assignPublicIp: DISABLED`, paired security groups, and collected task/workload evidence. TLS and bootstrap-key pinning are additional peer bindings; neither is treated as AWS workload identity or party identity.

### Stage 2: party-signed card bootstrap

After the Responder accepts the invitation and both parties create their local signer state:

1. the Responder creates a signed Agent Card with `peerCardDigest: null` and sends it directly over the same TLS-pinned bootstrap connection;
2. the Initiator verifies the Responder card, signs its own Agent Card with `peerCardDigest` equal to the Responder card digest, and sends it directly back;
3. the Responder verifies that Initiator pin;
4. both parties instantiate the existing `createHttpTaskTransport()` with the verified card pair;
5. bootstrap endpoints stop accepting new invitation/card material.

This preserves the existing deterministic asymmetric card bootstrap and avoids an impossible mutual-digest cycle.

### Party-local derived signing

The existing Clockchain helper remains the sole executor for MCP-returned `init`, `policy`, `register`, protocol signing, and certificate verification steps. Production helper version `2.1.2` and the deployed MCP release pin are unchanged.

A new Clockchain-owned party authority module may use the same runtime-private wallet only for two derived A2A signatures:

- sign the exact Agent Card binding the already-created party address, role, live session, runtime/workload facts, TLS endpoint, delegated A2A card public key, expiry, nonce, and jti;
- sign an additive commitment checkpoint only after independently verifying the exact existing v2 proposal or acceptance envelope signed by that same party.

The module has no arbitrary-sign API. It never returns a private key. It rejects any role, session, signer, policy, artifact, endpoint, workload, expiry, or digest mismatch. Signing a checkpoint does not create a new business decision; it binds an already party-signed authoritative v2 artifact to the direct A2A evidence chain.

The delegated A2A card key is generated separately inside the runtime and signs transport envelopes only. It is never the party key and cannot satisfy Clockchain party signature checks. The earlier bootstrap key is retired after the signed card pair is established.

### Private retained-action completion binding

The existing retained-action recorder already validates the exact MCP-returned helper command and rewrites it to the runtime-private helper/state paths. The live adapter will additionally retain the verified signing-request bytes and bind each action to a party-private Unix-domain completion socket. Phase 6C0 supports Linux and macOS only; it fails closed on other platforms. This covers the local Mac rehearsal and Linux Docker/Fargate proof without pretending a Unix socket is portable to Windows. A future Windows adapter must use a separately reviewed named-pipe implementation.

The completion socket lives under a validated mode-`0700` party-private root. Creation and cleanup use `lstat`/no-follow checks, enforce a platform-safe socket-path byte bound, reject symlink or non-socket collisions, and unlink only the exact owned socket inside that root. A stale path is removed only when it is an owned socket under that validated root; the socket module never recursively deletes a directory. Framing is one bounded newline-terminated JSON object per connection with connect/read/write deadlines, one action per connection, per-action nonce plus command/request-digest replay protection, generic external failures, and deterministic `close()` that stops accepting, drains or rejects the active action, closes the server, and removes only its socket.

The authorization wrapper captures the helper's bounded public JSON result and sends `{actionId, actionNonce, commandSha256, signingRequestSha256, result}` to that socket before writing the result to agent stdout. The party bridge correlates it to the signed retained action and private signing request. It reconstructs the exact proposal or acceptance envelope, verifies it, sends it over direct A2A, and signs the derived checkpoint. Only after the peer acknowledges the direct send does the socket return success and the wrapper release the signature result to the agent. The Test Director sees only digests and delivery acknowledgments. A terminal/model/Bash result that is not correlated to a signed retained action cannot create an A2A artifact.

This ordering makes the direct peer delivery causal rather than a post-hoc mirror:

```text
MCP signing request -> verified retained helper action -> local signature result
  -> direct A2A send + peer acknowledgment -> additive checkpoint
  -> MCP signature submission -> existing Clockchain authority flow
```

The production MCP coordinator must accept the additive checkpoint on the existing role/session-bound submission path, or through an equally bounded additive tool, before Phase 6C1 can pass. The wrapper withholds the signature from the agent until direct delivery succeeds; the MCP submission therefore cannot precede direct acknowledgment. Production checkpoint wiring is a later gate; Phase 6C0 does not claim it already exists.

## Live data flow

1. Test Director provisions two isolated runtimes and exchanges only public bootstrap configuration.
2. Responder bootstrap listener starts; Responder agent process has not started.
3. Initiator Codex ACP starts with production Clockchain MCP.
4. Initiator creates the one-time invitation.
5. Initiator party adapter sends it directly to Responder bootstrap; only invitation digest becomes public evidence.
6. Responder takes the invitation and starts Claude ACP with that exact invitation in its private prompt.
7. Both agents accept/join, commit their local policy, create fresh signer state, sign identity claims, and complete live ERC-8004 registration when mandated.
8. Responder card is signed and sent; Initiator card pins it and is sent back; bootstrap keys are retired.
9. Existing direct signed A2A transport starts.
10. Existing v2 proposal and acceptance remain the business-authority artifacts. The retained-action completion path sends each verified signed envelope directly to the peer and creates its additive signed checkpoint before MCP submission.
11. Clockchain receives the existing canonical artifacts plus additive checkpoints, anchors proposal -> acceptance -> acknowledgment, verifies both evidence packages, and issues one certificate.
12. Both parties verify the same certificate locally; Test Director collects sanitized public evidence and tears both runtimes down.

## Authority boundaries

The Test Director may:

- choose harness/runtime pair and public network configuration;
- exchange public endpoint, certificate pin, bootstrap public key, runtime id, and workload digest;
- observe public digests, normalized status, usage, and teardown evidence;
- terminate failed or expired runs.

The Test Director may not:

- receive or forward the raw invitation;
- receive or forward raw A2A bodies;
- create, change, accept, or reject terms;
- call a party signer;
- hold a party wallet, delegated A2A key, provider credential, or Clockchain role capability;
- author Agent Cards, proposals, acceptances, checkpoints, evidence, or certificates.

Clockchain remains the session host, anchor/verifier, and certificate issuer. It is not the private negotiation router.

## Failure behavior

The run fails closed on:

- bootstrap request with a wrong sender key/signature, wrong run/session/role/runtime/workload/endpoint binding, wrong receiver pin, or outside the configured private endpoint;
- invitation replay, timeout, digest mismatch, oversize body, or second consumption;
- Responder start before direct invitation receipt;
- Agent Card before the matching party signer exists;
- arbitrary or mismatched Agent Card/checkpoint signing input;
- card pin mismatch, duplicate jti/nonce, shared delegated key, or expired card;
- direct A2A send that lacks local validation or peer acknowledgment;
- MCP submission attempted before the matching retained helper completion has direct-peer acknowledgment;
- checkpoint that does not bind the exact existing signed v2 artifact;
- any raw invitation, raw A2A body, private path, credential, or private reasoning in retained evidence;
- teardown claimed before observed process/container/task exit.

## Alternatives rejected

- **Test Director forwards the invitation:** simpler, but makes it a content router and invalidates the proof.
- **Clockchain relay carries the invitation:** works technically, but does not prove direct party bootstrap.
- **Pre-sign both Agent Cards:** impossible because the Responder card is session-bound and the Responder lacks the invitation/session context.
- **Let the model run arbitrary curl/sign commands:** portable but unsafe, unauditable, and repeats the command-mutation failure already observed.
- **Change production helper/MCP release first:** unnecessarily couples the local A2A transport amendment to a production helper migration. The bounded derived authority can reuse the existing runtime-private wallet without changing deployed helper `2.1.2`.

## Acceptance criteria

1. A local test proves the raw invitation travels Initiator runtime -> Responder runtime directly and is never available to the Test Director.
2. The Responder cannot start before one direct invitation is accepted.
3. Card exchange follows Responder-null-pin -> Initiator-responder-pin order and then enables the existing signed channel.
4. Agent Card and checkpoint signatures recover to the same party address used by the existing v2 artifacts.
5. No arbitrary-sign surface exists.
6. Public evidence contains invitation/card/checkpoint/envelope digests only.
7. Existing v2 authority, helper `2.1.2`, proposal/acceptance/acknowledgment, verifier, and certificate tests remain unchanged and green.
8. The direct peer acknowledges each exact proposal/acceptance before its MCP submission is authorized.
9. Phase 6C1 remains blocked until the production MCP submission surface accepts and binds the additive checkpoints.
10. Only after these tests pass may the two-container production-MCP rehearsal begin.
