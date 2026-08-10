# Realistic invoice-authorization Handshake demo — design

## Outcome

Turn the existing bilateral Payer/Requestor demonstration into a realistic cross-company invoice-authorization story without creating a second protocol, agent implementation, presenter, or signing path.

Northstar Logistics authorizes Harbor Supply invoice `HS-8842` for `USD 18,750` against purchase order `NS-1847`. The Payer creates or joins the current hosted session, shares its session invitation, and signs a mandate after the Requestor identity resolves. The Requestor joins that exact invitation, compares the signed mandate with its independently supplied expected terms, and signs the payment request only when they match. Clockchain anchors, verifies, and certifies the authorization. `paymentMoved` remains `false`.

## Existing wheels that remain authoritative

- The existing `payer` and `requestor` roles remain the only party roles.
- The production MCP remains `https://mcp.clockchain.network/mcp` with the same five tools: `handshake_status`, `handshake_join`, `handshake_next`, `handshake_submit`, and `handshake_get_certificate`.
- Existing EIP-191 identity, mandate, payment-request, party-result, evidence, transition, verifier, and certificate implementations remain authoritative.
- The existing local wallet bridge remains the only fresh-client signer and ERC-8004 registration helper.
- The existing Hermes clean-room launcher remains the repeatable two-agent test harness.
- The existing `/handshake/claude-v6` research route, layout, monitor, receipt drawers, run history, and identity proof UI remain the stakeholder presentation.
- Existing relay session discovery already supports both `/v1/discovery/current` and `/v1/discovery/{sessionId}`. Invitation binding reuses the latter.

No new agent runtime, relay, state machine, wire role, monitor page, or cryptographic envelope is introduced.

## Approaches considered

### Selected: extend the existing join contract with an exact session invitation and business terms

`handshake_join` accepts an optional `invitationId` and optional structured invoice terms. The Payer may join the current session, while the Requestor joins the exact session id the Payer shared. Both principals retain their own expected terms in existing principal-scoped coordinator state. The Payer's terms construct the existing mandate; the Requestor's terms are checked against that signed mandate before the MCP returns payment-request signing bytes.

This is the smallest change that makes the short prompts truthful and keeps all signing and verification in the existing flow.

### Rejected: a new invitation service and short-code database

A human-friendly code is useful later, but a second mapping store adds expiry, collision, authorization, cleanup, and deployment work. The existing relay session UUID is already a stable, public invitation id and is sufficient for the first realistic demonstration.

### Rejected: encode the scenario only in prompts or presenter copy

Prompt-only terms are not protocol bindings. The MCP currently hard-codes `$100`, `INV-0001`, and `Invoice settlement`; changing only the text would make the display disagree with the signed artifacts.

## Business contract

The reusable business input is exact and intentionally small:

```json
{
  "amount": { "currency": "USD", "value": "18750" },
  "invoiceReference": "HS-8842",
  "purpose": "Invoice HS-8842 against PO NS-1847",
  "validForMinutes": 45
}
```

Rules:

- `currency` remains `USD`, matching the existing canonical amount type.
- `value` is a canonical non-negative decimal integer string.
- `invoiceReference` and `purpose` are trimmed printable ASCII bounded by the existing wire limits.
- `validForMinutes` is an integer from 30 through 240; it controls the existing mandate window and is required for the Payer.
- The Requestor supplies the same amount, invoice reference, and purpose independently. It may omit `validForMinutes` because it verifies the signed absolute expiry rather than choosing it.
- The Payer mandate uses the exact invoice reference as `invoiceReferencePrefix`, so the existing verifier's prefix rule becomes an exact match for this scenario.
- Purchase-order context rides inside the already-signed `purpose`; the wire schema does not gain a new purchase-order field.

The existing `$100 / INV-0001` values remain only as explicit legacy defaults for older callers that omit terms. They stay covered as regression fixtures and are not presented as the realistic stakeholder scenario.

## Invitation and state flow

1. The hosted Clockchain host opens a relay session and publishes the existing signed discovery document.
2. The Payer calls `handshake_join` with role `payer` and invoice terms. With no invitation id, MCP fetches current discovery exactly as it does today.
3. MCP returns the existing trust-root fields plus `invitationId`, which is the exact relay session UUID, and `invitationUrl`, which is the existing `/v1/discovery/{sessionId}` URL.
4. The Payer shares `invitationId` with the Requestor through any ordinary business channel. It is a rendezvous identifier, not a credential or identity proof.
5. The Requestor calls `handshake_join` with role `requestor`, that `invitationId`, and independently supplied expected terms.
6. MCP fetches and validates discovery for the named session. It never silently substitutes the newer current session.
7. Both parties continue through the unchanged identity, funding, ERC-8004, and `party_ready` path.
8. The Payer's stored terms feed the existing mandate preparation function.
9. When the Requestor receives the signed mandate, MCP compares its amount, exact invoice reference, and purpose with the Requestor's stored expectations before returning any payment-request signing bytes. A mismatch fails closed with a stable code and posts no Requestor signature.
10. Matching terms feed the existing payment-request preparation function. All downstream anchors, evidence, verification, and certificate behavior stays unchanged.

Coordinator state remains keyed by MCP principal, session, and role. One party cannot read or overwrite the other party's expectations.

## Fresh-agent experience

A truly fresh agent receives two separate inputs:

1. One-time MCP configuration for `https://mcp.clockchain.network/mcp` with that company's own token.
2. A short business instruction.

Payer instruction:

> Use Clockchain as Payer to authorize Harbor Supply invoice HS-8842 against PO NS-1847 for USD 18,750. The authorization is valid for 45 minutes. No funds should move. Return the invitation for Harbor, then complete the handshake.

Requestor instruction:

> Use Clockchain as Requestor and join invitation `<session-id>`. Proceed only if the signed mandate exactly authorizes Harbor Supply invoice HS-8842 against PO NS-1847 for USD 18,750. No funds should move.

The existing full Hermes role instructions remain an internal harness concern until the local signer and installer are packaged directly into fresh Codex and Claude Code environments. The business prompt does not carry JSON, private keys, relay URLs, or protocol choreography.

## Presenter

The existing research page keeps its layout and live-data predicates. Its narrative changes from a generic `$100` exercise to the invoice-authorization story. The live monitor continues to derive progress only from real snapshot artifacts.

The page explains:

- Northstar Logistics is the Payer and Harbor Supply is the Requestor in this scenario;
- the signed authorization covers invoice `HS-8842`, PO `NS-1847`, `USD 18,750`, the two resolved identities, and an expiry;
- the invitation identifies the exact rendezvous but is not a secret or authorization by itself;
- the certificate is an approval artifact for a later AP process, not a payment;
- fresh agents demonstrate independence and absence of shared context, while production organizations may reuse governed enterprise ERC-8004 identities.

Existing ERC-8004 details remain: agent id, controlling address, canonical chain reference, Sepolia registry link, and receipt-linked party identity. No separate identity component is created.

## Failure behavior

- Unknown, malformed, expired, or mismatched invitation ids fail before role state is advanced.
- A Requestor joining session A never falls through to current session B.
- Missing or malformed Payer terms fail before mandate signing bytes are returned for the realistic flow.
- Requestor expectation mismatch fails before payment-request signing bytes are returned or posted.
- Role-seat collision, identity mismatch, signature failure, expiry, evidence failure, or certificate failure retain their existing fail-closed behavior.
- No failure path changes `paymentMoved:false` or lets the presenter infer authorization without the verified certificate.

## Verification

### Automated

- MCP relay-client tests prove exact-session discovery URLs and strict discovery validation.
- Coordinator tests prove invitation binding, legacy current-session compatibility, principal-scoped terms, exact mandate construction, Requestor mismatch refusal, and unchanged downstream success.
- Tool-surface tests prove the same five tools remain and only `handshake_join` gains optional fields.
- Existing Handshake/Hermes tests prove the wallet, registration, evidence, verifier, certificate, and clean-room boundaries remain intact.
- Research tests prove the original layout remains, the realistic scenario copy is present, and no claim is made that money moved or Clockchain acted as a party.

### Live gate

1. Deploy the MCP change while keeping the same canonical endpoint.
2. Start a fresh hosted relay session.
3. Run two distinct fresh-agent principals with separate wallets and terms supplied through the extended existing `handshake_join`.
4. Confirm the Requestor joins the Payer's exact invitation rather than whichever session is current later.
5. Confirm the signed mandate and payment request contain `USD 18,750`, `HS-8842`, and `Invoice HS-8842 against PO NS-1847`.
6. Confirm distinct ERC-8004 identities, three anchors, two evidence packages, one verified certificate, and `paymentMoved:false`.
7. Confirm the unchanged research layout presents the invoice story and the same live session evidence.

## Delivery boundaries

This feature spans three existing repositories but remains one ordered delivery:

1. Clockchain developer tools: extend the existing MCP coordinator and tool schema.
2. Handshake: adapt the existing Hermes launcher/prompts to pass and verify the scenario inputs; retain the current local Payer/Requestor CLI defaults as regression compatibility.
3. Clockchain research: update the existing `/handshake/claude-v6` narrative without changing its layout or live-state contract.

Backend compatibility lands before client prompts, and client behavior lands before presenter copy. Production deployment and the live fresh-agent gate occur only after all three repository test suites pass.
