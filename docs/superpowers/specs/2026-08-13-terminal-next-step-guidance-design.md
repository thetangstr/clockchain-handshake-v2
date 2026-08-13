# Terminal Next-Step Guidance Design

## Goal

Keep nontechnical stakeholders oriented during a live Clockchain handshake by showing one short, role-aware `Next:` message after each major terminal milestone.

## Experience

The existing terminal format, names, proof detail, and security boundaries remain unchanged. New guidance appears only after a verified public milestone:

- After ERC-8004 identity registration, explain that proposal, acceptance, acknowledgment, and the final receipt bundle come next.
- After the Payer proposal, explain that the Requestor must independently accept the exact terms.
- After the Requestor acceptance, explain that Clockchain records the acknowledgment and checks both evidence packages.
- Before certificate completion, explain that the local agent is verifying the signed certificate and assembling the three receipt references.
- During a legitimate wait, state that work is continuing and no user action is required.

Messages are role-specific where the two stakeholders are waiting on different facts. They must use stakeholder language, avoid raw protocol objects, and never imply that a person must click, sign, or supply another credential.

## Data and Security Boundaries

Guidance is derived only from the presenter’s existing typed, public events. It must not echo role access, signing payloads, private keys, full MCP responses, or unvalidated agent prose. Existing deduplication remains in force so repeated polling does not repeat the same message.

## Testing

Add regression coverage that drives the presenter with representative registration, proposal, acceptance, certificate-verification, and waiting events. Assert the exact stakeholder-facing next-step messages appear in the correct pane, remain deduplicated, and contain no sensitive protocol fields.

## Non-Goals

- No monitor-page changes.
- No protocol, MCP, signing, or receipt-format changes.
- No new progress dashboard inside tmux.
- No additional user action or human approval step.
