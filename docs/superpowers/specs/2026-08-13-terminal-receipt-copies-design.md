# Terminal receipt copies

**Date:** 2026-08-13  
**Status:** Approved design, awaiting implementation-plan approval

## Objective

At the end of a successful live Codex-and-Claude handshake, each stakeholder's
stable tmux terminal must show a complete, human-readable receipt copy at the
same level of detail as the research monitor. The terminal output must be
derived from Clockchain's verified public evidence, never composed from model
narration.

## User experience

The existing live progress narration remains unchanged. After both agents
locally verify the same closing certificate, each terminal receives one final
receipt section.

The Payer terminal begins with:

```text
HANDSHAKE COMPLETE — PAYER COPY
```

The Requestor terminal begins with:

```text
HANDSHAKE COMPLETE — REQUESTOR COPY
```

Each copy contains:

1. The stakeholder's own ERC-8004 agent ID, controller address, registration
   transaction, and registration block.
2. The shared closing-certificate outcome, full digest, UTC issue time, and
   session ID.
3. The proposal, acceptance, and acknowledgment receipts in protocol order.
   Each receipt shows its full ledger entry ID, full receipt digest, and block
   height.
4. The closing statement: `No external business action occurred.`

Full public identifiers and hashes are shown. No private key, MCP credential,
role-access token, provider credential, local path, or raw model event may
appear.

## Data source and boundary

The formatter consumes only the terminal success object already emitted by the
fresh-agent canary:

- `roles.initiator` or `roles.responder` supplies that party's ERC-8004 and
  controller facts.
- `monitor.certificate` supplies the shared certificate digest, outcome, and
  issue time.
- `monitor.receipts` supplies the three ordered receipt records.
- `monitor.sessionId` supplies the shared session ID.

The formatter is deterministic and side-effect free. It does not fetch data,
call MCP, inspect agent state, make policy decisions, sign anything, or accept
model-authored display fields. The existing verified evidence object remains
the authority.

## Components

Add a small production formatter module under `src/testing/` that:

- accepts the verified public evidence object and one role;
- validates the exact fields required for the receipt copy;
- formats UTC time deterministically;
- emits a bounded array of terminal lines;
- fails closed if a required public fact is absent or malformed.

Update the existing tmux presenter in `scripts/run-live-tmux-demo.zsh` to call
the formatter only when it receives
`clockchain.fresh-agent-canary-evidence/v1`. Append the Payer copy only to the
Codex log and the Requestor copy only to the Claude log. The combined
controller log may show both copies for facilitator diagnostics.

Do not change the handshake protocol, MCP tools, agent prompts, signing helper,
monitor schema, certificate verification, or live-agent lifecycle.

## Error handling

The receipt formatter must not print a partial success receipt. If the success
object is missing a required field, the presenter prints one short safe line:

```text
Receipt copy unavailable — verified evidence was incomplete.
```

The underlying handshake result and retained evidence artifact remain
unchanged. Formatter errors must not transform a successful handshake into a
protocol failure, but they must cause the presenter-focused test to fail so the
display regression cannot ship unnoticed.

## Verification

Use test-driven development.

1. Add fixture tests that first fail because the formatter does not exist.
2. Prove the Payer copy contains Payer identity facts plus the shared
   certificate and all three receipts.
3. Prove the Requestor copy contains Requestor identity facts plus the same
   certificate and receipts.
4. Prove receipt order is proposal, acceptance, acknowledgment.
5. Prove the UTC issue time is deterministic.
6. Prove full public hashes and IDs remain intact.
7. Prove private/secret-shaped fields and local paths never appear.
8. Prove missing or malformed required fields fail closed without partial
   output.
9. Extend `test/live-tmux-demo.test.mjs` to prove the success event appends the
   correct role-specific copy to each stable terminal.
10. Run the focused formatter and tmux tests, shell syntax validation, patch
    integrity check, and the existing fresh-agent presenter regression suite.

## Acceptance criteria

- A successful live run ends with a detailed Payer receipt in the Codex pane.
- The same run ends with a detailed Requestor receipt in the Claude pane.
- Both show the identical certificate and three receipt references.
- Each shows only its own identity-registration proof.
- Output matches the monitor's public evidence and contains no secrets.
- Existing progress narration and stable tmux sessions continue to work.
