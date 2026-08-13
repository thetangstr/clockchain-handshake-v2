# Human-Readable Fresh-Agent Narration Design

## Goal

Make future Codex and Claude Code handshake runs easier for stakeholders to follow without changing the protocol, policy decisions, signer boundary, or evidence format.

## Design

The role prompt asks each agent to narrate meaningful milestones in one to three plain-language sentences. A useful update says what the agent verified, what completed, and what it is waiting for next. Routine polling, MCP payloads, private material, full hashes, and mechanical tool-call details remain silent.

The agent gives updates after connection or invitation handling, local policy validation, ERC-8004 registration, proposal or acceptance approval, evidence submission, and closing-certificate verification. Waiting updates name the other party or Clockchain action without implying failure.

The final response is a short stakeholder summary containing the role, ERC-8004 identity, agreement status, local certificate-verification result, and confirmation that no external business action occurred. It may not claim success until the certificate has been verified locally.

For proposal and acceptance, the prompt states the actual deterministic ownership boundary: after agent approval, the adapter submits the commitment checkpoint before releasing the helper signature. The agent must not create or call a checkpoint; it submits the exact released signature through `agent_handshake_submit`.

## Scope

- Update the production fresh-agent prompt fixture used by the live launcher.
- Update the four copyable Codex and Claude role prompts.
- Surface redacted model narration in the stable tmux panes; suppress URLs, capabilities, raw JSON, long tokens, and full hashes.
- Add prompt-contract tests for progress narration and the final summary.
- Do not alter MCP tools, schemas, signing, registration, adapter execution, monitoring data, or certificate verification.

## Verification

Focused prompt tests must first fail on the missing narration contract, then pass after the prompt changes. The tmux presenter contract must prove that both Codex and Claude narration is displayed only through a bounded safety filter. The fresh-agent client and live tmux launcher tests must remain green.
