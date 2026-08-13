# Human-Readable Fresh-Agent Narration Design

## Goal

Make future Codex and Claude Code handshake runs easier for stakeholders to follow without changing the protocol, policy decisions, signer boundary, or evidence format.

## Design

The role prompt asks each agent to narrate meaningful milestones in one to three plain-language sentences. A useful update says what the agent verified, what completed, and what it is waiting for next. Routine polling, MCP payloads, private material, full hashes, and mechanical tool-call details remain silent.

The agent gives updates after connection or invitation handling, local policy validation, ERC-8004 registration, proposal or acceptance approval, evidence submission, and closing-certificate verification. Waiting updates name the other party or Clockchain action without implying failure.

The final response is a short stakeholder summary containing the role, ERC-8004 identity, agreement status, local certificate-verification result, and confirmation that no external business action occurred. It may not claim success until the certificate has been verified locally.

## Scope

- Update the production fresh-agent prompt fixture used by the live launcher.
- Update the four copyable Codex and Claude role prompts.
- Add prompt-contract tests for progress narration and the final summary.
- Do not alter MCP tools, schemas, signing, registration, adapter execution, monitoring data, or certificate verification.

## Verification

Focused prompt tests must first fail on the missing narration contract, then pass after the prompt changes. The fresh-agent client and live tmux launcher tests must remain green.
