# Ephemeral Agent Community Framework Design

**Status:** Approved architecture, pre-implementation specification  
**Date:** 2026-08-13  
**Public project:** Ephemeral Agent Community Framework (EACF)  
**Normative protocol:** Ephemeral Agent Community Protocol (EAC Protocol)  
**Proposed repository:** `clockchain/ephemeral-agent-community`  
**Initial release:** `v0.1.0` experimental  
**License:** Apache-2.0

## 1. Purpose

EACF is a vendor-portable framework for creating a temporary community of independently controlled AI agents, giving each agent an isolated runtime and workload identity, allowing the agents to communicate and act under explicit mandates, collecting verifiable evidence, and destroying the community after the workflow ends.

The first reference implementation runs two fresh agents in separate AWS Fargate tasks and completes a production Clockchain handshake. The framework must not require Clockchain, AWS, Fargate, Codex, Claude Code, Hermes, or a particular model. Those systems are adapters or profiles that prove the portable contracts.

The public work has two inseparable outcomes:

1. A working, repeatable mechanics proof in which two isolated cloud agents complete the real Clockchain handshake and leave independently verifiable evidence.
2. A reusable coding protocol and conformance suite that other teams can use to build ephemeral multi-agent environments without inheriting Clockchain-specific workflow assumptions.

## 2. Design principles

### 2.1 Independent authority

Each party agent owns its decision. A controller may provision, observe, enforce budgets, and terminate a run, but it cannot decide, sign, or author a party artifact. A workflow service may coordinate shared state, but it cannot impersonate a party. A harness adapter may execute an already-authorized action, but it cannot invent one.

### 2.2 Deterministic edges around probabilistic agents

The model interprets the mandate, evaluates local policy, negotiates when permitted, and selects an allowed action. Deterministic components validate schemas, bind actions to the current run, sign locally, transport authorized results, enforce deadlines, collect evidence, and perform teardown.

The model is never used as a byte courier. Once the agent has authorized an exact typed action, the adapter transports that action without asking the model to reproduce opaque payloads, signatures, commands, or identifiers.

### 2.3 Portable contracts, replaceable profiles

The core defines behavior and evidence, not a cloud API or workflow vocabulary. Provider-specific fields live in extension objects governed by named profiles. A conforming implementation can replace AWS with another runtime provider, ACP with another harness-control protocol, or Clockchain with another workflow without changing the lifecycle contract.

### 2.4 Evidence over narration

Success is established from signed workflow artifacts, adapter authorization records, workload attestations, control-plane observations, protocol receipts, and verified teardown. Model prose and screenshots may explain a run but cannot prove it.

### 2.5 Failure still tears down

Workflow outcome and cleanup outcome are separate. Every success, denial, timeout, protocol failure, infrastructure failure, or cancellation enters the destruction phase. A run is not operationally complete until destruction is verified or explicitly reported as unconfirmed.

### 2.6 Fresh means state-fresh, not dependency-free

A fresh agent starts with a new writable home, workspace, memory store, session store, credential set, party signer, and workload identity. It has no prior contacts or conversation state and shares no writable state with another party. An immutable image may contain a preinstalled, digest-pinned harness and dependencies. Requiring every run to download dependencies weakens reproducibility and is not part of freshness.

## 3. Scope

### 3.1 Version 0.1 includes

- A normative run manifest and lifecycle state machine.
- Runtime, harness, workflow, identity, bootstrap, communication, evidence, observability, budget, and teardown contracts.
- Capability negotiation and explicit profile selection.
- Normalized event envelopes using CloudEvents semantics and W3C trace context.
- Harness adapters for Codex through ACP, Claude Code through ACP, Hermes through its native interface, and a minimal AWS Bedrock Converse agent loop.
- An AWS Fargate runtime profile with separate tasks, task roles, storage, networking, logging, and teardown proof.
- A Clockchain handshake workflow profile using MCP, direct A2A communication, optional mandate-required ERC-8004 registration, signed party artifacts, ledger receipts, and a final certificate.
- An offline conformance verifier and a live conformance runner.
- A reproducible two-party example and retained public evidence from verified runs.

### 3.2 Version 0.1 does not include

- A general-purpose agent orchestration product or hosted control plane.
- A replacement for ACP, MCP, A2A, SPIFFE, CloudEvents, OpenTelemetry, in-toto, or SLSA.
- A universal negotiation language.
- A shared organizational memory, task database, or human approval application.
- A requirement that agents communicate through Clockchain.
- A requirement that party identity be blockchain-based.
- Multi-cloud live reference deployments beyond AWS.
- An assertion that container isolation is equivalent to a virtual machine or confidential-computing boundary.

## 4. System architecture

```text
                         EACF Run Controller
                    plan / observe / budget / destroy
                                  |
                 +----------------+----------------+
                 |                                 |
        Runtime Adapter A                 Runtime Adapter B
        isolated workload                 isolated workload
        workload identity A               workload identity B
                 |                                 |
        Harness Adapter A                 Harness Adapter B
        agent + local policy              agent + local policy
        party identity A                  party identity B
                 |                                 |
                 +-------- direct A2A channel -----+
                 |                                 |
                 +---------- MCP services ---------+
                                  |
                         Workflow Coordinator
                      records shared public state

              Evidence Collector -> Offline Verifier
```

### 4.1 Run controller

The controller validates the run manifest, provisions runtimes, correlates workload identities, starts adapters, monitors deadlines and budgets, collects public events and evidence, invokes the verifier, and destroys resources. It has no party signer and cannot submit a party decision.

### 4.2 Runtime adapter

A runtime adapter creates and destroys an isolated execution environment. It reports a normalized runtime capability descriptor and evidence record. Provider extensions may expose cloud resource identifiers, but core consumers depend only on the normalized contract.

### 4.3 Harness adapter

A harness adapter controls a specific agent harness. It starts a fresh session, configures allowed MCP servers and tools, submits the mandate or invitation, streams normalized events, mediates explicit permission requests, executes typed locally authorized actions, supports cancellation, and returns a normalized result.

The adapter, not the model, owns workflow transport and progression. It invokes bootstrap, invitation acceptance, role admission, authoritative-state reads, retries, idempotent submissions, certificate retrieval, and terminal-state checks through a typed workflow client. In deterministic workflow mode, the model receives no MCP credential, role capability, invitation token, signer payload, helper command, or workflow tool surface. The adapter may expose only a compact decision request whose exact run, role, operation, mandate, committed local policy, workflow state, and request bytes are bound by digests.

The typed client validates the exact public server envelope at every step, including any echoed opaque role handle required by the server contract, before projecting a smaller internal result to the completion handler. A successful side effect followed by a locally rejected response shape is an ambiguous commit, not permission to resubmit; the adapter reconciles authoritative state before another action.

The model's response is an exact typed authorization or denial. It cannot change any binding, invoke the workflow itself, or return a signature. Setup, ephemeral party-key creation, optional identity registration, signing, submission, and certificate verification execute locally under deterministic policy and retained authorization records. A model-originated workflow tool call while this mode is active is an adapter-protocol failure.

Local execution failures use a secret-free boundary taxonomy rather than one generic “tool failed” result. At minimum, adapters distinguish launch failure, command-binding mismatch, expiry, replay, helper-operation failure, invalid public output, and completion-acknowledgment failure. The retained event contains the class plus public operation/action digests, never child stderr, commands, payloads, credentials, or private paths.

Local execution and workflow completion are separate phases. After a helper produces one validated public result, the adapter may retry only delivery of that exact digest-bound result; it must never rerun the helper, signer, registration transaction, or workflow submission to recover an acknowledgment. The completion deadline must exceed every bounded downstream operation performed by the completion handler, exact duplicate completions must coalesce onto one in-flight commit, and an already-consumed exact completion must acknowledge idempotently. If the deadline still expires, the adapter reports an ambiguous completion boundary and reconciles authoritative workflow state before authorizing any new action.

ACP is the preferred control protocol for Codex and Claude Code. Native adapters are allowed when the harness lacks ACP, provided they emit the same EACF events and satisfy the same authorization tests.

### 4.4 Workflow profile

A workflow profile defines roles, mandates, allowed actions, state transitions, artifacts, completion conditions, and workflow-specific verification. The core treats role identifiers and action types as opaque profile-governed strings; it does not assume two parties or Initiator/Responder semantics.

### 4.5 Identity provider

EACF distinguishes three identities:

- **Workload identity:** identifies the isolated runtime to infrastructure and peers.
- **Party identity:** identifies the agent or organization represented in the workflow.
- **Harness identity:** binds the executing harness, adapter, model configuration, and software digest to the run.

The admission record binds all three to one run and role. A workflow may accept an ephemeral public key as party identity, require an external identity standard, or make that requirement conditional on the mandate. The Clockchain profile supports live ERC-8004 registration when the mandate requires it.

### 4.6 Bootstrap exchange

Bootstrap exchanges only public, run-bound peer descriptors. It never transports private keys, bearer credentials, model credentials, party mandates, or confidential negotiation content. Each descriptor identifies its run, party, role, communication endpoints, public keys, expiry, and body digest. Publication authenticity is established by the runtime's workload identity and provider access policy; signed A2A envelopes establish message authenticity after bootstrap.

### 4.7 Communication adapters

- **A2A:** direct party-to-party negotiation, task messages, and artifacts.
- **MCP:** access to shared tools and services, including workflow coordination.
- **CloudEvents envelope:** normalized lifecycle and evidence events.
- **W3C trace context:** correlation across controller, runtime, harness, A2A, MCP, and workflow services.

EACF does not force all party communication through the coordinator. Profiles can require public commitments to be recorded while allowing private negotiation directly between parties.

## 5. Normative lifecycle

The run state separates current phase, workflow outcome, and cleanup outcome.

### 5.1 Phases

```text
PLANNED
  -> PROVISIONING
  -> ATTESTING
  -> ADMITTING
  -> EXECUTING
  -> COLLECTING_EVIDENCE
  -> VERIFYING
  -> DESTROYING
  -> TERMINAL
```

No workflow failure skips `DESTROYING`. A controller may move from any nonterminal phase to `DESTROYING` after recording the failure reason.

### 5.2 Workflow outcomes

- `SUCCEEDED`
- `POLICY_DENIED`
- `PROTOCOL_FAILED`
- `INFRASTRUCTURE_FAILED`
- `TIMED_OUT`
- `CANCELLED`

### 5.3 Cleanup outcomes

- `NOT_STARTED`
- `IN_PROGRESS`
- `VERIFIED`
- `UNCONFIRMED`

The overall public status is successful only when workflow outcome is `SUCCEEDED`, evidence verification passes, and cleanup outcome is `VERIFIED`. A protocol failure with verified cleanup is reported as a clean failed run, not as an operational leak. `UNCONFIRMED` is always prominent and fail-closed.

### 5.4 Transition record

Every transition contains:

- Run identifier and spec version.
- Previous transition digest.
- From and to phase.
- Outcome and cleanup state when applicable.
- Actor identifier and actor class.
- Event time and monotonic sequence.
- Trace identifier.
- Public reason code.
- Evidence references by digest.

The event log is append-only. Redaction may replace sensitive values with typed placeholders but cannot change ordering, digests, reason codes, or phase semantics.

## 6. Run manifest

The run manifest is immutable after admission and contains no secret values.

Required sections:

- `schema`, `specVersion`, `runId`, creation time, and overall deadline.
- Workflow profile identifier, version, and content digest.
- A nonempty party list with unique party and role bindings.
- Runtime and harness profile requirements for every party.
- Workload, party, and harness identity requirements.
- Bootstrap, A2A, MCP, and observability channel requirements.
- Local policy inputs and permitted action classes.
- Evidence requirements and verification policy.
- Per-stage timeouts, retry ceilings, and idempotency policy.
- Budget limits and kill policy.
- Destruction scope and proof requirements.
- Extension profiles and their schema digests.

Secret references are supplied separately to the provider adapter and are never serialized into the manifest, event stream, evidence bundle, prompts, or retained logs.

## 7. Authority and action protocol

### 7.1 Agent decision record

An agent decision is a typed record containing the current workflow state digest, mandate digest, selected action, policy evaluation result, expiration, and constraints. Free-form reasoning is excluded from the retained proof by default.

### 7.2 Local authorization

The harness adapter presents the exact typed action to the configured authorization boundary. In an autonomous demonstration, local policy may authorize the action without a human. The authorization recorder binds:

- Agent decision digest.
- Exact action payload digest.
- Run, party, role, and workflow state.
- Adapter and helper release digests.
- Authorization result and time.

### 7.3 Signing

The party signer is under the exclusive control of the party runtime. It signs only after authorization and never exports its private key. Signing can use an ephemeral software key held inside the runtime, a party-scoped cloud KMS/HSM key, or another profile-defined provider. The controller, peer, coordinator, and model provider never receive the key or signing authority.

### 7.4 Deterministic submission

After authorization and signing, the adapter submits the resulting signature or artifact directly through the relevant protocol client. The model does not copy the signature, reconstruct a shell command, or invoke a second tool call containing opaque bytes. Submission is idempotent and bound to the expected workflow state digest.

## 8. Workflow state protocol

The protocol client exposes a compact typed loop:

1. Read current authoritative state.
2. Receive zero or more allowed actions and their preconditions.
3. Let the agent select or deny an action under local policy.
4. Authorize and execute the selected action deterministically.
5. Submit the result with the expected state digest and idempotency key.
6. Observe the next authoritative state.

The client must reject stale actions, unexpected role changes, cross-run identifiers, expired requests, duplicate non-idempotent submissions, and state transitions not permitted by the workflow profile.

Prompts describe goals, local policy, and business context. They do not encode a procedural list of MCP calls, opaque payloads, provider commands, or retry loops. Recovery behavior comes from the adapter and workflow-state protocol.

The portable client therefore has two distinct interfaces:

- A deterministic transport interface for bootstrap, admission, state reads, waits, retries, authorized submission, and completion verification.
- A decision interface that presents only exact digest-bound business choices to the model and accepts only a schema-valid authorization or denial.

Implementations must prove by negative tests that a model cannot obtain or replay a role capability, bypass a local policy, mutate a requested action, call a workflow tool directly, or cause the adapter to submit an action twice.

## 9. Capability negotiation

Every adapter publishes a signed or runtime-attested capability descriptor before admission.

### 9.1 Runtime capabilities

- Isolation class.
- Ephemeral writable-storage behavior.
- Workload identity mechanism.
- Secret delivery mechanism.
- Ingress and egress control.
- Resource and budget enforcement.
- Logs, metrics, traces, and control-plane evidence.
- Cancellation and destruction guarantees.

### 9.2 Harness capabilities

- Harness and adapter identifiers and versions.
- Supported session and streaming semantics.
- MCP configuration and tool filtering.
- Permission request and local-action support.
- Cancellation, timeout, and result semantics.
- Model/provider configuration evidence.
- Context freshness and persistent-state controls.

### 9.3 Workflow capabilities

- Supported roles and cardinality.
- Action and artifact types.
- Required party identity profiles.
- A2A and MCP requirements.
- Required evidence and verifier versions.

Admission fails before business execution if required capabilities do not match. Silent degradation is prohibited.

## 10. Evidence bundle

A conforming retained bundle is independently verifiable without model or cloud credentials.

```text
evidence/<run-id>/
  manifest.json
  manifest.sha256
  summary.json
  lifecycle.events.jsonl
  parties/<party-id>/runtime.json
  parties/<party-id>/harness.json
  parties/<party-id>/admission.json
  parties/<party-id>/actions.jsonl
  communication/a2a-digests.jsonl
  communication/mcp-digests.jsonl
  workflow/artifacts/
  observability/trace-summary.json
  supply-chain/images.json
  supply-chain/provenance.intoto.jsonl
  cost.json
  teardown.json
  verification.json
```

The public bundle contains no bearer tokens, private keys, model credentials, raw environment dumps, private negotiation bodies, or unrestricted model transcripts. Sensitive artifact bodies may be retained separately under a profile-defined disclosure policy; their digests remain in the public bundle.

### 10.1 Minimum proof claims

- Every party had a distinct workload identity and isolated writable state.
- No party signer, MCP credential, harness home, or writable workspace was shared.
- Each admitted party was bound to its runtime, harness, role, and party identity.
- Every submitted party artifact originated from an authorized local action.
- A2A and MCP events were bound to the same run and expected state.
- Workflow-specific completion conditions passed.
- The exact images and source provenance are identified.
- Budget limits were configured and not exceeded.
- All in-scope temporary resources and secrets were destroyed or an unconfirmed cleanup failure is reported.

## 11. Observability

The controller and adapters emit CloudEvents-compatible envelopes with W3C trace context. OpenTelemetry is the reference telemetry implementation.

Required public event classes:

- Lifecycle transition.
- Runtime provisioned, attested, healthy, stopped, and destroyed.
- Harness started, session created, permission requested, action authorized, and result returned.
- A2A descriptor published, peer admitted, message accepted, and artifact accepted.
- MCP tool started, completed, failed, or rejected.
- Workflow state changed.
- Evidence collected and verified.
- Budget threshold crossed.
- Cleanup step started, passed, failed, or remained unconfirmed.

Events carry digests and safe classifications, not secrets or unbounded payloads. The framework provides a terminal live view and a machine-readable stream. A UI or demo video consumes this stream but is not part of the proof boundary.

## 12. Security model

### 12.1 Threats addressed

- Cross-run replay and stale-state submission.
- A malicious or confused peer.
- Prompt injection through peer or tool content.
- A controller attempting to impersonate a party.
- An adapter acting beyond the agent's authorization.
- Credential leakage through environment, shell, logs, traces, or evidence.
- Shared-home or shared-volume contamination.
- Malicious or substituted harness, helper, image, or workflow profile.
- Network access outside the declared policy.
- Orphaned resources and secrets.
- Unbounded retries or model use causing cost escalation.
- Evidence assembled from incompatible or unrelated runs.

### 12.2 Mandatory controls

- Unique run identifiers and nonces; deadlines on all signed requests.
- Exact schema validation and rejection of unknown security-sensitive fields.
- State-digest and idempotency binding for actions.
- Per-party least-privilege workload identities and credentials.
- Separate writable state and party signers.
- No static cloud credentials in managed-runtime mode.
- Allowlisted MCP servers, tools, A2A peers, and action classes.
- Pinned adapter, helper, image, workflow profile, and verifier digests.
- Credential redaction plus canary scanning before evidence retention.
- Bounded retries, process-group cancellation, and total run deadline.
- Destruction in a `finally`-equivalent control path.
- Offline verification of the final evidence bundle.

### 12.3 Trust boundaries

Model providers are not trusted with party private keys or cloud credentials. The workflow coordinator is trusted to publish shared state but not to author party decisions. The controller is trusted for provisioning and evidence collection but cannot produce a valid party signature. Cloud-provider control-plane evidence is correlated with in-runtime attestation; neither alone proves the full run.

## 13. Cost-control protocol

Every run declares:

- Maximum elapsed time.
- Maximum aggregate cloud cost estimate.
- Maximum per-party model tokens or provider spend.
- Maximum retry count by operation class.
- Maximum concurrently provisioned resources.
- Warning and hard-stop thresholds.

The controller estimates cost before provisioning, samples usage during execution when the provider exposes it, and stops the run at a hard limit. The evidence bundle records estimates, measured usage, known billing lag, and the final resource inventory. A cost limit is an enforcement input, not merely a monitoring label.

## 14. Teardown protocol

Teardown is a first-class verified workflow:

1. Stop accepting new workflow actions.
2. Cancel harness sessions and in-flight protocol operations.
3. Stop party runtimes.
4. Collect final safe logs, events, usage, and control-plane state.
5. Delete per-run secrets and credentials.
6. Delete queues, endpoints, logs subject to retention policy, network resources, roles, and the run stack.
7. Enumerate the provider control plane for resources carrying the run identifier.
8. Record deletion evidence and verify the expected empty inventory.

Evidence needed for deletion is retained before deleting its source. Destruction targets are resolved from the immutable plan and provider outputs, never from broad globs or unvalidated environment variables.

## 15. AWS Fargate reference profile

The first cloud profile deploys one controller-managed CloudFormation stack per run.

### 15.1 Isolation

- One Fargate task per party with `awsvpc` networking and public IP disabled.
- Distinct private subnets or profile-declared equivalent placement boundaries.
- Distinct task roles, execution roles, security groups, log streams, writable homes, workspaces, caches, and temporary directories.
- No shared EFS volume, host mount, signer, MCP credential, harness credential, or writable state.
- Immutable OCI images referenced by digest.
- Rootless application container where supported; narrowly scoped root workspace initializer allowed only as a nonessential, completed init container.

### 15.2 Identity and secrets

- ECS task-role credentials supply workload identity.
- In-runtime ECS metadata and STS identity are correlated with the exact task ARN, task definition, role ARN, cluster, and CloudFormation outputs.
- The task execution role retrieves only that party's declared startup secrets.
- Static access keys, shared credentials files, profile-based credentials, web-identity overrides, custom credential endpoints, and metadata endpoint overrides are rejected in managed mode.
- Every temporary secret is tagged with the run identifier and permanently deleted after evidence capture.

### 15.3 Bootstrap and communication

- A role-scoped SQS bootstrap exchange publishes one public descriptor per party.
- Queue policies allow only the expected role and run resources.
- Each consumer accepts only the opposite party's exact run-bound descriptor and deletes only the validated message.
- Private party traffic uses the direct signed A2A channel; SQS does not carry private negotiation.
- MCP access uses distinct resource-bound credentials per party.

### 15.4 Observability and cleanup

- CloudWatch logs and metrics use separate party streams and common trace identifiers.
- ECS task state, ENIs, task definitions, roles, queues, log groups, secrets, and stack resources are recorded by exact identifier.
- Standalone task failures are monitored by the controller because ECS does not replace them automatically.
- Cleanup verifies task stoppage, secret deletion, and absence of the exact stack and run-tagged resources.

The reference claim is container/task isolation under AWS Fargate, not hardware-enclave or VM-per-party isolation.

## 16. Harness adapters

### 16.1 Codex ACP adapter

- Starts a new Codex session in a fresh home and workspace.
- Configures only declared MCP servers and tools.
- Normalizes ACP session updates, tool activity, permissions, usage, and completion.
- Correlates a permission request with the exact preceding authorized local action by digest, even when ACP callbacks are delivered concurrently.
- Never exposes the party signer or protocol credentials to the model's terminal environment.

### 16.2 Claude Code ACP adapter

- Uses a pinned Sonnet model profile for the reference proof.
- Provides the same normalized events and permission semantics as Codex.
- Treats subscription authentication, API-key authentication, and Bedrock-backed authentication as separate credential profiles with explicit evidence.
- Does not infer success from natural-language completion.

### 16.3 Hermes native adapter

- Creates a standalone Hermes home with no inherited profile, memory, sessions, contacts, skills, or global authentication fallback.
- Limits Clockchain MCP exposure to the profile's declared tools.
- Emits normalized EACF events from Hermes-native output.
- Demonstrates that conformance does not depend on ACP.

### 16.4 AWS Bedrock Converse adapter

- Implements a minimal bounded agent loop using the Bedrock Converse tool-use interface.
- Accepts the same mandate, local policy, MCP tools, A2A channel, and action authorization boundary.
- Uses the runtime task role for Bedrock authorization.
- Provides a minimal AWS-native harness option without changing the workflow or runtime contracts.

## 17. Clockchain handshake workflow profile

Clockchain is the first workflow profile, not a dependency of the core.

The profile defines:

- Payer and Requestor roles.
- A Payer mandate and a matching Requestor request.
- Optional live ERC-8004 registration when the mandate requires that identity standard.
- Direct A2A invitation and term negotiation.
- MCP-based authoritative shared state and action requests.
- Proposal, acceptance, and acknowledgment ledger transitions.
- Separate signed party evidence packages.
- Independent Clockchain host/checker verification.
- A signed final certificate and a no-money-moved invariant for the handshake-only demonstration.

The party agents determine whether the mandate and request are acceptable. The Clockchain host funds test identity registration when required, records public commitments, verifies evidence, and certifies the result. It does not decide or sign for either party.

## 18. Conformance model

### 18.1 Conformance levels

- **Core:** Manifest, lifecycle, events, authority separation, evidence format, failure semantics, and teardown contract pass offline tests.
- **Isolated:** At least two parties run with distinct workload identities and no shared writable state or credentials; runtime negative tests pass.
- **Verifiable:** Signed party artifacts, run-bound communication, supply-chain provenance, complete evidence verification, cost evidence, and verified teardown pass a live run.

The AWS Clockchain reference release targets `Verifiable` conformance.

### 18.2 Test suites

- JSON schema and exact-shape tests.
- Lifecycle transition and failure-path model tests.
- Runtime adapter contract tests.
- Harness adapter contract tests using shared black-box fixtures.
- Workflow profile tests.
- Identity/admission and cross-run replay tests.
- A2A/MCP state and idempotency tests.
- Secret-leak and redaction tests.
- Timeout, cancellation, retry, cost-limit, and partial-failure tests.
- Evidence tamper and incompatible-run tests.
- Teardown failure and orphan detection tests.
- Containerized two-party local tests.
- Live AWS Fargate tests.
- Harness matrix runs for Codex, Claude Code, Hermes, and Bedrock Converse.

A live result is retained only if the offline verifier passes against the bundle after the cloud resources are gone.

## 19. Public repository structure

```text
clockchain/ephemeral-agent-community/
  SPEC.md
  LICENSE
  SECURITY.md
  GOVERNANCE.md
  CONTRIBUTING.md
  schemas/
    run-manifest/
    lifecycle-event/
    capability/
    admission/
    evidence/
    teardown/
  packages/
    core/
    runtime-contract/
    harness-contract/
    workflow-contract/
    conformance/
    evidence-verifier/
  adapters/
    codex-acp/
    claude-code-acp/
    hermes/
    bedrock-converse/
  profiles/
    aws-fargate/
    clockchain-handshake/
  examples/
    two-party-clockchain-handshake/
  docs/
    architecture.md
    authority-model.md
    threat-model.md
    operator-runbook.md
    adapter-authoring.md
    workflow-profile-authoring.md
    portability-guide.md
    cost-and-teardown.md
  evidence/
    verified-runs/
```

Normative schemas and protocol language live outside provider and workflow profiles. Package imports flow inward toward contracts; the core never imports AWS, harness, or Clockchain code.

## 20. Versioning and governance

- The initial protocol is explicitly experimental at `v0.1.0`.
- Normative schemas use semantic versions and stable `$id` values.
- Additive optional fields require a minor version; incompatible requirements require a major version.
- Security-sensitive objects reject unknown fields unless the selected extension profile explicitly owns them.
- Reference profiles declare the exact core versions they conform to.
- Changes to normative behavior require a short design record, conformance tests, and compatibility notes.
- Releases include signed source tags, package checksums, OCI image digests, and SLSA-compatible provenance.
- Apache-2.0 is used for its explicit patent grant and suitability for an implementable public protocol.

## 21. Extraction from the current Handshake repository

### 21.1 Reuse as design patterns and tested algorithms

- ACP Codex and Claude process control.
- Hermes clean-room creation and state inspection.
- Harness event normalization and permission correlation.
- Retained local-action authorization records.
- Direct signed A2A task channels and peer-card bootstrap.
- Runtime adapter and bootstrap-exchange interfaces.
- SQS workload-identity bootstrap exchange.
- Fargate planning, control-plane normalization, evidence collection, and cleanup sequencing.
- Strict validation, generic public failures, redaction, and canary scanning.

### 21.2 Generalize before moving into the public core

- Replace fixed Initiator/Responder and Payer/Requestor assumptions with profile-defined parties and roles.
- Replace `clockchain.*` core schema identifiers with EACF identifiers.
- Split normalized runtime evidence from AWS extensions.
- Split generic workflow state/action handling from `agent_handshake_*` MCP tools.
- Make party identity requirements profile-selected instead of ERC-8004-specific.
- Replace mechanics-proof-specific event classes with the normative lifecycle taxonomy.
- Make evidence requirements capability-driven and conformance-level-aware.

### 21.3 Keep in the Clockchain profile

- Clockchain MCP endpoints and tool names.
- ERC-8004 registration and funding behavior.
- Mandate, request, proposal, acceptance, acknowledgment, and party-result artifacts.
- Clockchain relay, host/checker, ledger receipts, certificate, and no-money-moved invariant.

### 21.4 Keep in the AWS profile

- ECS metadata, STS correlation, task definitions, ENIs, subnets, security groups, IAM roles, SQS, CloudWatch, Secrets Manager, ECR, and CloudFormation evidence.

The extraction is performed by copying narrowly reviewed modules into the new repository and rewriting their public contracts. The existing Handshake branch remains runnable and is not converted in place into the framework.

## 22. Delivery sequence

1. Complete and retain one clean two-party Clockchain run on the current pinned Fargate implementation. This preserves a working baseline before extraction.
2. Create the standalone public repository with governance, normative schemas, core contracts, and offline conformance tests.
3. Extract and generalize runtime, harness, A2A, state, evidence, and teardown modules behind the new contracts.
4. Add the AWS Fargate and Clockchain profiles and reproduce the baseline run from the new repository.
5. Run the harness matrix across Codex, Claude Code, Hermes, and Bedrock Converse.
6. Perform security review, secret scan, cost audit, teardown audit, documentation review, and independent evidence verification.
7. Publish `v0.1.0`, the verified evidence bundles, the operator tutorial, and the recorded demonstration.

## 23. Acceptance criteria

The project is complete only when all of the following are true:

- Two independently controlled fresh agents complete the production Clockchain handshake from separate Fargate tasks.
- The tasks have distinct workload identities, party signers, credentials, writable state, and network identities.
- The agents communicate directly over signed A2A where permitted and use Clockchain MCP for shared workflow state.
- The agent, adapter, controller, signer, coordinator, and verifier authority boundaries are demonstrated by positive and negative tests.
- ERC-8004 registration occurs live when required by the Payer mandate.
- The resulting Clockchain certificate and all required ledger/evidence artifacts verify.
- All temporary AWS resources and secrets are permanently removed and teardown verification passes.
- The standalone public repository contains the normative protocol, schemas, conformance runner, offline verifier, four harness adapters, AWS and Clockchain profiles, examples, threat model, operator documentation, and evidence.
- Repeated live runs pass within the declared cost and time budgets.
- The public evidence contains no credentials, private keys, unrestricted transcripts, or confidential negotiation bodies.
- A third party can reproduce the reference deployment from the documented inputs and independently verify the retained bundle after teardown.

## 24. Principal design decisions

1. **Standalone repository:** The protocol is published separately from Clockchain Handshake so vendor neutrality is structural, not aspirational.
2. **Framework plus normative protocol:** EACF supplies implementations and adapters; the EAC Protocol defines portable behavior and evidence.
3. **Profiles over conditionals:** AWS, harness, identity, and workflow differences are isolated in explicit profiles rather than accumulating in the core.
4. **Adapter as deterministic action boundary:** This resolves repeated prompt and opaque-payload drift without transferring decision authority away from the agent.
5. **A2A and MCP are complementary:** Agents can negotiate directly; shared services and public commitments remain mediated and verifiable.
6. **Three identities are distinct:** Workload, party, and harness identity answer different trust questions and are bound only for the run.
7. **Outcome and cleanup are separate:** A failed protocol can still be a clean run; successful business logic with unverified teardown is not complete.
8. **Freshness is measurable state isolation:** Preinstalled immutable dependencies are compatible with a fresh agent.
9. **Evidence is offline-verifiable:** A cloud console, model transcript, or live website is not required to validate a retained run.
10. **AWS is the first reference, not the portability boundary:** The core contract can be implemented by another cloud, container platform, sandbox, SSH target, or agent-hosting service.
