# Hermes adapter production live gate — design

## Objective

Prove the deployed Clockchain agent-handshake v2 flow end to end with two newly created Hermes runtimes, two distinct local signers, two fresh ERC-8004 registrations, the production MCP endpoint, the production host, and the existing stakeholder monitor.

This is a recovery test path for the approved `AgentHarnessAdapter` boundary. It does not change or weaken the production protocol.

## Boundary

Each role receives a disjoint Hermes home, OS home, workspace, cache, temporary directory, helper state, and wallet. Hermes K3 evaluates a public decision packet against that role's immutable local policy and returns only `approve` or `refuse` bound to the action digest.

The deterministic role adapter owns transport and byte exactness:

- connect to `https://mcp.clockchain.network/handshake/mcp`;
- retain role access outside model context;
- execute the exact pinned helper action through the existing signed adapter binding;
- construct and sign the private proposal or acceptance release checkpoint with the same role-local wallet;
- submit MCP signatures and checkpoints without asking the model to reproduce payload bytes;
- verify the final certificate with the pinned helper.

The adapter never evaluates business policy and never signs until the corresponding Hermes decision is an exact `approve` bound to the current action digest. The signer remains inside that role's isolated runtime. Clockchain remains the source of canonical signing requests.

## Live scenario

- Reference: `NS-1847`.
- Statement: Northstar Logistics and Harbor Supply authorize these two independently controlled agents to communicate about shipment reference NS-1847 for 90 seconds.
- Identity policy: fresh ERC-8004 identity required on Sepolia registry `0x8004a818bfb912233c491871b3d84c89a494bd9e`.
- External business action: prohibited and reported as false throughout.

## Evidence and success

The live gate succeeds only when:

1. Hermes K3 runs in two blank, disjoint homes and approves the same mandate independently.
2. The production MCP discovers exactly eight public handshake tools.
3. Both role-local helpers create distinct keys and commit distinct role policies.
4. The production host funds both seats and two fresh ERC-8004 registrations complete.
5. The proposal and acceptance each have a matching role-signed commitment checkpoint.
6. Clockchain records proposal, acceptance, and acknowledgment receipts.
7. Both evidence packages are accepted.
8. Both role-local helpers verify the same closing certificate and result digest.
9. The existing read-only monitor shows the same completed session.

Retained evidence is public and redacted: session ID, repository SHA, role addresses, ERC-8004 IDs and transaction references, checkpoint digests, receipt identifiers, result digest, Hermes model/provider/token counts, and cleanup status. Role access, invitations, private keys, provider credentials, raw payloads, and full transcripts are never retained.

## Honest limitation

For this live gate, the adapter invokes MCP on Hermes' behalf after Hermes approves each typed action. This validates the production protocol, independent model judgment, signer isolation, byte-exact execution, live registration, and certificate verification. It does not claim that unmodified Hermes can natively generate the mandatory private commitment checkpoint; that capability belongs in the approved harness-adapter layer.

