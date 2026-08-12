# Mechanics Proof Fargate Dry Run

Phase4 is dry-run only. The checked-in Fargate files are validation fixtures for the mechanics-proof runtime boundary; they are not an approval to register task definitions, run ECS tasks, deploy a stack, or claim a certificate.

Run:

```bash
node scripts/run-mechanics-proof-fargate.mjs --dry-run
```

The command validates the local template and task definition fixtures and prints only public digests plus dry-run controls. `liveResourcesCreated` and `deploymentReady` must remain `false`.

Runtime requirements for a future live phase:

- Two one-shot Fargate tasks, one initiator and one responder, with distinct task roles, execution roles, log groups, secret references, state roots, signer roots, and workspaces.
- Immutable Node 24 image references must use `repository@sha256:<64 hex>`. The checked-in image is the official `docker.io/library/node:24.11.1-bookworm-slim` x86_64 base fixture pinned by digest for dry-run validation only. It cannot run the mechanics proof by itself; Phase6 must replace it with a Clockchain application image pinned by manifest digest.
- Both tasks use `FARGATE`, `awsvpc`, CPU `512`, memory `1024`, read-only root filesystems, non-root users, and only per-task ephemeral writable workspace volumes.
- Private subnets are required with `assignPublicIp` disabled. HTTPS egress must be through NAT or VPC endpoints for ECR, CloudWatch Logs, Secrets Manager or SSM, STS, CloudTrail, and the dedicated Clockchain MCP endpoint.
- A2A traffic is only TCP 8443 between the two party security groups, with matching peer ingress and peer egress.
- CloudWatch awslogs mode is blocking, with distinct run-scoped log groups and retention.
- Every run needs TTL `3600`, max concurrency `2`, a per-run budget, required cost tags, and a cleanup sweeper plan that preserves STOPPED evidence before deletion.

Evidence requirements:

- Runtime evidence must be collected from injected AWS control-plane responses: ECS DescribeTasks, ECS task definition, ENI/subnet/security-group data, CloudTrail events, CloudWatch public log descriptors, in-task STS identity, runtime attestation, and STOPPED cleanup proof.
- The collector hashes raw public evidence internally. Precomputed digest-only inputs are rejected.
- Output retains only public identifiers and digests. Raw secrets, private paths, transcripts, raw logs, and secret canaries must not appear.
