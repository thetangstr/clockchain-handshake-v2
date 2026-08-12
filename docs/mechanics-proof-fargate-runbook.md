# Mechanics Proof Fargate Runtime

Phase4 is dry-run only. The checked-in Fargate files are validation fixtures for the mechanics-proof runtime boundary; they are not an approval to register task definitions, run ECS tasks, deploy a stack, or claim a certificate.

Run:

```bash
node scripts/run-mechanics-proof-fargate.mjs --dry-run
```

The command validates the local template and task definition fixtures and prints only public digests plus dry-run controls. `liveResourcesCreated` and `deploymentReady` must remain `false`.

Phase6 local preflight is still non-mutating. It assembles the deployment-ready public gate record from the checked plan plus an application image digest and local git `HEAD`; it does not register task definitions, run ECS tasks, contact production MCP, or read local authentication files.

```bash
node scripts/run-mechanics-proof-fargate.mjs \
  --preflight \
  --pair codex:claude \
  --direct-a2a \
  --evidence-dir /private/tmp/mechanics-proof-evidence \
  --app-image 123456789012.dkr.ecr.us-west-2.amazonaws.com/clockchain-mechanics-proof@sha256:<64 hex>
```

The evidence directory must be an explicit mechanics-proof-prefixed absolute path under repo-local `.tmp` or directly under `/private/tmp` or the platform temp root. The path is printed only as a digest. The app image must be shaped like a Clockchain mechanics-proof application image pinned by immutable digest. The pinned Docker Hub Node base fixture is rejected, but Phase6 preflight does not yet prove ECR/image provenance, so `deploymentReady` remains `false` and `imageProvenanceVerified` remains `false`.

## Phase 6C2 live stack plan

`infra/mechanics-proof/fargate-live-runtime.yaml` is the deployable, run-scoped infrastructure template. Merely loading or planning it remains read-only. Deployment belongs to the separately gated live controller and requires all of these explicit facts; none may be selected by inference:

- allowed 12-digit AWS account and exact region;
- selected VPC ID and every VPC CIDR;
- one existing public subnet ID, its VPC, CIDR, Availability Zone, `MapPublicIpOnLaunch:true`, exact associated route-table ID, and an active `0.0.0.0/0` route to an Internet Gateway;
- two unused private `/24` CIDRs inside that VPC, in two explicitly selected distinct Availability Zones, proven non-overlapping with every current VPC subnet immediately before mutation;
- immutable Clockchain ECR image by `repository@sha256:<digest>` in the allowed account and region;
- initiator-only Codex subscription-auth Secrets Manager ARN;
- account-scoped Claude Sonnet cross-region Bedrock inference-profile ARN;
- UUID run ID, exact start/expiry timestamps, TTL no more than 3600 seconds, concurrency exactly two, and budget no more than USD 25.

The live stack creates two private subnets and one temporary NAT gateway in the supplied existing public subnet. Both tasks use `assignPublicIp: DISABLED`; TCP 8443 is allowed only between the two role security groups, while TCP 443 exits through the private route tables' run-scoped NAT route. The stack also creates two native SSE-SQS queues with 15-minute retention. Each task role may send only to its own queue and receive/delete only from the peer queue. SQS IAM and the message binding authenticate publication of the public bootstrap descriptor; the exchanged public key then verifies later signed A2A envelopes. Private handshake traffic remains direct peer HTTPS.

The initiator and responder have distinct task roles, execution roles, security groups, log groups, subnets, and task-local writable volumes. The initiator execution role alone may retrieve the exact Codex secret. The responder task role alone may call both `bedrock:InvokeModel` and `bedrock:InvokeModelWithResponseStream`, scoped to the exact Sonnet inference profile and its three destination foundation-model ARNs. Neither role receives a signer, state, MCP-credential, Anthropic-key, EFS, host volume, or shared writable resource.

Each task definition uses a short-lived nonessential `workspace-init` container to set ownership on the task-local ephemeral `/workspace` volume. The application starts only after that container exits successfully, runs as `1000:1000`, and keeps its root filesystem read-only. The init container receives no explicit environment, secret, port, or protocol payload. Runtime ID, task ID, private ENI endpoint, and workload-attestation digest are derived inside the task from ECS metadata rather than supplied by the controller.

CloudFormation syntax can be checked without creating resources:

```bash
aws cloudformation validate-template \
  --region <allowed-region> \
  --template-body file://infra/mechanics-proof/fargate-live-runtime.yaml
```

Successful template validation is not a mechanics proof and does not authorize stack creation. Before deployment, the live controller must repeat the VPC, public-route, and CIDR non-overlap checks against current AWS control-plane data.

The deterministic run-scoped IAM role names require the explicit CloudFormation capability `CAPABILITY_NAMED_IAM`; `CAPABILITY_IAM` is insufficient. After stack creation, the controller must consume one complete `ListStackResources` envelope for the exact stack ID/name, validate all 25 canonical logical IDs and resource types with nonempty physical IDs, and bind the 13 task-definition inputs to those exact same-stack physical resources. A partial or prefiltered resource list cannot establish stack provenance.

Runtime requirements preserved from the historical dry fixture:

- Two one-shot Fargate tasks, one initiator and one responder, with distinct task roles, execution roles, log groups, secret references, state roots, signer roots, and workspaces.
- Immutable Node 24 image references must use `repository@sha256:<64 hex>`. The checked-in image is the official `docker.io/library/node:24.11.1-bookworm-slim` x86_64 base fixture pinned by digest for dry-run validation only. It cannot run the mechanics proof by itself; Phase6 must replace it with a Clockchain application image pinned by manifest digest.
- Both tasks use `FARGATE`, `awsvpc`, CPU `512`, memory `1024`, read-only root filesystems, non-root users, and only per-task ephemeral writable workspace volumes.
- Private subnets are required with `assignPublicIp` disabled. While this dry-run uses the public Docker Hub Node base, tasks need NAT or egress proxy for Docker Hub, the dedicated Clockchain MCP endpoint, and model provider HTTPS. AWS VPC endpoints may cover CloudWatch Logs, Secrets Manager or SSM, and STS. After Phase6 replaces the base fixture with a private ECR application image, add ECR api/dkr and S3 endpoints or keep NAT.
- A2A traffic is only TCP 8443 between the two party security groups, with matching peer ingress and peer egress.
- CloudWatch awslogs mode is blocking, with distinct run-scoped log groups and retention.
- Every run needs TTL `3600`, max concurrency `2`, a per-run budget, required cost tags, and a cleanup sweeper plan that preserves STOPPED evidence before deletion.
- Phase6 live prerequisites currently remain external: account/region access, private subnets with NAT or an egress proxy, out-of-band AWS secret ARNs for bootstrap credentials, and role policies that distinguish Codex secret retrieval from Claude Bedrock workload identity. The controller must not receive or pre-provision party signer private material; signer and A2A keys are generated inside each task runtime and retained only as public addresses/digests in evidence.
- Direct A2A requires a real authenticated HTTP transport between task endpoints on port 8443 using Agent Card and envelope verification. In-process direct-channel tests are not live proof, and controller-routed raw content is not permitted.

Evidence requirements:

- Runtime evidence must be collected from injected AWS control-plane responses: ECS DescribeTasks, ECS task definition, ENI/subnet/security-group data, CloudTrail events, CloudWatch public log descriptors, in-task STS identity, runtime attestation, and STOPPED cleanup proof.
- The collector hashes raw public evidence internally. Precomputed digest-only inputs are rejected.
- Output retains only public identifiers and digests. Raw secrets, private paths, transcripts, raw logs, and secret canaries must not appear.

## Phase 6C1 Task 5 Local Two-Container Proof

Task 5 is a local Docker proof against the exact MCP candidate endpoint only. It does not deploy production and it is not Fargate evidence. The current checkpoint-binding MCP candidate commit is `27ba04a` on the deployed `73954c4` lineage.

Dry-run validates the immutable image reference, endpoint, private env-file references, explicit evidence directory, TTL, and max concurrency without creating Docker resources:

```bash
PATH=/opt/homebrew/opt/node@24/bin:$PATH node scripts/run-mechanics-proof-containers.mjs \
  --dry-run \
  --app-image 123456789012.dkr.ecr.us-west-2.amazonaws.com/clockchain-mechanics-proof@sha256:<64 hex> \
  --mcp-endpoint https://mcp.clockchain.network/handshake/mcp \
  --initiator-env-file /private/tmp/clockchain-mechanics-proof-initiator.env \
  --responder-env-file /private/tmp/clockchain-mechanics-proof-responder.env \
  --evidence-dir /private/tmp/mechanics-proof-two-container-evidence \
  --ttl-seconds 600 \
  --max-concurrency 2
```

Run mode creates one user-defined bridge network with outbound egress, two containers from the same immutable app image, read-only root filesystems, no shared mounts or volumes, and distinct `/workspace` plus `/tmp` tmpfs mounts. The controller passes only public bootstrap descriptors over stdin, waits for responder `a2a.listener.ready`, then hands the responder descriptor to the initiator.

```bash
PATH=/opt/homebrew/opt/node@24/bin:$PATH node scripts/run-mechanics-proof-containers.mjs \
  --run \
  --app-image 123456789012.dkr.ecr.us-west-2.amazonaws.com/clockchain-mechanics-proof@sha256:<64 hex> \
  --mcp-endpoint https://mcp.clockchain.network/handshake/mcp \
  --initiator-env-file /private/tmp/clockchain-mechanics-proof-initiator.env \
  --responder-env-file /private/tmp/clockchain-mechanics-proof-responder.env \
  --evidence-dir /private/tmp/mechanics-proof-two-container-evidence \
  --ttl-seconds 600 \
  --max-concurrency 2
```

Credential files are role-specific and private. Before dry-run or run success, both env-file references are checked with `lstat`: each path must be absolute and normalized, regular, non-symlink, nonempty, bounded to 64 KiB, owned by the current user where POSIX ownership is available, mode `0600`, and a distinct inode/device pair. The controller treats these paths as references only; it never reads or retains credential values, and those values must not appear in argv, labels, compose YAML, logs, or retained evidence.

For the local matrix, the initiator env file may provide exactly one Codex auth mechanism. Subscription-backed Codex auth is carried as a role-private base64 env-file value and installed inside the initiator's isolated runtime HOME as `$HOME/.codex/auth.json`; it is mutually exclusive with `CODEX_API_KEY` and `OPENAI_API_KEY`. Prepare the initiator file with a local command shaped like this, then inspect only file metadata:

```bash
umask 077
node -e 'const fs=require("node:fs"); const path=require("node:path"); const source=path.join(process.env.HOME,".codex","auth.json"); const stat=fs.lstatSync(source); if (!stat.isFile() || stat.isSymbolicLink() || (stat.mode & 0o077) !== 0 || stat.size < 2 || stat.size > 65536) process.exit(1); process.stdout.write("CLOCKCHAIN_CODEX_AUTH_JSON_BASE64="+fs.readFileSync(source).toString("base64")+"\nCLOCKCHAIN_CODEX_MODEL=gpt-5.6-terra\n");' \
  > /private/tmp/clockchain-mechanics-proof-initiator.env
chmod 600 /private/tmp/clockchain-mechanics-proof-initiator.env
```

The responder env file uses Claude Bedrock only: `CLAUDE_CODE_USE_BEDROCK=1`, `ANTHROPIC_MODEL=us.anthropic.claude-sonnet-4-6`, region, and exactly one AWS credential mechanism. For the local Docker canary, a responder-only static AWS trio is allowed when needed: `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, and optional `AWS_SESSION_TOKEN`. ECS/web-identity credential mechanisms remain supported for later Fargate. Mixed mechanisms, cross-role provider variables, and `ANTHROPIC_API_KEY` are rejected.

The retained proof is `two-container-summary.json` only after protocol validation and exact teardown both succeed. It contains the matching verified certificate digest, distinct party/runtime/workload identities, fresh public ERC-8004 registration facts, each role's direct delivery and checkpoint acknowledgment, exactly three matching Clockchain receipt summaries, `externalBusinessActionPerformed:false`, zero exits, and `teardownObserved:true`. Cleanup failure makes the command fail and prevents verified evidence retention.
