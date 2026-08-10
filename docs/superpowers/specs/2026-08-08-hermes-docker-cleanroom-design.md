# Docker-isolated two-agent Hermes live gate — design

**Date:** 2026-08-08  
**Status:** proposed implementation design  
**Owner:** Clockchain Handshake

## Outcome

Provide a repeatable, production-targeted demonstration gate on the Mac mini
that runs two genuinely fresh Hermes parties—a Payer and a Requestor—through
the Clockchain MCP handshake. Each party starts in a separate disposable Linux
container inside a Colima-managed Linux VM. The run retains only sanitized
evidence and removes both party filesystems, wallets, Hermes state, tokens,
and containers after completion.

The environment targets the live production MCP endpoint
`https://mcp.clockchain.network/mcp` and the live Handshake relay/session
coordinator. It does not create a local mock of production.

## Requirements and non-goals

### Required

- Run all orchestration and isolation infrastructure on the Mac mini.
- Use a Linux VM boundary supplied by Colima, with Docker as the container
  engine.
- Start one independent Payer container and one independent Requestor
  container for every run.
- Fresh-bootstrap both roles: install the pinned Hermes release, clone the
  pinned Handshake revision, and run its locked dependency install inside that
  role's disposable filesystem during the run.
- Do not mount a host home directory, source checkout, wallet, Hermes profile,
  credential directory, or existing agent state into either party container.
- Give each role a distinct MCP token and distinct local wallet/identity.
- Retain only redacted, validated run evidence on the Mac mini.
- Support a no-write preflight plus an explicit live run command.
- Guarantee cleanup of exact run-labelled containers, networks, temporary
  secret files, wallets, caches, and workspaces even after a party fails.

### Non-goals

- This is not a claim that Docker containers are virtual machines. Colima is
  the VM boundary; the two containers are independent Linux process,
  filesystem, HOME, and network namespaces inside that VM.
- It does not firewall party egress to an allowlist. Both roles need Internet
  access for the package registry, pinned source revision, production MCP,
  relay, and Sepolia. They will not share a Docker network with one another.
- It does not make the Docker/Colima administrator untrusted. The Mac mini
  operator and the Colima daemon remain trusted infrastructure administrators.

## Chosen topology

```text
Mac mini (trusted operator host)
  └─ Colima ARM64 Linux VM
       ├─ payer-only Docker bridge network
       │    └─ ephemeral Payer container
       │         fresh Hermes + fresh Handshake checkout + fresh wallet
       └─ requestor-only Docker bridge network
            └─ ephemeral Requestor container
                 fresh Hermes + fresh Handshake checkout + fresh wallet

Both containers -> public Internet -> production MCP / live relay / Sepolia
No container-to-container network and no host source, HOME, wallet, or
credential mount.
```

Colima is selected over Docker Desktop because the Mac mini needs a
scriptable, resource-bounded ARM64 Linux VM with the ordinary Docker CLI, not
a desktop GUI dependency. The provisioned profile will be explicit and
observable (`aarch64`, bounded CPU, memory, and disk), rather than silently
using a developer's existing daemon configuration.

## Components

The implementation will add a small, auditable launcher surface rather than
teaching the existing standalone Hermes launcher about Docker implicitly.

| Component | Responsibility |
| --- | --- |
| `docker/hermes-cleanroom/Dockerfile` | Minimal ARM64 Node/Linux bootstrap image containing only base OS tooling, Node, Git, and CA certificates—not Hermes or Handshake dependencies. |
| `docker/hermes-cleanroom/entrypoint` | Per-container bootstrap: obtain the checksum-pinned Hermes release, clone the exact Handshake commit, run the locked install, create the role's isolated Hermes state, then execute its prompt. |
| `bin/hermes-docker-demo.mjs` and supporting core module | Mac-mini-only orchestrator: validate Colima/Docker, mint the two distinct MCP principals, create role-isolated networks and containers, collect evidence, and clean exact resources. |
| Docker labels and run ID | Bind every container, network, staging path, and artifact to one UUID, so cleanup never targets broad Docker state. |
| Existing certificate proof/verifier | Verify the returned, signed terminal certificate against discovery's public key and session ID before evidence is retained. |

The exact Hermes installer and checksum will be resolved from the currently
validated Hermes release before implementation. The launcher will reject an
unpinned version or checksum; it will never fetch `latest`.

## Run lifecycle

1. `--dry-run` verifies the pinned revision, container build inputs, Colima
   availability, Docker daemon, and production health endpoints. It mints no
   token, creates no identity, and sends no party protocol message.
2. A live command creates a run UUID and a private host staging directory,
   validates the one allowed provider credential source, and mints one MCP
   token for Payer and another for Requestor.
3. The launcher creates two unique user-defined bridge networks: one contains
   only the Payer container and one contains only the Requestor container. No
   shared network, link, hostname, volume, or Docker Compose service exists.
4. It creates and starts both containers before awaiting either result. Each
   container has a fresh writable root layer and distinct `HOME`,
   `HERMES_HOME`, workspace, npm cache, temporary directory, wallet path, and
   usage/evidence paths.
5. Each role installs the pinned tools into its own root layer, joins the live
   discovery, generates its own local signing key, receives funding,
   registers its ERC-8004 identity, signs only its role-specific protocol
   bytes, submits results, and locally verifies the shared certificate.
6. The host waits with a bounded run timeout, copies only the declared output
   directory from each stopped container to private staging, validates it for
   shape and secret absence, and retains a redacted evidence bundle.
7. In `finally`, the launcher terminates and removes only the labelled
   containers and role networks; deletes token env files, staging secrets,
   cloned worktrees, wallets, caches, Hermes homes, and all other disposable
   artifacts. Cleanup failure is recorded and makes the command fail.

## Freshness and isolation contract

Every live role receives all of the following independent state:

- its own container filesystem and writable root layer;
- its own Unix user/HOME, `HERMES_HOME`, cache, workspace, and temporary
  directory;
- a Hermes bootstrap created with no skills, no cloned profile, no sessions,
  contacts, messages, memories, agent wallet, or prior configuration;
- a newly generated EVM key and a new ERC-8004 registration, not a key copied
  from the host or another party;
- a distinct MCP principal token, minted once per role; and
- a distinct, one-container Docker bridge network.

The only intended point of collaboration is the public production MCP and
relay. Containers cannot use a shared local filesystem or a shared Docker
network to exchange state.

The retained manifest will report the Colima VM identity, image digest, pinned
Hermes version/checksum, Handshake commit, role-specific container IDs and
network IDs (hashed or redacted as appropriate), pre-provision zero-state
counts, distinct-principal proof, ERC-8004 IDs, testnet anchor references,
and certificate-verification outcome. It will never contain a token, provider
credential, private key, raw environment, or absolute sensitive host path.

## Secrets and evidence

The Mac mini reads the provider credential from the existing owner-only
operator file. It mints role-specific MCP tokens immediately before launch.
Those values are placed only in per-role, owner-only temporary environment
files and passed to the Docker engine for the short lifetime of the matching
container. The files are removed in `finally`; the container is removed after
evidence extraction. This means Docker's transient container configuration is
within the trusted-engine boundary but is never retained as run evidence.

No secret-bearing host directory is mounted into either role. The launcher
does not retain a container's raw stdout/stderr or copy its entire filesystem.
It copies only the declared terminal proof and manifest after the container
has stopped, runs the existing secret-redaction/validation checks in host
memory, and writes a sanitized evidence bundle. Any validation failure retains
no raw secret output and fails the run.

## Safety, cost, and cleanup

The command is deliberately explicit because a live run spends testnet gas,
mints two MCP tokens, creates two ERC-8004 identities, and calls the selected
provider model. The default production run uses the current lower-cost pinned
model setting; no fallback provider is allowed. A no-write `--dry-run` is the
normal smoke test.

All destructive Docker actions are constrained by the generated run UUID and
resource labels. The launcher never executes broad Docker prune, removes a
user-named container, or deletes a non-descendant path. It validates each
resource before removal and reports cleanup success or failure in the final
sanitized evidence.

## Verification plan

Implementation must prove each layer before a paid live run:

1. Unit tests cover Docker argument generation, resource labels, two-network
   separation, pin enforcement, secret-free evidence, role principal
   inequality, failure cleanup, and refusal of host source/HOME/wallet mounts.
2. A containerized fixture proves two blank roots independently bootstrap the
   pinned Hermes and Handshake dependencies, with no reused local profile or
   wallet.
3. `--dry-run` on the Mac mini verifies Colima, Docker, image build, and both
   production health endpoints without minting tokens or modifying a live
   session.
4. One explicitly invoked live production run proves two new ERC-8004 IDs,
   signed `party_ready` records, role-specific mandate/request, anchors,
   independent certificate verification, `paymentMoved:false`, and successful
   post-run deletion of all disposable resources.
5. The public two-agent monitor is checked against the resulting live session
   so the retained evidence and presenter agree.

## Acceptance criteria

- A single documented Mac-mini command can run the no-write preflight and a
  separately explicit live clean-room test.
- The live run creates exactly two new party identities and no shared party
  credential, filesystem, container, or Docker network.
- Each party installs Hermes and the pinned Handshake dependencies inside its
  own disposable container during that run.
- The two agents complete a live production handshake or fail with a
  diagnosable, secret-free evidence bundle.
- The verifier accepts only a correctly signed, session-bound authorized
  certificate with `paymentMoved:false`.
- A successful or failed run leaves neither party container, role network,
  temporary credential file, wallet, Hermes state, checkout, nor cache on the
  Mac mini; only sanitized evidence remains.
