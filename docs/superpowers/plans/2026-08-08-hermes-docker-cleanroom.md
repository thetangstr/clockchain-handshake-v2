# Hermes Docker Clean-room Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Run two fully fresh, production-targeted Hermes handshake parties in separate disposable Docker containers inside a Colima Linux VM on the Mac mini.

**Architecture:** A Mac-mini-only launcher creates two isolated Docker networks, mints distinct MCP principals, and concurrently starts one container per role. Each container downloads checksum-pinned Hermes, clones the exact pushed Handshake commit, runs `npm ci`, creates its own wallet/Hermes state, and yields declared output for host-side secret-safe validation and exact cleanup.

**Tech Stack:** Node.js 22 ESM, Docker CLI/Engine, Colima ARM64 Linux VM, existing Hermes clean-room and certificate-proof modules, Node test runner.

---

## File structure

| File | Responsibility |
| --- | --- |
| `src/core/hermes-docker-demo.mjs` | Resource validation, Docker command construction, exact lifecycle, evidence validation, cleanup. |
| `bin/hermes-docker-demo.mjs` | Production CLI, pushed-commit gate, dry-run/live parsing, safe output. |
| `docker/hermes-cleanroom/Dockerfile` | ARM64 bootstrap image containing Node, Git, curl, and CA certificates only. |
| `docker/hermes-cleanroom/entrypoint.mjs` | Fresh in-container Hermes/Handshake bootstrap and role execution. |
| `test/hermes-docker-demo.test.mjs` | Resource-isolation, secrets, cleanup, and dry-run tests. |
| `test/hermes-docker-entrypoint.test.mjs` | Pinned bootstrap tests with injected command adapter. |
| `test/hermes-docker-cli.test.mjs` | CLI parsing and pushed-commit tests. |
| `docs/hermes-turnkey-demo.md` | Colima provisioning and operator runbook. |

### Task 1: Lock the Docker resource boundary

**Files:**
- Create: `src/core/hermes-docker-demo.mjs`
- Create: `test/hermes-docker-demo.test.mjs`

- [ ] **Step 1: Write failing safety tests**

```js
import test from "node:test";
import assert from "node:assert/strict";
import { buildDockerRunPlan, validateDockerEvidence } from "../src/core/hermes-docker-demo.mjs";

test("buildDockerRunPlan creates disjoint labelled role resources", () => {
  const plan = buildDockerRunPlan({
    image: "clockchain/hermes-cleanroom@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    runId: "123e4567-e89b-42d3-a456-426614174000",
  });
  assert.notEqual(plan.roles.payer.network, plan.roles.requestor.network);
  assert.notEqual(plan.roles.payer.container, plan.roles.requestor.container);
  assert.equal(plan.roles.payer.labels["clockchain.run"], plan.runId);
  assert.deepEqual(plan.roles.payer.mounts, []);
});

test("validateDockerEvidence rejects secret-bearing output", () => {
  assert.throws(() => validateDockerEvidence({ stdout: "cc_secret", terminal: null }, ["cc_secret"]));
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `node --test test/hermes-docker-demo.test.mjs`  
Expected: FAIL because the module does not exist.

- [ ] **Step 3: Implement the pure plan and evidence validators**

```js
const ROLES = Object.freeze(["payer", "requestor"]);
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

export function buildDockerRunPlan({ image, runId }) {
  if (typeof image !== "string" || !image.includes("@sha256:") || !UUID.test(runId)) throw new Error("Docker demo failed safely.");
  const labels = Object.freeze({ "clockchain.managed": "hermes-docker-demo", "clockchain.run": runId });
  return Object.freeze({
    image, runId,
    roles: Object.freeze(Object.fromEntries(ROLES.map((role) => [role, Object.freeze({
      container: `clockchain-hermes-${runId}-${role}`,
      labels, mounts: Object.freeze([]),
      network: `clockchain-hermes-${runId}-${role}`, role,
    })]))),
  });
}
```

`validateDockerEvidence` must use existing `assertSecretFree`, reject raw logs, provider values, tokens, private keys, missing terminal proof, invalid certificate binding, and any result other than `paymentMoved:false`.

- [ ] **Step 4: Run focused tests**

Run: `node --test test/hermes-docker-demo.test.mjs`  
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/core/hermes-docker-demo.mjs test/hermes-docker-demo.test.mjs
git commit -m "Define Docker clean-room resource boundary"
```

### Task 2: Bootstrap agents inside disposable ARM64 containers

**Files:**
- Create: `docker/hermes-cleanroom/Dockerfile`
- Create: `docker/hermes-cleanroom/entrypoint.mjs`
- Create: `docker/hermes-cleanroom/package.json`
- Create: `test/hermes-docker-entrypoint.test.mjs`

- [ ] **Step 1: Write failing bootstrap tests**

```js
test("bootstrap refuses a floating revision or missing archive checksum", async () => {
  await assert.rejects(bootstrapRole({ hermesSha256: "", kitCommit: "main" }), /failed safely/i);
});

test("bootstrap installs only below /work and never uses a host path", async () => {
  const calls = [];
  await bootstrapRole(validInput({ run: async (...argv) => calls.push(argv) }));
  assert.deepEqual(calls.map(([file]) => file), ["curl", "sha256sum", "tar", "git", "npm", "node"]);
  assert.ok(calls.every(([, args]) => !args.join(" ").includes("/Users/")));
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `node --test test/hermes-docker-entrypoint.test.mjs`  
Expected: FAIL because the entrypoint does not exist.

- [ ] **Step 3: Add a minimal bootstrap image and strict entrypoint**

```dockerfile
FROM --platform=linux/arm64 node:22-bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates git curl && rm -rf /var/lib/apt/lists/*
RUN useradd --create-home --uid 10001 hermes
USER hermes
WORKDIR /work
COPY --chown=hermes:hermes package.json entrypoint.mjs /bootstrap/
ENTRYPOINT ["node", "/bootstrap/entrypoint.mjs"]
```

The entrypoint accepts only validated `ROLE`, `KIT_URL`, 40-hex `KIT_COMMIT`, `HERMES_URL`, 64-hex `HERMES_SHA256`, `MCP_TOKEN`, and one provider-key environment variable. It downloads Hermes to `/work/runtime`, verifies it with `sha256sum --check`, clones the exact commit into `/work/kit`, runs `npm ci`, runs the existing wallet/certificate proof flow, and writes only manifest/proof/usage JSON to `/out`. It rejects all host paths, floating refs, reused wallets, and undeclared output files.

- [ ] **Step 4: Run tests and build the image**

Run: `node --test test/hermes-docker-entrypoint.test.mjs && docker build --platform linux/arm64 -t clockchain/hermes-cleanroom:dev docker/hermes-cleanroom`  
Expected: tests PASS; image build succeeds after Colima provisioning.

- [ ] **Step 5: Commit**

```bash
git add docker/hermes-cleanroom test/hermes-docker-entrypoint.test.mjs
git commit -m "Bootstrap Hermes inside disposable containers"
```

### Task 3: Execute two roles concurrently and clean exact resources

**Files:**
- Modify: `src/core/hermes-docker-demo.mjs`
- Modify: `test/hermes-docker-demo.test.mjs`

- [ ] **Step 1: Write lifecycle and no-write tests**

```js
test("live lifecycle creates separate networks, starts both roles, and removes exact resources", async () => {
  const commands = [];
  await runHermesDockerDemo(validOptions({ docker: async (...argv) => commands.push(argv) }));
  assert.equal(commands.filter(([a, b]) => a === "network" && b === "create").length, 2);
  assert.equal(commands.filter(([a]) => a === "create").length, 2);
  assert.equal(commands.filter(([a, b]) => a === "rm" && b === "-f").length, 2);
  assert.ok(commands.every((argv) => !argv.includes("prune") && !argv.includes("system")));
});

test("dry run does not mint tokens or create Docker state", async () => {
  let minted = false;
  await runHermesDockerDemo(validOptions({ dryRun: true, mintDemoToken: async () => { minted = true; } }));
  assert.equal(minted, false);
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `node --test test/hermes-docker-demo.test.mjs`  
Expected: FAIL because `runHermesDockerDemo` is not implemented.

- [ ] **Step 3: Implement the exact lifecycle**

```js
export async function runHermesDockerDemo({ docker, dryRun = false, mintDemoToken, runId, ...options }) {
  const plan = buildDockerRunPlan({ image: await resolvePinnedImage(options), runId });
  await checkDockerAndProduction({ docker, ...options });
  if (dryRun) return Object.freeze({ dryRun: true, plan: publicPlan(plan) });
  const tokens = await mintDistinctTokens({ mintDemoToken, runId: plan.runId });
  try {
    for (const role of ROLES) await docker("network", "create", "--label", "clockchain.run=" + plan.runId, plan.roles[role].network);
    await Promise.all(ROLES.map((role) => createAndStartRole({ docker, plan, role, token: tokens[role] })));
    return await collectAndValidateRoleEvidence({ docker, plan, tokens });
  } finally {
    await removeExactRunResources({ docker, plan });
    await removeTemporarySecrets({ plan });
  }
}
```

Create (not `--rm`) containers so host code can copy only `/out` after stop, validate/redact it in memory, then remove precisely labelled containers and networks. Write role-specific mode-0600 env files, pass them only with `--env-file`, delete them in `finally`, and begin both role containers before awaiting either completion. Fail closed if session, principal fingerprint, identity, role proof, certificate binding, or cleanup result differs.

- [ ] **Step 4: Run focused regression suite**

Run: `node --test test/hermes-docker-demo.test.mjs test/redact.test.mjs test/hermes-cleanroom.test.mjs test/hermes-launcher.test.mjs`  
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/core/hermes-docker-demo.mjs test/hermes-docker-demo.test.mjs
git commit -m "Run and clean exact Docker Hermes agents"
```

### Task 4: Provide production CLI and Mac-mini runbook

**Files:**
- Create: `bin/hermes-docker-demo.mjs`
- Create: `test/hermes-docker-cli.test.mjs`
- Modify: `package.json`
- Modify: `docs/hermes-turnkey-demo.md`

- [ ] **Step 1: Write failing CLI tests**

```js
test("CLI accepts only dry-run, timeout, and absolute credential-file options", async () => {
  assert.deepEqual(await parseArgs(["--dry-run"]), { dryRun: true, timeoutMs: 1_800_000 });
  await assert.rejects(parseArgs(["--credential-file", "relative.key"]), /failed safely/i);
  await assert.rejects(parseArgs(["--keep-containers"]), /failed safely/i);
});

test("live CLI requires a pushed 40-hex Handshake commit", async () => {
  await assert.rejects(currentPushedCommit(fakeUnpushedGit), /failed safely/i);
});
```

- [ ] **Step 2: Run CLI tests to verify they fail**

Run: `node --test test/hermes-docker-cli.test.mjs`  
Expected: FAIL because the CLI module does not exist.

- [ ] **Step 3: Implement production surface and documentation**

Add this package script:

```json
{ "scripts": { "demo:hermes:docker": "node bin/hermes-docker-demo.mjs" } }
```

The CLI must default only to the existing owner-only Mac-mini provider file, canonical production MCP/relay endpoints, and pushed current commit. It prints exactly one secret-free JSON result on success and `Hermes Docker demo failed safely.` on failure. It has no keep-container flag. The runbook must include:

```bash
brew install colima docker docker-compose
colima start --arch aarch64 --cpu 4 --memory 8 --disk 20
npm run demo:hermes:docker -- --dry-run
npm run demo:hermes:docker
```

It must label the last command as live/mutating and document the Colima-admin trust boundary, two unshared networks, no host-state mounts, provider/testnet cost, evidence path, and cleanup behavior.

- [ ] **Step 4: Run CLI/docs checks**

Run: `node --test test/hermes-docker-cli.test.mjs test/hermes-demo-docs.test.mjs && npm run typecheck`  
Expected: PASS, or report any existing unrelated typecheck failure.

- [ ] **Step 5: Commit**

```bash
git add bin/hermes-docker-demo.mjs test/hermes-docker-cli.test.mjs package.json docs/hermes-turnkey-demo.md
git commit -m "Document Mac mini Docker Hermes gate"
```

### Task 5: Provision and verify on the Mac mini

**Files:**
- Modify: `docs/hermes-turnkey-demo.md`

- [ ] **Step 1: Run all local automated tests**

Run: `node --test test/hermes-docker-demo.test.mjs test/hermes-docker-entrypoint.test.mjs test/hermes-docker-cli.test.mjs test/hermes-cleanroom.test.mjs test/hermes-launcher.test.mjs test/certificate-proof.test.mjs test/redact.test.mjs`  
Expected: PASS.

- [ ] **Step 2: Provision the explicit Colima profile**

Run on `maxiaoer@192.168.86.48`:

```bash
brew install colima docker docker-compose
colima start --arch aarch64 --cpu 4 --memory 8 --disk 20
docker version --format '{{.Server.Os}}/{{.Server.Arch}}'
```

Expected: `linux/arm64`. Do not capture any credential, token, or raw Docker-inspect environment.

- [ ] **Step 3: Run no-write production preflight**

```bash
npm ci
npm run demo:hermes:docker -- --dry-run
```

Expected: Docker/Colima and production health pass; no MCP token, identity, protocol message, persistent container, or persistent network is created.

- [ ] **Step 4: Run the explicit live production proof**

```bash
npm run demo:hermes:docker
docker ps -a --filter label=clockchain.managed=hermes-docker-demo --format '{{.ID}}'
docker network ls --filter label=clockchain.managed=hermes-docker-demo --format '{{.ID}}'
```

Expected: terminal authorized certificate with `paymentMoved:false`, two distinct new ERC-8004 identities, and empty container/network listings after cleanup. Compare the returned session on the public two-agent monitor.

- [ ] **Step 5: Final verify and record safe evidence facts**

Run: `npm run verify`  
Expected: PASS.

Append only run ID, public ERC-8004 IDs, receipt references, certificate digest, outcome, cleanup status, and version identifiers to the runbook test record.

```bash
git add docs/hermes-turnkey-demo.md
git commit -m "Record Docker clean-room verification"
```

## Plan self-review

**Spec coverage:** Tasks 1–3 implement two isolated containers, no source/HOME/wallet mounts, distinct tokens/networks, fresh bootstrap, secret-safe evidence, and exact cleanup. Task 4 provides the safe Mac-mini interface and runbook. Task 5 covers Colima provisioning, no-write preflight, live production proof, monitor parity, and removal verification.

**Placeholder scan:** no TBD/TODO/"implement later" instruction remains.

**Type consistency:** `buildDockerRunPlan`, `validateDockerEvidence`, and `runHermesDockerDemo` are defined before use. Role names stay `payer` and `requestor`; every container bootstrap uses the same `KIT_COMMIT`, `HERMES_SHA256`, and role token contract.
