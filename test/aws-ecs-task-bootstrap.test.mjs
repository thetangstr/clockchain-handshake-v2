import assert from "node:assert/strict";
import test from "node:test";

import { resolveAwsEcsTaskBootstrap } from "../src/runtime/aws-ecs-task-bootstrap.mjs";

const RUN_ID = "11111111-2222-4333-8444-555555555555";
const ACCOUNT = "123456789012";
const REGION = "us-west-2";
const TASK_ID = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const IMAGE_ID = `sha256:${"b".repeat(64)}`;

function env(overrides = {}) {
  return {
    AWS_CONTAINER_CREDENTIALS_RELATIVE_URI: "/v2/credentials/12345678-1234-4234-9234-123456789abc",
    AWS_REGION: REGION,
    CLOCKCHAIN_A2A_LISTEN_HOST: "0.0.0.0",
    CLOCKCHAIN_A2A_PORT: "8443",
    CLOCKCHAIN_CLIENT: "claude",
    CLOCKCHAIN_HELPER_MANIFEST_DIGEST: "a".repeat(64),
    CLOCKCHAIN_MANDATE_JSON: JSON.stringify({
      identityPolicy: { chainId: "eip155:11155111", erc8004: "required_fresh", registryAddress: "0x8004a818bfb912233c491871b3d84c89a494bd9e" },
      reference: "northstar-harbor-demo",
      statement: "Confirm terms.",
      validForSeconds: "90",
    }),
    CLOCKCHAIN_MCP_URL: "https://mcp.clockchain.network/handshake/mcp",
    CLOCKCHAIN_OPENSSL_PATH: "/usr/bin/openssl",
    CLOCKCHAIN_PARTY_ROOT: "/workspace/responder",
    CLOCKCHAIN_ROLE: "responder",
    CLOCKCHAIN_RUN_ID: RUN_ID,
    ECS_CONTAINER_METADATA_URI_V4: "http://169.254.170.2/v4/12345678-1234-4234-9234-123456789abc",
    ...overrides,
  };
}

function metadata(overrides = {}) {
  return {
    AvailabilityZone: "us-west-2b",
    Cluster: `arn:aws:ecs:${REGION}:${ACCOUNT}:cluster/clockchain-${RUN_ID}`,
    Containers: [
      {
        ContainerARN: `arn:aws:ecs:${REGION}:${ACCOUNT}:container/clockchain-${RUN_ID}/${TASK_ID}/responder-container`,
        Image: `${ACCOUNT}.dkr.ecr.${REGION}.amazonaws.com/clockchain-mechanics-proof@${IMAGE_ID}`,
        ImageID: IMAGE_ID,
        KnownStatus: "RUNNING",
        Name: "responder",
        Networks: [{ IPv4Addresses: ["10.44.17.91"], NetworkMode: "awsvpc" }],
        Type: "NORMAL",
        safeFutureField: { ok: true },
      },
      {
        ContainerARN: `arn:aws:ecs:${REGION}:${ACCOUNT}:container/clockchain-${RUN_ID}/${TASK_ID}/init-container`,
        ImageID: IMAGE_ID,
        KnownStatus: "STOPPED",
        Name: "workspace-init",
        Networks: [],
        Type: "NORMAL",
      },
    ],
    Family: `clockchain-${RUN_ID}-responder`,
    KnownStatus: "RUNNING",
    KnownStatus: "RUNNING",
    LaunchType: "FARGATE",
    Revision: "7",
    TaskARN: `arn:aws:ecs:${REGION}:${ACCOUNT}:task/clockchain-${RUN_ID}/${TASK_ID}`,
    additiveFutureField: "accepted",
    ...overrides,
  };
}

function fetchMetadata(body) {
  return async (url, options) => {
    assert.equal(url, "http://169.254.170.2/v4/12345678-1234-4234-9234-123456789abc/task");
    assert.ok(options.signal);
    const text = JSON.stringify(body);
    return {
      ok: true,
      headers: { get: (name) => (name.toLowerCase() === "content-length" ? String(Buffer.byteLength(text)) : null) },
      async text() { return text; },
    };
  };
}

function sts(overrides = {}) {
  return {
    async send(command) {
      assert.equal(command.constructor.name, "GetCallerIdentityCommand");
      return {
        Account: ACCOUNT,
        Arn: `arn:aws:sts::${ACCOUNT}:assumed-role/clockchain-${RUN_ID}-responder-task/${TASK_ID}`,
        UserId: `AROAXAMPLE:${TASK_ID}`,
        ...overrides,
      };
    },
  };
}

test("ECS task bootstrap derives managed run options and public attestation from metadata plus STS", async () => {
  const result = await resolveAwsEcsTaskBootstrap({ env: env(), fetch: fetchMetadata(metadata()), stsClient: sts() });
  assert.equal(result.attestation.schema, "clockchain.mechanics-proof-ecs-attestation/v1");
  assert.equal(result.attestation.accountId, ACCOUNT);
  assert.equal(result.attestation.region, REGION);
  assert.equal(result.attestation.role, "responder");
  assert.equal(result.attestation.taskId, TASK_ID);
  assert.equal(result.attestation.containerArn, `arn:aws:ecs:${REGION}:${ACCOUNT}:container/clockchain-${RUN_ID}/${TASK_ID}/responder-container`);
  assert.equal(result.attestation.privateIp, "10.44.17.91");
  assert.equal(result.attestation.imageId, IMAGE_ID);
  assert.match(result.attestation.workloadAttestationDigest, /^[0-9a-f]{64}$/);
  assert.equal(result.runOptions.publicEndpoint, "https://10.44.17.91:8443");
  assert.equal(result.runOptions.runtimeId, `ecs-${TASK_ID}`);
  assert.equal(result.runOptions.taskId, TASK_ID);
  assert.equal(result.runOptions.workloadAttestationDigest, result.attestation.workloadAttestationDigest);
  assert.doesNotMatch(JSON.stringify(result), /169\.254\.170\.2|credentials|PRIVATE_KEY/i);
});

test("ECS task bootstrap rejects unsafe environment overrides before metadata or STS", async () => {
  for (const override of [
    { CLOCKCHAIN_A2A_PUBLIC_ENDPOINT: "https://10.0.0.1:8443" },
    { CLOCKCHAIN_RUNTIME_ID: "controller-runtime" },
    { CLOCKCHAIN_TASK_ID: "controller-task" },
    { CLOCKCHAIN_WORKLOAD_ATTESTATION_DIGEST: "f".repeat(64) },
    { AWS_ACCESS_KEY_ID: "static" },
    { AWS_SECRET_ACCESS_KEY: "static" },
    { AWS_SESSION_TOKEN: "static" },
    { AWS_WEB_IDENTITY_TOKEN_FILE: "/tmp/token" },
    { AWS_ROLE_ARN: `arn:aws:iam::${ACCOUNT}:role/controller` },
    { AWS_CONTAINER_CREDENTIALS_FULL_URI: "http://controller.invalid/credentials" },
    { AWS_CONTAINER_AUTHORIZATION_TOKEN: "token" },
    { AWS_ENDPOINT_URL: "https://controller.invalid" },
    { ECS_CONTAINER_METADATA_URI_V4: "http://127.0.0.1/v4/demo" },
    { AWS_CONTAINER_CREDENTIALS_RELATIVE_URI: "http://169.254.170.2/v2/credentials/full" },
  ]) {
    let fetched = false;
    await assert.rejects(
      () => resolveAwsEcsTaskBootstrap({
        env: env(override),
        fetch: async () => { fetched = true; throw new Error("must not fetch"); },
        stsClient: sts(),
      }),
      /Managed ECS task bootstrap failed safely/,
    );
    assert.equal(fetched, false);
  }
});

test("ECS task bootstrap rejects ambiguous metadata, unsafe IPs, and wrong STS identity", async () => {
  const cases = [
    ["wrong launch", metadata({ LaunchType: "EC2" }), sts()],
    ["wrong status", metadata({ KnownStatus: "STOPPED" }), sts()],
    ["duplicate role containers", metadata({ Containers: [metadata().Containers[0], metadata().Containers[0]] }), sts()],
    ["wrong container status", metadata({ Containers: [{ ...metadata().Containers[0], KnownStatus: "PENDING" }] }), sts()],
    ["wrong container arn", metadata({ Containers: [{ ...metadata().Containers[0], ContainerARN: `arn:aws:ecs:${REGION}:${ACCOUNT}:container/other/${TASK_ID}/responder-container` }] }), sts()],
    ["mutable image id", metadata({ Containers: [{ ...metadata().Containers[0], ImageID: "docker-pullable://repo:latest" }] }), sts()],
    ["multiple ips", metadata({ Containers: [{ ...metadata().Containers[0], Networks: [{ NetworkMode: "awsvpc", IPv4Addresses: ["10.0.0.1", "10.0.0.2"] }] }] }), sts()],
    ["loopback ip", metadata({ Containers: [{ ...metadata().Containers[0], Networks: [{ NetworkMode: "awsvpc", IPv4Addresses: ["127.0.0.1"] }] }] }), sts()],
    ["wrong account", metadata(), sts({ Account: "210987654321" })],
    ["wrong arn shape", metadata(), sts({ Arn: `arn:aws:iam::${ACCOUNT}:role/not-assumed` })],
  ];
  for (const [name, body, client] of cases) {
    await assert.rejects(
      () => resolveAwsEcsTaskBootstrap({ env: env(), fetch: fetchMetadata(body), stsClient: client }),
      /Managed ECS task bootstrap failed safely/,
      name,
    );
  }
});

test("ECS task bootstrap rejects accessors, proxies, oversize metadata, and timeout without leaking details", async () => {
  const hostileResponse = {};
  Object.defineProperty(hostileResponse, "ok", { enumerable: true, get() { throw new Error("leaked getter"); } });
  await assert.rejects(
    () => resolveAwsEcsTaskBootstrap({ env: env(), fetch: async () => hostileResponse, stsClient: sts() }),
    /Managed ECS task bootstrap failed safely/,
  );
  await assert.rejects(
    () => resolveAwsEcsTaskBootstrap({ env: env(), fetch: async () => new Proxy({ ok: true, async text() { return "{}"; } }, {}), stsClient: sts() }),
    /Managed ECS task bootstrap failed safely/,
  );
  await assert.rejects(
    () => resolveAwsEcsTaskBootstrap({
      env: env(),
      fetch: async () => ({ ok: true, headers: { get: () => String(257 * 1024) }, async text() { return "{}"; } }),
      stsClient: sts(),
    }),
    /Managed ECS task bootstrap failed safely/,
  );
  await assert.rejects(
    () => resolveAwsEcsTaskBootstrap({
      env: env(),
      fetch: () => new Promise(() => undefined),
      stsClient: sts(),
      timeoutMs: 1,
    }),
    /Managed ECS task bootstrap failed safely/,
  );
});
