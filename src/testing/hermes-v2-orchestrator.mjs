import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdir, readFile, rm } from "node:fs/promises";
import { join, relative } from "node:path";
import { promisify } from "node:util";
import { gunzipSync } from "node:zlib";

import { privateKeyToAccount } from "viem/accounts";

import { readPrivateText, writePrivateFile } from "../core/private-path.mjs";
import {
  createFreshAgentRun,
  prepareAgentHarnessAdapter,
} from "./fresh-agent-client.mjs";
import {
  CLOCKCHAIN_V2_TOOLS,
  buildHermesConfig,
  buildHermesInvocation,
  commitmentCheckpointDigest,
  createCommitmentCheckpoint,
  createHermesDecisionPrompt,
  createStreamableMcpClient,
  extractSigningRequestFromArgv,
  parseHermesDecision,
} from "./hermes-v2-live.mjs";

const execFileAsync = promisify(execFile);
const ENDPOINT = "https://mcp.clockchain.network/handshake/mcp";
const RELAY = "http://44.249.47.220:8080";
const HERMES = "/Users/Kailor/.local/bin/hermes";
const NODE24 = "/opt/homebrew/opt/node@24/bin/node";
const MANIFEST_DIGEST = "fa3c408a3739227b5bdb71486b4d291b8f4dffdb0d1f2fa79dd59644ba5e09ad";
const WAIT_MS = 3_000;
const RUN_TIMEOUT_MS = 12 * 60_000;
const MIN_INVITE_REMAINING_MS = 15_000;
const ADDRESS = /^0x[0-9a-f]{40}$/;
const SIGNATURE = /^0x[0-9a-f]{130}$/;
const DIGEST = /^[0-9a-f]{64}$/;
const DECIMAL = /^(?:0|[1-9][0-9]*)$/;

function fail(code = "HERMES_V2_LIVE_FAILED") {
  const error = new Error("Hermes v2 live gate failed safely.");
  error.code = code;
  throw error;
}

function delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function publicEvent(value) {
  process.stderr.write(`${JSON.stringify(value)}\n`);
}

function parseHelper(stdout) {
  try {
    const value = JSON.parse(stdout.trim());
    if (value?.schema !== "clockchain.agent-handshake-cli-result/v1" || value?.helperVersion !== "2.1.2") fail("HELPER_RESULT_INVALID");
    return value;
  } catch (error) {
    if (error?.code) throw error;
    fail("HELPER_RESULT_INVALID");
  }
}

async function executeBoundStep(agent, step) {
  let expected;
  try { expected = agent.adapter.record(step); } catch { fail("BOUND_ACTION_INVALID"); }
  try { await agent.adapter.authorize(step); } catch { fail("BOUND_ACTION_EXECUTION_FAILED"); }
  let output;
  try {
    output = await execFileAsync(agent.adapter.executable, [expected.commandSha256], {
      cwd: agent.room.workspace,
      env: {
        HOME: agent.room.home,
        LANG: "C.UTF-8",
        LC_ALL: "C.UTF-8",
        PATH: `${agent.adapter.bin}:/opt/homebrew/opt/node@24/bin:/usr/bin:/bin`,
        TMPDIR: agent.room.tmp,
      },
      maxBuffer: 1024 * 1024,
      timeout: 180_000,
    });
  } catch {
    fail("HELPER_EXECUTION_FAILED");
  }
  return Object.freeze({ expected, result: parseHelper(output.stdout) });
}

async function executeLocalAction(agent, localAction) {
  if (Array.isArray(localAction?.helperSteps)) {
    const results = [];
    for (const step of localAction.helperSteps) results.push(await executeBoundStep(agent, step));
    return results;
  }
  if (localAction?.helperStep) return [await executeBoundStep(agent, localAction.helperStep)];
  fail("LOCAL_ACTION_MISSING");
}

async function prepareHermesAgent({ providerSecret, role, room }) {
  const hermesHome = join(room.state, "hermes-home");
  await mkdir(hermesHome, { mode: 0o700 });
  await writePrivateFile({
    path: join(hermesHome, "config.yaml"),
    bytes: Buffer.from(`${JSON.stringify(buildHermesConfig(), null, 2)}\n`, "utf8"),
  });
  const base = buildHermesInvocation({
    cache: room.cache,
    hermesHome,
    home: room.home,
    providerSecret,
    prompt: "preflight",
    tmp: room.tmp,
    usageFile: join(room.state, "preflight-usage.json"),
    workspace: room.workspace,
  });
  let tested;
  try {
    tested = await execFileAsync(HERMES, ["mcp", "test", "clockchain"], {
      cwd: base.cwd,
      env: base.env,
      maxBuffer: 256 * 1024,
      timeout: 30_000,
    });
  } catch {
    fail("HERMES_MCP_CONNECT_FAILED");
  }
  if (!/Tools discovered: 8/.test(tested.stdout)) fail("HERMES_MCP_TOOL_COUNT_INVALID");
  let adapter;
  try {
    adapter = await prepareAgentHarnessAdapter({
      manifestDigest: MANIFEST_DIGEST,
      room,
      runtimeExecPath: NODE24,
    });
  } catch {
    fail("HELPER_BOOTSTRAP_FAILED");
  }
  return {
    adapter,
    decisions: 0,
    hermesHome,
    policy: null,
    providerSecret,
    role,
    room,
    usage: [],
  };
}

async function decide(agent, action) {
  const prompt = createHermesDecisionPrompt({ action, policy: agent.policy });
  const usageFile = join(agent.room.state, `usage-${String(++agent.decisions).padStart(2, "0")}.json`);
  const invocation = buildHermesInvocation({
    cache: agent.room.cache,
    hermesHome: agent.hermesHome,
    home: agent.room.home,
    providerSecret: agent.providerSecret,
    prompt,
    tmp: agent.room.tmp,
    usageFile,
    workspace: agent.room.workspace,
  });
  let completed;
  try {
    completed = await execFileAsync(HERMES, invocation.args, {
      cwd: invocation.cwd,
      env: invocation.env,
      maxBuffer: 256 * 1024,
      timeout: 120_000,
    });
  } catch {
    fail("HERMES_DECISION_FAILED");
  }
  const decision = parseHermesDecision(completed.stdout, { expectedActionDigest: action.bytesSha256 });
  if (decision.decision !== "approve") fail("HERMES_REFUSED_ACTION");
  try {
    const usage = JSON.parse(await readFile(usageFile, "utf8"));
    agent.usage.push({
      apiCalls: Number(usage.api_calls ?? 0),
      inputTokens: Number(usage.input_tokens ?? 0),
      outputTokens: Number(usage.output_tokens ?? 0),
    });
  } catch {
    fail("HERMES_USAGE_INVALID");
  }
  publicEvent({ event: "hermes_approved", role: agent.role, operation: action.operation, actionDigest: action.bytesSha256 });
}

function signingPayload(request) {
  try {
    const bytes = gunzipSync(Buffer.from(request.bytesGzipBase64Url, "base64url"));
    if (createHash("sha256").update(bytes).digest("hex") !== request.bytesSha256) fail("SIGNING_REQUEST_DIGEST_MISMATCH");
    return JSON.parse(bytes.toString("utf8"));
  } catch (error) {
    if (error?.code) throw error;
    fail("SIGNING_REQUEST_INVALID");
  }
}

async function signPending({ agent, checkpoints, client, response }) {
  const step = response?.localAction?.helperStep;
  if (!step || response?.localAction?.operation !== "sign") fail("SIGNING_ACTION_MISSING");
  let expected;
  try { expected = agent.adapter.record(step); } catch { fail("BOUND_ACTION_INVALID"); }
  let request;
  try { request = extractSigningRequestFromArgv(expected.argv); } catch { fail("SIGNING_REQUEST_INVALID"); }
  if (
    response.signingSummary?.bytesSha256 !== request.bytesSha256 ||
    response.signingSummary?.operation !== request.operation ||
    response.signingSummary?.role !== agent.role ||
    response.signingSummary?.sessionId !== request.sessionId
  ) fail("SIGNING_SUMMARY_MISMATCH");
  // MCP adds a display schema to its public signing summary. The policy engine
  // deliberately receives only the four stable decision fields; the original
  // request bytes remain bound to the deterministic helper action below.
  await decide(agent, {
    bytesSha256: response.signingSummary.bytesSha256,
    operation: response.signingSummary.operation,
    role: response.signingSummary.role,
    sessionId: response.signingSummary.sessionId,
  });
  publicEvent({ event: "bound_sign_execution_started", role: agent.role, operation: request.operation });
  const executed = await executeBoundStep(agent, step);
  if (
    executed.result.operation !== "sign" ||
    executed.result.bytesSha256 !== request.bytesSha256 ||
    !SIGNATURE.test(executed.result.signatureHex ?? "")
  ) fail("SIGNATURE_RESULT_INVALID");
  if (["proposal", "acceptance"].includes(request.operation)) {
    if (typeof executed.expected.stateDir !== "string" || !executed.expected.stateDir.startsWith(`${agent.room.tmp}/`)) {
      fail("ROLE_WALLET_PATH_INVALID");
    }
    const walletPath = join(executed.expected.stateDir, "wallet.json");
    let wallet;
    try { wallet = JSON.parse(await readPrivateText({ path: walletPath })); } catch { fail("ROLE_WALLET_INVALID"); }
    const account = privateKeyToAccount(wallet.privateKey);
    const address = account.address.toLowerCase();
    if (wallet.address.toLowerCase() !== address || address !== executed.result.address.toLowerCase()) fail("ROLE_WALLET_MISMATCH");
    const checkpoint = await createCommitmentCheckpoint({
      artifactPayload: signingPayload(request),
      artifactSignatureHex: executed.result.signatureHex,
      artifactType: request.operation,
      nowMs: Date.now(),
      previousCheckpoint: request.operation === "proposal" ? null : checkpoints.proposal,
      role: agent.role,
      sessionId: request.sessionId,
      signerAddress: address,
      signMessage: ({ raw }) => account.signMessage({ message: { raw } }),
    });
    const checkpointResult = await client.callTool("agent_handshake_submit_checkpoint", {
      access: agent.access,
      artifactSignatureHex: executed.result.signatureHex,
      checkpoint,
    });
    if (checkpointResult.checkpointDigest !== commitmentCheckpointDigest(checkpoint)) fail("CHECKPOINT_DIGEST_MISMATCH");
    checkpoints[request.operation] = checkpoint;
    publicEvent({ event: "checkpoint_submitted", role: agent.role, artifactType: request.operation, checkpointDigest: checkpointResult.checkpointDigest });
  }
  const submitted = await client.callTool("agent_handshake_submit", {
    access: agent.access,
    policyDigest: agent.policyDigest,
    signatureHex: executed.result.signatureHex,
  });
  publicEvent({ event: "signature_submitted", role: agent.role, operation: request.operation, stage: submitted.stage });
  return submitted;
}

async function setupAndJoin({ agent, client, invitationResult }) {
  // Public MCP responses intentionally expose the caller's capability through
  // one neutral field rather than through a role-specific private field.
  if (typeof invitationResult?.roleAccess !== "string" || invitationResult.roleAccess.length < 27) fail("ROLE_ACCESS_MISSING");
  agent.access = invitationResult.roleAccess;
  agent.policy = invitationResult.localPolicy;
  await decide(agent, {
    operation: "identity_claim",
    role: agent.role,
    sessionId: invitationResult.sessionId,
    bytesSha256: agent.policy.statementDigest,
  });
  publicEvent({ event: "local_setup_started", role: agent.role });
  let setup;
  try { setup = await executeLocalAction(agent, invitationResult.localAction); } catch (error) {
    if (error?.code) throw error;
    fail("LOCAL_SETUP_FAILED");
  }
  const inspected = setup.at(-1)?.result;
  if (inspected?.operation !== "inspect" || !ADDRESS.test(inspected.address?.toLowerCase() ?? "") || !DIGEST.test(inspected.policyDigest ?? "")) fail("HELPER_SETUP_INVALID");
  agent.address = inspected.address.toLowerCase();
  agent.policyDigest = inspected.policyDigest;
  publicEvent({ event: "local_setup_complete", role: agent.role, address: agent.address });
  const joined = await client.callTool("agent_handshake_join", {
    access: agent.access,
    helperVersion: "2.1.2",
    sessionKeyAddress: agent.address,
    policyDigest: agent.policyDigest,
  });
  publicEvent({ event: "role_join_response_received", role: agent.role });
  await signPending({ agent, checkpoints: {}, client, response: joined });
  publicEvent({ event: "role_joined", role: agent.role, address: agent.address });
}

async function reachPartyReady({ agent, client, deadline }) {
  let registered = false;
  while (Date.now() < deadline) {
    const next = await client.callTool("agent_handshake_next", { access: agent.access });
    if (next.stage === "party_ready" && next.identity) {
      agent.identity = next.identity;
      publicEvent({ event: "party_ready", role: agent.role, address: agent.address, agentId: next.identity.erc8004?.agentId ?? null });
      return;
    }
    if (next.needed === "erc8004_registration" && !registered) {
      const [registration] = await executeLocalAction(agent, next.localAction);
      agent.registration = registration.result.registration;
      registered = true;
      publicEvent({ event: "erc8004_registered", role: agent.role, agentId: agent.registration.agentId, registrationTx: agent.registration.registrationTx });
      continue;
    }
    if (["funding_record", "funding_visibility", "counterpart_identity"].includes(next.needed)) {
      await delay(Number(next.retryAfterMs ?? WAIT_MS));
      continue;
    }
    fail("PARTY_READY_STATE_INVALID");
  }
  fail("PARTY_READY_TIMEOUT");
}

async function waitForSigning({ agent, client, operation, deadline }) {
  publicEvent({ event: "signing_wait_started", role: agent.role, operation });
  while (Date.now() < deadline) {
    const next = await client.callTool("agent_handshake_next", { access: agent.access });
    if (next.localAction?.operation === "sign" && next.signingSummary?.operation === operation) {
      publicEvent({ event: "signing_action_received", role: agent.role, operation });
      return next;
    }
    if (next.retryAfterMs !== undefined || next.needed !== undefined) {
      await delay(Math.min(Number(next.retryAfterMs ?? WAIT_MS), WAIT_MS));
      continue;
    }
    fail("SIGNING_STATE_INVALID");
  }
  fail("SIGNING_STATE_TIMEOUT");
}

async function waitForBothEvidence({ agents, client, deadline }) {
  const found = {};
  while (Object.keys(found).length < 2 && Date.now() < deadline) {
    for (const agent of agents) {
      if (found[agent.role]) continue;
      const next = await client.callTool("agent_handshake_next", { access: agent.access });
      if (next.localAction?.operation === "sign" && next.signingSummary?.operation === "evidence") {
        found[agent.role] = next;
      }
    }
    if (Object.keys(found).length < 2) await delay(WAIT_MS);
  }
  if (Object.keys(found).length !== 2) fail("EVIDENCE_STATE_TIMEOUT");
  return found;
}

async function waitForCertificate({ agent, client, deadline }) {
  while (Date.now() < deadline) {
    const result = await client.callTool("agent_handshake_get_certificate", { access: agent.access });
    if (result.localAction?.operation === "verify-certificate" && result.certificateSummary) {
      const [verified] = await executeLocalAction(agent, result.localAction);
      if (verified.result.operation !== "verify-certificate" || verified.result.outcome !== "VERIFIED" || verified.result.certificateVerified !== true) fail("CERTIFICATE_PROOF_INVALID");
      return { proof: verified.result, summary: result.certificateSummary };
    }
    await delay(Number(result.retryAfterMs ?? WAIT_MS));
  }
  fail("CERTIFICATE_TIMEOUT");
}

async function waitForFreshDiscovery(deadline) {
  while (Date.now() < deadline) {
    const response = await fetch(`${RELAY}/v1/discovery/current`);
    if (!response.ok) fail("DISCOVERY_HTTP_FAILED");
    const discovery = await response.json();
    if (Number(discovery.invitationExpiresAtMs) - Date.now() >= MIN_INVITE_REMAINING_MS) return discovery;
    await delay(WAIT_MS);
  }
  fail("FRESH_DISCOVERY_TIMEOUT");
}

function usageTotals(agent) {
  return agent.usage.reduce((result, entry) => ({
    apiCalls: result.apiCalls + entry.apiCalls,
    inputTokens: result.inputTokens + entry.inputTokens,
    outputTokens: result.outputTokens + entry.outputTokens,
  }), { apiCalls: 0, inputTokens: 0, outputTokens: 0 });
}

export function isVerifiedV2Monitor(monitor, { initiatorAddress, responderAddress, sessionId } = {}) {
  return Boolean(
    monitor && typeof monitor === "object" && !Array.isArray(monitor) &&
    monitor.schema === "clockchain.agent-handshake-snapshot/v2" &&
    monitor.sessionId === sessionId &&
    monitor.checker?.stage === "VERIFIED" &&
    monitor.certificate?.outcome === "VERIFIED" &&
    monitor.externalBusinessActionPerformed === false &&
    monitor.parties?.initiator?.sessionKeyAddress === initiatorAddress &&
    monitor.parties?.responder?.sessionKeyAddress === responderAddress
  );
}

export async function runHermesV2ProductionGate({ parent, providerSecret } = {}) {
  if (typeof providerSecret !== "string" || providerSecret.length < 16 || typeof parent !== "string") fail("INPUT_INVALID");
  if (!process.versions.node.startsWith("24.")) fail("NODE24_REQUIRED");
  const startedAt = Date.now();
  const deadline = startedAt + RUN_TIMEOUT_MS;
  await mkdir(parent, { recursive: true, mode: 0o700 });
  const run = await createFreshAgentRun({ parent });
  if (relative(parent, run.root).startsWith("..")) fail("RUN_PATH_INVALID");
  const adapters = [];
  try {
    publicEvent({ event: "hermes_preflight_started" });
    const [initiator, responder] = await Promise.all([
      prepareHermesAgent({ providerSecret, role: "initiator", room: run.roles.initiator }),
      prepareHermesAgent({ providerSecret, role: "responder", room: run.roles.responder }),
    ]);
    publicEvent({ event: "hermes_preflight_complete" });
    adapters.push(initiator.adapter, responder.adapter);
    const agents = [initiator, responder];
    // The relay invitation has a short, intentional lifetime. A fresh-agent
    // preflight is slower than the transport calls below, so do it before
    // selecting the current session rather than consuming its invite window.
    const discovery = await waitForFreshDiscovery(deadline);
    publicEvent({ event: "fresh_session_ready", sessionId: discovery.sessionId });
    const client = createStreamableMcpClient({ endpoint: ENDPOINT });
    await client.connect();
    publicEvent({ event: "production_mcp_connected" });
    const tools = await client.listTools();
    if (JSON.stringify(tools) !== JSON.stringify(CLOCKCHAIN_V2_TOOLS)) fail("MCP_TOOL_SURFACE_INVALID");
    const terms = {
      reference: "NS-1847",
      statement: "Northstar Logistics and Harbor Supply authorize these two independently controlled agents to communicate about shipment reference NS-1847 for 90 seconds.",
      validForSeconds: "90",
      identityPolicy: {
        erc8004: "required_fresh",
        chainId: "eip155:11155111",
        registryAddress: "0x8004a818bfb912233c491871b3d84c89a494bd9e",
      },
    };
    const invited = await client.callTool("agent_handshake_invite", terms);
    if (invited.sessionId !== discovery.sessionId) fail("INVITATION_SESSION_MISMATCH");
    const accepted = await client.callTool("agent_handshake_accept_invitation", { invitation: invited.responderInvitation });
    if (accepted.sessionId !== invited.sessionId) fail("RESPONDER_SESSION_MISMATCH");
    await Promise.all([
      setupAndJoin({ agent: initiator, client, invitationResult: invited }),
      setupAndJoin({ agent: responder, client, invitationResult: accepted }),
    ]);
    await Promise.all(agents.map((agent) => reachPartyReady({ agent, client, deadline })));
    let initiatorAgentId;
    let responderAgentId;
    try {
      initiatorAgentId = initiator.identity?.erc8004?.agentId;
      responderAgentId = responder.identity?.erc8004?.agentId;
      if (!DECIMAL.test(initiatorAgentId ?? "") || !DECIMAL.test(responderAgentId ?? "")) fail("PARTY_IDENTITY_INVALID");
      if (initiator.address === responder.address || initiatorAgentId === responderAgentId) fail("ROLE_IDENTITY_NOT_DISTINCT");
    } catch (error) {
      publicEvent({ event: "party_identity_validation_failed", code: typeof error?.code === "string" ? error.code : "UNCLASSIFIED" });
      throw error;
    }
    publicEvent({ event: "both_parties_ready" });
    const checkpoints = {};
    const proposal = await waitForSigning({ agent: initiator, client, operation: "proposal", deadline });
    await signPending({ agent: initiator, checkpoints, client, response: proposal });
    const acceptance = await waitForSigning({ agent: responder, client, operation: "acceptance", deadline });
    await signPending({ agent: responder, checkpoints, client, response: acceptance });
    const evidence = await waitForBothEvidence({ agents, client, deadline });
    await Promise.all(agents.map((agent) => signPending({ agent, checkpoints, client, response: evidence[agent.role] })));
    const certificates = await Promise.all(agents.map((agent) => waitForCertificate({ agent, client, deadline })));
    if (certificates[0].summary.resultDigest !== certificates[1].summary.resultDigest) fail("CERTIFICATE_DIGEST_MISMATCH");
    const monitorResponse = await fetch(`${RELAY}/v1/sessions/${encodeURIComponent(invited.sessionId)}/snapshot`);
    if (!monitorResponse.ok) fail("MONITOR_HTTP_FAILED");
    const monitor = await monitorResponse.json();
    if (!isVerifiedV2Monitor(monitor, {
      initiatorAddress: initiator.address,
      responderAddress: responder.address,
      sessionId: invited.sessionId,
    })) fail("MONITOR_RESULT_INVALID");
    const result = {
      schema: "clockchain.hermes-v2-production-gate/v1",
      ok: true,
      endpoint: ENDPOINT,
      sessionId: invited.sessionId,
      repositorySha: discovery.repositorySha,
      externalBusinessActionPerformed: false,
      identities: {
        initiator: { address: initiator.address, ...initiator.identity.erc8004 },
        responder: { address: responder.address, ...responder.identity.erc8004 },
      },
      checkpoints: {
        proposal: commitmentCheckpointDigest(checkpoints.proposal),
        acceptance: commitmentCheckpointDigest(checkpoints.acceptance),
      },
      certificate: {
        outcome: certificates[0].summary.outcome,
        resultDigest: certificates[0].summary.resultDigest,
        locallyVerifiedBy: ["initiator", "responder"],
      },
      hermes: {
        model: "k3",
        provider: "kimi-coding",
        version: "0.19.0",
        initiator: usageTotals(initiator),
        responder: usageTotals(responder),
      },
      monitor: {
        schema: monitor.schema,
        verdict: monitor.verdict.outcome,
        receipts: Object.values(monitor.receipts ?? {}).filter(Boolean).length,
      },
      elapsedMs: Date.now() - startedAt,
    };
    publicEvent({ event: "production_gate_complete", sessionId: result.sessionId, resultDigest: result.certificate.resultDigest });
    return result;
  } finally {
    await Promise.allSettled(adapters.map((adapter) => adapter.close()));
    await rm(run.root, { recursive: true, force: true });
  }
}
