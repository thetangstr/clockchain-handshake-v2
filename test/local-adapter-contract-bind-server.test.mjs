// Server parity for sign_agent_contract_bind.
//
//  1. Hermetic: the adapter reproduces test/fixtures/agent-contract-bind-vectors.json
//     byte-for-byte — canonical JSON, digest and signature — where the
//     canonical JSON, digest and recovered address were computed by the real
//     agent-contract server code (scripts/generate-agent-contract-bind-vectors.mjs).
//  2. Live: when the clockchain-developer-tools source is present, the real
//     server re-verifies those vectors and runs the full late bind:
//     contract_bind_challenge -> adapter tool -> service.bind(...) with the
//     adapter's {statement, signature} as {bindStatement, bindStatementSignature}.

import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, sign as edSign } from "node:crypto";
import { readFileSync } from "node:fs";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import {
  AGENT_HANDSHAKE_HELPER_VERSION,
  AGENT_HANDSHAKE_RELEASE_ASSET_PREFIX,
} from "../src/agent-handshake/v2/constants.mjs";
import {
  CONTRACT_BIND_TOOL,
  contractCanonicalDigest,
  contractCanonicalJson,
  signContractBindStatement,
} from "../src/local-adapter/contract-bind.mjs";
import { createLocalAdapterServer } from "../src/local-adapter/server.mjs";
import { loadAgentContractServer } from "./helpers/agent-contract-server.mjs";
import { layDownSession, testSessionKey } from "./helpers/contract-bind-session.mjs";

const VECTORS = JSON.parse(readFileSync(
  new URL("./fixtures/agent-contract-bind-vectors.json", import.meta.url),
  "utf8",
));

async function tempRoot(t) {
  const dir = await mkdtemp(join(tmpdir(), "local-adapter-bind-server-"));
  t.after(() => rm(dir, { recursive: true, force: true }));
  return dir;
}

test("adapter reproduces the server-computed bind vectors byte-for-byte", async (t) => {
  assert.equal(VECTORS.schema, "clockchain.local-adapter.agent-contract-bind-vectors/v1");
  assert.ok(VECTORS.vectors.length >= 2);
  for (const vector of VECTORS.vectors) {
    const tmpRoot = await tempRoot(t);
    const key = testSessionKey(vector.keyLabel);
    await layDownSession(tmpRoot, {
      sessionId: vector.statement.runId, role: vector.statement.side, privateKey: key.privateKey,
    });
    const signed = await signContractBindStatement(vector.statement, {
      nowMs: Date.parse(vector.statement.issuedAt), tmpRoot,
    });
    assert.equal(contractCanonicalJson(signed.statement), vector.canonicalJson);
    assert.equal(JSON.stringify(signed.statement), vector.canonicalJson);
    assert.equal(contractCanonicalDigest(signed.statement), vector.digest);
    assert.equal(signed.signature, vector.signature);
    assert.equal(vector.serverCanonicalSignature, true);
    assert.equal(signed.sessionKeyAddress, vector.serverRecoveredAddress);
    assert.equal(signed.sessionKeyAddress, key.address);
  }
});

test("live: the real server code verifies the committed vectors", async (t) => {
  const server = await loadAgentContractServer();
  if (server === null) {
    t.skip("clockchain-developer-tools agent-contract source not present (set CLOCKCHAIN_AGENT_CONTRACT_SRC)");
    return;
  }
  for (const vector of VECTORS.vectors) {
    assert.equal(server.canonicalJson(vector.statement), vector.canonicalJson);
    assert.equal(server.canonicalDigest(vector.statement), vector.digest);
    assert.equal(server.isCanonicalEip191Signature(vector.signature), true);
    const recovered = server.eip191RecoverPublicKey(Buffer.from(vector.digest.slice(2), "hex"), vector.signature);
    assert.equal(server.publicKeyToAddress(recovered).toLowerCase(), vector.serverRecoveredAddress);
  }
});

// --- live end-to-end late bind against createContractService ----------------

function rawPublicKeyBase64(publicKey) {
  const der = publicKey.export({ format: "der", type: "spki" });
  return Buffer.from(der.subarray(12)).toString("base64");
}

// Test-only certificate minter (port of the server repo's n4b7 test fixture):
// a root-signed host session-key certificate over a VERIFIED result whose
// parties carry the given sessionKeyAddress values.
function mintCertificate(server, { rootKey, sessionId, parties }) {
  const session = generateKeyPairSync("ed25519");
  const t = Date.now();
  const certificate = {
    schema: "clockchain.host-session-key/v1",
    rootKid: "root-test",
    sessionId,
    repositorySha: "d".repeat(40),
    sessionPublicKey: rawPublicKeyBase64(session.publicKey),
    validFromMs: String(t - 60_000),
    validUntilMs: String(t + 10 * 60_000),
  };
  const hostSessionKeyCertificate = {
    certificate,
    rootSignature: {
      algorithm: "ed25519",
      keyId: "root-test",
      publicKey: rawPublicKeyBase64(rootKey.publicKey),
      signature: edSign(null, Buffer.from(server.canonicalJson(certificate), "utf8"), rootKey.privateKey).toString("base64"),
    },
  };
  const party = ({ sessionKeyAddress, agentId }, n) => ({
    sessionKeyAddress,
    policyDigest: `${n === 0 ? "a" : "b"}${"0".repeat(63)}`,
    erc8004: {
      agentId,
      chainId: "eip155:11155111",
      registryAddress: "0x8004a818bfb912233c491871b3d84c89a494bd9e",
      reference: `eip155:11155111:0x8004a818bfb912233c491871b3d84c89a494bd9e:${agentId}`,
      registrationTx: `0x${"a".repeat(64)}`,
      registrationBlock: `700${n}`,
    },
  });
  const initiator = party(parties.initiator, 0);
  const responder = party(parties.responder, 1);
  const anchor = (kind, n) => ({
    blockHeight: String(7010 + n), blockTimeRaw: `2026-08-09T17:0${n}:00.000Z`,
    digest: `${n}${"0".repeat(63)}`, kind, ledgerId: `33333333-4444-4555-8666-77777777777${n}`,
  });
  const result = {
    anchors: [anchor("proposal", 0), anchor("acceptance", 1), anchor("acknowledgment", 2)],
    externalBusinessActionPerformed: false,
    hostSessionKeyCertificateDigest: server.canonicalDigest(hostSessionKeyCertificate).slice(2),
    identityPolicy: {
      chainId: "eip155:11155111", erc8004: "required_fresh",
      registryAddress: "0x8004a818bfb912233c491871b3d84c89a494bd9e",
    },
    issuedAtMs: String(t), outcome: "VERIFIED",
    parties: { initiator, responder },
    policyDigests: { initiator: initiator.policyDigest, responder: responder.policyDigest },
    reference: "NS-1847", schema: "clockchain.agent-handshake-result/v2",
    sessionDigest: "e".repeat(64), sessionId,
    statementDigest: "f".repeat(64), subjectRun: "stakeholder",
  };
  return {
    hostSessionKeyCertificate, result,
    signer: {
      algorithm: "ed25519", keyId: "session-host",
      publicKey: rawPublicKeyBase64(session.publicKey),
      signature: edSign(null, Buffer.from(server.canonicalJson(result), "utf8"), session.privateKey).toString("base64"),
    },
  };
}

function adapterFor(tmpRoot) {
  const helperBytes = Buffer.from("\"use strict\";\n");
  const manifestBytes = Buffer.from("{}");
  const sha = (value) => createHash("sha256").update(value).digest("hex");
  return createLocalAdapterServer({
    assets: {
      helperBytes,
      helperPath: "/nonexistent/clockchain-agent-handshake.cjs",
      helperSha256: sha(helperBytes),
      manifestBytes,
      manifestPath: "/nonexistent/manifest.json",
      pin: {
        version: AGENT_HANDSHAKE_HELPER_VERSION,
        sourceCommit: "a".repeat(40),
        manifestDigest: sha(manifestBytes),
        allowedAssetPrefix: AGENT_HANDSHAKE_RELEASE_ASSET_PREFIX,
        hostRoots: [{ kid: "root-2026-08", fingerprint: "c".repeat(64) }],
      },
    },
    endpoint: "https://upstream.test/handshake/mcp",
    fetchImpl: async () => { throw new Error("no upstream in tests"); },
    tmpdir: tmpRoot,
  });
}

async function adapterSign(adapter, args) {
  const response = await adapter.handleMessage({
    jsonrpc: "2.0", id: 1, method: "tools/call",
    params: { name: CONTRACT_BIND_TOOL, arguments: args },
  });
  return { isError: response.result.isError === true, text: response.result.content[0].text };
}

test("live: contract_bind accepts the adapter's statement for a late token", async (t) => {
  const server = await loadAgentContractServer();
  if (server === null) {
    t.skip("clockchain-developer-tools agent-contract source not present (set CLOCKCHAIN_AGENT_CONTRACT_SRC)");
    return;
  }
  const rootKey = generateKeyPairSync("ed25519");
  const hostRoots = [{
    kid: "root-test",
    fingerprint: createHash("sha256").update(Buffer.from(rawPublicKeyBase64(rootKey.publicKey), "base64")).digest("hex"),
  }];
  const signer = { keyId: "contract-server-test", privateKey: generateKeyPairSync("ed25519").privateKey };
  const stateDir = await tempRoot(t);
  const service = server.createContractService({
    hostRoots, signer,
    policyDigests: { buyer: `0x${"7".repeat(64)}`, provider: `0x${"8".repeat(64)}` },
    allowLegacySealV2: true,
    requireBindStatement: true,
    stateDir,
  });
  t.after(() => service.close());
  const secpPub = (n) => {
    const digest = Buffer.alloc(32, 1);
    const priv = `0x${n.toString(16).padStart(64, "0")}`;
    return `0x${Buffer.from(server.eip191RecoverPublicKey(digest, server.eip191SignDigest32(digest, priv))).toString("hex")}`;
  };
  const bindKeys = (role) => ({
    signerKey: { keyId: `signer-${role}`, publicKeyHex: secpPub(role === "buyer" ? 0xb1 : 0xc1) },
    approvalKey: { keyId: `approval-${role}`, publicKeyHex: secpPub(role === "buyer" ? 0xb2 : 0xc2) },
  });
  const evidence = { argsDigest: `0x${"0".repeat(64)}`, serverNonce: `0x${"1".repeat(32)}`, tool: "contract_bind" };

  const tmpRoot = await tempRoot(t);
  const adapter = adapterFor(tmpRoot);
  const initiatorKey = testSessionKey("live-initiator");
  const responderKey = testSessionKey("live-responder");
  const strangerKey = testSessionKey("live-stranger");

  // Session A: the adapter holds the INITIATOR wallet whose address the
  // certificate names as parties.initiator.sessionKeyAddress.
  const sessionA = "deadbeef-00a1-4444-8888-0000000000a1";
  await layDownSession(tmpRoot, { sessionId: sessionA, role: "initiator", privateKey: initiatorKey.privateKey });
  const certA = mintCertificate(server, {
    rootKey, sessionId: sessionA,
    parties: {
      initiator: { sessionKeyAddress: initiatorKey.address, agentId: "9601" },
      responder: { sessionKeyAddress: responderKey.address, agentId: "9602" },
    },
  });
  const buyer = { keyId: "klb1", role: "buyer", agentId: "*", side: "initiator" };
  const issued = service.issueBindChallenge(buyer);
  assert.equal(issued.ok, true);
  const signed = await adapterSign(adapter, {
    domain: "agent-contract.bind/v1", runId: sessionA, side: "initiator",
    tokenKeyId: buyer.keyId, serverKeyId: signer.keyId,
    challenge: issued.challenge, issuedAt: new Date().toISOString(),
  });
  assert.equal(signed.isError, false, signed.text);
  const output = JSON.parse(signed.text);
  assert.equal(output.sessionKeyAddress, initiatorKey.address);
  const bound = service.bind(buyer, {
    certificate: certA, ...bindKeys("buyer"),
    bindStatement: output.statement, bindStatementSignature: output.signature,
  }, evidence);
  assert.equal(bound.ok, true, JSON.stringify(bound));
  assert.equal(bound.result.runId, sessionA);
  const receipt = service.receiptFeed(sessionA).receipts.find((r) => r.tool === "contract_bind");
  assert.equal(receipt.bindMode, "late");
  assert.equal(receipt.bindStatement, "verified");

  // Session B: the adapter's wallet is NOT the certificate's party key (the
  // certificate names a stranger) — the server refuses the adapter's proof.
  const sessionB = "deadbeef-00b2-4444-8888-0000000000b2";
  await layDownSession(tmpRoot, { sessionId: sessionB, role: "responder", privateKey: responderKey.privateKey });
  const certB = mintCertificate(server, {
    rootKey, sessionId: sessionB,
    parties: {
      initiator: { sessionKeyAddress: initiatorKey.address, agentId: "9611" },
      responder: { sessionKeyAddress: strangerKey.address, agentId: "9612" },
    },
  });
  const provider = { keyId: "klp1", role: "provider", agentId: "*", side: "responder" };
  const issuedB = service.issueBindChallenge(provider);
  const signedB = JSON.parse((await adapterSign(adapter, {
    domain: "agent-contract.bind/v1", runId: sessionB, side: "responder",
    tokenKeyId: provider.keyId, serverKeyId: signer.keyId,
    challenge: issuedB.challenge, issuedAt: new Date().toISOString(),
  })).text);
  const refused = service.bind(provider, {
    certificate: certB, ...bindKeys("provider"),
    bindStatement: signedB.statement, bindStatementSignature: signedB.signature,
  }, evidence);
  assert.equal(refused.ok, false);
  assert.equal(refused.code, "BIND_STATEMENT_INVALID");

  // A statement the adapter signed for one token cannot be replayed by another.
  const provider2 = { keyId: "klp2", role: "provider", agentId: "*", side: "responder" };
  const certB2 = mintCertificate(server, {
    rootKey, sessionId: sessionB,
    parties: {
      initiator: { sessionKeyAddress: initiatorKey.address, agentId: "9621" },
      responder: { sessionKeyAddress: responderKey.address, agentId: "9622" },
    },
  });
  const issuedB2 = service.issueBindChallenge(provider);
  const signedB2 = JSON.parse((await adapterSign(adapter, {
    domain: "agent-contract.bind/v1", runId: sessionB, side: "responder",
    tokenKeyId: provider.keyId, serverKeyId: signer.keyId,
    challenge: issuedB2.challenge, issuedAt: new Date().toISOString(),
  })).text);
  const replay = service.bind(provider2, {
    certificate: certB2, ...bindKeys("provider"),
    bindStatement: signedB2.statement, bindStatementSignature: signedB2.signature,
  }, evidence);
  assert.equal(replay.ok, false);
  assert.equal(replay.code, "BIND_STATEMENT_INVALID");
  // ...while the token it was signed for binds successfully with it.
  const ok = service.bind(provider, {
    certificate: certB2, ...bindKeys("provider"),
    bindStatement: signedB2.statement, bindStatementSignature: signedB2.signature,
  }, evidence);
  assert.equal(ok.ok, true, JSON.stringify(ok));
});
