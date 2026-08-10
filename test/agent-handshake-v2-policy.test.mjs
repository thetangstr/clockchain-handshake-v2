import assert from "node:assert/strict";
import test from "node:test";

import { digestHex } from "../src/core/canonical.mjs";
import { localPolicyDigest, validateLocalPolicy } from "../src/agent-handshake/v2/policy.mjs";

const identityPolicy = Object.freeze({
  erc8004: "required_fresh",
  chainId: "eip155:11155111",
  registryAddress: "0x8004a818bfb912233c491871b3d84c89a494bd9e",
});
const policy = Object.freeze({
  schema: "clockchain.agent-handshake-policy/v1",
  protocol: "clockchain.agent-handshake/v2",
  role: "initiator",
  mcpOrigin: "https://mcp.clockchain.network",
  reference: "NS-1847",
  statementDigest: "a".repeat(64),
  maxValidForSeconds: "90",
  identityPolicy,
  externalBusinessActionsAllowed: false,
});

function mutations(value) {
  const result = [{ ...value, extra: true }];
  for (const key of Object.keys(value)) {
    const removed = { ...value };
    delete removed[key];
    result.push(removed);
    result.push({ ...removed, ["renamed_" + key]: value[key] });
  }
  return result;
}

test("local policy canonicalizes the exact agent authority boundary", () => {
  assert.deepEqual(validateLocalPolicy(policy), policy);
  assert.equal(localPolicyDigest(policy), digestHex(policy));
  assert.deepEqual(validateLocalPolicy({ ...policy, role: "responder" }).role, "responder");
  for (const changed of [
    { ...policy, role: "responder" },
    { ...policy, reference: "OTHER" },
    { ...policy, statementDigest: "b".repeat(64) },
    { ...policy, maxValidForSeconds: "89" },
    {
      ...policy,
      identityPolicy: { erc8004: "not_required", chainId: null, registryAddress: null },
    },
  ]) {
    assert.notEqual(localPolicyDigest(changed), localPolicyDigest(policy));
  }
});

test("local policy rejects every key and authority mutation", () => {
  for (const invalid of [
    ...mutations(policy),
    { ...policy, schema: "clockchain.agent-handshake-policy/v2" },
    { ...policy, protocol: "clockchain.agent-handshake/v1" },
    { ...policy, role: "payer" },
    { ...policy, mcpOrigin: "https://example.test" },
    { ...policy, statementDigest: "A".repeat(64) },
    { ...policy, maxValidForSeconds: "91" },
    { ...policy, maxValidForSeconds: 90 },
    { ...policy, identityPolicy: { ...identityPolicy, erc8004: "not_required" } },
    { ...policy, externalBusinessActionsAllowed: true },
  ]) assert.throws(() => validateLocalPolicy(invalid));
});
