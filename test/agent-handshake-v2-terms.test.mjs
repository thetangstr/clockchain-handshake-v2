import assert from "node:assert/strict";
import test from "node:test";

import {
  AGENT_HANDSHAKE_V2_PROTOCOL,
  AGENT_HANDSHAKE_V2_REGISTRY_ADDRESS,
  AGENT_HANDSHAKE_V2_SEPOLIA_CHAIN,
} from "../src/agent-handshake/v2/constants.mjs";
import {
  agentHandshakeV2StatementDigest,
  validateAgentHandshakeV2Terms,
  validateIdentityPolicy,
} from "../src/agent-handshake/v2/terms.mjs";
import { canonicalBytes, digestHex } from "../src/core/canonical.mjs";

const requiredFresh = Object.freeze({
  erc8004: "required_fresh",
  chainId: "eip155:11155111",
  registryAddress: "0x8004a818bfb912233c491871b3d84c89a494bd9e",
});
const terms = Object.freeze({
  reference: "NS-1847",
  statement: "Northstar Logistics and Harbor Supply authorize these two independently controlled agents to communicate about shipment reference NS-1847 for 90 seconds.",
  validForSeconds: "90",
  identityPolicy: requiredFresh,
});

function exactKeyMutations(value) {
  const result = [{ ...value, extra: true }];
  for (const key of Object.keys(value)) {
    const removed = { ...value };
    delete removed[key];
    result.push(removed);
    result.push({ ...removed, ["renamed_" + key]: value[key] });
  }
  return result;
}

test("v2 terms use exact second-based non-payment bytes", () => {
  assert.equal(AGENT_HANDSHAKE_V2_PROTOCOL, "clockchain.agent-handshake/v2");
  assert.equal(AGENT_HANDSHAKE_V2_SEPOLIA_CHAIN, "eip155:11155111");
  assert.equal(AGENT_HANDSHAKE_V2_REGISTRY_ADDRESS, requiredFresh.registryAddress);
  assert.deepEqual(validateAgentHandshakeV2Terms(terms), terms);
  assert.equal(agentHandshakeV2StatementDigest(terms), digestHex(terms));
  const publicBytes = canonicalBytes(terms).toString("utf8").toLowerCase();
  for (const forbidden of [
    "amount", "currency", "invoice", "payment_request", "payer", "payee",
    "requestor", "paymentmoved",
  ]) assert.equal(publicBytes.includes(forbidden), false, forbidden);
});

test("identity policy accepts exactly the three ERC-8004 modes", () => {
  for (const erc8004 of ["required_fresh", "required_existing_or_fresh"]) {
    const policy = { ...requiredFresh, erc8004 };
    assert.deepEqual(validateIdentityPolicy(policy), policy);
  }
  const optional = { erc8004: "not_required", chainId: null, registryAddress: null };
  assert.deepEqual(validateIdentityPolicy(optional), optional);
  for (const invalid of [
    { ...requiredFresh, erc8004: "required" },
    { ...requiredFresh, chainId: "11155111" },
    { ...requiredFresh, registryAddress: requiredFresh.registryAddress.toUpperCase() },
    { ...optional, chainId: requiredFresh.chainId },
    { ...optional, registryAddress: requiredFresh.registryAddress },
    ...exactKeyMutations(requiredFresh),
    ...exactKeyMutations(optional),
  ]) assert.throws(() => validateIdentityPolicy(invalid));
});

test("terms reject every key mutation, non-decimal duration, and windows over 90 seconds", () => {
  for (const invalid of [
    ...exactKeyMutations(terms),
    { ...terms, validForSeconds: 90 },
    { ...terms, validForSeconds: "090" },
    { ...terms, validForSeconds: "91" },
    { ...terms, validForSeconds: "0" },
    { ...terms, reference: " NS-1847" },
    { ...terms, statement: terms.statement + " " },
    { ...terms, identityPolicy: { ...requiredFresh, erc8004: "not_required" } },
  ]) assert.throws(() => validateAgentHandshakeV2Terms(invalid));
});
