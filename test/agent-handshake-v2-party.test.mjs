import assert from "node:assert/strict";
import test from "node:test";

import { validateAgentHandshakeV2Party } from "../src/agent-handshake/v2/party.mjs";

const requiredFresh = Object.freeze({
  erc8004: "required_fresh",
  chainId: "eip155:11155111",
  registryAddress: "0x8004a818bfb912233c491871b3d84c89a494bd9e",
});
const party = Object.freeze({
  sessionKeyAddress: "0x00112233445566778899aabbccddeeff00112233",
  policyDigest: "a".repeat(64),
  erc8004: {
    agentId: "9452",
    chainId: requiredFresh.chainId,
    registryAddress: requiredFresh.registryAddress,
    reference: requiredFresh.chainId + ":" + requiredFresh.registryAddress + ":9452",
    registrationTx: "0x" + "b".repeat(64),
    registrationBlock: "7001",
  },
});

function mutateKeys(value) {
  const result = [{ ...value, extra: true }];
  for (const key of Object.keys(value)) {
    const removed = { ...value };
    delete removed[key];
    result.push(removed);
    result.push({ ...removed, ["renamed_" + key]: value[key] });
  }
  return result;
}

test("required ERC-8004 party binds one local session key to complete registration facts", () => {
  assert.deepEqual(validateAgentHandshakeV2Party(party, { identityPolicy: requiredFresh }), party);
  for (const erc8004 of ["required_fresh", "required_existing_or_fresh"]) {
    assert.equal(validateAgentHandshakeV2Party(party, {
      identityPolicy: { ...requiredFresh, erc8004 },
    }).erc8004.agentId, "9452");
  }
});

test("not-required identity keeps the same party keys and requires erc8004 null", () => {
  const identityPolicy = { erc8004: "not_required", chainId: null, registryAddress: null };
  const keyOnly = { ...party, erc8004: null };
  assert.deepEqual(validateAgentHandshakeV2Party(keyOnly, { identityPolicy }), keyOnly);
  assert.throws(() => validateAgentHandshakeV2Party(party, { identityPolicy }));
  assert.throws(() => validateAgentHandshakeV2Party(keyOnly, { identityPolicy: requiredFresh }));
});

test("party rejects key mutations, address casing, and incomplete ERC-8004 facts", () => {
  for (const invalid of [
    ...mutateKeys(party),
    { ...party, sessionKeyAddress: party.sessionKeyAddress.toUpperCase() },
    { ...party, policyDigest: "A".repeat(64) },
    ...mutateKeys(party.erc8004).map((erc8004) => ({ ...party, erc8004 })),
    { ...party, erc8004: { ...party.erc8004, agentId: "09452" } },
    { ...party, erc8004: { ...party.erc8004, registrationBlock: "07001" } },
    { ...party, erc8004: { ...party.erc8004, registrationTx: "b".repeat(64) } },
    { ...party, erc8004: { ...party.erc8004, reference: "eip155:11155111:wrong:9452" } },
  ]) assert.throws(() => validateAgentHandshakeV2Party(invalid, { identityPolicy: requiredFresh }));
});
