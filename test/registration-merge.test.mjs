import { test } from "node:test";
import assert from "node:assert/strict";

import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";

import * as registration from "../src/core/registration.mjs";
import { CHAIN_ID, REGISTRY_ADDRESS } from "../src/core/constants.mjs";

/**
 * registration-internal.mjs was merged into registration.mjs (two donor modules
 * -> one). These tests pin the merge: the public export surface must be exactly
 * the donor's src/registration.mjs surface (no internal helper leaked out, no
 * public export lost), and the on-chain literals must be untouched.
 *
 * The donor literals below are transcribed verbatim from the read-only donor at
 * riyadh-v3/src/registration.mjs so this test stands alone without reading it.
 */

/** Donor export surface of src/registration.mjs, sorted. */
const DONOR_PUBLIC_EXPORTS = [
  "ERC8004_ABI",
  "PartialRegistrationError",
  "RegistrationConfigurationError",
  "RegistrationNetworkError",
  "buildRegistrationDocument",
  "finalizeIdentityRegistration",
  "identityReference",
  "parseRegisteredAgentId",
  "registerIdentity",
  "registrationDataUri",
  "registryNamespace",
  "validateRegistrationCheckpoint",
  "validateRegistrationIntentCheckpoint",
  "validateRegistrationRecoveryCheckpoint",
];

/** Donor ERC8004_ABI literal, verbatim. */
const DONOR_ERC8004_ABI = [
  {
    type: "function",
    name: "getVersion",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "string" }],
  },
  {
    type: "function",
    name: "register",
    stateMutability: "nonpayable",
    inputs: [{ name: "agentURI", type: "string" }],
    outputs: [{ name: "agentId", type: "uint256" }],
  },
  {
    type: "function",
    name: "setAgentURI",
    stateMutability: "nonpayable",
    inputs: [
      { name: "agentId", type: "uint256" },
      { name: "newURI", type: "string" },
    ],
    outputs: [],
  },
  {
    type: "function",
    name: "ownerOf",
    stateMutability: "view",
    inputs: [{ name: "tokenId", type: "uint256" }],
    outputs: [{ name: "", type: "address" }],
  },
  {
    type: "function",
    name: "tokenURI",
    stateMutability: "view",
    inputs: [{ name: "tokenId", type: "uint256" }],
    outputs: [{ name: "", type: "string" }],
  },
  {
    type: "function",
    name: "getAgentWallet",
    stateMutability: "view",
    inputs: [{ name: "agentId", type: "uint256" }],
    outputs: [{ name: "", type: "address" }],
  },
  {
    type: "event",
    name: "Registered",
    anonymous: false,
    inputs: [
      {
        name: "agentId",
        type: "uint256",
        indexed: true,
      },
      {
        name: "agentURI",
        type: "string",
        indexed: false,
      },
      {
        name: "owner",
        type: "address",
        indexed: true,
      },
    ],
  },
];

/** Donor registry identity: ERC-8004 registry on Ethereum Sepolia. */
const DONOR_REGISTRY_ADDRESS = "0x8004A818BFB912233c491871b3d84c89A494BD9e";
const DONOR_CHAIN_ID = 11155111;

/** Donor registration document constants. */
const DONOR_REGISTRATION_TYPE =
  "https://eips.ethereum.org/EIPS/eip-8004#registration-v1";
const DONOR_REGISTRATION_DESCRIPTION =
  "Ephemeral Clockchain Handshake testnet identity; registration does not establish capability or trust.";

test("merged module exposes exactly the donor public export surface", () => {
  assert.deepEqual(Object.keys(registration).sort(), DONOR_PUBLIC_EXPORTS);
});

test("merged module exports are all defined and correctly typed", () => {
  for (const name of [
    "buildRegistrationDocument",
    "registrationDataUri",
    "parseRegisteredAgentId",
    "registryNamespace",
    "identityReference",
    "finalizeIdentityRegistration",
    "registerIdentity",
    "validateRegistrationCheckpoint",
    "validateRegistrationIntentCheckpoint",
    "validateRegistrationRecoveryCheckpoint",
  ]) {
    assert.equal(typeof registration[name], "function", name);
  }

  for (const name of [
    "PartialRegistrationError",
    "RegistrationConfigurationError",
    "RegistrationNetworkError",
  ]) {
    assert.equal(typeof registration[name], "function", name);
    assert.ok(
      registration[name].prototype instanceof Error,
      `${name} must extend Error`,
    );
  }

  assert.ok(Array.isArray(registration.ERC8004_ABI));
});

test("registration-internal helpers did not leak into the public surface", () => {
  // These were `export`ed by the donor's registration-internal.mjs. The merge
  // makes them module-local; nothing outside registration.mjs consumes them.
  for (const internalName of [
    "RECOVERY_SCHEMA",
    "INTENT_SCHEMA",
    "REGISTER_NONCE",
    "RECEIPT_TIMEOUT_MILLISECONDS",
    "RECEIPT_CONFIRMATIONS",
    "CONSERVATIVE_METADATA_GAS_RESERVE",
    "normalizeAgentId",
    "validateDisplayName",
    "registryNamespaceValue",
    "identityReferenceValue",
    "addressesEqual",
    "isSuccessfulReceipt",
    "isRevertedReceipt",
    "isTransactionHash",
    "validateTransactionHash",
    "validateReceiptEvidence",
    "validateReceipt",
    "addGasHeadroom",
    "runStage",
    "estimateFeeQuote",
    "validateRecovery",
    "createRecovery",
    "withMetadataTransaction",
    "withoutMetadataTransaction",
    "validateRegistrationIntent",
    "createRegistrationIntent",
    "intentTransactionFields",
    "intentTransactionType",
    "validateCheckpointCallback",
    "invokeCheckpoint",
    "normalizePendingNonce",
    "createRegistrationClients",
  ]) {
    assert.equal(
      Object.hasOwn(registration, internalName),
      false,
      `${internalName} must not be exported`,
    );
  }
});

test("ERC8004_ABI is unchanged from the donor literal", () => {
  assert.deepEqual(registration.ERC8004_ABI, DONOR_ERC8004_ABI);
  assert.equal(registration.ERC8004_ABI.length, 7);
});

test("ERC8004_ABI retains the ownerOf entry the verifier reads", () => {
  const ownerOf = registration.ERC8004_ABI.find(
    (entry) => entry.name === "ownerOf",
  );
  assert.deepEqual(ownerOf, {
    type: "function",
    name: "ownerOf",
    stateMutability: "view",
    inputs: [{ name: "tokenId", type: "uint256" }],
    outputs: [{ name: "", type: "address" }],
  });
});

test("registry address and chain id are unchanged from the donor", () => {
  assert.equal(REGISTRY_ADDRESS, DONOR_REGISTRY_ADDRESS);
  assert.equal(CHAIN_ID, DONOR_CHAIN_ID);
});

test("registryNamespace and identityReference bind the donor registry", () => {
  const namespace = `eip155:${DONOR_CHAIN_ID}:${DONOR_REGISTRY_ADDRESS}`;
  assert.equal(registration.registryNamespace(), namespace);
  assert.equal(registration.identityReference(7), `${namespace}:7`);
  assert.equal(registration.identityReference(0n), `${namespace}:0`);
});

test("merged internal helpers still back the public functions", () => {
  // buildRegistrationDocument routes through the merged-in validateDisplayName
  // and normalizeAgentId; exercising it proves the internals linked correctly.
  const anonymous = registration.buildRegistrationDocument({
    displayName: "Alice",
  });
  assert.deepEqual(anonymous, {
    type: DONOR_REGISTRATION_TYPE,
    name: "Alice",
    description: DONOR_REGISTRATION_DESCRIPTION,
    services: [],
    x402Support: false,
    active: true,
    registrations: [],
  });

  const registered = registration.buildRegistrationDocument({
    displayName: "Alice",
    agentId: 42n,
  });
  assert.deepEqual(registered.registrations, [
    {
      agentRegistry: `eip155:${DONOR_CHAIN_ID}:${DONOR_REGISTRY_ADDRESS}`,
      agentId: 42,
    },
  ]);

  // validateDisplayName (fail-closed) is still wired in.
  assert.throws(
    () => registration.buildRegistrationDocument({ displayName: "" }),
    TypeError,
  );
  assert.throws(
    () => registration.buildRegistrationDocument({ displayName: "x".repeat(129) }),
    TypeError,
  );
  // normalizeAgentId (fail-closed) is still wired in.
  assert.throws(
    () =>
      registration.buildRegistrationDocument({
        displayName: "Alice",
        agentId: -1n,
      }),
    RangeError,
  );
});

test("registrationDataUri encodes the document as a base64 data URI", () => {
  const document = registration.buildRegistrationDocument({
    displayName: "Alice",
  });
  const uri = registration.registrationDataUri(document);
  assert.ok(uri.startsWith("data:application/json;base64,"));
  const payload = uri.slice("data:application/json;base64,".length);
  assert.deepEqual(
    JSON.parse(Buffer.from(payload, "base64").toString("utf8")),
    document,
  );
});

test("re-exported error classes keep their donor codes and categories", () => {
  const network = new registration.RegistrationNetworkError("boom");
  assert.equal(network.name, "RegistrationNetworkError");
  assert.equal(network.code, "HANDSHAKE_REGISTRATION_NETWORK");
  assert.equal(network.category, "network");

  const configuration = new registration.RegistrationConfigurationError("boom");
  assert.equal(configuration.name, "RegistrationConfigurationError");
  assert.equal(configuration.code, "HANDSHAKE_REGISTRATION_CONFIGURATION");
  assert.equal(configuration.category, "configuration");
});

test("PartialRegistrationError still classifies via the merged error classes", () => {
  const recovery = {
    schema: "clockchain.handshake-registration-recovery/v1",
    chainId: DONOR_CHAIN_ID,
    registryAddress: DONOR_REGISTRY_ADDRESS,
    registryNamespace: `eip155:${DONOR_CHAIN_ID}:${DONOR_REGISTRY_ADDRESS}`,
    identityReference: `eip155:${DONOR_CHAIN_ID}:${DONOR_REGISTRY_ADDRESS}:9`,
    agentId: "9",
    address: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
    displayName: "Alice",
    registerTx: `0x${"ab".repeat(32)}`,
    registerBlock: "1234",
  };

  const network = new registration.PartialRegistrationError(
    recovery,
    new registration.RegistrationNetworkError("rpc down"),
  );
  assert.equal(network.name, "PartialRegistrationError");
  assert.equal(network.code, "ERC8004_PARTIAL_REGISTRATION");
  assert.equal(network.category, "network");
  assert.ok(Object.isFrozen(network.recovery));
  assert.equal(network.recovery.registerTx, recovery.registerTx);

  const configuration = new registration.PartialRegistrationError(
    recovery,
    new registration.RegistrationConfigurationError("bad key"),
  );
  assert.equal(configuration.category, "configuration");

  const protocolError = new registration.PartialRegistrationError(
    recovery,
    new Error("other"),
  );
  assert.equal(protocolError.category, "protocol");

  // validateRecovery (merged in) is still fail-closed on a tampered checkpoint.
  assert.throws(
    () =>
      new registration.PartialRegistrationError(
        { ...recovery, agentId: "010" },
        new Error("other"),
      ),
    /Registration recovery checkpoint is invalid\./,
  );
  assert.throws(
    () =>
      new registration.PartialRegistrationError(
        { ...recovery, extra: true },
        new Error("other"),
      ),
    /Registration recovery checkpoint is invalid\./,
  );
});

test("parseRegisteredAgentId rejects an unsuccessful receipt", () => {
  assert.throws(
    () =>
      registration.parseRegisteredAgentId(
        { status: "reverted", logs: [] },
        {
          expectedOwner: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
          expectedAgentURI: "data:application/json;base64,e30=",
        },
      ),
    /Registration receipt was not successful\./,
  );
});

test("parseRegisteredAgentId requires exactly one official Registered event", () => {
  assert.throws(
    () =>
      registration.parseRegisteredAgentId(
        { status: "success", logs: [] },
        {
          expectedOwner: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
          expectedAgentURI: "data:application/json;base64,e30=",
        },
      ),
    /Registration receipt must contain exactly one official Registered event\./,
  );
});

test("src/core/registration-internal.mjs no longer exists", () => {
  const internalPath = fileURLToPath(
    new URL("../src/core/registration-internal.mjs", import.meta.url),
  );
  assert.equal(
    existsSync(internalPath),
    false,
    "registration-internal.mjs must be deleted after the merge",
  );
});

test("no module in the repo imports registration-internal.mjs", async () => {
  const { readFile, readdir } = await import("node:fs/promises");
  const srcRoot = fileURLToPath(new URL("../src", import.meta.url));

  async function collect(directory) {
    const entries = await readdir(directory, { withFileTypes: true });
    const files = [];
    for (const entry of entries) {
      const full = `${directory}/${entry.name}`;
      if (entry.isDirectory()) {
        files.push(...(await collect(full)));
      } else if (entry.name.endsWith(".mjs")) {
        files.push(full);
      }
    }
    return files;
  }

  const offenders = [];
  for (const file of await collect(srcRoot)) {
    const source = await readFile(file, "utf8");
    if (source.includes("registration-internal")) {
      offenders.push(file);
    }
  }
  assert.deepEqual(offenders, []);
});
