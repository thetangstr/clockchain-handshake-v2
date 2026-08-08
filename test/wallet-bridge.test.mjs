import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { chmodSync, renameSync, symlinkSync } from "node:fs";
import {
  chmod,
  link,
  lstat,
  mkdir,
  mkdtemp,
  readdir,
  readFile,
  rename,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { promisify } from "node:util";
import test from "node:test";

import { recoverMessageAddress } from "viem";

import {
  initializeWallet,
  inspectWallet,
  registerWalletIdentity,
  signExactBytes,
} from "../src/core/wallet-bridge.mjs";

const execFileAsync = promisify(execFile);
const PRIVATE_KEY = `0x${"11".repeat(32)}`;
const ADDRESS = "0x19E7E376E7C213B7E7e7e46cc70A5dD086DAff2A";
const LETTER_PRIVATE_KEY = `0x${"ab".repeat(32)}`;
const OTHER_PRIVATE_KEY = `0x${"22".repeat(32)}`;
const REGISTER_TX = `0x${"33".repeat(32)}`;
const METADATA_TX = `0x${"44".repeat(32)}`;

async function temporaryState(t) {
  const root = await mkdtemp(join(tmpdir(), "clockchain-wallet-bridge-"));
  t.after(() => rm(root, { force: true, recursive: true }));
  return {
    root,
    statePath: join(root, "party", "wallet.json"),
  };
}

async function initializeDeterministicWallet(t) {
  const { root, statePath } = await temporaryState(t);
  const result = await initializeWallet({
    statePath,
    platform: "darwin",
    generatePrivateKey: () => PRIVATE_KEY,
  });
  return { root, statePath, result };
}

async function initializeWalletWithPrivateKey(t, privateKey) {
  const { root, statePath } = await temporaryState(t);
  const result = await initializeWallet({
    statePath,
    platform: "darwin",
    generatePrivateKey: () => privateKey,
  });
  return { root, statePath, result };
}

async function readOptional(path) {
  try {
    return await readFile(path, "utf8");
  } catch (error) {
    if (error?.code === "ENOENT") return "";
    throw error;
  }
}

function scan(value) {
  if (typeof value === "string") return value;
  if (value instanceof Error) {
    return [
      value.name,
      value.message,
      value.stack,
      JSON.stringify(value),
    ].join("\n");
  }
  return JSON.stringify(value);
}

function assertNoSecret(value) {
  const text = scan(value);
  assert.equal(text.includes(PRIVATE_KEY), false);
  assert.equal(text.includes(PRIVATE_KEY.slice(2)), false);
}

function assertNoText(value, needle) {
  assert.equal(scan(value).includes(needle), false);
}

function mixedCasePrivateKeyHex(privateKey) {
  return privateKey
    .slice(2)
    .split("")
    .map((character, index) =>
      index % 2 === 0 ? character.toUpperCase() : character.toLowerCase(),
    )
    .join("");
}

async function rejectSafe(operation) {
  let error;
  try {
    await operation();
  } catch (caught) {
    error = caught;
  }
  assert.ok(error instanceof Error, "operation must reject safely");
  assertNoSecret(error);
  assert.match(error.message, /Wallet bridge operation failed safely/);
  return error;
}

function fakeRegistrationEvidence(address = ADDRESS) {
  return {
    agentId: "42",
    address,
    displayName: "Hermes party",
    identityReference:
      "eip155:11155111:0x8004A818BFB912233c491871b3d84c89A494BD9e:42",
    registryNamespace:
      "eip155:11155111:0x8004A818BFB912233c491871b3d84c89A494BD9e",
    registerTx: REGISTER_TX,
    registerBlock: "100",
    metadataTx: METADATA_TX,
    metadataBlock: "101",
    document: {
      name: "Hermes party",
      registrations: [
        {
          agentRegistry:
            "eip155:11155111:0x8004A818BFB912233c491871b3d84c89A494BD9e",
          agentId: 42,
        },
      ],
    },
  };
}

function recoveryCheckpoint(overrides = {}) {
  return {
    schema: "clockchain.handshake-registration-recovery/v1",
    chainId: 11155111,
    registryAddress: "0x8004A818BFB912233c491871b3d84c89A494BD9e",
    registryNamespace:
      "eip155:11155111:0x8004A818BFB912233c491871b3d84c89A494BD9e",
    identityReference:
      "eip155:11155111:0x8004A818BFB912233c491871b3d84c89A494BD9e:42",
    agentId: "42",
    address: ADDRESS,
    displayName: "Hermes party",
    registerTx: REGISTER_TX,
    registerBlock: "100",
    ...overrides,
  };
}

function intentCheckpoint(overrides = {}) {
  return {
    schema: "clockchain.handshake-registration-intent/v1",
    chainId: 11155111,
    registryAddress: "0x8004A818BFB912233c491871b3d84c89A494BD9e",
    registryNamespace:
      "eip155:11155111:0x8004A818BFB912233c491871b3d84c89A494BD9e",
    address: ADDRESS,
    displayName: "Hermes party",
    registerNonce: 0,
    registerCalldata: "0x1234",
    registerGas: "226000",
    maxFeePerGas: "2",
    maxPriorityFeePerGas: "1",
    ...overrides,
  };
}

async function runCli(args, env = {}) {
  try {
    const { stdout, stderr } = await execFileAsync(
      process.execPath,
      [new URL("../bin/wallet-bridge.mjs", import.meta.url).pathname, ...args],
      {
        env: { ...process.env, ...env },
        maxBuffer: 1_048_576,
      },
    );
    return {
      code: 0,
      json: JSON.parse(stdout),
      stderr,
      stdout,
    };
  } catch (error) {
    return {
      code: error.code,
      json: JSON.parse(error.stderr),
      stderr: error.stderr,
      stdout: error.stdout,
    };
  }
}

test("initializes one local key at a canonical private state path and returns only the address", async (t) => {
  const { statePath, result } = await initializeDeterministicWallet(t);

  assert.deepEqual(result, { address: ADDRESS });
  assert.equal((await lstat(dirname(statePath))).mode & 0o777, 0o700);
  assert.equal((await lstat(statePath)).mode & 0o777, 0o600);
  assertNoSecret(result);

  const stored = JSON.parse(await readFile(statePath, "utf8"));
  assert.equal(stored.privateKey, PRIVATE_KEY);
  assert.equal(stored.address, ADDRESS);

  await rejectSafe(() =>
    initializeWallet({
      statePath,
      platform: "darwin",
      generatePrivateKey: () => OTHER_PRIVATE_KEY,
    }),
  );
  assert.equal(JSON.parse(await readFile(statePath, "utf8")).privateKey, PRIVATE_KEY);
});

test("fails closed for relative, root, symlink, hard-linked, and permissive wallet paths", async (t) => {
  await rejectSafe(() =>
    initializeWallet({
      statePath: "relative-wallet.json",
      platform: "darwin",
      generatePrivateKey: () => PRIVATE_KEY,
    }),
  );
  await rejectSafe(() =>
    initializeWallet({
      statePath: resolve("/"),
      platform: "darwin",
      generatePrivateKey: () => PRIVATE_KEY,
    }),
  );

  const { root, statePath } = await temporaryState(t);
  await initializeWallet({
    statePath,
    platform: "darwin",
    generatePrivateKey: () => PRIVATE_KEY,
  });

  const linked = join(root, "linked-wallet.json");
  await symlink(statePath, linked);
  await rejectSafe(() => inspectWallet({ statePath: linked, platform: "darwin" }));

  const hardLink = join(root, "hard-linked-wallet.json");
  await link(statePath, hardLink);
  await rejectSafe(() => inspectWallet({ statePath, platform: "darwin" }));

  const permissiveParent = join(root, "permissive");
  await mkdir(permissiveParent, { mode: 0o700 });
  await chmod(permissiveParent, 0o755);
  await rejectSafe(() =>
    initializeWallet({
      statePath: join(permissiveParent, "wallet.json"),
      platform: "darwin",
      generatePrivateKey: () => OTHER_PRIVATE_KEY,
    }),
  );
});

test("fails closed when initialization parent is swapped for a symlink before writing the private key", async (t) => {
  const { root, statePath } = await temporaryState(t);
  const originalParent = dirname(statePath);
  const redirectedParent = join(root, "redirected");
  const displacedParent = join(root, "party-displaced");
  await mkdir(originalParent, { mode: 0o700, recursive: true });
  await mkdir(redirectedParent, { mode: 0o700 });

  await rejectSafe(() =>
    initializeWallet({
      statePath,
      platform: "darwin",
      generatePrivateKey: () => {
        renameSync(originalParent, displacedParent);
        symlinkSync(redirectedParent, originalParent);
        return PRIVATE_KEY;
      },
    }),
  );

  assert.equal(
    (await readOptional(join(redirectedParent, "wallet.json"))).includes(
      PRIVATE_KEY,
    ),
    false,
  );
  assert.equal(
    (await readOptional(join(redirectedParent, "wallet.json"))).includes(
      PRIVATE_KEY.slice(2),
    ),
    false,
  );
});

test("fails closed when initialization parent becomes permissive before writing the private key", async (t) => {
  const { statePath } = await temporaryState(t);
  const originalParent = dirname(statePath);
  await mkdir(originalParent, { mode: 0o700, recursive: true });

  await rejectSafe(() =>
    initializeWallet({
      statePath,
      platform: "darwin",
      generatePrivateKey: () => {
        chmodSync(originalParent, 0o755);
        return PRIVATE_KEY;
      },
    }),
  );

  const stateText = await readOptional(statePath);
  assert.equal(stateText.includes(PRIVATE_KEY), false);
  assert.equal(stateText.includes(PRIVATE_KEY.slice(2)), false);
});

test("fails closed when an existing wallet parent is replaced by a symlink before reading", async (t) => {
  const { root, statePath } = await initializeDeterministicWallet(t);
  const originalParent = dirname(statePath);
  const displacedParent = join(root, "party-displaced");
  await rename(originalParent, displacedParent);
  await symlink(displacedParent, originalParent);

  await rejectSafe(() =>
    inspectWallet({
      statePath,
      platform: "darwin",
    }),
  );
  await rejectSafe(() =>
    signExactBytes({
      statePath,
      bytesHex: "0x00",
      platform: "darwin",
    }),
  );
});

test("inspects only public address and registration state", async (t) => {
  const { statePath } = await initializeDeterministicWallet(t);

  const inspected = await inspectWallet({ statePath, platform: "darwin" });

  assert.deepEqual(inspected, {
    address: ADDRESS,
    registration: null,
  });
  assertNoSecret(inspected);
});

test("fails closed without leaking when newest checkpoint contains private-key-shaped public fields", async (t) => {
  const { statePath } = await initializeDeterministicWallet(t);
  const maliciousCheckpoint = join(
    dirname(statePath),
    ".wallet.json.checkpoint-000001.json",
  );
  await writeFile(
    maliciousCheckpoint,
    JSON.stringify(recoveryCheckpoint({ displayName: PRIVATE_KEY }), null, 2),
    { mode: 0o600 },
  );

  await rejectSafe(() => inspectWallet({ statePath, platform: "darwin" }));

  const cliInspection = await runCli(["inspect", "--state", statePath]);
  assert.notEqual(cliInspection.code, 0);
  assertNoSecret(cliInspection.stdout);
  assertNoSecret(cliInspection.stderr);
  assert.equal(cliInspection.stdout.includes(PRIVATE_KEY), false);
  assert.equal(cliInspection.stdout.includes(PRIVATE_KEY.slice(2)), false);
  assert.equal(cliInspection.stderr.includes(PRIVATE_KEY), false);
  assert.equal(cliInspection.stderr.includes(PRIVATE_KEY.slice(2)), false);
});

test("fails closed without leaking when checkpoint fields contain case-varied private-key bytes", async (t) => {
  for (const [name, secretEquivalent, checkpointForAddress] of [
    [
      "uppercase no-prefix raw recovery field",
      LETTER_PRIVATE_KEY.slice(2).toUpperCase(),
      (address) =>
        recoveryCheckpoint({
          address,
          displayName: LETTER_PRIVATE_KEY.slice(2).toUpperCase(),
        }),
    ],
    [
      "mixed-case 0x-equivalent intent projection",
      `0x${mixedCasePrivateKeyHex(LETTER_PRIVATE_KEY)}`,
      (address) =>
        intentCheckpoint({
          address,
          displayName: `0x${mixedCasePrivateKeyHex(LETTER_PRIVATE_KEY)}`,
        }),
    ],
  ]) {
    await t.test(name, async (t) => {
      const { statePath, result } = await initializeWalletWithPrivateKey(
        t,
        LETTER_PRIVATE_KEY,
      );
      const maliciousCheckpoint = join(
        dirname(statePath),
        ".wallet.json.checkpoint-000001.json",
      );
      await writeFile(
        maliciousCheckpoint,
        JSON.stringify(checkpointForAddress(result.address), null, 2),
        { mode: 0o600 },
      );

      const error = await rejectSafe(() =>
        inspectWallet({ statePath, platform: "darwin" }),
      );
      assertNoText(error, secretEquivalent);

      const cliInspection = await runCli(["inspect", "--state", statePath]);
      assert.notEqual(cliInspection.code, 0);
      assertNoSecret(cliInspection.stdout);
      assertNoSecret(cliInspection.stderr);
      assert.equal(cliInspection.stdout.includes(secretEquivalent), false);
      assert.equal(cliInspection.stderr.includes(secretEquivalent), false);
    });
  }
});

test("signs only one exact even-length 0x byte string with EIP-191 raw bytes", async (t) => {
  const { statePath } = await initializeDeterministicWallet(t);
  const signed = await signExactBytes({
    statePath,
    bytesHex: "0x000102feff",
    platform: "darwin",
  });

  assert.equal(signed.address, ADDRESS);
  assert.match(signed.signatureHex, /^0x[0-9a-f]{130}$/i);
  assert.deepEqual(Object.keys(signed).sort(), ["address", "signatureHex"]);
  assertNoSecret(signed);
  assert.equal(
    await recoverMessageAddress({
      message: { raw: "0x000102feff" },
      signature: signed.signatureHex,
    }),
    ADDRESS,
  );

  for (const bytesHex of ["", "0x0", "0011", "0xzz", ["0x00"]]) {
    await rejectSafe(() =>
      signExactBytes({ statePath, bytesHex, platform: "darwin" }),
    );
  }
});

test("registers with the wallet key, persists checkpoints before broadcast, and returns public identity fields", async (t) => {
  const { statePath } = await initializeDeterministicWallet(t);
  const calls = [];
  let durableCheckpointExistsAtBroadcast = false;

  const registered = await registerWalletIdentity({
    statePath,
    displayName: "Hermes party",
    platform: "darwin",
    registration: {
      registerIdentity: async ({ privateKey, expectedAddress, displayName, onCheckpoint }) => {
        assert.equal(privateKey, PRIVATE_KEY);
        assert.equal(expectedAddress, ADDRESS);
        assert.equal(displayName, "Hermes party");
        const intent = intentCheckpoint({
          displayName,
        });
        await onCheckpoint(intent);
        durableCheckpointExistsAtBroadcast =
          (await inspectWallet({ statePath, platform: "darwin" })).registration
            .schema === intent.schema;
        calls.push("broadcast");
        await onCheckpoint(recoveryCheckpoint({
          displayName,
        }));
        return fakeRegistrationEvidence();
      },
    },
  });

  assert.equal(durableCheckpointExistsAtBroadcast, true);
  assert.deepEqual(calls, ["broadcast"]);
  assert.deepEqual(registered, {
    agentId: "42",
    address: ADDRESS,
    transaction: {
      register: REGISTER_TX,
      metadata: METADATA_TX,
    },
    block: {
      register: "100",
      metadata: "101",
    },
    identity: {
      identityReference:
        "eip155:11155111:0x8004A818BFB912233c491871b3d84c89A494BD9e:42",
      registryNamespace:
        "eip155:11155111:0x8004A818BFB912233c491871b3d84c89A494BD9e",
      document: fakeRegistrationEvidence().document,
    },
  });
  assert.deepEqual(
    (await inspectWallet({ statePath, platform: "darwin" })).registration,
    {
      schema: "clockchain.handshake-registration-recovery/v1",
      agentId: "42",
      address: ADDRESS,
      displayName: "Hermes party",
      identityReference:
        "eip155:11155111:0x8004A818BFB912233c491871b3d84c89A494BD9e:42",
      registerTx: REGISTER_TX,
      registerBlock: "100",
      metadataTx: null,
      metadataBlock: null,
    },
  );
  assertNoSecret(registered);
});

test("rejects checkpoint callbacks carrying case-varied private-key bytes before persistence or broadcast", async (t) => {
  for (const [name, checkpointForAddress] of [
    [
      "uppercase no-prefix callback field",
      (address) =>
        intentCheckpoint({
          address,
          displayName: LETTER_PRIVATE_KEY.slice(2).toUpperCase(),
        }),
    ],
    [
      "mixed-case 0x-equivalent callback field",
      (address) =>
        recoveryCheckpoint({
          address,
          displayName: `0x${mixedCasePrivateKeyHex(LETTER_PRIVATE_KEY)}`,
        }),
    ],
  ]) {
    await t.test(name, async (t) => {
      const { statePath, result } = await initializeWalletWithPrivateKey(
        t,
        LETTER_PRIVATE_KEY,
      );
      let broadcastReached = false;

      const error = await rejectSafe(() =>
        registerWalletIdentity({
          statePath,
          displayName: "Hermes party",
          platform: "darwin",
          registration: {
            registerIdentity: async ({ onCheckpoint }) => {
              await onCheckpoint(checkpointForAddress(result.address));
              broadcastReached = true;
            },
          },
        }),
      );
      assertNoText(error, checkpointForAddress(result.address).displayName);

      assert.equal(broadcastReached, false);
      const checkpointEntries = (await readdir(dirname(statePath))).filter((entry) =>
        entry.includes("checkpoint"),
      );
      assert.deepEqual(checkpointEntries, []);
    });
  }
});

test("fails closed when registration checkpoint parent is swapped for a symlink before persistence", async (t) => {
  const { root, statePath } = await initializeDeterministicWallet(t);
  const originalParent = dirname(statePath);
  const redirectedParent = join(root, "redirected");
  const displacedParent = join(root, "party-displaced");
  await mkdir(redirectedParent, { mode: 0o700 });

  await rejectSafe(() =>
    registerWalletIdentity({
      statePath,
      displayName: "Hermes party",
      platform: "darwin",
      registration: {
        registerIdentity: async ({ onCheckpoint }) => {
          await rename(originalParent, displacedParent);
          await symlink(redirectedParent, originalParent);
          await onCheckpoint({
            schema: "clockchain.handshake-registration-intent/v1",
            chainId: 11155111,
            registryAddress: "0x8004A818BFB912233c491871b3d84c89A494BD9e",
            registryNamespace:
              "eip155:11155111:0x8004A818BFB912233c491871b3d84c89A494BD9e",
            address: ADDRESS,
            displayName: "Hermes party",
            registerNonce: 0,
            registerCalldata: "0x1234",
            registerGas: "226000",
            maxFeePerGas: "2",
            maxPriorityFeePerGas: "1",
          });
        },
      },
    }),
  );

  const redirectedEntries = await readdir(redirectedParent);
  assert.deepEqual(redirectedEntries, []);
});

test("fails closed when registration checkpoint parent becomes permissive before persistence", async (t) => {
  const { statePath } = await initializeDeterministicWallet(t);
  const originalParent = dirname(statePath);

  await rejectSafe(() =>
    registerWalletIdentity({
      statePath,
      displayName: "Hermes party",
      platform: "darwin",
      registration: {
        registerIdentity: async ({ onCheckpoint }) => {
          await chmod(originalParent, 0o755);
          await onCheckpoint({
            schema: "clockchain.handshake-registration-intent/v1",
            chainId: 11155111,
            registryAddress: "0x8004A818BFB912233c491871b3d84c89A494BD9e",
            registryNamespace:
              "eip155:11155111:0x8004A818BFB912233c491871b3d84c89A494BD9e",
            address: ADDRESS,
            displayName: "Hermes party",
            registerNonce: 0,
            registerCalldata: "0x1234",
            registerGas: "226000",
            maxFeePerGas: "2",
            maxPriorityFeePerGas: "1",
          });
        },
      },
    }),
  );

  const checkpointEntries = (await readdir(originalParent)).filter((entry) =>
    entry.includes("checkpoint"),
  );
  assert.deepEqual(checkpointEntries, []);
});

test("resumes durable recovery records with finalization instead of registering again", async (t) => {
  const { statePath } = await initializeDeterministicWallet(t);

  await registerWalletIdentity({
    statePath,
    displayName: "Hermes party",
    platform: "darwin",
    registration: {
      registerIdentity: async ({ onCheckpoint }) => {
        await onCheckpoint({
          schema: "clockchain.handshake-registration-recovery/v1",
          chainId: 11155111,
          registryAddress: "0x8004A818BFB912233c491871b3d84c89A494BD9e",
          registryNamespace:
            "eip155:11155111:0x8004A818BFB912233c491871b3d84c89A494BD9e",
          identityReference:
            "eip155:11155111:0x8004A818BFB912233c491871b3d84c89A494BD9e:42",
          agentId: "42",
          address: ADDRESS,
          displayName: "Hermes party",
          registerTx: REGISTER_TX,
          registerBlock: "100",
        });
        throw new Error(`network failure ${PRIVATE_KEY}`);
      },
    },
  }).catch(() => {});

  let registerCalled = false;
  let finalizeCalled = false;
  const resumed = await registerWalletIdentity({
    statePath,
    displayName: "Hermes party",
    platform: "darwin",
    registration: {
      registerIdentity: async () => {
        registerCalled = true;
        throw new Error("must not register");
      },
      finalizeIdentityRegistration: async ({ privateKey, expectedAddress, recovery }) => {
        finalizeCalled = true;
        assert.equal(privateKey, PRIVATE_KEY);
        assert.equal(expectedAddress, ADDRESS);
        assert.equal(recovery.registerTx, REGISTER_TX);
        return fakeRegistrationEvidence();
      },
    },
  });

  assert.equal(registerCalled, false);
  assert.equal(finalizeCalled, true);
  assert.equal(resumed.agentId, "42");
  assertNoSecret(resumed);
});

test("CLI emits one safe JSON object for success and failure", async (t) => {
  const { statePath } = await temporaryState(t);

  const init = await runCli(["init", "--state", statePath]);
  assert.equal(init.code, 0);
  assert.match(init.json.address, /^0x[0-9a-fA-F]{40}$/);
  assert.equal(init.stderr, "");
  assertNoSecret(init.stdout);
  const cliPrivateKey = JSON.parse(await readFile(statePath, "utf8")).privateKey;
  assert.equal(init.stdout.includes(cliPrivateKey), false);

  const sign = await runCli(["sign", "--state", statePath, "--bytes", "0x0102"]);
  assert.equal(sign.code, 0);
  assert.equal(sign.json.address, init.json.address);
  assert.match(sign.json.signatureHex, /^0x[0-9a-f]{130}$/i);
  assertNoSecret(sign.stdout);
  assert.equal(sign.stdout.includes(cliPrivateKey), false);

  const failure = await runCli(["sign", "--state", statePath, "--bytes", "0x0"]);
  assert.notEqual(failure.code, 0);
  assert.deepEqual(failure.json, {
    error: {
      code: "WALLET_BRIDGE_FAILED",
      message: "Wallet bridge operation failed safely.",
    },
  });
  assert.equal(failure.stdout, "");
  assert.equal(failure.stderr.split("\n").filter(Boolean).length, 1);
  assert.equal(failure.stderr.includes("Error:"), false);
  assert.equal(failure.stderr.includes("at "), false);
  assertNoSecret(failure.stderr);
  assert.equal(failure.stderr.includes(cliPrivateKey), false);
});
