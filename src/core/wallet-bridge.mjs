import { lstat, readdir } from "node:fs/promises";
import { basename, dirname, join } from "node:path";

import { isHex } from "viem";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";

import {
  finalizeIdentityRegistration,
  registerIdentity,
  validateRegistrationCheckpoint,
} from "./registration.mjs";
import {
  preparePrivateDirectory,
  readPrivateText,
  writePrivateFile,
} from "./private-path.mjs";

const WALLET_SCHEMA = "clockchain.handshake-wallet-bridge/v1";
const BRIDGE_ERROR_MESSAGE = "Wallet bridge operation failed safely.";
const INTENT_SCHEMA = "clockchain.handshake-registration-intent/v1";
const RECOVERY_SCHEMA = "clockchain.handshake-registration-recovery/v1";
const PRIVATE_KEY_PATTERN = /^0x[0-9a-fA-F]{64}$/;
const BYTES_PATTERN = /^0x(?:[0-9a-fA-F]{2})*$/;
const HEX_PRIVATE_KEY_CANDIDATE_PATTERN =
  /0[xX][0-9a-fA-F]{64}|[0-9a-fA-F]{64}/g;
const HEX_CHARACTER_PATTERN = /[0-9a-fA-F]/;

function fail() {
  throw new Error(BRIDGE_ERROR_MESSAGE);
}

function sanitize(error) {
  if (error?.message === BRIDGE_ERROR_MESSAGE) throw error;
  fail();
}

function jsonBytes(value) {
  return Buffer.from(
    `${JSON.stringify(
      value,
      (_, entry) => (typeof entry === "bigint" ? entry.toString(10) : entry),
      2,
    )}\n`,
  );
}

function assertPath(value) {
  if (typeof value !== "string") fail();
  return value;
}

function assertDisplayName(value) {
  if (typeof value !== "string" || value.trim().length === 0) fail();
  return value;
}

function assertPrivateKey(value) {
  if (!PRIVATE_KEY_PATTERN.test(value)) fail();
  return value;
}

function validatePublicRegistration(record, expectedAddress) {
  if (record === null) return null;
  return validateRegistrationCheckpoint(record, { expectedAddress });
}

function publicRegistration(record) {
  if (record === null) return null;
  if (record?.schema === INTENT_SCHEMA) {
    return {
      schema: record.schema,
      address: record.address,
      displayName: record.displayName,
      registerNonce: record.registerNonce,
    };
  }
  if (record?.schema === RECOVERY_SCHEMA) {
    return {
      schema: record.schema,
      agentId: record.agentId,
      address: record.address,
      displayName: record.displayName,
      identityReference: record.identityReference,
      registerTx: record.registerTx,
      registerBlock: record.registerBlock,
      metadataTx: record.metadataTx ?? null,
      metadataBlock: record.metadataBlock ?? null,
    };
  }
  fail();
}

function publicRegistrationEvidence(evidence) {
  if (
    typeof evidence?.agentId !== "string" ||
    typeof evidence?.address !== "string"
  ) {
    fail();
  }
  return {
    agentId: evidence.agentId,
    address: evidence.address,
    transaction: {
      register: evidence.registerTx ?? null,
      metadata: evidence.metadataTx ?? null,
    },
    block: {
      register: evidence.registerBlock ?? null,
      metadata: evidence.metadataBlock ?? null,
    },
    identity: {
      identityReference: evidence.identityReference ?? null,
      registryNamespace: evidence.registryNamespace ?? null,
      document: evidence.document ?? null,
    },
  };
}

function assertOmitsPrivateKey(value, privateKey) {
  const text = JSON.stringify(value);
  const secretHex = privateKey.slice(2).toLowerCase();
  if (
    typeof text !== "string" ||
    hexCandidates(text).some((candidate) => candidate === secretHex)
  ) {
    fail();
  }
}

function hexCandidates(text) {
  return [...text.matchAll(HEX_PRIVATE_KEY_CANDIDATE_PATTERN)]
    .filter((match) => isStandaloneHexCandidate(text, match))
    .map(([candidate]) =>
      candidate.replace(/^0[xX]/, "").toLowerCase(),
    );
}

function isStandaloneHexCandidate(text, match) {
  const candidate = match[0];
  if (candidate.startsWith("0x") || candidate.startsWith("0X")) {
    return true;
  }
  const before = text[match.index - 1];
  const after = text[match.index + candidate.length];
  return (
    (before === undefined || !HEX_CHARACTER_PATTERN.test(before)) &&
    (after === undefined || !HEX_CHARACTER_PATTERN.test(after))
  );
}

async function captureParentIdentity(statePath, { platform, runIcacls }) {
  const parent = dirname(statePath);
  await preparePrivateDirectory({
    path: parent,
    platform,
    runIcacls,
  });
  const stats = await lstat(parent);
  verifyParentStats(stats, { platform });
  return Object.freeze({
    dev: stats.dev,
    ino: stats.ino,
    path: parent,
    platform,
    runIcacls,
  });
}

function verifyParentStats(stats, { platform }) {
  if (
    !stats.isDirectory() ||
    stats.isSymbolicLink()
  ) {
    fail();
  }
  if (platform !== "win32") {
    if (
      typeof process.getuid === "function" &&
      stats.uid !== process.getuid()
    ) {
      fail();
    }
    if ((stats.mode & 0o777) !== 0o700) {
      fail();
    }
  }
}

async function verifyParentIdentity(identity) {
  const stats = await lstat(identity.path);
  verifyParentStats(stats, identity);
  if (stats.dev !== identity.dev || stats.ino !== identity.ino) fail();
  if (identity.platform === "win32") {
    await preparePrivateDirectory({
      path: identity.path,
      platform: identity.platform,
      runIcacls: identity.runIcacls,
    });
    const verified = await lstat(identity.path);
    verifyParentStats(verified, identity);
    if (verified.dev !== identity.dev || verified.ino !== identity.ino) fail();
  }
}

function checkpointName(statePath, sequence) {
  return `.${basename(statePath)}.checkpoint-${String(sequence).padStart(6, "0")}.json`;
}

function checkpointPath(statePath, sequence) {
  return join(dirname(statePath), checkpointName(statePath, sequence));
}

function checkpointPattern(statePath) {
  const escaped = basename(statePath).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  return new RegExp(`^\\.${escaped}\\.checkpoint-([0-9]{6})\\.json$`);
}

async function latestCheckpoint({
  expectedAddress,
  platform,
  privateKey,
  runIcacls,
  statePath,
}) {
  const parentIdentity = await captureParentIdentity(statePath, {
    platform,
    runIcacls,
  });
  const pattern = checkpointPattern(statePath);
  await verifyParentIdentity(parentIdentity);
  const entries = await readdir(dirname(statePath));
  await verifyParentIdentity(parentIdentity);
  const sequences = entries
    .map((entry) => pattern.exec(entry)?.[1])
    .filter((entry) => entry !== undefined)
    .map((entry) => Number(entry))
    .sort((left, right) => right - left);
  for (const sequence of sequences) {
    await verifyParentIdentity(parentIdentity);
    const text = await readPrivateText({
      path: checkpointPath(statePath, sequence),
      platform,
      runIcacls,
    });
    await verifyParentIdentity(parentIdentity);
    assertOmitsPrivateKey(text, privateKey);
    const record = JSON.parse(text);
    const checkpoint = validatePublicRegistration(record, expectedAddress);
    assertOmitsPrivateKey(checkpoint, privateKey);
    const projected = publicRegistration(checkpoint);
    assertOmitsPrivateKey(projected, privateKey);
    return { parentIdentity, record: checkpoint, sequence };
  }
  return { parentIdentity, record: null, sequence: 0 };
}

async function persistCheckpoint({
  parentIdentity,
  platform,
  record,
  runIcacls,
  sequence,
  statePath,
}) {
  const target = checkpointPath(statePath, sequence);
  await verifyParentIdentity(parentIdentity);
  await writePrivateFile({
    bytes: jsonBytes(record),
    path: target,
    platform,
    runIcacls,
  });
  await verifyParentIdentity(parentIdentity);
}

async function readWallet({ platform, runIcacls, statePath }) {
  const parentIdentity = await captureParentIdentity(statePath, {
    platform,
    runIcacls,
  });
  await verifyParentIdentity(parentIdentity);
  const text = await readPrivateText({
    path: statePath,
    platform,
    runIcacls,
  });
  await verifyParentIdentity(parentIdentity);
  const wallet = JSON.parse(text);
  if (
    wallet?.schema !== WALLET_SCHEMA ||
    typeof wallet.address !== "string" ||
    assertPrivateKey(wallet.privateKey) !== wallet.privateKey
  ) {
    fail();
  }
  const account = privateKeyToAccount(wallet.privateKey);
  if (account.address !== wallet.address) fail();
  return { account, parentIdentity, wallet };
}

export async function initializeWallet({
  generatePrivateKey: createPrivateKey = generatePrivateKey,
  platform = process.platform,
  runIcacls,
  statePath: inputStatePath,
} = {}) {
  try {
    const statePath = assertPath(inputStatePath);
    const parentIdentity = await captureParentIdentity(statePath, {
      platform,
      runIcacls,
    });
    if (typeof createPrivateKey !== "function") fail();
    const privateKey = assertPrivateKey(createPrivateKey());
    await verifyParentIdentity(parentIdentity);
    const account = privateKeyToAccount(privateKey);
    const wallet = {
      schema: WALLET_SCHEMA,
      address: account.address,
      privateKey,
    };
    await writePrivateFile({
      bytes: jsonBytes(wallet),
      path: statePath,
      platform,
      runIcacls,
    });
    await verifyParentIdentity(parentIdentity);
    return { address: account.address };
  } catch (error) {
    sanitize(error);
  }
  fail();
}

export async function inspectWallet({
  platform = process.platform,
  runIcacls,
  statePath: inputStatePath,
} = {}) {
  try {
    const statePath = assertPath(inputStatePath);
    const { wallet } = await readWallet({ platform, runIcacls, statePath });
    const { record } = await latestCheckpoint({
      expectedAddress: wallet.address,
      platform,
      privateKey: wallet.privateKey,
      runIcacls,
      statePath,
    });
    return {
      address: wallet.address,
      registration: publicRegistration(record),
    };
  } catch (error) {
    sanitize(error);
  }
  fail();
}

export async function signExactBytes({
  bytesHex,
  platform = process.platform,
  runIcacls,
  statePath: inputStatePath,
} = {}) {
  try {
    const statePath = assertPath(inputStatePath);
    if (typeof bytesHex !== "string" || !BYTES_PATTERN.test(bytesHex)) fail();
    if (!isHex(bytesHex)) fail();
    const { account } = await readWallet({ platform, runIcacls, statePath });
    const signatureHex = await account.signMessage({
      message: { raw: bytesHex },
    });
    return {
      address: account.address,
      signatureHex,
    };
  } catch (error) {
    sanitize(error);
  }
  fail();
}

export async function registerWalletIdentity({
  displayName: inputDisplayName,
  platform = process.platform,
  registration = {},
  rpcUrl,
  publicClient,
  runIcacls,
  statePath: inputStatePath,
  walletClient,
} = {}) {
  try {
    const statePath = assertPath(inputStatePath);
    const displayName = assertDisplayName(inputDisplayName);
    const { account, wallet } = await readWallet({
      platform,
      runIcacls,
      statePath,
    });
    const { parentIdentity, record, sequence } = await latestCheckpoint({
      expectedAddress: account.address,
      platform,
      privateKey: wallet.privateKey,
      runIcacls,
      statePath,
    });
    let nextSequence = sequence + 1;
    const onCheckpoint = async (checkpoint) => {
      validatePublicRegistration(checkpoint, account.address);
      assertOmitsPrivateKey(checkpoint, wallet.privateKey);
      await persistCheckpoint({
        parentIdentity,
        platform,
        record: checkpoint,
        runIcacls,
        sequence: nextSequence,
        statePath,
      });
      nextSequence += 1;
    };
    const register =
      registration.registerIdentity ?? registerIdentity;
    const finalize =
      registration.finalizeIdentityRegistration ?? finalizeIdentityRegistration;
    if (typeof register !== "function" || typeof finalize !== "function") fail();

    const common = {
      privateKey: wallet.privateKey,
      expectedAddress: account.address,
      displayName,
      rpcUrl,
      publicClient,
      walletClient,
      onCheckpoint,
    };
    const evidence =
      record?.schema === RECOVERY_SCHEMA
        ? await finalize({ ...common, recovery: record })
        : await register({
            ...common,
            intent: record?.schema === INTENT_SCHEMA ? record : undefined,
          });
    return publicRegistrationEvidence(evidence);
  } catch (error) {
    sanitize(error);
  }
  fail();
}
