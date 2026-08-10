import { isAbsolute, join } from "node:path";

import { localPolicyDigest, validateLocalPolicy } from "../agent-handshake/v2/policy.mjs";
import {
  preparePrivateDirectory,
  readPrivateText,
  writePrivateFile,
} from "../core/private-path.mjs";

const POLICY_FILE = "policy.json";
const SAFE_MESSAGE = "Agent handshake operation failed safely.";

function fail() {
  throw new Error(SAFE_MESSAGE);
}

function statePath(stateDir) {
  if (typeof stateDir !== "string" || !isAbsolute(stateDir)) fail();
  return join(stateDir, POLICY_FILE);
}

function bytes(value) {
  return Buffer.from(JSON.stringify(value) + "\n", "utf8");
}

export async function commitAgentPolicy({ stateDir, policy: input, platform, runIcacls } = {}) {
  try {
    const policy = validateLocalPolicy(input);
    const policyDigest = localPolicyDigest(policy);
    await preparePrivateDirectory({ path: stateDir, platform, runIcacls });
    await writePrivateFile({
      bytes: bytes({ policy, policyDigest }),
      path: statePath(stateDir),
      platform,
      runIcacls,
    });
    return Object.freeze({ policyDigest });
  } catch (error) {
    if (error?.message === SAFE_MESSAGE) throw error;
    fail();
  }
}

export async function readAgentPolicy({ stateDir, platform, runIcacls } = {}) {
  try {
    const text = await readPrivateText({
      path: statePath(stateDir),
      platform,
      runIcacls,
    });
    const record = JSON.parse(text);
    if (
      record === null ||
      typeof record !== "object" ||
      Array.isArray(record) ||
      Object.keys(record).length !== 2 ||
      !Object.hasOwn(record, "policy") ||
      !Object.hasOwn(record, "policyDigest")
    ) fail();
    const policy = validateLocalPolicy(record.policy);
    const policyDigest = localPolicyDigest(policy);
    if (record.policyDigest !== policyDigest) fail();
    return Object.freeze({ policy, policyDigest });
  } catch (error) {
    if (error?.code === "ENOENT") throw error;
    if (error?.message === SAFE_MESSAGE) throw error;
    fail();
  }
}
