import {
  getHandshakeV3Contract,
  listHandshakeV3Tools,
  prepareHandshakeV3Signing,
  validateHandshakeV3CliResultShape,
  validateHandshakeV3SdkToolInput,
  validateHandshakeV3SdkToolResult,
  verifyHandshakeV3SdkCertificate,
  verifyHandshakeV3SdkContinuation,
} from "@clockchain/handshake-sdk";

const COMMANDS = Object.freeze([
  "help",
  "contract",
  "validate-tool-input",
  "validate-tool-result",
  "prepare-signing",
  "verify-result-fixture",
  "verify-certificate-fixture",
]);

function success(command, result) {
  return validateHandshakeV3CliResultShape({
    ok: true,
    command,
    verificationMode: "explicit_fixture_only",
    clockchainTrustVerified: false,
    externalBusinessActionPerformed: false,
    result,
  });
}

export function formatHandshakeCliFailure(command, error) {
  return validateHandshakeV3CliResultShape({
    ok: false,
    command,
    externalBusinessActionPerformed: false,
    error: {
      code: error?.code ?? "INTERNAL_SAFE_FAILURE",
      message: "Handshake CLI command failed safely.",
    },
  });
}

function fixtureAdapter(adapter) {
  if (adapter === undefined || adapter === null) return null;
  const valid = validateFixtureTrustAdapter(adapter);
  return {
    verifyIssuerSignature: async ({ signedDigest, clockchainNetwork, trustRootId }) =>
      valid.acceptedIssuerDigests.includes(signedDigest) === true &&
      valid.clockchainNetwork === clockchainNetwork &&
      valid.trustRootId === trustRootId,
    getRevocationStatus: async (handle) => valid.revokedHandles.includes(handle) ? "REVOKED" : "GOOD",
    checkAndRecordReplay: async (replayNonce) => valid.replayedNonces.includes(replayNonce) !== true,
  };
}

function schemaError() {
  return Object.assign(new Error("Fixture trust adapter was rejected."), { code: "SCHEMA_INVALID" });
}

function rejectSchema() {
  throw schemaError();
}

function safeObjectEntries(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) rejectSchema();
  let prototype;
  try {
    prototype = Object.getPrototypeOf(value);
  } catch {
    rejectSchema();
  }
  if (prototype !== Object.prototype && prototype !== null) rejectSchema();
  let keys;
  try {
    keys = Reflect.ownKeys(value);
  } catch {
    rejectSchema();
  }
  const entries = [];
  for (const key of keys) {
    if (typeof key !== "string") rejectSchema();
    let descriptor;
    try {
      descriptor = Object.getOwnPropertyDescriptor(value, key);
    } catch {
      rejectSchema();
    }
    if (!descriptor || !descriptor.enumerable || !Object.hasOwn(descriptor, "value")) rejectSchema();
    entries.push([key, descriptor.value]);
  }
  return entries;
}

function validateBoundedString(value, pattern, maxLength) {
  if (typeof value !== "string" || value.length === 0 || value.length > maxLength || !pattern.test(value)) rejectSchema();
  return value;
}

function validateArray(value, validator) {
  if (!Array.isArray(value) || value.length > 64) rejectSchema();
  let keys;
  try {
    keys = Reflect.ownKeys(value);
  } catch {
    rejectSchema();
  }
  for (const key of keys) {
    if (typeof key !== "string") rejectSchema();
    if (key !== "length" && !/^(0|[1-9][0-9]*)$/.test(key)) rejectSchema();
  }
  const output = [];
  for (let index = 0; index < value.length; index += 1) {
    let descriptor;
    try {
      descriptor = Object.getOwnPropertyDescriptor(value, String(index));
    } catch {
      rejectSchema();
    }
    if (!descriptor || !descriptor.enumerable || !Object.hasOwn(descriptor, "value")) rejectSchema();
    output.push(validator(descriptor.value));
  }
  return Object.freeze(output);
}

function validateFixtureTrustAdapter(adapter) {
  const allowedKeys = new Set([
    "acceptedIssuerDigests",
    "revokedHandles",
    "replayedNonces",
    "clockchainNetwork",
    "trustRootId",
  ]);
  const output = {
    acceptedIssuerDigests: [],
    revokedHandles: [],
    replayedNonces: [],
  };
  let sawAcceptedIssuerDigests = false;
  for (const [key, value] of safeObjectEntries(adapter)) {
    if (!allowedKeys.has(key)) rejectSchema();
    if (key === "acceptedIssuerDigests") {
      sawAcceptedIssuerDigests = true;
      output.acceptedIssuerDigests = validateArray(value, (entry) => validateBoundedString(entry, /^sha256:[0-9a-f]{64}$/, 71));
    } else if (key === "revokedHandles" || key === "replayedNonces") {
      output[key] = validateArray(value, (entry) => validateBoundedString(entry, /^[A-Za-z0-9._:-]+$/, 128));
    } else if (key === "clockchainNetwork") {
      output.clockchainNetwork = validateBoundedString(value, /^[A-Za-z0-9._:-]+$/, 64);
    } else if (key === "trustRootId") {
      output.trustRootId = validateBoundedString(value, /^[A-Za-z0-9._:-]+$/, 128);
    }
  }
  if (typeof output.clockchainNetwork !== "string" || typeof output.trustRootId !== "string") rejectSchema();
  if (!sawAcceptedIssuerDigests || !Array.isArray(output.acceptedIssuerDigests)) rejectSchema();
  return Object.freeze(output);
}

export async function runHandshakeCliCommand(command, input = {}, options = {}) {
  try {
    if (command === "contract") {
      const contract = getHandshakeV3Contract();
      return success(command, {
        protocolVersion: contract.protocolVersion,
        schemaVersion: contract.schemaVersion,
        tools: listHandshakeV3Tools(),
      });
    }
    if (command === "help" || command === "--help") {
      return success(command, {
        commands: COMMANDS,
        input: "Commands except help and contract read one JSON object from stdin.",
        trustBoundary: "Fixture verification commands do not establish Clockchain trust; they only exercise explicitly supplied local fixture callbacks.",
      });
    }
    if (command === "validate-tool-input") {
      return success(command, validateHandshakeV3SdkToolInput(options.toolName, input));
    }
    if (command === "validate-tool-result") {
      return success(command, validateHandshakeV3SdkToolResult(options.toolName, input));
    }
    if (command === "prepare-signing") {
      return success(command, prepareHandshakeV3Signing(input));
    }
    if (command === "verify-result-fixture") {
      const adapter = fixtureAdapter(input.fixtureTrustAdapter);
      if (!adapter) throw Object.assign(new Error("explicit verification fixture required"), { code: "RESULT_VERIFICATION_FAILED" });
      return success(command, await verifyHandshakeV3SdkContinuation({
        certificate: input.certificate,
        continuation: input.continuation,
        expectedPolicyDigest: input.expectedPolicyDigest,
        expectedPartyRoleDigests: input.expectedPartyRoleDigests,
        now: input.now,
        ...adapter,
      }));
    }
    if (command === "verify-certificate-fixture") {
      const adapter = fixtureAdapter(input.fixtureTrustAdapter);
      if (!adapter) throw Object.assign(new Error("explicit verification fixture required"), { code: "RESULT_VERIFICATION_FAILED" });
      return success(command, await verifyHandshakeV3SdkCertificate({
        certificate: input.certificate,
        expectedPolicyDigest: input.expectedPolicyDigest,
        now: input.now,
        verifyIssuerSignature: adapter.verifyIssuerSignature,
        getRevocationStatus: adapter.getRevocationStatus,
      }));
    }
    throw Object.assign(new Error("unknown command"), { code: "SCHEMA_INVALID" });
  } catch (error) {
    return formatHandshakeCliFailure(command || "unknown", error);
  }
}
