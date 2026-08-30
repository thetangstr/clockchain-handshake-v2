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
  if (!adapter || typeof adapter !== "object" || Array.isArray(adapter)) return null;
  return {
    verifyIssuerSignature: async ({ signedDigest, clockchainNetwork, trustRootId }) =>
      adapter.acceptedIssuerDigests?.includes(signedDigest) === true &&
      adapter.clockchainNetwork === clockchainNetwork &&
      adapter.trustRootId === trustRootId,
    getRevocationStatus: async (handle) => adapter.revokedHandles?.includes(handle) ? "REVOKED" : "GOOD",
    checkAndRecordReplay: async (replayNonce) => adapter.replayedNonces?.includes(replayNonce) !== true,
  };
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
