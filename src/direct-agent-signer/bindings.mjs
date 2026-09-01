export function normalizeRegistrationForDirectSigner(record, identityPolicy) {
  if (identityPolicy.erc8004 === "not_required") return null;
  if (
    record?.schema === undefined &&
    typeof record?.agentId === "string" &&
    record.chainId === identityPolicy.chainId &&
    record.registryAddress === identityPolicy.registryAddress &&
    typeof record.reference === "string" &&
    typeof record.registrationTx === "string" &&
    typeof record.registrationBlock === "string"
  ) {
    return {
      agentId: record.agentId,
      chainId: record.chainId,
      registryAddress: record.registryAddress,
      reference: record.reference,
      registrationTx: record.registrationTx.toLowerCase(),
      registrationBlock: record.registrationBlock,
    };
  }
  if (
    record?.schema !== "clockchain.handshake-registration-recovery/v1" ||
    typeof record.agentId !== "string" ||
    typeof record.identityReference !== "string" ||
    typeof record.registerTx !== "string" ||
    typeof record.registerBlock !== "string"
  ) {
    throw new Error("Direct agent signer failed safely.");
  }
  return {
    agentId: record.agentId,
    chainId: identityPolicy.chainId,
    registryAddress: identityPolicy.registryAddress,
    reference: `${identityPolicy.chainId}:${identityPolicy.registryAddress}:${record.agentId}`,
    registrationTx: record.registerTx.toLowerCase(),
    registrationBlock: record.registerBlock,
  };
}
