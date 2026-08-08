export function classifyFundingRecord(message, { address, role }) {
  const funded = String(message?.body?.funded ?? "").toLowerCase();
  const ownAddress = String(address ?? "").toLowerCase();
  if (funded === ownAddress) {
    return "proceed";
  }

  const fundedRole = message?.body?.role;
  if (fundedRole !== undefined && fundedRole !== role) {
    return "skip";
  }
  return "already-bound";
}

export function selectFundingRecord(messages, options) {
  for (const message of messages ?? []) {
    if (message?.kind !== "funding_record") continue;
    const status = classifyFundingRecord(message, options);
    if (status === "skip") continue;
    return { message, status };
  }
  return { message: null, status: "none" };
}
