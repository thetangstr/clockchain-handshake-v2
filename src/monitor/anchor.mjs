// Duplicated from bin/operator.mjs until P4 moves both entrypoints onto one
// monitor-anchor path. Keep the operator copy in place for this track.
export function transitionToAnchor(kind, transition, { relayUrl = "" } = {}) {
  return {
    blockHeight: transition.onChain.blockHeight,
    blockTime: Number(transition.blockTimeMs),
    // Clockchain has no public explorer: mcp.clockchain.network answers 401 on
    // every path except /health, and it advertises only a token endpoint. The
    // URL this used to build -- MCP_BASE_URL/explorer/{kind}/{ledgerId} -- was
    // our own invention for a route that has never existed, and the audience
    // page linked it, so every "check this receipt" link on the projector led
    // to an auth error. Point at the relay's own re-read, which resolves.
    explorerUrl: `${relayUrl.replace(/\/+$/, "")}/v1/blocks/${transition.onChain.blockHeight}`,
    kind,
    ledgerId: transition.onChain.ledgerId,
    receipt: {
      anchoredHash: transition.onChain.anchoredHash,
      blockTimeRaw: transition.blockTimeRaw,
      digest: transition.digest,
    },
    // Who signed this transition. The payer writes the proposal and the
    // acknowledgement while watching for the acceptance; the payee does the
    // inverse (src/core/roles-core.mjs).
    signedBy: signerOf(kind, transition.message),
    // The terms as signed. This was being thrown away: transitionToAnchor kept
    // six fields and discarded the message, so the board could show that a
    // receipt existed but not what it said.
    terms: termsOf(transition.message),
  };
}

const CANONICAL_DECIMAL = /^(0|[1-9]\d*)$/u;

function safeNonnegativeInteger(value) {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
    return null;
  }
  return value;
}

function parseSafeNonnegativeInteger(value) {
  if (typeof value !== "string" || !CANONICAL_DECIMAL.test(value)) {
    return null;
  }
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed)) {
    return null;
  }
  return parsed;
}

export function anchorToWireReport(anchor) {
  const blockTime = safeNonnegativeInteger(anchor?.blockTime);
  if (blockTime === null) {
    throw new TypeError("anchor blockTime must be a safe nonnegative integer.");
  }
  return { ...anchor, blockTime: String(blockTime) };
}

export function wireReportToAnchor(anchor) {
  const blockTime = parseSafeNonnegativeInteger(anchor?.blockTime);
  if (blockTime === null) {
    throw new TypeError("anchor wire blockTime must be a canonical decimal string.");
  }
  return { ...anchor, blockTime };
}

export function signerOf(kind, message) {
  const party = kind === "acceptance" ? message?.payee : message?.payer;
  if (!party?.address || !party?.agentId) return null;
  return { address: String(party.address).toLowerCase(), agentId: String(party.agentId) };
}

export function termsOf(message) {
  if (!message?.amount) return null;
  return {
    currency: String(message.amount.currency),
    expirySeconds: String(message.expirySeconds),
    // The predecessor is a triple pointing at the previous receipt
    // ({anchoredHash, blockHeight, kind, ledgerId}); its block height is the
    // half a reader can act on. Stringifying the object gave "[object Object]",
    // which reached a live board before a real run caught it.
    predecessor: message.predecessor?.blockHeight
      ? String(message.predecessor.blockHeight)
      : null,
    sequence: String(message.sequence),
    sessionDigest: String(message.sessionDigest),
    value: String(message.amount.value),
  };
}
