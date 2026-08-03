// Party-result fixture extracted from the ported donor evidence test so the
// upload-seam test exercises a genuinely valid package (validation is strict).
import { createHash } from "node:crypto";
import { parseBlockTime } from "../../src/core/blocktime.mjs";
import { canonicalBytes, digestHex } from "../../src/core/canonical.mjs";
import {
  buildPartySignaturePreimage,
  LOCAL_VERDICTS,
  PARTY_RESULT_SCHEMA,
  PARTY_SIGNATURE_SCHEMA,
  partySignatureBytes,
} from "../../src/core/evidence.mjs";

const SESSION_DIGEST = "cd".repeat(32);
const REPOSITORY_SHA = "0123456789abcdef0123456789abcdef01234567";
const PROMPT_SHA256 = "ef".repeat(32);
const PAYER_ADDRESS = `0x${"11".repeat(20)}`;
const PAYEE_ADDRESS = `0x${"22".repeat(20)}`;
const REGISTRY = "0x8004a818bfb912233c491871b3d84c89a494bd9e";
const LEDGER_IDS = Object.freeze([
  "3f8a1c2e-9d4b-4a6c-8f2e-0123456789ab",
  "4a9b2d3f-0e5c-4b7d-9a3f-123456789abc",
  "5b0c3e40-1f6d-4c8e-ab40-23456789abcd",
]);
const RAW_TIMES = Object.freeze([
  "2026-07-24T20:00:00.100000001Z",
  "2026-07-24T20:00:31.204500000Z",
  "2026-07-24T20:01:02.309999999Z",
]);
const HEIGHTS = Object.freeze(["1869000", "1869030", "1869060"]);

function transitionHead(sessionDigest = SESSION_DIGEST) {
  return {
    amount: { currency: "USD", moved: false, value: "100" },
    expirySeconds: "600",
    payee: { address: PAYEE_ADDRESS, agentId: "9001" },
    payer: {
      address: PAYER_ADDRESS,
      agentId: "8677",
      reference: `eip155:11155111:${REGISTRY}:8677`,
    },
    protocol: "clockchain.bilateral-authorization/v1",
    schema: "clockchain.bilateral-transition/v1",
    sessionDigest,
  };
}

// Builds an internally consistent party-result fixture: every digest,
// anchored hash, predecessor triple, block-time and deadline value is
// recomputed here from the messages, so tamper tests can flip exactly
// one derived relation at a time.
function buildFixture({
  role = "payer",
  transitionsCount = 3,
  heights = HEIGHTS,
  rawTimes = RAW_TIMES,
  sessionDigest = SESSION_DIGEST,
  messageExtras = {},
  tamperPredecessor = false,
} = {}) {
  const m1 = {
    ...transitionHead(sessionDigest),
    kind: "proposal",
    predecessor: null,
    sequence: "1",
    ...(messageExtras.proposal ?? {}),
  };
  const h1 = digestHex(m1);
  const proposalTriple = {
    anchoredHash: h1,
    blockHeight: heights[0],
    kind: "proposal",
    ledgerId: LEDGER_IDS[0],
  };

  const m2 = {
    ...transitionHead(sessionDigest),
    decision: "ACCEPT",
    kind: "acceptance",
    predecessor: tamperPredecessor
      ? { ...proposalTriple, blockHeight: "999" }
      : proposalTriple,
    sequence: "2",
    ...(messageExtras.acceptance ?? {}),
  };
  const h2 = digestHex(m2);
  const acceptanceTriple = {
    anchoredHash: h2,
    blockHeight: heights[1],
    kind: "acceptance",
    ledgerId: LEDGER_IDS[1],
  };

  const m3 = {
    ...transitionHead(sessionDigest),
    kind: "acknowledgment",
    outcome: "ACKNOWLEDGED",
    paymentMoved: false,
    predecessor: acceptanceTriple,
    proposal: proposalTriple,
    sequence: "3",
    ...(messageExtras.acknowledgment ?? {}),
  };
  const h3 = digestHex(m3);

  const messages = [m1, m2, m3];
  const digests = [h1, h2, h3];
  const transitions = messages.map((message, index) => {
    const blockTimeMs = parseBlockTime(rawTimes[index]);
    return {
      blockTimeMs: String(blockTimeMs),
      blockTimeRaw: rawTimes[index],
      digest: digests[index],
      message,
      onChain: {
        anchoredHash: digests[index],
        blockHeight: heights[index],
        ledgerId: LEDGER_IDS[index],
      },
      upperBoundMs:
        index === 0 ? null : String(blockTimeMs + 1100),
    };
  });

  return {
    ackObserved: transitionsCount === 3,
    deadlineMs: String(parseBlockTime(rawTimes[0]) + 600000),
    localVerdict: "LOCAL_OK",
    paymentMoved: false,
    poolHealth: {
      degradedAtSubmission: true,
      nodeParticipationPct: "0.0",
      totalNodes: "1.0",
    },
    promptSha256: PROMPT_SHA256,
    protocolVersion: "1",
    rendezvous: {
      channel: "derived-reference-id",
      degradedAtSubmission: true,
      tenancy: "cross-client",
    },
    repositorySha: REPOSITORY_SHA,
    role,
    schema: PARTY_RESULT_SCHEMA,
    sessionDigest,
    signature: {
      address: role === "payer" ? PAYER_ADDRESS : PAYEE_ADDRESS,
      algorithm: "eip191",
      signature: `0x${"ab".repeat(65)}`,
    },
    transitions: transitions.slice(0, transitionsCount),
  };
}

export { buildFixture };
