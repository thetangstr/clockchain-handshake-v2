import { a2aAgentCardDigest, verifyA2AAgentCard } from "./agent-card.mjs";
import { a2aEnvelopeDigest, verifyA2AEnvelope } from "./envelope.mjs";
import { invalid } from "./auth.mjs";

export async function createDirectTaskChannel({ sessionId, initiatorCard, responderCard, nowMs }) {
  const responderDigest = a2aAgentCardDigest(responderCard);
  const seenCardJtis = new Set();
  const seenCardNonces = new Set();
  const cards = Object.freeze({
    initiator: await verifyA2AAgentCard({
      card: initiatorCard,
      expectedSessionId: sessionId,
      expectedRole: "initiator",
      expectedPeerCardDigest: responderDigest,
      nowMs,
      seenJtis: seenCardJtis,
      seenNonces: seenCardNonces,
    }),
    responder: await verifyA2AAgentCard({
      card: responderCard,
      expectedSessionId: sessionId,
      expectedRole: "responder",
      nowMs,
      seenJtis: seenCardJtis,
      seenNonces: seenCardNonces,
    }),
  });
  if (cards.responder.peerCardDigest !== null || cards.initiator.a2aCardPublicKey.toLowerCase() === cards.responder.a2aCardPublicKey.toLowerCase()) invalid();
  const queues = { initiator: [], responder: [] };
  const seenNonces = new Set();
  const lastByDirection = new Map();
  const publicMessages = [];

  function direction(fromRole, toRole) {
    if (!cards[fromRole] || !cards[toRole] || fromRole === toRole) invalid();
    return `${fromRole}->${toRole}`;
  }

  return Object.freeze({
    async send({ fromRole, toRole, envelope, nowMs: messageNowMs }) {
      const key = direction(fromRole, toRole);
      const verified = await verifyA2AEnvelope({
        envelope,
        fromCard: cards[fromRole],
        toCard: cards[toRole],
        nowMs: messageNowMs,
      });
      if (seenNonces.has(verified.nonce)) invalid();
      const previous = lastByDirection.get(key) ?? null;
      const expectedSequence = previous === null ? "1" : String(Number(previous.sequence) + 1);
      if (verified.sequence !== expectedSequence || verified.previousMessageDigest !== (previous?.digest ?? null)) invalid();
      const messageDigest = a2aEnvelopeDigest(verified);
      seenNonces.add(verified.nonce);
      lastByDirection.set(key, { sequence: verified.sequence, digest: messageDigest });
      queues[toRole].push(verified);
      publicMessages.push(Object.freeze({
        fromRole,
        toRole,
        sequence: verified.sequence,
        artifactType: verified.artifactType,
        artifactDigest: verified.artifactDigest,
        messageDigest,
      }));
      return Object.freeze({ messageDigest });
    },
    async receive({ role }) {
      if (!cards[role]) invalid();
      return queues[role].shift() ?? null;
    },
    publicEvidence() {
      return Object.freeze({
        schema: "clockchain.a2a-direct-task-channel-evidence/v1",
        sessionId,
        cardDigests: Object.freeze({
          initiator: a2aAgentCardDigest(cards.initiator),
          responder: a2aAgentCardDigest(cards.responder),
        }),
        messages: Object.freeze(publicMessages.map((message) => Object.freeze({ ...message }))),
      });
    },
  });
}
