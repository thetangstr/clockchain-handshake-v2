import { canonicalBytes } from "../../core/canonical.mjs";
import { verifyAgentHandshakeV2DescriptorEnvelope, agentHandshakeV2DescriptorDigest } from "./descriptor.mjs";
import { verifyAgentHandshakeV2Evidence } from "./evidence.mjs";
import {
  agentHandshakeV2TransitionDigest,
  validateAgentHandshakeV2TransitionChain,
  verifyAgentHandshakeV2Acceptance,
  verifyAgentHandshakeV2Proposal,
} from "./protocol.mjs";
import { validateAgentHandshakeV2Terms } from "./terms.mjs";

const DIGEST=/^[0-9a-f]{64}$/;const DECIMAL=/^(?:0|[1-9][0-9]*)$/;const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
export class AgentHandshakeV2VerdictError extends Error{constructor(){super("Agent handshake v2 authorization verification failed.");this.name="AgentHandshakeV2VerdictError";this.category="verification";this.code="AGENT_HANDSHAKE_V2_VERDICT_INVALID";}}
function invalid(){throw new AgentHandshakeV2VerdictError();}
function receipt(value,kind,digest){if(value===null||typeof value!=="object"||Array.isArray(value)||Object.keys(value).length!==5||!["blockHeight","blockTimeRaw","digest","kind","ledgerId"].every((key)=>Object.hasOwn(value,key))||value.kind!==kind||value.digest!==digest||!DECIMAL.test(value.blockHeight)||typeof value.blockTimeRaw!=="string"||value.blockTimeRaw.length===0||!UUID.test(value.ledgerId))invalid();return Object.freeze({...value});}
export async function verifyAgentHandshakeV2Authorization({
  acceptanceEnvelope,descriptorEnvelope,evidence,expectedHostSessionKeyCertificateDigest,
  expectedPublicKey,expectedRepositorySha,expectedSessionId,expectedTerms,nowMs,
  proposalEnvelope,receipts,resolveRegistration,transitions,
}){
  let terms;try{terms=validateAgentHandshakeV2Terms(expectedTerms);}catch{invalid();}
  const proposal=await verifyAgentHandshakeV2Proposal({envelope:proposalEnvelope,expectedRepositorySha,expectedSessionId,expectedTerms:terms,nowMs});
  const acceptance=await verifyAgentHandshakeV2Acceptance({envelope:acceptanceEnvelope,proposalEnvelope,expectedRepositorySha,expectedSessionId,expectedTerms:terms,nowMs});
  let descriptor,chain;try{descriptor=verifyAgentHandshakeV2DescriptorEnvelope(descriptorEnvelope,{expectedHostSessionKeyCertificateDigest,expectedPublicKey}).descriptor;chain=validateAgentHandshakeV2TransitionChain(transitions);}catch{invalid();}
  if(descriptor.sessionId!==expectedSessionId||descriptor.repositorySha!==expectedRepositorySha||descriptor.reference!==terms.reference||descriptor.statementDigest!==proposal.payload.statementDigest||descriptor.agreementExpiresAtMs!==proposal.payload.expiresAtMs||agentHandshakeV2DescriptorDigest(descriptor)!==chain[0].sessionDigest||!canonicalBytes(descriptor.initiator).equals(canonicalBytes(proposal.payload.initiator))||!canonicalBytes(descriptor.responder).equals(canonicalBytes(proposal.payload.responder))||acceptance.payload.proposalDigest===undefined)invalid();
  const parties={initiator:descriptor.initiator,responder:descriptor.responder};
  if(parties.initiator.sessionKeyAddress===parties.responder.sessionKeyAddress||parties.initiator.policyDigest===parties.responder.policyDigest)invalid();
  if(terms.identityPolicy.erc8004!=="not_required"){
    if(parties.initiator.erc8004.agentId===parties.responder.erc8004.agentId||typeof resolveRegistration!=="function")invalid();
    for(const role of ["initiator","responder"]){
      let resolved;try{resolved=await resolveRegistration(parties[role].erc8004.agentId);}catch{invalid();}
      if(resolved?.owner!==parties[role].sessionKeyAddress||resolved.registrationBlock!==parties[role].erc8004.registrationBlock||!DECIMAL.test(resolved.registrationBlock)||(terms.identityPolicy.erc8004==="required_fresh"&&BigInt(resolved.registrationBlock)<=BigInt(descriptor.sessionOpenedBlock)))invalid();
    }
  }
  const transitionDigests=chain.map(agentHandshakeV2TransitionDigest);
  if(!Array.isArray(receipts)||receipts.length!==3)invalid();
  const verifiedReceipts=receipts.map((entry,index)=>receipt(entry,["proposal","acceptance","acknowledgment"][index],transitionDigests[index]));
  if(BigInt(verifiedReceipts[0].blockHeight)>=BigInt(verifiedReceipts[1].blockHeight)||BigInt(verifiedReceipts[1].blockHeight)>=BigInt(verifiedReceipts[2].blockHeight))invalid();
  for(const role of ["initiator","responder"]){
    try{await verifyAgentHandshakeV2Evidence({envelope:evidence?.[role],expectedParty:parties[role],expectedPolicyDigest:parties[role].policyDigest,expectedReference:terms.reference,expectedRepositorySha,expectedRole:role,expectedSessionDigest:chain[0].sessionDigest,expectedStatementDigest:chain[0].statementDigest,expectedTransitionDigests:transitionDigests,identityPolicy:terms.identityPolicy});}catch{invalid();}
  }
  if(!DIGEST.test(expectedHostSessionKeyCertificateDigest))invalid();
  return Object.freeze({
    externalBusinessActionPerformed:false,
    hostSessionKeyCertificateDigest:expectedHostSessionKeyCertificateDigest,
    identityPolicy:terms.identityPolicy,
    outcome:"VERIFIED",
    policyDigests:Object.freeze({initiator:parties.initiator.policyDigest,responder:parties.responder.policyDigest}),
    reference:terms.reference,
    sessionDigest:chain[0].sessionDigest,
    statementDigest:chain[0].statementDigest,
    transitions:Object.freeze(verifiedReceipts),
  });
}
