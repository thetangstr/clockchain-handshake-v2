import { recoverMessageAddress } from "viem";
import { types } from "node:util";

import { canonicalBytes, digestHex } from "../../core/canonical.mjs";
import { AGENT_HANDSHAKE_V2_PROTOCOL } from "./constants.mjs";
import { validateAgentHandshakeV2Party } from "./party.mjs";
import { agentHandshakeV2StatementDigest, validateAgentHandshakeV2Terms, validateIdentityPolicy } from "./terms.mjs";

export const AGENT_HANDSHAKE_V2_PROPOSAL_SCHEMA = "clockchain.agent-handshake-proposal/v2";
export const AGENT_HANDSHAKE_V2_ACCEPTANCE_SCHEMA = "clockchain.agent-handshake-acceptance/v2";
export const AGENT_HANDSHAKE_V2_TRANSITION_SCHEMA = "clockchain.agent-handshake-transition/v2";
const PROPOSAL_KEYS = Object.freeze(["schema","protocol","sessionId","repositorySha","reference","statementDigest","identityPolicy","initiator","responder","issuedAtMs","expiresAtMs","externalBusinessActionPerformed"]);
const ACCEPTANCE_KEYS = Object.freeze(["schema","protocol","sessionId","repositorySha","reference","statementDigest","identityPolicy","initiator","responder","proposalDigest","decision","issuedAtMs","expiresAtMs","externalBusinessActionPerformed"]);
const SIGNATURE_KEYS = Object.freeze(["address","algorithm","value"]);
const ENVELOPE_KEYS = Object.freeze(["payload","schema","signature"]);
const TRANSITION_KEYS = Object.freeze(["expiresAtMs","externalBusinessActionPerformed","initiator","kind","predecessor","protocol","reference","responder","schema","sequence","sessionDigest","statementDigest"]);
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const SHA=/^[0-9a-f]{40}$/;
const DIGEST=/^[0-9a-f]{64}$/;
const DECIMAL=/^(?:0|[1-9][0-9]*)$/;
const SIGNATURE=/^0x[0-9a-f]{130}$/;
export class AgentHandshakeV2ProtocolError extends Error {
  constructor(){super("Agent handshake v2 protocol verification failed.");this.name="AgentHandshakeV2ProtocolError";this.category="verification";this.code="AGENT_HANDSHAKE_V2_PROTOCOL_INVALID";}
}
function invalid(){throw new AgentHandshakeV2ProtocolError();}
function exact(value,keys){try{if(value===null||typeof value!=="object"||Array.isArray(value)||types.isProxy(value)||![Object.prototype,null].includes(Object.getPrototypeOf(value)))invalid();const actual=Reflect.ownKeys(value);if(actual.length!==keys.length||actual.some((key)=>typeof key!=="string"||!keys.includes(key)))invalid();const result={};for(const key of keys){const property=Object.getOwnPropertyDescriptor(value,key);if(property?.enumerable!==true||!Object.hasOwn(property,"value"))invalid();result[key]=property.value;}return result;}catch(error){if(error instanceof AgentHandshakeV2ProtocolError)throw error;invalid();}}
function same(a,b){return canonicalBytes(a).equals(canonicalBytes(b));}
function basePayload(value,keys,schema){
  const item=exact(value,keys);
  let policy,initiator,responder;
  try{policy=validateIdentityPolicy(item.identityPolicy);initiator=validateAgentHandshakeV2Party(item.initiator,{identityPolicy:policy});responder=validateAgentHandshakeV2Party(item.responder,{identityPolicy:policy});}catch{invalid();}
  if(item.schema!==schema||item.protocol!==AGENT_HANDSHAKE_V2_PROTOCOL||!UUID.test(item.sessionId)||!SHA.test(item.repositorySha)||typeof item.reference!=="string"||item.reference.length<1||item.reference.length>128||!DIGEST.test(item.statementDigest)||!DECIMAL.test(item.issuedAtMs)||!DECIMAL.test(item.expiresAtMs)||BigInt(item.issuedAtMs)>=BigInt(item.expiresAtMs)||item.externalBusinessActionPerformed!==false||initiator.sessionKeyAddress===responder.sessionKeyAddress||initiator.policyDigest===responder.policyDigest)invalid();
  if(policy.erc8004!=="not_required"&&initiator.erc8004.agentId===responder.erc8004.agentId)invalid();
  return {...item,identityPolicy:policy,initiator,responder};
}
function proposal(value){return Object.freeze(basePayload(value,PROPOSAL_KEYS,AGENT_HANDSHAKE_V2_PROPOSAL_SCHEMA));}
function acceptance(value){
  const item=basePayload(value,ACCEPTANCE_KEYS,AGENT_HANDSHAKE_V2_ACCEPTANCE_SCHEMA);
  if(!DIGEST.test(item.proposalDigest)||item.decision!=="ACCEPTED")invalid();
  return Object.freeze(item);
}
export function validateAgentHandshakeV2ProposalPayload(value){return proposal(value);}
export function validateAgentHandshakeV2AcceptancePayload(value){return acceptance(value);}
function signature(value){const item=exact(value,SIGNATURE_KEYS);if(!/^0x[0-9a-f]{40}$/.test(item.address)||item.algorithm!=="eip191"||!SIGNATURE.test(item.value))invalid();return Object.freeze(item);}
function signedEnvelope(value,type){const item=exact(value,ENVELOPE_KEYS);const payload=type==="proposal"?proposal(item.payload):acceptance(item.payload);const expectedSchema="clockchain.agent-handshake-"+type+"-envelope/v2";if(item.schema!==expectedSchema)invalid();return Object.freeze({payload,schema:item.schema,signature:signature(item.signature)});}
async function recover(payload,value){try{return (await recoverMessageAddress({message:{raw:canonicalBytes(payload)},signature:value})).toLowerCase();}catch{invalid();}}
export async function signAgentHandshakeV2Proposal({proposal:value,signMessage}){const payload=proposal(value);if(typeof signMessage!=="function")invalid();let valueSignature;try{valueSignature=await signMessage(canonicalBytes(payload));}catch{invalid();}return signedEnvelope({payload,schema:"clockchain.agent-handshake-proposal-envelope/v2",signature:{address:payload.initiator.sessionKeyAddress,algorithm:"eip191",value:valueSignature}},"proposal");}
export function agentHandshakeV2ProposalDigest(value){return digestHex(signedEnvelope(value,"proposal").payload);}
export async function verifyAgentHandshakeV2Proposal({envelope,expectedTerms,expectedSessionId,expectedRepositorySha,nowMs}){
  const verified=signedEnvelope(envelope,"proposal");let terms;try{terms=validateAgentHandshakeV2Terms(expectedTerms);}catch{invalid();}
  if(!Number.isSafeInteger(nowMs)||verified.payload.sessionId!==expectedSessionId||verified.payload.repositorySha!==expectedRepositorySha||verified.payload.reference!==terms.reference||verified.payload.statementDigest!==agentHandshakeV2StatementDigest(terms)||!same(verified.payload.identityPolicy,terms.identityPolicy)||BigInt(verified.payload.expiresAtMs)!==BigInt(verified.payload.issuedAtMs)+BigInt(terms.validForSeconds)*1000n||nowMs<Number(verified.payload.issuedAtMs)||nowMs>=Number(verified.payload.expiresAtMs)||verified.signature.address!==verified.payload.initiator.sessionKeyAddress||await recover(verified.payload,verified.signature.value)!==verified.payload.initiator.sessionKeyAddress)invalid();
  return verified;
}
export async function signAgentHandshakeV2Acceptance({acceptance:value,proposalEnvelope,signMessage}){
  const proposed=signedEnvelope(proposalEnvelope,"proposal");const payload=acceptance(value);
  if(payload.proposalDigest!==agentHandshakeV2ProposalDigest(proposed)||payload.sessionId!==proposed.payload.sessionId||payload.repositorySha!==proposed.payload.repositorySha||payload.reference!==proposed.payload.reference||payload.statementDigest!==proposed.payload.statementDigest||!same(payload.identityPolicy,proposed.payload.identityPolicy)||!same(payload.initiator,proposed.payload.initiator)||!same(payload.responder,proposed.payload.responder)||payload.expiresAtMs!==proposed.payload.expiresAtMs||BigInt(payload.issuedAtMs)<BigInt(proposed.payload.issuedAtMs)||typeof signMessage!=="function")invalid();
  let valueSignature;try{valueSignature=await signMessage(canonicalBytes(payload));}catch{invalid();}
  return signedEnvelope({payload,schema:"clockchain.agent-handshake-acceptance-envelope/v2",signature:{address:payload.responder.sessionKeyAddress,algorithm:"eip191",value:valueSignature}},"acceptance");
}
export async function verifyAgentHandshakeV2Acceptance({envelope,proposalEnvelope,expectedTerms,expectedSessionId,expectedRepositorySha,nowMs}){
  const proposed=await verifyAgentHandshakeV2Proposal({envelope:proposalEnvelope,expectedTerms,expectedSessionId,expectedRepositorySha,nowMs});const verified=signedEnvelope(envelope,"acceptance");
  if(verified.payload.proposalDigest!==agentHandshakeV2ProposalDigest(proposed)||verified.payload.sessionId!==proposed.payload.sessionId||verified.payload.expiresAtMs!==proposed.payload.expiresAtMs||!same(verified.payload.initiator,proposed.payload.initiator)||!same(verified.payload.responder,proposed.payload.responder)||nowMs<Number(verified.payload.issuedAtMs)||nowMs>=Number(verified.payload.expiresAtMs)||verified.signature.address!==verified.payload.responder.sessionKeyAddress||await recover(verified.payload,verified.signature.value)!==verified.payload.responder.sessionKeyAddress)invalid();
  return verified;
}
function transition(value){
  const item=exact(value,TRANSITION_KEYS);let initiator,responder;
  const policy=item.initiator?.erc8004===null?{erc8004:"not_required",chainId:null,registryAddress:null}:{erc8004:"required_existing_or_fresh",chainId:item.initiator?.erc8004?.chainId,registryAddress:item.initiator?.erc8004?.registryAddress};
  try{initiator=validateAgentHandshakeV2Party(item.initiator,{identityPolicy:policy});responder=validateAgentHandshakeV2Party(item.responder,{identityPolicy:policy});}catch{invalid();}
  if(item.schema!==AGENT_HANDSHAKE_V2_TRANSITION_SCHEMA||item.protocol!==AGENT_HANDSHAKE_V2_PROTOCOL||!["PROPOSED","ACCEPTED","ACKNOWLEDGED"].includes(item.kind)||!["1","2","3"].includes(item.sequence)||item.sequence!==String(["PROPOSED","ACCEPTED","ACKNOWLEDGED"].indexOf(item.kind)+1)||!DECIMAL.test(item.expiresAtMs)||!DIGEST.test(item.sessionDigest)||!DIGEST.test(item.statementDigest)||typeof item.reference!=="string"||item.reference.length===0||item.externalBusinessActionPerformed!==false||(item.sequence==="1"?item.predecessor!==null:!DIGEST.test(item.predecessor)))invalid();
  return Object.freeze({...item,initiator,responder});
}
function binding(input,kind,sequence,predecessor){return transition({expiresAtMs:input.expiresAtMs,externalBusinessActionPerformed:input.externalBusinessActionPerformed,initiator:input.initiator,kind,predecessor,protocol:AGENT_HANDSHAKE_V2_PROTOCOL,reference:input.reference,responder:input.responder,schema:AGENT_HANDSHAKE_V2_TRANSITION_SCHEMA,sequence,sessionDigest:input.sessionDigest,statementDigest:input.statementDigest});}
export function createAgentHandshakeV2Proposal(input){return binding(input,"PROPOSED","1",null);}
export function agentHandshakeV2TransitionDigest(value){return digestHex(transition(value));}
function assertPrevious(input,previous,kind){const verified=transition(previous);if(verified.kind!==kind||input.predecessor!==agentHandshakeV2TransitionDigest(verified)||input.expiresAtMs!==verified.expiresAtMs||input.reference!==verified.reference||input.sessionDigest!==verified.sessionDigest||input.statementDigest!==verified.statementDigest||!same(input.initiator,verified.initiator)||!same(input.responder,verified.responder))invalid();return verified;}
export function createAgentHandshakeV2Acceptance(input,proposed){assertPrevious(input,proposed,"PROPOSED");return binding(input,"ACCEPTED","2",input.predecessor);}
export function createAgentHandshakeV2Acknowledgment(input,accepted){assertPrevious(input,accepted,"ACCEPTED");return binding(input,"ACKNOWLEDGED","3",input.predecessor);}
export function validateAgentHandshakeV2TransitionChain(value){if(!Array.isArray(value)||value.length!==3)invalid();const transitions=value.map(transition);if(transitions[0].kind!=="PROPOSED"||transitions[1].kind!=="ACCEPTED"||transitions[2].kind!=="ACKNOWLEDGED"||transitions[1].predecessor!==agentHandshakeV2TransitionDigest(transitions[0])||transitions[2].predecessor!==agentHandshakeV2TransitionDigest(transitions[1]))invalid();for(const later of transitions.slice(1)){for(const key of ["expiresAtMs","reference","sessionDigest","statementDigest"]){if(later[key]!==transitions[0][key])invalid();}if(!same(later.initiator,transitions[0].initiator)||!same(later.responder,transitions[0].responder))invalid();}return Object.freeze(transitions);}
