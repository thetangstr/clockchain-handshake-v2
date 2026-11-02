import { generateKeyPairSync, randomUUID, sign as signBytes } from "node:crypto";

import {
  createPublicClient,
  createWalletClient,
  http,
  parseEther,
} from "viem";
import { sepolia } from "viem/chains";

import * as relay from "../../relay/client.mjs";
import { retryBeforeStop } from "../../relay/client.mjs";
import { RelayError } from "../../relay/errors.mjs";
import { RPC_URL } from "../../core/constants.mjs";
import { openFundingWallet } from "../../core/funding/wallet.mjs";
import { ERC8004_ABI } from "../../core/registration.mjs";
import { awaitRoleMessages, SessionEnded } from "../../roles/host.mjs";
import { postNext } from "../../roles/session.mjs";
import {
  createFileFundingBudgetStore,
  createFundingBudget,
} from "./funding-budget.mjs";
import { agentHandshakeV2DescriptorDigest } from "./descriptor.mjs";
import { createHostSessionKeyCertificate, rawEd25519PublicKey } from "./host-key-certificate.mjs";
import { monotonicClock } from "./clock.mjs";
import { loadHostRoot } from "./host-root.mjs";
import { verifyAgentHandshakeV2IdentityClaimEnvelope } from "./identity-claim.mjs";
import {
  AGENT_HANDSHAKE_V2_SENDER_ENROLLMENT_KIND,
  createRelayAuthorization,
  createSenderBindings,
  validateCoordinatorKeyRing,
} from "./relay-enrollment.mjs";
import {
  agentHandshakeV2StatementDigest,
  validateAgentHandshakeV2Terms,
} from "./terms.mjs";
import { createAgentHandshakeV2Monitor } from "../../monitor/agent-snapshot-v2-producer.mjs";

const DEFAULT_RELAY = "http://44.249.47.220:8080";
const DEFAULT_REPOSITORY = "https://github.com/thetangstr/clockchain-handshake-v2.git";
const SESSION_MILLISECONDS = 10 * 60_000;
// invitationExpiresAtMs is the MINT cutoff: the session stops accepting new
// invitations then and an unclaimed session rotates. The responder's claim
// window is mint-relative (the coordinator publishes it as claimExpiresAtMs
// on agent_v2_invitation_created), so the claim wait below extends its bound
// to the minted expiry once that message is observed — a claim still can
// never outlive the host's observation, but a late-window mint keeps its
// full runway instead of inheriting only the remaining slice.
const INVITATION_MILLISECONDS = 120_000;
// Older coordinators minted the claim window without publishing it (either
// mint-relative at +120s or pinned to the session invitation expiry); when an
// invitation_created carries no claimExpiresAtMs the host derives an upper
// bound from its createdAtMs so the observation window still covers whatever
// window that mint actually produced.
const LEGACY_INVITATION_CLAIM_WINDOW_MS = 120_000;
// The host observes a few seconds past the minted claim expiry so a claim
// accepted at the edge still lands while the relay log is being read; the
// claimedAtMs check inside awaitInvitationClaimed stays the authority on
// whether the claim was in-window.
const INVITATION_CLAIM_OBSERVE_GRACE_MS = 5_000;
// H-REQ-07: everything the host sends to the relay has a stop time, and no
// relay call starts at or after it or runs past it (retryBeforeStop):
//   - protocol messages (the descriptor, funding records): the session
//     deadline, the end of the host key's validity and, once known, the
//     agreement expiry, whichever comes first;
//   - the closing certificate, failure notices and snapshots: the session
//     deadline or the end of the host key's validity, whichever comes first.
//     They report on a session and move no agreement forward, so a notice
//     that a lapse ended the session still reaches the relay after the
//     agreement expiry.
// The certificate and snapshots also retry for at most their own budget.
const RESULT_PUBLICATION_RETRY_BUDGET_MS = 30_000;
const SNAPSHOT_PUBLICATION_RETRY_BUDGET_MS = 30_000;
const FUND = parseEther("0.01");
const REGISTRY_ADDRESS = "0x8004a818bfb912233c491871b3d84c89a494bd9e";
const REGISTERED_EVENT = ERC8004_ABI.find(
  (entry) => entry.type === "event" && entry.name === "Registered",
);
const DEFAULT_TERMS = Object.freeze({
  reference: "NS-1847",
  statement: "Northstar Logistics and Harbor Supply authorize these two independently controlled agents to communicate about shipment reference NS-1847 for 90 seconds.",
  validForSeconds: "90",
  identityPolicy: Object.freeze({
    erc8004: "required_fresh",
    chainId: "eip155:11155111",
    registryAddress: "0x8004a818bfb912233c491871b3d84c89a494bd9e",
  }),
});

// A host-side terminal failure the parties must hear about. `code` is the
// public reason the host publishes on the snapshot (failure.reasonCode) and on
// the relay log (agent_v2_session_failed), so both stakeholders get a prompt,
// explicit terminal state instead of polling an abandoned session until its
// deadline.
// `published` marks a failure whose terminal snapshot and notice the port
// already sent; the host runner must not re-publish it under another code.
export class AgentHandshakeV2SessionFailure extends Error {
  constructor(code, { cause, published = false } = {}) {
    super("Agent handshake v2 session failed.", cause === undefined ? undefined : { cause });
    this.name = "AgentHandshakeV2SessionFailure";
    this.code = code;
    this.published = published;
  }
}

export const AGENT_HANDSHAKE_V2_SESSION_FAILED_KIND = "agent_v2_session_failed";
// The relay is an unauthenticated mailbox, so the notice is signed with the
// host's per-session Ed25519 key (the key the root-signed host session-key
// certificate binds as sessionPublicKey). A reader must ignore an unsigned or
// mis-signed notice: otherwise anyone who knows a session id could end it.
export const AGENT_HANDSHAKE_V2_SESSION_FAILED_DOMAIN =
  "clockchain.agent-handshake-session-failed/v1";

export function agentHandshakeV2SessionFailedSigningBytes(sessionId, reasonCode) {
  return Buffer.from(
    `${AGENT_HANDSHAKE_V2_SESSION_FAILED_DOMAIN}\n${sessionId}\n${reasonCode}`,
    "utf8",
  );
}

// H-REQ-07: the fetch behind the funding transaction's JSON-RPC calls. No
// request starts once `timeLeft()` refuses or `stopSignal` has fired, and a
// request in flight, its response body included, is aborted when
// `stopSignal` fires. Either way the failure is an abort, which viem does not
// retry.
function fetchBeforeStop(timeLeft, stopSignal) {
  return async (url, init = {}) => {
    let open = !stopSignal.aborted;
    if (open) {
      try { timeLeft(); } catch { open = false; }
    }
    if (!open) throw new DOMException("The funding window has closed.", "AbortError");
    return fetch(url, {
      ...init,
      signal: init.signal ? AbortSignal.any([init.signal, stopSignal]) : stopSignal,
    });
  };
}

// A relay 4xx (other than 429 rate limiting) is a refusal, not a transient
// fault: retrying the same snapshot can never succeed.
export function isRelayRejection(error) {
  return error?.name === "RelayError" &&
    Number.isSafeInteger(error.status) &&
    error.status >= 400 &&
    error.status < 500 &&
    error.status !== 429;
}

// H-REQ-01: how the host treats relay role labels.
//   off      v1 behaviour: any correctly self-signed envelope speaks for the
//            role it names. The mode when AGENT_HANDSHAKE_V2_RELAY_BINDING is
//            unset; the host then logs one startup warning.
//   observe  the off behaviour with logging. It is not side-effect free: the
//            host consumes every message that enforce would refuse, exactly
//            as off does, and logs each message that the coordinator's sender
//            enrollments would not admit. The relay session is not opted in.
//   enforce  a role's message is consumed only when it is signed by the key
//            the coordinator enrolled for that role; the invitation's mint and
//            claim come from those enrollments; the relay session is opted in
//            to the same check.
// observe and enforce come only from an explicit value. An empty or unknown
// value fails at load, and so does a key ring that is configured but does not
// validate, whatever the mode.
export const AGENT_HANDSHAKE_V2_RELAY_BINDING_MODES = Object.freeze(["off", "observe", "enforce"]);
export const AGENT_HANDSHAKE_V2_RELAY_BINDING_VIOLATION_EVENT =
  "agent_handshake_v2_relay_binding_violation";
export const AGENT_HANDSHAKE_V2_RELAY_BINDING_DEFAULT_OFF_EVENT =
  "agent_handshake_v2_relay_binding_default_off";
const RELAY_BINDING_FAILURE_CODE = "AGENT_HANDSHAKE_V2_RELAY_BINDING_INVALID";
const PARTY_ROLES = Object.freeze(["initiator", "responder"]);

function relayBindingInvalid() {
  throw Object.assign(new Error(RELAY_BINDING_FAILURE_CODE), {
    code: RELAY_BINDING_FAILURE_CODE,
  });
}

// observe and enforce both need the coordinator key ring: without it no
// enrollment can be checked.
export function relayBindingConfiguration(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) relayBindingInvalid();
  if (!AGENT_HANDSHAKE_V2_RELAY_BINDING_MODES.includes(value.mode)) relayBindingInvalid();
  if (value.mode === "off") return Object.freeze({ mode: "off", coordinatorKeyRing: null });
  let coordinatorKeyRing;
  try {
    coordinatorKeyRing = validateCoordinatorKeyRing(value.coordinatorKeyRing);
  } catch {
    relayBindingInvalid();
  }
  return Object.freeze({ mode: value.mode, coordinatorKeyRing });
}

const defaultLog = (event) => console.warn(JSON.stringify(event));

export function relayBindingFromEnvironment(env = process.env, { log = defaultLog } = {}) {
  const unset = env.AGENT_HANDSHAKE_V2_RELAY_BINDING === undefined;
  const mode = unset ? "off" : env.AGENT_HANDSHAKE_V2_RELAY_BINDING;
  let coordinatorKeyRing = null;
  if (env.AGENT_HANDSHAKE_V2_COORDINATOR_KEYS !== undefined) {
    try {
      coordinatorKeyRing = validateCoordinatorKeyRing(
        JSON.parse(env.AGENT_HANDSHAKE_V2_COORDINATOR_KEYS),
      );
    } catch {
      relayBindingInvalid();
    }
  }
  const relayBinding = relayBindingConfiguration({ mode, coordinatorKeyRing });
  if (unset) {
    log({ event: AGENT_HANDSHAKE_V2_RELAY_BINDING_DEFAULT_OFF_EVENT, mode: relayBinding.mode });
  }
  return relayBinding;
}

function termsFromEnvironment(env) {
  if (!env.AGENT_HANDSHAKE_V2_TERMS) return DEFAULT_TERMS;
  let parsed;
  try { parsed = JSON.parse(env.AGENT_HANDSHAKE_V2_TERMS); } catch { throw new Error("AGENT_HANDSHAKE_V2_TERMS_INVALID"); }
  return validateAgentHandshakeV2Terms(parsed);
}

function positiveInteger(value, fallback) {
  const parsed = Number(value ?? fallback);
  if (!Number.isSafeInteger(parsed) || parsed < 1) {
    throw new Error("AGENT_HANDSHAKE_V2_FUNDING_CONFIGURATION_INVALID");
  }
  return parsed;
}

function fundingAlertCents(value, fallback) {
  const parsed = Number(value ?? fallback);
  const cents = Math.round(parsed * 100);
  if (!Number.isFinite(parsed) || parsed <= 0 || cents / 100 !== parsed) {
    throw new Error("AGENT_HANDSHAKE_V2_FUNDING_CONFIGURATION_INVALID");
  }
  return cents;
}

export async function loadAgentHandshakeV2Session({
  env = process.env,
  loadRoot = loadHostRoot,
  log = defaultLog,
  now = Date.now,
  publicClient: publicClientOverride,
  relayClient = relay,
  // A referenced timer: a creation retry's backoff keeps the process alive.
  sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
} = {}) {
  const repositorySha = env.HANDSHAKE_SHA;
  if (typeof repositorySha !== "string" || !/^[0-9a-f]{40}$/.test(repositorySha)) {
    throw new Error("HANDSHAKE_SHA_INVALID");
  }
  const relayBinding = relayBindingFromEnvironment(env, { log });
  const root = await loadRoot({ env });
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const privateKeyPem = privateKey.export({ format: "pem", type: "pkcs8" });
  const expectedPublicKey = rawEd25519PublicKey(publicKey);
  const sessionId = randomUUID();
  // H-REQ-07: the publication clock is established when the session window
  // opens. Every later stop-time decision for this session reads it, in the
  // ports too; a read that goes backwards throws.
  let publicationClock;
  let sessionOpenedAtMs;
  try {
    publicationClock = monotonicClock(now);
    sessionOpenedAtMs = publicationClock.read();
  } catch {
    throw new Error("HANDSHAKE_CLOCK_INVALID");
  }
  const sessionDeadlineMs = sessionOpenedAtMs + SESSION_MILLISECONDS;
  const invitationExpiresAtMs = sessionOpenedAtMs + INVITATION_MILLISECONDS;
  const hostSessionKeyCertificate = createHostSessionKeyCertificate({
    certificate: {
      schema: "clockchain.host-session-key/v1",
      rootKid: root.keyId,
      sessionId,
      repositorySha,
      sessionPublicKey: expectedPublicKey,
      validFromMs: String(sessionOpenedAtMs),
      validUntilMs: String(sessionDeadlineMs),
    },
    root,
  });
  const relayUrl = env.HANDSHAKE_RELAY ?? DEFAULT_RELAY;
  const terms = termsFromEnvironment(env);
  const publicClient = publicClientOverride ?? createPublicClient({
    chain: sepolia,
    transport: http(env.SEPOLIA_RPC_URL ?? RPC_URL),
  });
  const sessionOpenedBlock = String(await publicClient.getBlockNumber());
  // The session is published only while its invitation window is open, which
  // closes before the session deadline and the end of the host key's
  // validity. The block-number read can be slow: once the window has closed
  // the session is not published and ends as an unclaimed one does, so the
  // supervisor starts a fresh session.
  const publicationStopMs = Math.min(
    invitationExpiresAtMs,
    sessionDeadlineMs,
    Number(hostSessionKeyCertificate.certificate.validUntilMs),
  );
  if (!(publicationClock.read() < publicationStopMs)) {
    throw new SessionEnded("EXPIRED", "The invitation window closed before the session was published.");
  }
  const discovery = Object.freeze({
    schema: "clockchain.agent-handshake-discovery/v2",
    protocol: "clockchain.agent-handshake/v2",
    sessionId,
    repositorySha,
    kitRepoUrl: env.HANDSHAKE_KIT_REPO ?? DEFAULT_REPOSITORY,
    relayUrl,
    createdAtMs: String(sessionOpenedAtMs),
    invitationExpiresAtMs: String(invitationExpiresAtMs),
    sessionDeadlineMs: String(sessionDeadlineMs),
    sessionOpenedBlock,
    hostSessionKeyCertificate,
    externalBusinessActionPerformed: false,
    terms,
  });
  // The key this host signs its relay messages with. In enforce mode the
  // relay session is opted in to sender binding with it and the coordinator
  // key ring; the discovery document is unchanged.
  const relayEnvelopeKey = (relayClient.generateEnvelopeKeyPair ?? relay.generateEnvelopeKeyPair)();
  const relayAuthorization = relayBinding.mode === "enforce"
    ? createRelayAuthorization({
      coordinatorKeyRing: relayBinding.coordinatorKeyRing,
      hostSenderKey: relayEnvelopeKey.senderKey,
    })
    : undefined;
  // One bounded attempt at a time, none at or after the stop time.
  await retryBeforeStop({ clock: publicationClock, sleep, stopAtMs: publicationStopMs }, (timeLeft) =>
    relayClient.createSession({
      relayUrl,
      sessionId,
      discovery,
      ...(relayAuthorization === undefined ? {} : { relayAuthorization }),
      retryBudgetMs: 0,
      timeoutMs: timeLeft(),
    }));
  return Object.freeze({
    expectedPublicKey,
    hostSessionKeyCertificate,
    invitationExpiresAtMs,
    keyId: env.AGENT_HANDSHAKE_V2_KEY_ID ?? "session-host",
    privateKeyPem,
    protocol: "clockchain.agent-handshake/v2",
    publicationClock,
    relayBinding,
    relayEnvelopeKey,
    relayUrl,
    repositorySha,
    sessionDeadlineMs,
    sessionId,
    sessionOpenedAtMs,
    sessionOpenedBlock,
    terms,
  });
}

export async function createAgentHandshakeV2HostPorts(_session, overrides = {}) {
  const session = _session;
  const relayClient = overrides.relayClient ?? relay;
  const publicClient = overrides.publicClient ?? createPublicClient({
    chain: sepolia,
    transport: http(process.env.SEPOLIA_RPC_URL ?? RPC_URL),
  });
  const log = overrides.log ?? defaultLog;
  const relayBinding = overrides.relayBinding !== undefined
    ? relayBindingConfiguration(overrides.relayBinding)
    : session.relayBinding !== undefined
      ? relayBindingConfiguration(session.relayBinding)
      : relayBindingFromEnvironment(process.env, { log });
  const enforcing = relayBinding.mode === "enforce";
  const envelopeKey = session.relayEnvelopeKey ??
    relayClient.generateEnvelopeKeyPair?.() ?? relay.generateEnvelopeKeyPair();
  const sleep = overrides.sleep ??
    ((ms) => new Promise((resolve) => setTimeout(resolve, ms)));
  // One clock for every publication stop time: the one the session window was
  // opened on, unless a clock is supplied. A read that goes backwards or is
  // not a safe integer throws, so publication fails closed.
  const publicationClock = overrides.now === undefined && session.publicationClock !== undefined
    ? session.publicationClock
    : monotonicClock(overrides.now ?? Date.now);
  const keyValidUntilMs = Number(session.hostSessionKeyCertificate?.certificate?.validUntilMs);
  let agreementExpiresAtMs = null;
  const reportStopMs = () => Math.min(session.sessionDeadlineMs, keyValidUntilMs);
  const protocolStopMs = () => agreementExpiresAtMs === null
    ? reportStopMs()
    : Math.min(reportStopMs(), agreementExpiresAtMs);
  const publicationUnavailable = (lastError) => new RelayError(
    "The relay could not be reached within the wait budget.",
    "RENDEZVOUS_UNAVAILABLE",
    { status: 0, detail: { lastError } },
  );
  let bindings = null;
  if (relayBinding.mode !== "off") {
    try {
      bindings = createSenderBindings({
        coordinatorKeyRing: relayBinding.coordinatorKeyRing,
        now: overrides.now ?? Date.now,
        sessionDeadlineMs: session.sessionDeadlineMs,
        sessionId: session.sessionId,
        statementDigest: agentHandshakeV2StatementDigest(session.terms),
      });
    } catch {
      relayBindingInvalid();
    }
  }
  const relayBindingFailure = () =>
    new AgentHandshakeV2SessionFailure(RELAY_BINDING_FAILURE_CODE);
  // One log line per relay position and reason, however often the deferred
  // buffer is reconsidered.
  const reportedViolations = new Set();
  const bindingViolation = (message, reason) => {
    const seq = typeof message?.seq === "string" ? message.seq : null;
    const key = `${seq}:${reason}`;
    if (reportedViolations.has(key)) return;
    reportedViolations.add(key);
    log({
      event: AGENT_HANDSHAKE_V2_RELAY_BINDING_VIOLATION_EVENT,
      action: enforcing ? "refused" : "observed",
      kind: typeof message?.kind === "string" ? message.kind : null,
      mode: relayBinding.mode,
      reason,
      role: typeof message?.role === "string" ? message.role : null,
      seq,
      sessionId: session.sessionId,
    });
  };
  // Every message is shown to the bindings as it is considered, so sender
  // enrollments are learned in relay order. A second valid enrollment for a
  // role, or two roles enrolled for different invitations, ends the session
  // in enforce mode.
  const observeMessage = bindings === null ? null : (message) => {
    const outcome = bindings.observe(message);
    if (outcome?.status === "refused") {
      bindingViolation(message, outcome.reason);
      if (outcome.fatal && enforcing) throw relayBindingFailure();
      return;
    }
    if (
      outcome === null && !enforcing &&
      PARTY_ROLES.includes(message?.role) && !bindings.admits(message)
    ) bindingViolation(message, "BINDING_MISMATCH");
  };
  const admitMessage = !enforcing ? null : (message) => {
    if (bindings.admits(message)) return true;
    if (
      PARTY_ROLES.includes(message?.role) &&
      message?.kind !== AGENT_HANDSHAKE_V2_SENDER_ENROLLMENT_KIND
    ) bindingViolation(message, bindings.failure() ?? "BINDING_MISMATCH");
    return false;
  };
  const isBody = (body) =>
    body !== null && typeof body === "object" && !Array.isArray(body);
  // An invitation_created body must agree with the mint enrollment.
  const mintAgrees = (body, minted) =>
    (!Object.hasOwn(body, "claimExpiresAtMs") ||
      String(body.claimExpiresAtMs) === minted.claimExpiresAtMs) &&
    (!Object.hasOwn(body, "createdAtMs") ||
      String(body.createdAtMs) === minted.eventAtMs);

  let after = "0";
  let buffer = [];
  // The minted responder claim window. In enforce mode it is the
  // claimExpiresAtMs of the coordinator's mint enrollment, and the message
  // bodies are only cross-checked against it. Otherwise it is learned from
  // agent_v2_invitation_created on the session log (or derived from its
  // createdAtMs for coordinators that predate claimExpiresAtMs). Drives both
  // the extended observation bound below and the claimedAtMs validity check in
  // awaitInvitationClaimed.
  let mintedClaimExpMs = null;
  const extendClaimDeadline = (message) => {
    if (message?.role !== "initiator" || !isBody(message.body)) return null;
    let derived;
    if (enforcing) {
      if (
        message.kind !== "agent_v2_invitation_created" &&
        message.kind !== AGENT_HANDSHAKE_V2_SENDER_ENROLLMENT_KIND
      ) return null;
      const minted = bindings.enrollment("initiator");
      if (minted === null) return null;
      if (
        message.kind === "agent_v2_invitation_created" &&
        !mintAgrees(message.body, minted)
      ) throw relayBindingFailure();
      derived = Number(minted.claimExpiresAtMs);
    } else {
      if (message.kind !== "agent_v2_invitation_created") return null;
      const explicit = Number(message.body.claimExpiresAtMs);
      const minted = Number(message.body.createdAtMs);
      derived = Number.isSafeInteger(explicit)
        ? explicit
        : Number.isSafeInteger(minted)
          ? minted + LEGACY_INVITATION_CLAIM_WINDOW_MS
          : null;
      const enrolled = bindings?.enrollment("initiator") ?? null;
      if (bindings !== null && (enrolled === null || !mintAgrees(message.body, enrolled))) {
        bindingViolation(message, "BINDING_MISMATCH");
      }
    }
    const openedMs = Number.isSafeInteger(session.sessionOpenedAtMs)
      ? session.sessionOpenedAtMs
      : 0;
    if (derived === null || derived <= openedMs) return null;
    mintedClaimExpMs = Math.min(derived, session.sessionDeadlineMs);
    return Math.min(
      session.sessionDeadlineMs,
      mintedClaimExpMs + INVITATION_CLAIM_OBSERVE_GRACE_MS,
    );
  };

  const defaultWaitForMessage = async (kind, role) => {
    // invitationExpiresAtMs is the mint cutoff, so it bounds only the START of
    // the claim wait: an unminted session exits and the supervisor rotates a
    // fresh "current" session. Once the invitation_created message is seen the
    // wait extends to the minted claim expiry, so a late-window mint still gets
    // its full responder runway; every later wait keeps the session deadline.
    const isClaimWait = kind === "agent_v2_invitation_claimed";
    const boundMs = isClaimWait &&
      Number.isSafeInteger(session.invitationExpiresAtMs)
      ? Math.min(session.sessionDeadlineMs, session.invitationExpiresAtMs)
      : session.sessionDeadlineMs;
    const result = await awaitRoleMessages({
      admit: admitMessage,
      after,
      buffer,
      budgetMs: Math.max(0, boundMs - Date.now()),
      expectedBindings: null,
      extendDeadline: isClaimWait ? extendClaimDeadline : null,
      kind,
      observe: observeMessage,
      relayClient,
      relayUrl: session.relayUrl,
      roles: [role],
      sessionId: session.sessionId,
      waitMs: 20_000,
    });
    after = result.after;
    buffer = result.buffer;
    const message = result.messages[role];
    // In enforce mode the envelope is checked against the key enrolled for
    // its role, not the key it names.
    const verifyOptions = enforcing
      ? { expectedSenderKey: bindings.enrollment(role)?.senderKey ?? null }
      : undefined;
    if (relayClient.verifyEnvelope(message, verifyOptions) !== true) {
      throw new Error("AGENT_HANDSHAKE_V2_RELAY_ENVELOPE_INVALID");
    }
    if (enforcing && bindings.admits(message) !== true) throw relayBindingFailure();
    return message;
  };
  const waitForMessage = overrides.waitForMessage ?? defaultWaitForMessage;
  // Sends a host message only before stopAtMs (H-REQ-07).
  const postHostMessage = overrides.postHostMessage ?? ((kind, body, stopAtMs) =>
    postNext(relayClient, {
      body,
      clock: publicationClock,
      keyPair: envelopeKey,
      kind,
      relayUrl: session.relayUrl,
      role: "host",
      sessionId: session.sessionId,
      sleep,
      stopAtMs,
    }));
  // Tell both parties, on the session's relay log, that the host has ended
  // this session and why. Best effort and at most once: the failure is also on
  // the snapshot, and a relay that refuses this post cannot be helped here.
  let sessionFailureNotified = false;
  const notifySessionFailed = async (reasonCode) => {
    if (sessionFailureNotified) return;
    sessionFailureNotified = true;
    try {
      const sessionSignature = signBytes(
        null,
        agentHandshakeV2SessionFailedSigningBytes(session.sessionId, reasonCode),
        session.privateKeyPem,
      ).toString("base64");
      await postHostMessage(AGENT_HANDSHAKE_V2_SESSION_FAILED_KIND, {
        externalBusinessActionPerformed: false,
        reasonCode,
        sessionSignature,
      }, reportStopMs());
    } catch (error) {
      log({
        event: "agent_handshake_v2_session_failed_notice_unpublished",
        reasonCode,
        relayCode: typeof error?.code === "string" ? error.code : null,
        sessionId: session.sessionId,
      });
    }
  };
  const rawMonitor = overrides.monitor ?? createAgentHandshakeV2Monitor({
    now: overrides.now ?? Date.now,
    publish: (snapshot) => retryBeforeStop({
      clock: publicationClock,
      sleep,
      stopAtMs: Math.min(
        reportStopMs(),
        publicationClock.read() + SNAPSHOT_PUBLICATION_RETRY_BUDGET_MS,
      ),
    }, (timeLeft) => relayClient.putSnapshot({
      relayUrl: session.relayUrl,
      retryBudgetMs: 0,
      sessionId: session.sessionId,
      snapshot,
      timeoutMs: timeLeft(),
    })),
    session,
  });
  // Any relay 4xx on a snapshot PUT ends the session visibly: log it, publish
  // the failure on top of the last snapshot the relay accepted, notify both
  // parties, and stop with an explicit error. Without this the host process
  // died on the rejection and both parties long-polled an abandoned session
  // until its 10-minute deadline (production P8, 2026-10-07).
  let snapshotRejected = false;
  const handleSnapshotRejection = async (error) => {
    const reasonCode = "AGENT_HANDSHAKE_V2_SNAPSHOT_REJECTED";
    if (!snapshotRejected) {
      snapshotRejected = true;
      log({
        event: "agent_handshake_v2_snapshot_rejected",
        relayCode: typeof error?.code === "string" ? error.code : null,
        relayStatus: error?.status ?? null,
        sessionId: session.sessionId,
      });
      if (typeof rawMonitor.failedAfterRejection === "function") {
        try {
          await rawMonitor.failedAfterRejection(reasonCode);
        } catch (failure) {
          log({
            event: "agent_handshake_v2_failure_snapshot_unpublished",
            relayCode: typeof failure?.code === "string" ? failure.code : null,
            sessionId: session.sessionId,
          });
        }
      }
      await notifySessionFailed(reasonCode);
    }
    throw new AgentHandshakeV2SessionFailure(reasonCode, { cause: error, published: true });
  };
  const monitor = Object.freeze(Object.fromEntries(
    Object.entries(rawMonitor).map(([name, method]) => [
      name,
      typeof method !== "function" ? method : async (...args) => {
        try {
          return await method(...args);
        } catch (error) {
          if (isRelayRejection(error)) return handleSnapshotRejection(error);
          throw error;
        }
      },
    ]),
  ));

  const store = overrides.fundingStore ?? createFileFundingBudgetStore({
    path: process.env.AGENT_HANDSHAKE_V2_FUNDING_LEDGER ??
      "/var/lib/clockchain/private/v2-funding-ledger.jsonl",
  });
  const fundingBudget = overrides.fundingBudget ?? createFundingBudget({
    ...store,
    alertDayCents: fundingAlertCents(
      process.env.AGENT_HANDSHAKE_V2_FUNDING_ALERT_DAILY_ETH,
      "0.80",
    ),
    alertHourCents: fundingAlertCents(
      process.env.AGENT_HANDSHAKE_V2_FUNDING_ALERT_HOURLY_ETH,
      "0.16",
    ),
    onAlert: (usage) => console.warn(JSON.stringify({
      event: "agent_handshake_v2_funding_budget_alert",
      ...usage,
    })),
    queueLimit: positiveInteger(
      process.env.AGENT_HANDSHAKE_V2_FUNDING_QUEUE_LIMIT,
      "16",
    ),
  });
  // H-REQ-07: funding stops at the protocol stop time. The clock is read again
  // after the funding wallet opens (file reads and key derivation), before the
  // transaction is signed and before it is broadcast. The transaction's RPC
  // calls, their retries and the receipt wait all end by the stop time, and
  // nothing is sent once it has passed.
  const fundingTimeLeft = () => {
    const leftMs = protocolStopMs() - publicationClock.read();
    if (!(leftMs > 0)) throw publicationUnavailable(null);
    return leftMs;
  };
  // One funding step, settled by the stop time. At the stop time the step
  // fails as unreachable and the RPC requests still in flight are aborted,
  // response bodies included. A step that fails once the stop time has passed
  // fails for that reason.
  const fundingStep = (run) => new Promise((resolve, reject) => {
    const stop = new AbortController();
    const timer = setTimeout(() => {
      reject(publicationUnavailable(null));
      stop.abort();
    }, fundingTimeLeft());
    Promise.resolve()
      .then(() => run(stop.signal))
      .then(resolve, reject)
      .finally(() => clearTimeout(timer));
  }).catch((error) => {
    fundingTimeLeft();
    throw error;
  });
  const openWallet = overrides.openFundingWallet ?? (() => openFundingWallet({
    keystorePath: process.env.CLOCKCHAIN_FUNDING_KEYSTORE ??
      "/var/lib/clockchain/private/funding-wallet.json",
  }));
  let walletPromise = null;
  const sendFundingTransaction = overrides.sendFundingTransaction ?? (async ({
    address,
    signal,
    timeLeft,
    value,
  }) => {
    walletPromise ??= openWallet();
    const treasury = await walletPromise;
    timeLeft();
    const wallet = createWalletClient({
      account: treasury.account,
      chain: sepolia,
      transport: http(process.env.SEPOLIA_RPC_URL ?? RPC_URL, {
        fetchFn: fetchBeforeStop(timeLeft, signal),
      }),
    });
    const request = await wallet.prepareTransactionRequest({ to: address, value });
    timeLeft();
    const serializedTransaction = await treasury.account.signTransaction(request, {
      serializer: sepolia.serializers?.transaction,
    });
    timeLeft();
    return wallet.sendRawTransaction({ serializedTransaction });
  });
  const defaultFundIdentity = async ({ address, role }) => {
    const hash = await fundingStep((signal) => sendFundingTransaction({
      address,
      signal,
      timeLeft: fundingTimeLeft,
      value: FUND,
    }));
    const receipt = await fundingStep(() => publicClient.waitForTransactionReceipt({
      hash,
      timeout: Math.min(180_000, fundingTimeLeft()),
    }));
    // The receipt wait can take minutes: the clock is read again before the
    // record is posted, and again before each relay call that posts it.
    const stopAtMs = protocolStopMs();
    if (!(publicationClock.read() < stopAtMs)) throw publicationUnavailable(null);
    await postHostMessage("agent_v2_funding_record", {
      address,
      amountEth: "0.01",
      blockNumber: String(receipt.blockNumber),
      externalBusinessActionPerformed: false,
      role,
      transactionHash: hash,
    }, stopAtMs);
  };

  const ownerOf = async (tokenId) => String(await publicClient.readContract({
    abi: ERC8004_ABI,
    address: REGISTRY_ADDRESS,
    args: [tokenId],
    functionName: "ownerOf",
  })).toLowerCase();

  // eth_getLogs providers cap the block range per call (the live RPC rejects
  // anything over 50,000), so the existing-identity scan walks the official
  // Registered event backwards from the head in inclusive chunks of at most
  // 50,000 blocks — newest first — all the way to genesis. There is no
  // recent-window cap: an identity minted long ago must still be found.
  const LOG_SCAN_CHUNK_BLOCKS = 50_000n;
  const defaultFindExistingIdentity = async (address) => {
    const owner = String(address).toLowerCase();
    let to = await publicClient.getBlockNumber();
    for (;;) {
      const from = to > LOG_SCAN_CHUNK_BLOCKS - 1n
        ? to - (LOG_SCAN_CHUNK_BLOCKS - 1n)
        : 0n;
      const logs = await publicClient.getLogs({
        address: REGISTRY_ADDRESS,
        args: { owner },
        event: REGISTERED_EVENT,
        fromBlock: from,
        toBlock: to,
      });
      for (const entry of [...logs].reverse()) {
        const agentId = entry.args?.agentId;
        const block = String(entry.blockNumber);
        if (agentId === undefined || !/^(?:0|[1-9][0-9]*)$/.test(block)) continue;
        // ownerOf can revert for a burned or otherwise unreadable token;
        // that candidate is simply not currently owned — keep scanning.
        let current;
        try {
          current = await ownerOf(agentId);
        } catch {
          continue;
        }
        if (current === owner) {
          return Object.freeze({
            agentId: String(agentId),
            owner,
            registrationBlock: block,
          });
        }
      }
      if (from === 0n) return null;
      to = from - 1n;
    }
  };
  // The caller supplies the party's claimed owner and registration block; the
  // claim is authoritative only if the exact block contains the official
  // Registered(agentId, owner) event and ownerOf still matches. No history
  // scan is needed — the claim pins the block — so the lookup stays inside
  // every provider's range limit.
  const defaultResolveRegistration = async (agentId, expected) => {
    const tokenId = BigInt(agentId);
    const owner = String(expected?.expectedOwner ?? "").toLowerCase();
    const block = String(expected?.registrationBlock ?? "");
    if (
      !/^0x[0-9a-f]{40}$/.test(owner) ||
      !/^(?:0|[1-9][0-9]*)$/.test(block)
    ) throw new Error("AGENT_HANDSHAKE_V2_REGISTRATION_MISSING");
    const height = BigInt(block);
    const logs = await publicClient.getLogs({
      address: REGISTRY_ADDRESS,
      args: { agentId: tokenId, owner },
      event: REGISTERED_EVENT,
      fromBlock: height,
      toBlock: height,
    });
    if (
      !logs.some((entry) =>
        entry.args?.agentId === tokenId &&
        String(entry.args?.owner).toLowerCase() === owner
      )
    ) throw new Error("AGENT_HANDSHAKE_V2_REGISTRATION_MISSING");
    if ((await ownerOf(tokenId)) !== owner) {
      throw new Error("AGENT_HANDSHAKE_V2_REGISTRATION_MISSING");
    }
    return Object.freeze({ owner, registrationBlock: block });
  };
  const defaultPublishResult = async (envelope) => {
    const resultKeyValidUntilMs = Number(envelope?.hostSessionKeyCertificate?.certificate?.validUntilMs);
    if (!Number.isSafeInteger(resultKeyValidUntilMs)) {
      throw new Error("AGENT_HANDSHAKE_V2_RESULT_INVALID");
    }
    // A clock that goes backwards stops publication instead of extending it.
    const stopAtMs = Math.min(
      session.sessionDeadlineMs,
      resultKeyValidUntilMs,
      publicationClock.read() + RESULT_PUBLICATION_RETRY_BUDGET_MS,
    );
    return retryBeforeStop({ clock: publicationClock, sleep, stopAtMs }, (timeLeft) =>
      relayClient.putResult({
        envelope,
        relayUrl: session.relayUrl,
        retryBudgetMs: 0,
        sessionId: session.sessionId,
        timeoutMs: timeLeft(),
      }));
  };
  const anchorReport = (message) => {
    const entries = message?.body?.transitions;
    if (!Array.isArray(entries) || entries.length !== 3) {
      throw new Error("AGENT_HANDSHAKE_V2_ANCHORS_INVALID");
    }
    return Object.freeze({
      receipts: Object.freeze(entries.map((entry, index) => Object.freeze({
        blockHeight: String(entry?.onChain?.blockHeight ?? ""),
        blockTimeRaw: String(entry?.blockTimeRaw ?? ""),
        digest: String(entry?.digest ?? ""),
        kind: ["proposal", "acceptance", "acknowledgment"][index],
        ledgerId: String(entry?.onChain?.ledgerId ?? ""),
      }))),
      transitions: Object.freeze(entries.map((entry) => entry.message)),
    });
  };

  return Object.freeze({
    awaitAcceptance: async () =>
      (await waitForMessage("agent_v2_acceptance", "responder")).body.acceptanceEnvelope,
    awaitAnchors: async () =>
      anchorReport(await waitForMessage("agent_v2_anchor_report", "initiator")),
    awaitEvidence: async (role) =>
      (await waitForMessage("agent_v2_evidence", role)).body.evidenceEnvelope,
    awaitInvitationClaimed: async () => {
      let message;
      try {
        message = await waitForMessage("agent_v2_invitation_claimed", "responder");
      } catch (error) {
        // An invitation was minted on this session but nobody claimed it in
        // its window: that is an explicit invitation expiry the initiator must
        // hear about. With no mint the session simply rotates, as before.
        if (mintedClaimExpMs !== null && error?.name === "SessionEnded") {
          throw new AgentHandshakeV2SessionFailure(
            "AGENT_HANDSHAKE_V2_INVITATION_EXPIRED",
            { cause: error },
          );
        }
        throw error;
      }
      const body = message.body;
      if (
        body === null || typeof body !== "object" || Array.isArray(body) ||
        Object.keys(body).sort().join(",") !==
          "claimedAtMs,externalBusinessActionPerformed" ||
        typeof body.claimedAtMs !== "string" ||
        !/^(?:0|[1-9][0-9]*)$/.test(body.claimedAtMs) ||
        body.externalBusinessActionPerformed !== false
      ) throw new Error("AGENT_HANDSHAKE_V2_INVITATION_CLAIM_INVALID");
      let claimedAtMs = Number(body.claimedAtMs);
      // The minted claim window is authoritative: a claim is in-window when it
      // lands before the expiry that mint published on invitation_created, not
      // the session's invitationExpiresAtMs (that is only the mint cutoff).
      let claimDeadlineMs = mintedClaimExpMs ?? session.invitationExpiresAtMs;
      const redeemed = bindings?.enrollment("responder") ?? null;
      if (enforcing) {
        // The claim time and window are the coordinator-signed redemption's;
        // the claim message body must agree with it.
        if (redeemed === null || body.claimedAtMs !== redeemed.eventAtMs) {
          throw relayBindingFailure();
        }
        claimedAtMs = Number(redeemed.eventAtMs);
        claimDeadlineMs = Math.min(
          Number(redeemed.claimExpiresAtMs),
          session.sessionDeadlineMs,
        );
      } else if (
        bindings !== null &&
        (redeemed === null || body.claimedAtMs !== redeemed.eventAtMs)
      ) {
        bindingViolation(message, "BINDING_MISMATCH");
      }
      if (
        !Number.isSafeInteger(claimedAtMs) ||
        claimedAtMs < session.sessionOpenedAtMs
      ) throw new Error("AGENT_HANDSHAKE_V2_INVITATION_CLAIM_INVALID");
      // A claim after the invitation's window is a clean, explicit expiry:
      // the host publishes it as a terminal state (never the late claim
      // itself) and both parties are told, instead of a stalled session.
      if (claimedAtMs >= claimDeadlineMs) {
        throw new AgentHandshakeV2SessionFailure("AGENT_HANDSHAKE_V2_INVITATION_EXPIRED");
      }
      await monitor.invitationClaimed(claimedAtMs);
      return claimedAtMs;
    },
    awaitIdentityClaim: async (role) => {
      const message = await waitForMessage("agent_v2_identity_claim", role);
      const verified = await verifyAgentHandshakeV2IdentityClaimEnvelope(
        message.body,
        {
          expectedRepositorySha: session.repositorySha,
          expectedRole: role,
          expectedSessionId: session.sessionId,
          expectedStatementDigest: agentHandshakeV2StatementDigest(session.terms),
        },
      );
      await monitor.identityClaimed(role, verified.claim);
      return Object.freeze({
        policyDigest: verified.claim.policyDigest,
        sessionKeyAddress: verified.claim.sessionKeyAddress,
      });
    },
    awaitPartyReady: async (role) =>
      (await waitForMessage("agent_v2_party_ready", role)).body,
    awaitProposal: async () =>
      (await waitForMessage("agent_v2_proposal", "initiator")).body.proposalEnvelope,
    findExistingIdentity:
      overrides.findExistingIdentity ?? defaultFindExistingIdentity,
    fundIdentity: overrides.fundIdentity ?? defaultFundIdentity,
    // The descriptor carries the agreement expiry; from here on it bounds
    // every protocol message, the descriptor included.
    publishDescriptor: async (descriptorEnvelope) => {
      const sessionDigest = agentHandshakeV2DescriptorDigest(descriptorEnvelope.descriptor);
      const expiresAtMs = Number(descriptorEnvelope.descriptor.agreementExpiresAtMs);
      agreementExpiresAtMs = agreementExpiresAtMs === null
        ? expiresAtMs
        : Math.min(agreementExpiresAtMs, expiresAtMs);
      return postHostMessage("agent_v2_handshake_required", {
        descriptorEnvelope,
        externalBusinessActionPerformed: false,
        sessionDigest,
      }, protocolStopMs());
    },
    publishResult: overrides.publishResult ?? defaultPublishResult,
    publishInitial: () => monitor.start(),
    partiesReady: (parties) => monitor.partiesReady(parties),
    proposalSigned: (envelope) => monitor.proposalSigned(envelope),
    acceptanceSigned: (envelope) => monitor.acceptanceSigned(envelope),
    anchorsRecorded: (report) => monitor.anchorsRecorded(report),
    evidenceReceived: (role, envelope) => monitor.evidenceReceived(role, envelope),
    checkerStage: (stage) => monitor.checkerStage(stage),
    failed: (reasonCode) => monitor.failed(reasonCode),
    notifySessionFailed,
    certificateIssued: (envelope) => monitor.certificateIssued(envelope),
    reserveFunding: (input) => fundingBudget.reserve(input),
    resolveRegistration:
      overrides.resolveRegistration ?? defaultResolveRegistration,
  });
}
