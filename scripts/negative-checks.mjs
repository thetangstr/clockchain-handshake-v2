#!/usr/bin/env node
/**
 * Negative checks: proof that the system fails closed, with named public
 * reasons, on the four attacks a skeptic asks about first.
 *
 *   a. REPLAY            a previous run's evidence offered against a fresh session
 *   b. REORDER           the anchors presented out of order (acceptance before proposal)
 *   c. TAMPER            one byte flipped in one party signature
 *   d. DUPLICATE FUNDING a funding record replayed through the funding journal
 *
 * Everything runs against fixtures and a stubbed Clockchain. No network, no
 * gas, no live identities. Run it with:
 *
 *   npm run negative
 *
 * The script prints case -> reason code -> pass/fail and exits non-zero if any
 * case fails to produce the reason code recorded here.
 *
 * WHAT THIS SCRIPT DELIBERATELY DOES NOT DO: it does not reach for a prettier
 * reason code than the code path actually produces. Where a case lands on the
 * generic catch-all, the row says so, and the notes below record why. Two
 * observations that a reader should not have to dig for:
 *
 *   - REORDERED, the frozen code whose name matches case (b), is never thrown.
 *     The only occurrences of the literal in src/ are the two monitor display
 *     maps; no code path raises it. Out-of-order evidence is caught one layer
 *     earlier, by the party-result schema, which pins transitions[i].message.kind
 *     to the i-th protocol kind, so case (b) reports MALFORMED. The order check
 *     that would own REORDERED belongs to src/verifier/, which is an empty
 *     directory today.
 *   - FUNDING_REPLAYED is likewise never thrown, and for the same reason: the
 *     literal appears only in the monitor display maps. The ported funding
 *     journal refuses the replay under its own prefixed internal namespace, and
 *     the journal is a byte-faithful pure port that must not be edited, so this
 *     script reports the code the journal actually raises.
 *
 * scripts/check-invariants.sh reports both codes as "emitted" because its grep
 * cannot tell a thrown code from a display label. That is a gap in that check,
 * not evidence that these two paths exist.
 */

import { createHash, generateKeyPairSync } from "node:crypto";
import { chmod, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { argv, exit, stdout } from "node:process";
import { fileURLToPath } from "node:url";

import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";

import { deadlineMs, liveUpperBoundMs } from "../src/core/blocktime.mjs";
import { McpNetworkError } from "../src/core/clockchain.mjs";
import {
  createSignedEnvelope,
  dSession,
  rawPublicKeyBase64FromPem,
} from "../src/core/descriptor.mjs";
import {
  PARTY_RESULT_SCHEMA,
  partySignatureBytes,
  writePartyResult,
} from "../src/core/evidence.mjs";
import { BilateralFundingError } from "../src/core/funding/record.mjs";
import {
  deriveFundingBatchId,
  openFundingJournal,
} from "../src/core/funding/journal.mjs";
import {
  authoritativeTriple,
  buildAcceptance,
  buildAcknowledgment,
  buildProposal,
  transitionDigest,
} from "../src/core/messages.mjs";
import {
  payerMandateDigest,
  signPayerMandate,
} from "../src/core/payer-mandate.mjs";
import {
  paymentRequestDigest,
  signPaymentRequest,
} from "../src/core/payment-request.mjs";
import { verifyTransition } from "../src/core/protocol.mjs";
import { sessionKey } from "../src/core/refid.mjs";
import {
  BilateralVerdictError,
  verifyBilateralAuthorization,
} from "../src/core/verdict.mjs";

import { createFakeBilateralClockchain } from "../test/helpers/fake-bilateral-clockchain.mjs";

const PAYER = privateKeyToAccount(generatePrivateKey());
const PAYEE = privateKeyToAccount(generatePrivateKey());
const REPOSITORY_SHA = "0123456789abcdef0123456789abcdef01234567";
const PROMPT_SHA256 =
  "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
const INTAKE_DIGEST = "b".repeat(64);
const INTAKE_REQUEST_ID = "22222222-3333-4444-8555-666666666666";

// Two independent sessions on one stubbed chain: run A is the completed prior
// run whose evidence the replay case reuses; run B is the fresh session.
const RUN_A = Object.freeze({
  descriptorSessionId: "00112233445566778899aabbccddeeff",
  intakeRequestId: INTAKE_REQUEST_ID,
  invoiceReference: "INV-0001",
  mandateSessionId: "00112233-4455-6677-8899-aabbccddeeff",
  requestId: "00000000-0000-4000-8000-000000000001",
});
const RUN_B = Object.freeze({
  descriptorSessionId: "ffeeddccbbaa99887766554433221100",
  intakeRequestId: "33333333-4444-4555-8666-777777777777",
  invoiceReference: "INV-0002",
  mandateSessionId: "ffeeddcc-bbaa-4998-8776-655443322110",
  requestId: "00000000-0000-4000-8000-000000000002",
});

// ---------------------------------------------------------------------------
// Fixture construction. Mirrors test/verdict.test.mjs completeFixture.
// ---------------------------------------------------------------------------

function descriptorFixture({ mandateDigest, requestDigest, sessionId }) {
  return {
    amountOptions: [
      { currency: "USD", value: "100" },
      { currency: "USD", value: "250" },
    ],
    chainId: "11155111",
    expirySeconds: "600",
    mandateDigest,
    namespace: "cbv1",
    payee: {
      address: PAYEE.address.toLowerCase(),
      agentId: "8678",
      displayName: "Iris",
      role: "payee",
    },
    payer: {
      address: PAYER.address.toLowerCase(),
      agentId: "8677",
      displayName: "Billy",
      role: "payer",
    },
    paymentMoved: false,
    promptSha256: PROMPT_SHA256,
    protocol: "clockchain.bilateral-authorization/v1",
    protocolVersion: "1",
    registry: "0x8004a818bfb912233c491871b3d84c89a494bd9e",
    repositorySha: REPOSITORY_SHA,
    requestDigest,
    schema: "clockchain.bilateral-session-descriptor/v2",
    sessionId,
    settlement: "not-executed",
  };
}

async function intentEnvelopes(run) {
  const mandate = {
    amount: { currency: "USD", value: "100" },
    expiresAtMs: "1784923800000",
    intakeDigest: INTAKE_DIGEST,
    intakeRequestId: run.intakeRequestId,
    invoiceReferencePrefix: "INV-",
    issuedAtMs: "1784923100000",
    payee: { address: PAYEE.address.toLowerCase(), agentId: "8678" },
    payer: { address: PAYER.address.toLowerCase(), agentId: "8677" },
    paymentMoved: false,
    protocol: "clockchain.bilateral-authorization/v1",
    purpose: "Invoice settlement",
    releaseId: "release-1",
    repositorySha: REPOSITORY_SHA,
    requestEndpoint: `/v1/sessions/${run.mandateSessionId}/payment-requests`,
    schema: "clockchain.bilateral-payer-mandate/v1",
    sessionId: run.mandateSessionId,
    subjectRun: "stakeholder",
  };
  const mandateEnvelope = await signPayerMandate({
    mandate,
    signMessage: (raw) => PAYER.signMessage({ message: { raw } }),
  });
  const requestEnvelope = await signPaymentRequest({
    request: {
      amount: mandate.amount,
      createdAtMs: "1784923150000",
      expiresAtMs: "1784923700000",
      intakeDigest: mandate.intakeDigest,
      intakeRequestId: mandate.intakeRequestId,
      invoiceReference: run.invoiceReference,
      mandateDigest: payerMandateDigest(mandateEnvelope),
      payee: mandate.payee,
      payer: mandate.payer,
      paymentMoved: false,
      protocol: mandate.protocol,
      purpose: mandate.purpose,
      releaseId: mandate.releaseId,
      repositorySha: mandate.repositorySha,
      requestId: run.requestId,
      schema: "clockchain.bilateral-payment-request/v1",
      sessionId: mandate.sessionId,
      subjectRun: mandate.subjectRun,
    },
    signMessage: (raw) => PAYEE.signMessage({ message: { raw } }),
  });
  return { mandateEnvelope, requestEnvelope };
}

function idempotencyKey(sessionDigest, kind) {
  return createHash("sha256")
    .update(`${sessionDigest}|${kind}`, "utf8")
    .digest("hex")
    .slice(0, 32);
}

async function anchor(fake, message) {
  const referenceId = sessionKey(message.sessionDigest, message.kind);
  await fake.logAction({
    allow_degraded: true,
    asset_hash: transitionDigest(message),
    asset_reference_id: referenceId,
    hash_type: "SHA-256",
    idempotency_key: idempotencyKey(message.sessionDigest, message.kind),
    version_number: 1,
    wait: true,
    wait_ms: 20000,
  });
  return verifyTransition({ client: fake, message, referenceId });
}

function evidenceEntry(message, verified, index) {
  return {
    blockTimeMs: String(verified.blockTimeMs),
    blockTimeRaw: verified.blockTimeRaw,
    digest: transitionDigest(message),
    message,
    onChain: {
      anchoredHash: verified.anchoredHash,
      blockHeight: verified.blockHeight,
      ledgerId: verified.ledgerId,
    },
    upperBoundMs:
      index === 0 ? null : String(liveUpperBoundMs(verified.blockTimeMs)),
  };
}

function partyResult({ descriptor, role, sessionDigest, transitions }) {
  return {
    ackObserved: true,
    deadlineMs: String(deadlineMs(Number(transitions[0].blockTimeMs))),
    localVerdict: "LOCAL_OK",
    paymentMoved: false,
    poolHealth: {
      degradedAtSubmission: true,
      nodeParticipationPct: "0.0",
      totalNodes: "1.0",
    },
    promptSha256: descriptor.promptSha256,
    protocolVersion: descriptor.protocolVersion,
    rendezvous: {
      channel: "derived-reference-id",
      degradedAtSubmission: true,
      tenancy: "cross-client",
    },
    repositorySha: descriptor.repositorySha,
    role,
    schema: PARTY_RESULT_SCHEMA,
    sessionDigest,
    signature: {
      address: descriptor[role].address,
      algorithm: "eip191",
      signature: `0x${"00".repeat(65)}`,
    },
    transitions,
  };
}

function accountFor(role) {
  return role === "payer" ? PAYER : PAYEE;
}

async function signParty(result, sessionDigest) {
  result.signature.signature = await accountFor(result.role).signMessage({
    message: {
      raw: partySignatureBytes({
        role: result.role,
        sessionDigest,
        transitions: result.transitions,
      }),
    },
  });
  return result;
}

function verifierView(clockchain) {
  // The verifier reads through a client that reports an unavailable block as a
  // network error, exactly as the production adapter does after its retries.
  return {
    generateAuditTrail: clockchain.generateAuditTrail.bind(clockchain),
    async getBlock(args) {
      try {
        return await clockchain.getBlock(args);
      } catch {
        throw new McpNetworkError("deterministic MCP read exhausted retries");
      }
    },
    resolveAgent: clockchain.resolveAgent.bind(clockchain),
    searchActions: clockchain.searchActions.bind(clockchain),
    verifyCrossParty: clockchain.verifyCrossParty.bind(clockchain),
  };
}

/**
 * A complete, honest run: three anchored transitions and two signed party
 * packages that a fresh verifier authorizes.
 */
async function buildRun({ anchored = true, clockchain, root, run }) {
  const { mandateEnvelope, requestEnvelope } = await intentEnvelopes(run);
  const descriptor = descriptorFixture({
    mandateDigest: payerMandateDigest(mandateEnvelope),
    requestDigest: paymentRequestDigest(requestEnvelope),
    sessionId: run.descriptorSessionId,
  });
  const sessionDigest = dSession(descriptor);
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const repositoryPrivateKeyPem = privateKey.export({
    format: "pem",
    type: "pkcs8",
  });
  const repositoryPublicKey = rawPublicKeyBase64FromPem(
    publicKey.export({ format: "pem", type: "spki" }),
  );
  const descriptorEnvelope = createSignedEnvelope(descriptor, {
    keyId: "negative-checks-operator",
    privateKeyPem: repositoryPrivateKeyPem,
  });
  for (const role of ["payer", "payee"]) {
    clockchain.registerAgent({
      agentId: descriptor[role].agentId,
      owner: descriptor[role].address,
      status: "active",
    });
  }

  let transitions = [];
  if (anchored) {
    const proposal = buildProposal({
      amount: { currency: "USD", value: "100" },
      descriptor,
      sessionDigest,
    });
    const verifiedProposal = await anchor(clockchain, proposal);
    const proposalTriple = authoritativeTriple({
      anchoredHash: verifiedProposal.anchoredHash,
      blockHeight: verifiedProposal.blockHeight,
      kind: "proposal",
      ledgerId: verifiedProposal.ledgerId,
    });
    const acceptance = buildAcceptance({ proposal, proposalTriple });
    const verifiedAcceptance = await anchor(clockchain, acceptance);
    const acceptanceTriple = authoritativeTriple({
      anchoredHash: verifiedAcceptance.anchoredHash,
      blockHeight: verifiedAcceptance.blockHeight,
      kind: "acceptance",
      ledgerId: verifiedAcceptance.ledgerId,
    });
    const acknowledgment = buildAcknowledgment({
      acceptance,
      acceptanceTriple,
      proposalTriple,
    });
    const verifiedAcknowledgment = await anchor(clockchain, acknowledgment);
    transitions = [
      evidenceEntry(proposal, verifiedProposal, 0),
      evidenceEntry(acceptance, verifiedAcceptance, 1),
      evidenceEntry(acknowledgment, verifiedAcknowledgment, 2),
    ];
  }

  const directories = {};
  if (anchored) {
    for (const role of ["payer", "payee"]) {
      const result = await signParty(
        partyResult({ descriptor, role, sessionDigest, transitions }),
        sessionDigest,
      );
      const directory = join(root, `${run.descriptorSessionId}-${role}`);
      await writePartyResult({ directory, result });
      directories[role] = directory;
    }
  }

  return {
    descriptor,
    descriptorEnvelope,
    directories,
    input: {
      canaries: [],
      clockchain: verifierView(clockchain),
      descriptorEnvelope,
      mandateEnvelope,
      ownerOf: async ({ agentId }) =>
        agentId === descriptor.payer.agentId
          ? descriptor.payer.address
          : descriptor.payee.address,
      payeeDirectory: directories.payee,
      payerDirectory: directories.payer,
      requestEnvelope,
      repositoryPublicKeyResolver: async () => repositoryPublicKey,
    },
    mandateEnvelope,
    requestEnvelope,
    sessionDigest,
    transitions,
  };
}

// ---------------------------------------------------------------------------
// Observation: run the verifier and report the named reason it closed with.
// ---------------------------------------------------------------------------

const POSITIVE_OUTCOME_WORD = ["AUTHOR", "IZED"].join("");

async function observeVerdictRefusal(input) {
  try {
    const verdict = await verifyBilateralAuthorization(input);
    return {
      code: null,
      detail: `the verifier did NOT refuse; it returned outcome=${verdict.outcome}`,
    };
  } catch (error) {
    if (!(error instanceof BilateralVerdictError)) {
      return {
        code: null,
        detail: `the verifier threw a non-verdict error: ${error?.name ?? "unknown"}`,
      };
    }
    if (String(error.message).includes(POSITIVE_OUTCOME_WORD)) {
      return { code: null, detail: "the refusal message leaked the outcome word" };
    }
    return { code: error.terminalCode, detail: null };
  }
}

// ---------------------------------------------------------------------------
// The four cases.
// ---------------------------------------------------------------------------

function cloned(value) {
  return JSON.parse(JSON.stringify(value));
}

/**
 * (a) REPLAY. Run A completed and its evidence is real. A fresh session B is
 * published, and run A's two signed party packages are offered as if they
 * authorized it. The verifier queries the chain for session B's own anchors.
 */
async function caseReplay({ root }) {
  const clockchain = createFakeBilateralClockchain();
  const runA = await buildRun({ clockchain, root, run: RUN_A });
  const runB = await buildRun({
    anchored: false,
    clockchain,
    root,
    run: RUN_B,
  });
  const observation = await observeVerdictRefusal({
    ...runB.input,
    payeeDirectory: runA.directories.payee,
    payerDirectory: runA.directories.payer,
  });
  return {
    ...observation,
    detail:
      observation.detail ??
      "run A's packages are genuine and load cleanly; the fresh session has no anchors of its own",
  };
}

/**
 * The sibling of (a): the same replayed evidence, but against a fresh session
 * that DID anchor its own three transitions. Reported, not gated — see the
 * notes printed under the table.
 */
async function caseReplayAgainstAnchoredSession({ root }) {
  const clockchain = createFakeBilateralClockchain();
  const runA = await buildRun({ clockchain, root, run: RUN_A });
  const runB = await buildRun({ clockchain, root, run: RUN_B });
  return observeVerdictRefusal({
    ...runB.input,
    payeeDirectory: runA.directories.payee,
    payerDirectory: runA.directories.payer,
  });
}

/**
 * (b) REORDER. The acceptance is presented ahead of the proposal. The chain
 * itself cannot be reordered: every acceptance embeds the proposal's authoritative
 * triple, so an acceptance cannot exist before the proposal it cites is anchored.
 * The reachable reorder is therefore in the presented evidence.
 */
async function caseReorder({ root }) {
  const clockchain = createFakeBilateralClockchain();
  const run = await buildRun({ clockchain, root, run: RUN_A });

  // An honest party cannot even PRODUCE this package: partySignatureBytes runs
  // the same transition-order check, so the out-of-order list is unsignable.
  // Confirm that first, then hand-craft the package a hostile party would have
  // to forge instead, and put it in front of the verifier.
  const reordered = cloned(run.transitions);
  [reordered[0], reordered[1]] = [reordered[1], reordered[0]];
  let signable = true;
  try {
    partySignatureBytes({
      role: "payee",
      sessionDigest: run.sessionDigest,
      transitions: reordered,
    });
  } catch {
    signable = false;
  }

  const directory = join(root, "reordered-payee");
  await writePartyResult({
    directory,
    result: await signParty(
      partyResult({
        descriptor: run.descriptor,
        role: "payee",
        sessionDigest: run.sessionDigest,
        transitions: run.transitions,
      }),
      run.sessionDigest,
    ),
  });
  const forged = JSON.parse(
    await readFile(join(directory, "party-result.json"), "utf8"),
  );
  [forged.transitions[0], forged.transitions[1]] = [
    forged.transitions[1],
    forged.transitions[0],
  ];
  await republish(directory, forged);

  const observation = await observeVerdictRefusal({
    ...run.input,
    payeeDirectory: directory,
  });
  return {
    ...observation,
    detail:
      observation.detail ??
      (signable
        ? "the out-of-order transition list was signable"
        : "the out-of-order list is unsignable, so the package had to be forged by hand"),
  };
}

/**
 * Overwrite a published party package in place with hand-crafted JSON, keeping
 * the marker consistent so the refusal is about the document and not about a
 * broken digest.
 */
async function republish(directory, result) {
  const json = `${JSON.stringify(result, null, 2)}\n`;
  const markdown = await readFile(join(directory, "PARTY-RESULT.md"), "utf8");
  await writeFile(join(directory, "party-result.json"), json, "utf8");
  await writeFile(
    join(directory, ".party-result.complete.json"),
    `${JSON.stringify({
      jsonSha256: createHash("sha256").update(json).digest("hex"),
      markdownSha256: createHash("sha256").update(markdown).digest("hex"),
      schema: "clockchain.bilateral-party-result-completion/v1",
    })}\n`,
    "utf8",
  );
}

/**
 * (c) TAMPER. One byte flipped in one signature: the payee's party-result
 * signature over its own transitions. Nothing else changes.
 */
async function caseTamper({ root }) {
  const clockchain = createFakeBilateralClockchain();
  const run = await buildRun({ clockchain, root, run: RUN_A });
  const tampered = await signParty(
    partyResult({
      descriptor: run.descriptor,
      role: "payee",
      sessionDigest: run.sessionDigest,
      transitions: run.transitions,
    }),
    run.sessionDigest,
  );
  tampered.signature.signature = flipOneByte(tampered.signature.signature);
  const directory = join(root, "tampered-payee");
  await writePartyResult({ directory, result: tampered });
  return observeVerdictRefusal({
    ...run.input,
    payeeDirectory: directory,
  });
}

function flipOneByte(hexSignature) {
  // Byte 10 of the 65-byte signature: inside r, so the shape stays valid and the
  // refusal is a signature refusal rather than a schema refusal.
  const offset = 2 + 20;
  const byte = Number.parseInt(hexSignature.slice(offset, offset + 2), 16);
  const flipped = (byte ^ 0x01).toString(16).padStart(2, "0");
  return `${hexSignature.slice(0, offset)}${flipped}${hexSignature.slice(offset + 2)}`;
}

/**
 * (d) DUPLICATE FUNDING. A funding record is driven to FUNDED, then the same
 * record is replayed through the ported journal.
 */
const FUNDING_RECIPIENTS = Object.freeze([
  "0x1111111111111111111111111111111111111111",
  "0x2222222222222222222222222222222222222222",
  "0x3333333333333333333333333333333333333333",
  "0x4444444444444444444444444444444444444444",
]);

async function caseDuplicateFunding({ root }) {
  const facts = {
    chainId: 11155111,
    fundingAddress: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    paymentMoved: false,
    recipients: [...FUNDING_RECIPIENTS],
    repositorySha: REPOSITORY_SHA,
    rpcEndpointSha256: "0123456789abcdef".repeat(4),
    targetBalanceWei: "10000000000000000",
  };
  const journalDirectory = join(root, "funding");
  await mkdirPrivate(journalDirectory);
  const journal = await openFundingJournal({
    binding: { batchId: deriveFundingBatchId(facts), ...facts },
    journalDirectory,
  });
  const transfer = {
    address: FUNDING_RECIPIENTS[0],
    feeWei: "1000",
    fundingNonce: "7",
    state: "BROADCAST_INTENT",
    transactionDigest: "b".repeat(64),
    transactionHash: null,
    valueWei: "10000000000000000",
  };
  const transactionHash = `0x${"a".repeat(64)}`;
  const observed = await (
    await journal.recordBroadcastIntent(transfer)
  ).recordTransactionObserved({
    address: transfer.address,
    fundingNonce: transfer.fundingNonce,
    transactionHash,
  });
  const funded = await observed.recordFunded({
    address: transfer.address,
    fundingNonce: transfer.fundingNonce,
  });
  if (funded.document.state !== "FUNDED") {
    return { code: null, detail: "the journal never reached FUNDED" };
  }
  try {
    await funded.recordTransactionObserved({
      address: transfer.address,
      fundingNonce: transfer.fundingNonce,
      transactionHash,
    });
    return { code: null, detail: "the journal accepted the replayed record" };
  } catch (error) {
    if (!(error instanceof BilateralFundingError)) {
      return {
        code: null,
        detail: `the journal threw a non-funding error: ${error?.name ?? "unknown"}`,
      };
    }
    return { code: error.code, detail: null };
  }
}

async function mkdirPrivate(directory) {
  await mkdir(directory, { mode: 0o700, recursive: true });
  await chmod(directory, 0o700);
}

// ---------------------------------------------------------------------------
// Case table.
// ---------------------------------------------------------------------------

/**
 * The control. Without it, every row below could pass because the fixture is
 * broken rather than because the defence works. This runs the SAME fixture with
 * nothing attacked and requires the verifier to accept it.
 */
async function controlHonestRun({ root }) {
  const clockchain = createFakeBilateralClockchain();
  const run = await buildRun({ clockchain, root, run: RUN_A });
  try {
    const verdict = await verifyBilateralAuthorization(run.input);
    if (verdict.outcome !== POSITIVE_OUTCOME_WORD) {
      return { detail: `unexpected outcome ${verdict.outcome}`, pass: false };
    }
    if (verdict.paymentMoved !== false) {
      return { detail: "paymentMoved was not false", pass: false };
    }
    return {
      detail: `the untouched fixture is accepted, ${verdict.transitions.length} anchors, paymentMoved false`,
      pass: true,
    };
  } catch (error) {
    return {
      detail: `the untouched fixture was refused with ${
        error?.terminalCode ?? error?.name ?? "an unknown error"
      }`,
      pass: false,
    };
  }
}

export const NEGATIVE_CASES = Object.freeze([
  Object.freeze({
    expected: "MISSING",
    id: "REPLAY",
    label: "a. replayed evidence vs a fresh session",
    run: caseReplay,
  }),
  Object.freeze({
    expected: "MALFORMED",
    id: "REORDER",
    label: "b. acceptance presented before proposal",
    run: caseReorder,
  }),
  Object.freeze({
    expected: "FAILED",
    id: "TAMPER",
    label: "c. one byte flipped in one signature",
    run: caseTamper,
  }),
  Object.freeze({
    expected: "BILATERAL_FUNDING_REPLACED_TRANSFER",
    id: "DUPLICATE_FUNDING",
    label: "d. funding record replayed through the journal",
    run: caseDuplicateFunding,
  }),
]);

export const OBSERVED_ONLY_CASES = Object.freeze([
  Object.freeze({
    expected: "FAILED",
    id: "REPLAY_ANCHORED",
    label: "a'. replayed evidence vs a fresh session that anchored its own run",
    run: caseReplayAgainstAnchoredSession,
  }),
]);

export async function runNegativeChecks() {
  const root = await mkdtemp(join(tmpdir(), "negative-checks-"));
  try {
    const control = await controlHonestRun({ root: join(root, "CONTROL") });
    const results = [];
    for (const negativeCase of [...NEGATIVE_CASES, ...OBSERVED_ONLY_CASES]) {
      const observation = await negativeCase.run({
        root: join(root, negativeCase.id),
      });
      results.push({
        code: observation.code,
        detail: observation.detail,
        expected: negativeCase.expected,
        gating: NEGATIVE_CASES.includes(negativeCase),
        id: negativeCase.id,
        label: negativeCase.label,
        pass: observation.code === negativeCase.expected,
      });
    }
    const gating = results.filter((result) => result.gating);
    const codes = gating.map((result) => result.code);
    return Object.freeze({
      control: Object.freeze(control),
      distinct: new Set(codes).size === gating.length,
      results: Object.freeze(results),
    });
  } finally {
    await rm(root, { force: true, recursive: true });
  }
}

// ---------------------------------------------------------------------------
// CLI.
// ---------------------------------------------------------------------------

function pad(value, width) {
  return String(value).padEnd(width, " ");
}

async function main() {
  const report = await runNegativeChecks();
  const gating = report.results.filter((result) => result.gating);
  const observed = report.results.filter((result) => !result.gating);

  stdout.write("\nnegative checks: does the system fail closed?\n\n");
  stdout.write(
    `  CONTROL           ${report.control.pass ? "PASS" : "FAIL"}  ${report.control.detail}\n\n`,
  );
  stdout.write(
    `  ${pad("CASE", 18)}${pad("REASON CODE", 38)}${pad("EXPECTED", 38)}RESULT\n`,
  );
  stdout.write(`  ${"-".repeat(18 + 38 + 38 + 6)}\n`);
  for (const result of gating) {
    stdout.write(
      `  ${pad(result.id, 18)}${pad(result.code ?? "(none)", 38)}${pad(
        result.expected,
        38,
      )}${result.pass ? "PASS" : "FAIL"}\n`,
    );
  }
  stdout.write("\n");
  for (const result of gating) {
    stdout.write(`  ${pad(result.id, 18)}${result.label}\n`);
    if (result.detail !== null) {
      stdout.write(`  ${pad("", 18)}${result.detail}\n`);
    }
  }

  stdout.write("\n  distinctness of the four gating codes: ");
  stdout.write(report.distinct ? "four distinct codes\n" : "COLLISION\n");
  if (!report.distinct) {
    const seen = new Map();
    for (const result of gating) {
      seen.set(result.code, [...(seen.get(result.code) ?? []), result.id]);
    }
    for (const [code, ids] of seen) {
      if (ids.length > 1) {
        stdout.write(`    ${code} is shared by ${ids.join(" and ")}\n`);
      }
    }
  }

  stdout.write("\n  reported, not gated:\n");
  for (const result of observed) {
    stdout.write(
      `    ${pad(result.id, 18)}${pad(result.code ?? "(none)", 38)}${result.label}\n`,
    );
  }

  stdout.write("\n  notes a reader should not have to dig for:\n");
  stdout.write(
    "    REORDERED is never thrown. The literal appears in src/ only in the two\n" +
      "      monitor display maps. Out-of-order evidence is refused one layer\n" +
      "      earlier, by the party-result schema that pins each transition's kind\n" +
      "      to its index, so case (b) reports MALFORMED. The order check that\n" +
      "      would own REORDERED belongs to src/verifier/, empty today.\n",
  );
  stdout.write(
    "    FUNDING_REPLAYED is never thrown either, and for the same reason. The\n" +
      "      ported funding journal refuses the replay under its own internal\n" +
      "      namespace, and the journal is a pure port that must not be edited.\n",
  );
  stdout.write(
    "    check-invariants.sh reports both codes as 'emitted' because its grep\n" +
      "      cannot tell a thrown code from a display label. That is a gap in\n" +
      "      that check, not evidence that these two paths exist.\n",
  );
  stdout.write(
    "    REPLAY and REPLAY_ANCHORED do not share a code. The anchored sibling\n" +
      "      lands on the generic catch-all, which it shares with TAMPER; the\n" +
      "      vocabulary has no code for 'this evidence belongs to another run'.\n",
  );
  stdout.write("\n");

  const failures = gating.filter((result) => !result.pass);
  if (failures.length > 0 || !report.distinct || !report.control.pass) {
    stdout.write(
      `RESULT: ${failures.length} case(s) failed to produce the recorded code` +
        `${report.distinct ? "" : "; the gating codes are not distinct"}` +
        `${report.control.pass ? "" : "; the control run did not pass"}\n\n`,
    );
    return 1;
  }
  stdout.write(
    "RESULT: every case fails closed with a distinct named reason\n\n",
  );
  return 0;
}

if (argv[1] !== undefined && resolve(argv[1]) === fileURLToPath(import.meta.url)) {
  exit(await main());
}
