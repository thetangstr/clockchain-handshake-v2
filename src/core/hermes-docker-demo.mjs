import { assertSecretFree } from "./redact.mjs";

const FAILURE_MESSAGE = "Docker demo failed safely.";
const ROLES = Object.freeze(["payer", "requestor"]);
const IMAGE_PATTERN =
  /^clockchain\/hermes-cleanroom@sha256:[0-9a-f]{64}$/;
const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const RAW_LOG_KEYS = Object.freeze(["logs", "stderr", "stdout"]);
const EVIDENCE_KEYS = Object.freeze(["terminal"]);
const TERMINAL_KEYS = Object.freeze([
  "canariesAbsent",
  "certificate",
  "certificateDigest",
  "containersExited",
  "imageDigestPinned",
  "mountsFrozen",
  "networkIsolated",
  "role",
  "sessionId",
]);
const CERTIFICATE_KEYS = Object.freeze([
  "digest",
  "outcome",
  "paymentMoved",
]);
const REQUIRED_TRUE_FLAGS = Object.freeze([
  "canariesAbsent",
  "containersExited",
  "imageDigestPinned",
  "mountsFrozen",
  "networkIsolated",
]);
const DIGEST_PATTERN = /^[A-Za-z0-9._:-]{1,128}$/;

function fail() {
  throw new Error(FAILURE_MESSAGE);
}

function isPlainObject(value) {
  if (value === null || typeof value !== "object") {
    return false;
  }

  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function assertUuid(value) {
  if (typeof value !== "string" || !UUID_PATTERN.test(value)) {
    fail();
  }
}

function assertImage(value) {
  if (typeof value !== "string" || !IMAGE_PATTERN.test(value)) {
    fail();
  }
}

function deepFreeze(value) {
  if (value === null || typeof value !== "object" || Object.isFrozen(value)) {
    return value;
  }

  for (const entry of Object.values(value)) {
    deepFreeze(entry);
  }

  return Object.freeze(value);
}

function labels(runId) {
  return Object.freeze({
    "clockchain.managed": "hermes-docker-demo",
    "clockchain.run": runId,
  });
}

function containerResource({ image, role, runId }) {
  return {
    image,
    labels: labels(runId),
    mounts: [],
    name: `hermes-${runId}-${role}`,
    role,
  };
}

function sameKeys(value, keys) {
  const actual = Object.keys(value).sort();
  return (
    actual.length === keys.length &&
    actual.every((key, index) => key === keys[index])
  );
}

function containsRawLogKey(value, seen = new WeakSet()) {
  if (value === null || typeof value !== "object") {
    return false;
  }

  if (seen.has(value)) {
    return false;
  }
  seen.add(value);

  if (Array.isArray(value)) {
    return value.some((entry) => containsRawLogKey(entry, seen));
  }

  return Object.entries(value).some(
    ([key, entry]) =>
      RAW_LOG_KEYS.includes(key) || containsRawLogKey(entry, seen),
  );
}

function validateCertificate(certificate, certificateDigest) {
  if (!isPlainObject(certificate) || !sameKeys(certificate, CERTIFICATE_KEYS)) {
    fail();
  }

  if (
    certificate.paymentMoved !== false ||
    certificate.outcome !== "AUTHORIZED" ||
    !DIGEST_PATTERN.test(certificate.digest) ||
    certificate.digest !== certificateDigest
  ) {
    fail();
  }
}

function validateTerminal(terminal) {
  if (!isPlainObject(terminal) || !sameKeys(terminal, TERMINAL_KEYS)) {
    fail();
  }

  if (!ROLES.includes(terminal.role)) {
    fail();
  }

  assertUuid(terminal.sessionId);

  if (
    typeof terminal.certificateDigest !== "string" ||
    !DIGEST_PATTERN.test(terminal.certificateDigest)
  ) {
    fail();
  }

  for (const flag of REQUIRED_TRUE_FLAGS) {
    if (terminal[flag] !== true) {
      fail();
    }
  }

  validateCertificate(terminal.certificate, terminal.certificateDigest);

  return {
    role: terminal.role,
    sessionId: terminal.sessionId,
    certificateDigest: terminal.certificateDigest,
    certificate: {
      digest: terminal.certificate.digest,
      outcome: terminal.certificate.outcome,
      paymentMoved: terminal.certificate.paymentMoved,
    },
    canariesAbsent: terminal.canariesAbsent,
    containersExited: terminal.containersExited,
    imageDigestPinned: terminal.imageDigestPinned,
    mountsFrozen: terminal.mountsFrozen,
    networkIsolated: terminal.networkIsolated,
  };
}

export function buildDockerRunPlan(input = {}) {
  if (!isPlainObject(input)) {
    fail();
  }

  const { image, runId } = input;
  assertImage(image);
  assertUuid(runId);

  return deepFreeze({
    image,
    roles: [...ROLES],
    network: {
      labels: labels(runId),
      name: `hermes-${runId}`,
    },
    containers: {
      payer: containerResource({ image, role: "payer", runId }),
      requestor: containerResource({ image, role: "requestor", runId }),
    },
  });
}

export function validateDockerEvidence(value, canaries = []) {
  try {
    assertSecretFree(value, canaries);

    if (
      !isPlainObject(value) ||
      !sameKeys(value, EVIDENCE_KEYS) ||
      containsRawLogKey(value)
    ) {
      fail();
    }

    return deepFreeze({ terminal: validateTerminal(value.terminal) });
  } catch (_error) {
    fail();
  }
}
