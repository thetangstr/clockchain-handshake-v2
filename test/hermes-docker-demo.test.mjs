import assert from "node:assert/strict";
import test from "node:test";

import {
  buildDockerRunPlan,
  validateDockerEvidence,
} from "../src/core/hermes-docker-demo.mjs";

const RUN_ID = "123e4567-e89b-42d3-a456-426614174000";
const IMAGE = `clockchain/hermes-cleanroom@sha256:${"a".repeat(64)}`;
const FAILURE = /Docker demo failed safely\./;

function validEvidence(overrides = {}) {
  return {
    terminal: {
      role: "payer",
      sessionId: RUN_ID,
      certificateDigest: "certificate-digest-001",
      certificate: {
        digest: "certificate-digest-001",
        outcome: "AUTHORIZED",
        paymentMoved: false,
      },
      canariesAbsent: true,
      containersExited: true,
      imageDigestPinned: true,
      mountsFrozen: true,
      networkIsolated: true,
      ...overrides,
    },
  };
}

function captureThrow(fn) {
  try {
    fn();
  } catch (error) {
    return error;
  }

  assert.fail("Expected function to throw.");
}

test("buildDockerRunPlan rejects mutable images and invalid run IDs generically", () => {
  assert.throws(
    () => buildDockerRunPlan({ image: "clockchain/hermes-cleanroom:latest", runId: RUN_ID }),
    FAILURE,
  );
  assert.throws(
    () => buildDockerRunPlan({ image: IMAGE.toUpperCase(), runId: RUN_ID }),
    FAILURE,
  );
  assert.throws(
    () => buildDockerRunPlan({ image: IMAGE, runId: "not-a-uuid" }),
    FAILURE,
  );
});

test("buildDockerRunPlan creates distinct frozen role resources without mounts", () => {
  const plan = buildDockerRunPlan({ image: IMAGE, runId: RUN_ID });

  assert.deepEqual(plan.roles, ["payer", "requestor"]);
  assert.equal(plan.network.name, `hermes-${RUN_ID}`);
  assert.equal(plan.containers.payer.name, `hermes-${RUN_ID}-payer`);
  assert.equal(plan.containers.requestor.name, `hermes-${RUN_ID}-requestor`);
  assert.notEqual(plan.containers.payer, plan.containers.requestor);
  assert.notEqual(plan.containers.payer.name, plan.containers.requestor.name);
  assert.deepEqual(plan.containers.payer.mounts, []);
  assert.deepEqual(plan.containers.requestor.mounts, []);
  assert.notEqual(
    plan.containers.payer.mounts,
    plan.containers.requestor.mounts,
  );
  assert.ok(Object.isFrozen(plan));
  assert.ok(Object.isFrozen(plan.roles));
  assert.ok(Object.isFrozen(plan.network));
  assert.ok(Object.isFrozen(plan.containers));
  assert.ok(Object.isFrozen(plan.containers.payer));
  assert.ok(Object.isFrozen(plan.containers.payer.mounts));
  assert.ok(Object.isFrozen(plan.containers.requestor.mounts));
});

test("buildDockerRunPlan applies the Docker demo label contract", () => {
  const plan = buildDockerRunPlan({ image: IMAGE, runId: RUN_ID });

  for (const resource of [
    plan.network,
    plan.containers.payer,
    plan.containers.requestor,
  ]) {
    assert.deepEqual(resource.labels, {
      "clockchain.managed": "hermes-docker-demo",
      "clockchain.run": RUN_ID,
    });
    assert.ok(Object.isFrozen(resource.labels));
  }
  assert.notEqual(plan.network.labels, plan.containers.payer.labels);
  assert.notEqual(plan.network.labels, plan.containers.requestor.labels);
  assert.notEqual(
    plan.containers.payer.labels,
    plan.containers.requestor.labels,
  );
});

test("validateDockerEvidence rejects secret canaries without exposing values", () => {
  const canary = "super-secret-canary";
  const error = captureThrow(() =>
    validateDockerEvidence(validEvidence({ note: canary }), [canary]));

  assert.match(error.message, FAILURE);
  assert.doesNotMatch(error.message, new RegExp(canary));
});

test("validateDockerEvidence rejects raw log channels", () => {
  for (const key of ["stdout", "stderr", "logs"]) {
    assert.throws(
      () => validateDockerEvidence(validEvidence({ [key]: "public text" })),
      FAILURE,
    );
  }
});

test("validateDockerEvidence rejects unexpected top-level objects", () => {
  assert.throws(
    () => validateDockerEvidence({
      ...validEvidence(),
      diagnostics: { public: true },
    }),
    FAILURE,
  );
});

test("validateDockerEvidence rejects unbounded certificate digest strings", () => {
  assert.throws(
    () => validateDockerEvidence(
      validEvidence({
        certificateDigest: "a".repeat(129),
        certificate: {
          digest: "a".repeat(129),
          outcome: "AUTHORIZED",
          paymentMoved: false,
        },
      }),
    ),
    FAILURE,
  );
});

test("validateDockerEvidence accepts minimal valid terminal evidence", () => {
  const evidence = validEvidence();
  const accepted = validateDockerEvidence(evidence);

  assert.notEqual(accepted, evidence);
  assert.deepEqual(accepted, evidence);
});

test("validateDockerEvidence returns a normalized proof that cannot be mutated", () => {
  const accepted = validateDockerEvidence(validEvidence());

  assert.ok(Object.isFrozen(accepted));
  assert.ok(Object.isFrozen(accepted.terminal));
  assert.ok(Object.isFrozen(accepted.terminal.certificate));
  assert.throws(() => {
    accepted.terminal.certificate.paymentMoved = true;
  }, TypeError);
  assert.throws(() => {
    accepted.stdout = "public text";
  }, TypeError);
  assert.equal(accepted.terminal.certificate.paymentMoved, false);
  assert.equal(Object.hasOwn(accepted, "stdout"), false);
});
