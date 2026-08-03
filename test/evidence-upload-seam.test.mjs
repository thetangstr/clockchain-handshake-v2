// The cross-machine seam. In v2 the requestor runs on a different machine from the
// verifier, so a role must PUSH its party package to the untrusted relay in addition
// to writing it locally; the verifier later PULLS it. These tests pin the properties
// that make that safe: same bytes, upload strictly after the local write, and a
// failed upload that leaves a complete local package behind to retry from.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { writePartyResult } from "../src/core/evidence.mjs";
import { buildFixture } from "./helpers/party-result-fixture.mjs";

async function temporaryDirectory(t) {
  const directory = await mkdtemp(join(tmpdir(), "handshake-seam-"));
  t.after(async () => {
    await rm(directory, { force: true, recursive: true });
  });
  return directory;
}

test("with no transport injected, the local-only path is unchanged", async (t) => {
  const directory = await temporaryDirectory(t);
  const paths = await writePartyResult({
    directory,
    result: buildFixture(),
    canaries: [],
  });
  assert.deepEqual(paths, {
    jsonPath: join(directory, "party-result.json"),
    markdownPath: join(directory, "PARTY-RESULT.md"),
    markerPath: join(directory, ".party-result.complete.json"),
  });
});

test("the transport receives exactly the bytes written to disk", async (t) => {
  const directory = await temporaryDirectory(t);
  const uploads = [];
  const paths = await writePartyResult({
    directory,
    result: buildFixture(),
    canaries: [],
    dependencies: {
      uploadPartyPackage: async (payload) => {
        uploads.push(payload);
      },
    },
  });

  assert.equal(uploads.length, 1, "expected exactly one upload");
  const [payload] = uploads;
  assert.equal(payload.role, "payer");
  assert.equal(payload.json, await readFile(paths.jsonPath, "utf8"));
  assert.equal(payload.markdown, await readFile(paths.markdownPath, "utf8"));
  // The marker carries the sha256 of the other two; the verifier re-checks it,
  // which is why the uploaded copy must be the same bytes, not a re-render.
  assert.deepEqual(
    JSON.parse(payload.marker),
    JSON.parse(await readFile(paths.markerPath, "utf8")),
  );
});

test("upload happens after the local package is complete, never before", async (t) => {
  const directory = await temporaryDirectory(t);
  let markerPresentAtUpload = null;
  await writePartyResult({
    directory,
    result: buildFixture(),
    canaries: [],
    dependencies: {
      uploadPartyPackage: async () => {
        // If the marker is already readable, the local package was durable first.
        markerPresentAtUpload = await readFile(
          join(directory, ".party-result.complete.json"),
          "utf8",
        ).then(() => true, () => false);
      },
    },
  });
  assert.equal(
    markerPresentAtUpload,
    true,
    "upload must run only after the completion marker is on disk, so a rejection is retryable",
  );
});

test("a rejected upload fails closed but leaves the local package intact", async (t) => {
  const directory = await temporaryDirectory(t);
  await assert.rejects(
    writePartyResult({
      directory,
      result: buildFixture(),
      canaries: [],
      dependencies: {
        uploadPartyPackage: async () => {
          throw new Error("relay unreachable");
        },
      },
    }),
    (error) => {
      assert.equal(error.code, "BILATERAL_EVIDENCE_UPLOAD_FAILED");
      // The underlying transport error may echo package bytes; it must not leak.
      assert.equal(/relay unreachable/.test(error.message), false);
      return true;
    },
  );

  // All three files survive, so the caller can retry the upload without re-running
  // the protocol step that produced them.
  for (const name of ["party-result.json", "PARTY-RESULT.md", ".party-result.complete.json"]) {
    await readFile(join(directory, name), "utf8");
  }
});

test("the injected dependency bag rejects unknown keys", async (t) => {
  const directory = await temporaryDirectory(t);
  await assert.rejects(
    writePartyResult({
      directory,
      result: buildFixture(),
      canaries: [],
      dependencies: { notAnUploader: async () => {} },
    }),
    (error) => error.name === "BilateralEvidenceConfigurationError",
  );
});

test("core does not import the relay: the transport is injected only", async () => {
  const source = await readFile(new URL("../src/core/evidence.mjs", import.meta.url), "utf8");
  assert.equal(
    /from\s+["'].*relay/.test(source),
    false,
    "core/evidence.mjs must not import relay code — the relay is untrusted transport injected by the caller",
  );
});

test("the AUTHORIZED ban pattern survives the seam edit", async () => {
  const source = await readFile(new URL("../src/core/evidence.mjs", import.meta.url), "utf8");
  assert.match(
    source,
    /AUTHORIZING_WORD_PATTERN/,
    "the anti-false-authorization guard must remain: a role may never write the verdict word into its own evidence",
  );
});
