import { readFile } from "node:fs/promises";

import { certificateProof } from "../src/core/certificate-proof.mjs";

function argumentsFor(argv) {
  if (
    argv.length !== 9 ||
    argv[0] !== "verify" ||
    argv[1] !== "--file" ||
    argv[3] !== "--role" ||
    argv[5] !== "--expected-public-key" ||
    argv[7] !== "--session-id"
  ) {
    throw new Error("certificate proof failed");
  }
  return {
    file: argv[2],
    role: argv[4],
    expectedPublicKey: argv[6],
    sessionId: argv[8],
  };
}

try {
  const { file, role, expectedPublicKey, sessionId } = argumentsFor(process.argv.slice(2));
  const envelope = JSON.parse(await readFile(file, "utf8"));
  process.stdout.write(`${JSON.stringify(certificateProof(envelope, {
    role,
    expectedPublicKey,
    sessionId,
  }))}\n`);
} catch {
  process.stderr.write("Certificate proof failed.\n");
  process.exitCode = 1;
}
