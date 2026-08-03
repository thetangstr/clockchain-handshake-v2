import assert from "node:assert/strict";
import test from "node:test";
import { execFile } from "node:child_process";
import { createHash, generateKeyPairSync } from "node:crypto";
import { constants as fsConstants } from "node:fs";
import {
  chmod,
  lstat,
  mkdir,
  mkdtemp,
  open,
  readFile,
  readdir,
  realpath,
  rename,
  stat,
  symlink,
  unlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";

import {
  canonicalBytes,
  digestHex,
} from "../src/core/canonical.mjs";
import {
  AMOUNT_OPTION_KEYS,
  BILATERAL_PROTOCOL,
  DESCRIPTOR_CHAIN_ID,
  DESCRIPTOR_EXPIRY_SECONDS,
  DESCRIPTOR_KEYS,
  DESCRIPTOR_NAMESPACE,
  DESCRIPTOR_SCHEMA,
  DESCRIPTOR_SETTLEMENT,
  DescriptorError,
  DescriptorSignatureError,
  DescriptorValidationError,
  ENVELOPE_KEYS,
  KEY_ID_PATTERN,
  MAX_AMOUNT_OPTIONS,
  OPERATOR_KEYS,
  OPERATOR_KEY_ALGORITHM,
  OperatorKeyMismatchError,
  PARTY_KEYS,
  PROTOCOL_VERSION,
  REGISTRY_ADDRESS,
  createSignedEnvelope,
  dSession,
  operatorPublicKeyPath,
  publicKeyPemFromRawBase64,
  rawPublicKeyBase64FromPem,
  signDescriptor,
  validateDescriptor,
  verifyDescriptorEnvelope,
  verifyDescriptorSignature,
} from "../src/core/descriptor.mjs";

function ephemeralOperator(keyId) {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const publicKeyPem = publicKey.export({
    format: "pem",
    type: "spki",
  });
  return Object.freeze({
    keyId,
    privateKeyPem: privateKey.export({
      format: "pem",
      type: "pkcs8",
    }),
    publicKeyPem,
    publicKeyRawBase64: publicKey
      .export({ format: "der", type: "spki" })
      .subarray(-32)
      .toString("base64"),
  });
}

const OPERATOR = ephemeralOperator("test-operator-1");
const IMPOSTOR = ephemeralOperator("test-operator-2");
const execFileAsync = promisify(execFile);

const PAYER_ADDRESS = "0x00112233445566778899aabbccddeeff00112233";
const PAYEE_ADDRESS = "0xffeeddccbbaa99887766554433221100ffeeddcc";
const REPOSITORY_SHA = "0123456789abcdef0123456789abcdef01234567";
const PROMPT_SHA256 =
  "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
const SESSION_ID = "00112233445566778899aabbccddeeff";
const PINNED_D_SESSION =
  "04e932d5144bb18a12481657c5c351be3dc760927748c966fee64bc891bd3d73";

const DESCRIPTOR = Object.freeze({
  amountOptions: [
    { currency: "USD", value: "100" },
    { currency: "USD", value: "250" },
  ],
  chainId: "11155111",
  expirySeconds: "600",
  mandateDigest: "b".repeat(64),
  namespace: "cbv1",
  payee: {
    address: PAYEE_ADDRESS,
    agentId: "8678",
    displayName: "Iris",
    role: "payee",
  },
  payer: {
    address: PAYER_ADDRESS,
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
  requestDigest: "c".repeat(64),
  schema: "clockchain.bilateral-session-descriptor/v2",
  sessionId: SESSION_ID,
  settlement: "not-executed",
});

function clone() {
  return structuredClone(DESCRIPTOR);
}

function assertRejected(mutate, code) {
  const descriptor = clone();
  mutate(descriptor);
  assert.throws(
    () => validateDescriptor(descriptor),
    (error) => {
      assert.ok(
        error instanceof DescriptorValidationError,
        `expected DescriptorValidationError, got ${error?.name}: ${error?.message}`,
      );
      if (code !== undefined) {
        assert.equal(error.code, code);
      }
      return true;
    },
  );
}

test("schema, protocol, and policy constants are pinned exactly", () => {
  assert.equal(
    DESCRIPTOR_SCHEMA,
    "clockchain.bilateral-session-descriptor/v2",
  );
  assert.equal(
    BILATERAL_PROTOCOL,
    "clockchain.bilateral-authorization/v1",
  );
  assert.equal(PROTOCOL_VERSION, "1");
  assert.equal(DESCRIPTOR_NAMESPACE, "cbv1");
  assert.equal(DESCRIPTOR_CHAIN_ID, "11155111");
  assert.equal(DESCRIPTOR_EXPIRY_SECONDS, "600");
  assert.equal(DESCRIPTOR_SETTLEMENT, "not-executed");
  assert.equal(
    REGISTRY_ADDRESS,
    "0x8004a818bfb912233c491871b3d84c89a494bd9e",
  );
  assert.equal(MAX_AMOUNT_OPTIONS, 8);
  assert.equal(OPERATOR_KEY_ALGORITHM, "ed25519");
});

test("frozen exact-key lists match the spec descriptor block", () => {
  assert.deepEqual(DESCRIPTOR_KEYS, [
    "amountOptions",
    "chainId",
    "expirySeconds",
    "mandateDigest",
    "namespace",
    "payee",
    "payer",
    "paymentMoved",
    "promptSha256",
    "protocol",
    "protocolVersion",
    "registry",
    "repositorySha",
    "requestDigest",
    "schema",
    "sessionId",
    "settlement",
  ]);
  assert.deepEqual(PARTY_KEYS, [
    "address",
    "agentId",
    "displayName",
    "role",
  ]);
  assert.deepEqual(AMOUNT_OPTION_KEYS, ["currency", "value"]);
  assert.deepEqual(ENVELOPE_KEYS, ["descriptor", "operator"]);
  assert.deepEqual(OPERATOR_KEYS, [
    "algorithm",
    "keyId",
    "publicKey",
    "signature",
  ]);
  for (const list of [
    DESCRIPTOR_KEYS,
    PARTY_KEYS,
    AMOUNT_OPTION_KEYS,
    ENVELOPE_KEYS,
    OPERATOR_KEYS,
  ]) {
    assert.ok(Object.isFrozen(list));
  }
});

test("validateDescriptor accepts the golden descriptor and returns undefined", () => {
  assert.equal(validateDescriptor(clone()), undefined);
});

test("dSession is digestHex(canonicalBytes(descriptor)) and byte-pinned", () => {
  const descriptor = clone();
  const digest = dSession(descriptor);
  assert.equal(digest, PINNED_D_SESSION);
  assert.equal(digest, digestHex(descriptor));
  assert.equal(
    digest,
    createHash("sha256").update(canonicalBytes(descriptor)).digest("hex"),
  );
});

test("dSession is key-order independent", () => {
  const reversed = Object.fromEntries(
    Object.entries(clone()).reverse(),
  );
  assert.equal(dSession(reversed), PINNED_D_SESSION);
});

test("dSession validates before digesting", () => {
  const descriptor = clone();
  descriptor.paymentMoved = true;
  assert.throws(() => dSession(descriptor), DescriptorValidationError);
});

test("both exact intent digests are mandatory signed descriptor commitments", () => {
  const envelope = createSignedEnvelope(clone(), {
    keyId: OPERATOR.keyId,
    privateKeyPem: OPERATOR.privateKeyPem,
  });
  const originalBytes = canonicalBytes(envelope.descriptor);
  const originalSession = dSession(envelope.descriptor);
  for (const key of ["mandateDigest", "requestDigest"]) {
    const deleted = clone();
    delete deleted[key];
    assert.throws(
      () => validateDescriptor(deleted),
      DescriptorValidationError,
    );

    const changed = clone();
    changed[key] = "d".repeat(64);
    assert.notDeepEqual(canonicalBytes(changed), originalBytes);
    assert.notEqual(dSession(changed), originalSession);
    assert.throws(
      () => verifyDescriptorSignature(
        changed,
        envelope.operator.signature,
        OPERATOR.publicKeyPem,
      ),
      DescriptorSignatureError,
    );
  }
  const swapped = clone();
  [swapped.mandateDigest, swapped.requestDigest] = [
    swapped.requestDigest,
    swapped.mandateDigest,
  ];
  assert.notEqual(dSession(swapped), originalSession);
  assert.throws(
    () => verifyDescriptorSignature(
      swapped,
      envelope.operator.signature,
      OPERATOR.publicKeyPem,
    ),
    DescriptorSignatureError,
  );
});

test("top-level shape: non-objects, missing keys, and extra keys are rejected", () => {
  for (const invalid of [null, undefined, 42, "descriptor", [], true]) {
    assert.throws(
      () => validateDescriptor(invalid),
      DescriptorValidationError,
    );
  }
  for (const key of DESCRIPTOR_KEYS) {
    assertRejected((descriptor) => {
      delete descriptor[key];
    }, "DESCRIPTOR_SHAPE");
  }
  assertRejected((descriptor) => {
    descriptor.extra = "x";
  }, "DESCRIPTOR_SHAPE");
});

test("every pinned constant field rejects any other value", () => {
  const wrong = [
    ["chainId", "1"],
    ["chainId", "11155112"],
    ["expirySeconds", "601"],
    ["expirySeconds", "60"],
    ["namespace", "cbv2"],
    ["protocol", "clockchain.bilateral-authorization/v2"],
    ["protocolVersion", "2"],
    ["registry", "0x8004A818BFB912233C491871B3D84C89A494BD9E"],
    ["registry", "0x8004a818bfb912233c491871b3d84c89a494bd9f"],
    ["schema", "clockchain.bilateral-session-descriptor/v1"],
    ["settlement", "executed"],
    ["settlement", "Not-Executed"],
  ];
  for (const [key, value] of wrong) {
    assertRejected((descriptor) => {
      descriptor[key] = value;
    }, "DESCRIPTOR_FIELD");
  }
});

test("numbers never pass where decimal strings are pinned", () => {
  for (const [key, value] of [
    ["chainId", 11155111],
    ["expirySeconds", 600],
  ]) {
    assertRejected((descriptor) => {
      descriptor[key] = value;
    });
  }
  assertRejected((descriptor) => {
    descriptor.payer.agentId = 8677;
  });
  assertRejected((descriptor) => {
    descriptor.amountOptions[0].value = 100;
  });
});

test("paymentMoved must be boolean false exactly", () => {
  for (const value of [true, "false", 0, null, undefined]) {
    assertRejected((descriptor) => {
      descriptor.paymentMoved = value;
    }, "DESCRIPTOR_FIELD");
  }
});

test("repository and digest identifiers are strict lowercase hex", () => {
  const cases = [
    ["repositorySha", REPOSITORY_SHA.slice(0, 39)],
    ["repositorySha", `${REPOSITORY_SHA}0`],
    ["repositorySha", REPOSITORY_SHA.toUpperCase()],
    ["repositorySha", REPOSITORY_SHA.replace("0", "g")],
    ["promptSha256", PROMPT_SHA256.slice(0, 63)],
    ["promptSha256", `${PROMPT_SHA256}0`],
    ["promptSha256", PROMPT_SHA256.toUpperCase()],
    ["mandateDigest", "b".repeat(63)],
    ["mandateDigest", "B".repeat(64)],
    ["requestDigest", "c".repeat(63)],
    ["requestDigest", "C".repeat(64)],
    ["sessionId", SESSION_ID.slice(0, 31)],
    ["sessionId", `${SESSION_ID}0`],
    ["sessionId", SESSION_ID.toUpperCase()],
    ["sessionId", ""],
  ];
  for (const [key, value] of cases) {
    assertRejected((descriptor) => {
      descriptor[key] = value;
    }, "DESCRIPTOR_FIELD");
  }
});

test("party blocks enforce exact keys", () => {
  for (const party of ["payer", "payee"]) {
    for (const key of PARTY_KEYS) {
      assertRejected((descriptor) => {
        delete descriptor[party][key];
      }, "DESCRIPTOR_PARTY");
    }
    assertRejected((descriptor) => {
      descriptor[party].extra = "x";
    }, "DESCRIPTOR_PARTY");
    assertRejected((descriptor) => {
      descriptor[party] = "not-an-object";
    }, "DESCRIPTOR_PARTY");
  }
});

test("party addresses must be 0x-prefixed lowercase 40-hex", () => {
  const bad = [
    PAYER_ADDRESS.toUpperCase(),
    "0x00112233445566778899AABBCCDDEEFF00112233",
    PAYER_ADDRESS.slice(2),
    PAYER_ADDRESS.slice(0, 41),
    `${PAYER_ADDRESS}0`,
    "0x00112233445566778899aabbccddeeff0011223g",
    "",
  ];
  for (const value of bad) {
    assertRejected((descriptor) => {
      descriptor.payer.address = value;
    }, "DESCRIPTOR_PARTY");
  }
});

test("party agentId must be a canonical decimal string", () => {
  for (const value of ["007", "-1", "1.5", "", "0x10", " 8677", null]) {
    assertRejected((descriptor) => {
      descriptor.payee.agentId = value;
    }, "DESCRIPTOR_PARTY");
  }
  // agentId "0" is a valid decimal string.
  const descriptor = clone();
  descriptor.payee.agentId = "0";
  assert.equal(validateDescriptor(descriptor), undefined);
});

test("descriptor payer agentId fits the canonical EIP-155 reference boundary", () => {
  const atBoundary = clone();
  atBoundary.payer.agentId = "9".repeat(197);
  assert.equal(validateDescriptor(atBoundary), undefined);

  const overBoundary = clone();
  overBoundary.payer.agentId = "9".repeat(198);
  assert.throws(
    () => validateDescriptor(overBoundary),
    DescriptorValidationError,
  );
});

test("dSession accepts the payer reference boundary and rejects overflow", () => {
  const atBoundary = clone();
  atBoundary.payer.agentId = "9".repeat(197);
  assert.match(dSession(atBoundary), /^[0-9a-f]{64}$/);

  const overBoundary = clone();
  overBoundary.payer.agentId = "9".repeat(198);
  assert.throws(
    () => dSession(overBoundary),
    DescriptorValidationError,
  );
});

test("party displayName is bounded trimmed printable ASCII", () => {
  for (const value of [
    "",
    " Billy",
    "Billy ",
    "B\u0000illy",
    "Bïlly",
    "x".repeat(65),
    42,
  ]) {
    assertRejected((descriptor) => {
      descriptor.payer.displayName = value;
    }, "DESCRIPTOR_PARTY");
  }
  const descriptor = clone();
  descriptor.payer.displayName = "x".repeat(64);
  assert.equal(validateDescriptor(descriptor), undefined);
});

test("party roles are fixed to their slots", () => {
  assertRejected((descriptor) => {
    descriptor.payer.role = "payee";
  }, "DESCRIPTOR_PARTY");
  assertRejected((descriptor) => {
    descriptor.payee.role = "payer";
  }, "DESCRIPTOR_PARTY");
  assertRejected((descriptor) => {
    descriptor.payer.role = "Payer";
  }, "DESCRIPTOR_PARTY");
});

test("payer and payee must be distinct in address and agentId", () => {
  assertRejected((descriptor) => {
    descriptor.payee.address = descriptor.payer.address;
  }, "DESCRIPTOR_PARTY");
  assertRejected((descriptor) => {
    descriptor.payee.agentId = descriptor.payer.agentId;
  }, "DESCRIPTOR_PARTY");
});

test("amountOptions is bounded to 8 entries and non-empty", () => {
  assertRejected((descriptor) => {
    descriptor.amountOptions = [];
  }, "DESCRIPTOR_AMOUNT_OPTIONS");
  assertRejected((descriptor) => {
    descriptor.amountOptions = "USD:100";
  }, "DESCRIPTOR_AMOUNT_OPTIONS");

  const nine = Array.from({ length: 9 }, (_, index) => ({
    currency: "USD",
    value: `${index + 1}00`,
  })).sort((left, right) => (left.value < right.value ? -1 : 1));
  assertRejected((descriptor) => {
    descriptor.amountOptions = nine;
  }, "DESCRIPTOR_AMOUNT_OPTIONS");

  const eight = nine.slice(0, 8);
  const descriptor = clone();
  descriptor.amountOptions = eight;
  assert.equal(validateDescriptor(descriptor), undefined);
});

test("amountOptions entries have exactly currency and value", () => {
  assertRejected((descriptor) => {
    delete descriptor.amountOptions[0].currency;
  }, "DESCRIPTOR_AMOUNT_OPTIONS");
  assertRejected((descriptor) => {
    delete descriptor.amountOptions[0].value;
  }, "DESCRIPTOR_AMOUNT_OPTIONS");
  assertRejected((descriptor) => {
    descriptor.amountOptions[0].moved = false;
  }, "DESCRIPTOR_AMOUNT_OPTIONS");
  assertRejected((descriptor) => {
    descriptor.amountOptions[0] = null;
  }, "DESCRIPTOR_AMOUNT_OPTIONS");
});

test("amountOptions currency is three uppercase ASCII letters", () => {
  for (const value of ["usd", "US", "USDC", "U$D", "", 42]) {
    assertRejected((descriptor) => {
      descriptor.amountOptions[0].currency = value;
    }, "DESCRIPTOR_AMOUNT_OPTIONS");
  }
});

test("amountOptions values are positive canonical decimal strings", () => {
  for (const value of [
    "0",
    "0.0",
    "0.00",
    "0.50",
    "007",
    "-100",
    "+100",
    "1.0",
    "1.00",
    "1.",
    ".5",
    "1,000",
    "1e3",
    "",
    "100 ",
  ]) {
    assertRejected((descriptor) => {
      descriptor.amountOptions = [{ currency: "USD", value }];
    }, "DESCRIPTOR_AMOUNT_OPTIONS");
  }
  for (const value of ["100", "1.25", "0.5"]) {
    const descriptor = clone();
    descriptor.amountOptions = [{ currency: "USD", value }];
    assert.equal(validateDescriptor(descriptor), undefined);
  }
});

test("amountOptions must be strictly sorted and unique", () => {
  assertRejected((descriptor) => {
    descriptor.amountOptions = [
      { currency: "USD", value: "250" },
      { currency: "USD", value: "100" },
    ];
  }, "DESCRIPTOR_AMOUNT_OPTIONS");
  assertRejected((descriptor) => {
    descriptor.amountOptions = [
      { currency: "USD", value: "100" },
      { currency: "USD", value: "100" },
    ];
  }, "DESCRIPTOR_AMOUNT_OPTIONS");
  assertRejected((descriptor) => {
    descriptor.amountOptions = [
      { currency: "USD", value: "100" },
      { currency: "EUR", value: "100" },
    ];
  }, "DESCRIPTOR_AMOUNT_OPTIONS");
  // Sorted by currency first, then value, both in byte order.
  const descriptor = clone();
  descriptor.amountOptions = [
    { currency: "EUR", value: "100" },
    { currency: "USD", value: "100" },
    { currency: "USD", value: "250" },
  ];
  assert.equal(validateDescriptor(descriptor), undefined);
});

test("amountOptions must be a dense index-only data-property array", () => {
  assertRejected((descriptor) => {
    delete descriptor.amountOptions[0];
  }, "DESCRIPTOR_SNAPSHOT");
  assertRejected((descriptor) => {
    descriptor.amountOptions.extra = true;
  }, "DESCRIPTOR_SNAPSHOT");
  assertRejected((descriptor) => {
    descriptor.amountOptions[Symbol("extra")] = true;
  }, "DESCRIPTOR_SNAPSHOT");
  assertRejected((descriptor) => {
    Object.defineProperty(descriptor.amountOptions, "0", {
      enumerable: true,
      get() {
        return { currency: "USD", value: "100" };
      },
    });
  }, "DESCRIPTOR_SNAPSHOT");
});

test("descriptor snapshot uses own data descriptors without invoking get traps", () => {
  const descriptor = new Proxy(clone(), {
    get() {
      throw new Error("descriptor [[Get]] must be unreachable");
    },
  });
  assert.equal(validateDescriptor(descriptor), undefined);
  assert.equal(dSession(descriptor), PINNED_D_SESSION);
  const signature = signDescriptor(
    descriptor,
    OPERATOR.privateKeyPem,
  );
  assert.equal(
    verifyDescriptorSignature(
      descriptor,
      signature,
      OPERATOR.publicKeyPem,
    ),
    undefined,
  );
});

test("descriptor snapshot rejects get-vs-data-descriptor divergence", () => {
  const target = clone();
  target.paymentMoved = true;
  const descriptor = new Proxy(target, {
    get(object, key, receiver) {
      if (key === "paymentMoved") {
        return false;
      }
      return Reflect.get(object, key, receiver);
    },
  });
  assert.throws(
    () => validateDescriptor(descriptor),
    DescriptorValidationError,
  );
});

test("descriptor snapshot converts traversal trap failures to fixed typed errors", () => {
  for (const descriptor of [
    new Proxy(clone(), {
      ownKeys() {
        throw new Error("sensitive ownKeys detail");
      },
    }),
    new Proxy(clone(), {
      getOwnPropertyDescriptor() {
        throw new Error("sensitive descriptor detail");
      },
    }),
    new Proxy(clone(), {
      getPrototypeOf() {
        throw new Error("sensitive prototype detail");
      },
    }),
  ]) {
    assert.throws(
      () => validateDescriptor(descriptor),
      (error) => {
        assert.ok(error instanceof DescriptorValidationError);
        assert.equal(error.code, "DESCRIPTOR_SNAPSHOT");
        assert.doesNotMatch(error.message, /sensitive/u);
        return true;
      },
    );
  }
});

test("signDescriptor emits canonical base64 over canonical bytes", () => {
  const descriptor = clone();
  const signature = signDescriptor(descriptor, OPERATOR.privateKeyPem);
  assert.match(signature, /^[A-Za-z0-9+/]+={0,2}$/);
  assert.equal(Buffer.from(signature, "base64").length, 64);
  assert.equal(
    verifyDescriptorSignature(
      descriptor,
      signature,
      OPERATOR.publicKeyPem,
    ),
    undefined,
  );
});

test("descriptor signature decoding rejects oversized input before base64 decode", () => {
  const descriptor = clone();
  const oversized = "A".repeat(92);
  const originalBufferFrom = Buffer.from;
  Buffer.from = function guardedBufferFrom(value, ...arguments_) {
    if (value === oversized) {
      throw new Error("oversized signature reached decoder");
    }
    return originalBufferFrom(value, ...arguments_);
  };
  try {
    assert.throws(
      () =>
        verifyDescriptorSignature(
          descriptor,
          oversized,
          OPERATOR.publicKeyPem,
        ),
      DescriptorSignatureError,
    );
  } finally {
    Buffer.from = originalBufferFrom;
  }
});

test("hex descriptor signatures are rejected", () => {
  const descriptor = clone();
  const signature = signDescriptor(descriptor, OPERATOR.privateKeyPem);
  assert.throws(
    () =>
      verifyDescriptorSignature(
        descriptor,
        Buffer.from(signature, "base64").toString("hex"),
        OPERATOR.publicKeyPem,
      ),
    DescriptorSignatureError,
  );
});

test("a tampered descriptor fails signature verification", () => {
  const descriptor = clone();
  const signature = signDescriptor(descriptor, OPERATOR.privateKeyPem);
  const tampered = clone();
  tampered.amountOptions[1].value = "251";
  assert.throws(
    () =>
      verifyDescriptorSignature(
        tampered,
        signature,
        OPERATOR.publicKeyPem,
      ),
    DescriptorSignatureError,
  );
});

test("a signature only verifies under the signing key", () => {
  const descriptor = clone();
  const signature = signDescriptor(descriptor, OPERATOR.privateKeyPem);
  assert.throws(
    () =>
      verifyDescriptorSignature(
        descriptor,
        signature,
        IMPOSTOR.publicKeyPem,
      ),
    DescriptorSignatureError,
  );
});

test("malformed signature encodings are rejected with a typed error", () => {
  const descriptor = clone();
  for (const signature of [
    "",
    "not base64 !!",
    Buffer.alloc(63).toString("base64"),
    Buffer.alloc(65).toString("base64"),
    "ab".repeat(63),
    "ab".repeat(65),
    42,
    null,
  ]) {
    assert.throws(
      () =>
        verifyDescriptorSignature(
          descriptor,
          signature,
          OPERATOR.publicKeyPem,
        ),
      DescriptorSignatureError,
    );
  }
});

test("signing validates the descriptor and the key type", () => {
  const invalid = clone();
  invalid.paymentMoved = true;
  assert.throws(
    () => signDescriptor(invalid, OPERATOR.privateKeyPem),
    DescriptorValidationError,
  );

  assert.throws(
    () => signDescriptor(clone(), "not a pem"),
    DescriptorSignatureError,
  );
  const { privateKey } = generateKeyPairSync("ec", {
    namedCurve: "P-256",
  });
  const ecPem = privateKey.export({ format: "pem", type: "pkcs8" });
  assert.throws(
    () => signDescriptor(clone(), ecPem),
    DescriptorSignatureError,
  );
});

test("raw public key helpers round-trip against generated operator key", () => {
  assert.equal(
    publicKeyPemFromRawBase64(OPERATOR.publicKeyRawBase64),
    OPERATOR.publicKeyPem,
  );
  assert.equal(
    rawPublicKeyBase64FromPem(OPERATOR.publicKeyPem),
    OPERATOR.publicKeyRawBase64,
  );
  for (const raw of ["", "AAAA", `${OPERATOR.publicKeyRawBase64}\n`, 42]) {
    assert.throws(
      () => publicKeyPemFromRawBase64(raw),
      DescriptorError,
    );
  }
});

test("raw public key decoding rejects oversized input before base64 decode", () => {
  const oversized = "A".repeat(48);
  const originalBufferFrom = Buffer.from;
  Buffer.from = function guardedBufferFrom(value, ...arguments_) {
    if (value === oversized) {
      throw new Error("oversized public key reached decoder");
    }
    return originalBufferFrom(value, ...arguments_);
  };
  try {
    assert.throws(
      () => publicKeyPemFromRawBase64(oversized),
      DescriptorError,
    );
  } finally {
    Buffer.from = originalBufferFrom;
  }
});

test("public key PEM conversion accepts only canonical SPKI public PEM", () => {
  assert.throws(
    () => rawPublicKeyBase64FromPem(OPERATOR.privateKeyPem),
    DescriptorError,
  );
  assert.throws(
    () =>
      rawPublicKeyBase64FromPem(`${OPERATOR.publicKeyPem}\n`),
    DescriptorError,
  );
  assert.equal(
    rawPublicKeyBase64FromPem(OPERATOR.publicKeyPem),
    OPERATOR.publicKeyRawBase64,
  );
});

test("operatorPublicKeyPath pins the repository key location and keyId charset", () => {
  assert.equal(
    operatorPublicKeyPath("test-operator-1"),
    "docs/operator-keys/test-operator-1.pub",
  );
  assert.equal(KEY_ID_PATTERN.source, "^[a-z0-9][a-z0-9-]{0,63}$");
  for (const keyId of [
    "",
    "-leading",
    "Upper",
    "under_score",
    "dot.dot",
    "a/../escape",
    "x".repeat(65),
    42,
  ]) {
    assert.throws(
      () => operatorPublicKeyPath(keyId),
      DescriptorValidationError,
    );
  }
});

test("createSignedEnvelope emits the spec envelope shape", () => {
  const envelope = createSignedEnvelope(clone(), {
    keyId: OPERATOR.keyId,
    privateKeyPem: OPERATOR.privateKeyPem,
  });
  assert.deepEqual(Object.keys(envelope).sort(), [
    "descriptor",
    "operator",
  ]);
  assert.deepEqual(Object.keys(envelope.operator).sort(), [
    "algorithm",
    "keyId",
    "publicKey",
    "signature",
  ]);
  assert.equal(envelope.operator.algorithm, "ed25519");
  assert.equal(envelope.operator.keyId, OPERATOR.keyId);
  assert.equal(
    envelope.operator.publicKey,
    OPERATOR.publicKeyRawBase64,
  );
  assert.equal(
    verifyDescriptorSignature(
      envelope.descriptor,
      envelope.operator.signature,
      OPERATOR.publicKeyPem,
    ),
    undefined,
  );
});

test("createSignedEnvelope authenticates and deep-freezes one detached snapshot", () => {
  const descriptor = clone();
  const envelope = createSignedEnvelope(descriptor, {
    keyId: OPERATOR.keyId,
    privateKeyPem: OPERATOR.privateKeyPem,
  });
  descriptor.payer.displayName = "Mallory";
  descriptor.amountOptions[0].value = "101";

  assert.equal(envelope.descriptor.payer.displayName, "Billy");
  assert.equal(envelope.descriptor.amountOptions[0].value, "100");
  for (const value of [
    envelope,
    envelope.descriptor,
    envelope.descriptor.payer,
    envelope.descriptor.payee,
    envelope.descriptor.amountOptions,
    envelope.descriptor.amountOptions[0],
    envelope.operator,
  ]) {
    assert.ok(Object.isFrozen(value));
  }
  assert.throws(() => {
    envelope.descriptor.payer.displayName = "changed";
  }, TypeError);
  assert.equal(
    verifyDescriptorEnvelope(envelope, {
      repositoryPublicKey: OPERATOR.publicKeyRawBase64,
    }).dSession,
    PINNED_D_SESSION,
  );
});

test("verifyDescriptorEnvelope verifies against the repository key and returns dSession", () => {
  const envelope = createSignedEnvelope(clone(), {
    keyId: OPERATOR.keyId,
    privateKeyPem: OPERATOR.privateKeyPem,
  });
  const result = verifyDescriptorEnvelope(envelope, {
    repositoryPublicKey: OPERATOR.publicKeyRawBase64,
  });
  assert.deepEqual(result, { dSession: PINNED_D_SESSION });
  assert.ok(Object.isFrozen(result));
});

test("a shipped publicKey differing from the repository key is rejected even with a valid signature", () => {
  // The impostor signs honestly with its own key and ships its own
  // public key; the signature is internally consistent. The envelope
  // must still be rejected because the REPOSITORY key wins.
  const envelope = createSignedEnvelope(clone(), {
    keyId: OPERATOR.keyId,
    privateKeyPem: IMPOSTOR.privateKeyPem,
  });
  assert.equal(
    verifyDescriptorSignature(
      envelope.descriptor,
      envelope.operator.signature,
      IMPOSTOR.publicKeyPem,
    ),
    undefined,
  );
  assert.throws(
    () =>
      verifyDescriptorEnvelope(envelope, {
        repositoryPublicKey: OPERATOR.publicKeyRawBase64,
      }),
    OperatorKeyMismatchError,
  );
});

test("an envelope signed by the wrong key fails even when the shipped key matches the repository", () => {
  const envelope = createSignedEnvelope(clone(), {
    keyId: OPERATOR.keyId,
    privateKeyPem: IMPOSTOR.privateKeyPem,
  });
  const forged = structuredClone(envelope);
  forged.operator.publicKey = OPERATOR.publicKeyRawBase64;
  assert.throws(
    () =>
      verifyDescriptorEnvelope(forged, {
        repositoryPublicKey: OPERATOR.publicKeyRawBase64,
      }),
    DescriptorSignatureError,
  );
});

test("verifyDescriptorEnvelope rejects malformed envelopes with typed errors", () => {
  const good = createSignedEnvelope(clone(), {
    keyId: OPERATOR.keyId,
    privateKeyPem: OPERATOR.privateKeyPem,
  });
  const repositoryPublicKey = OPERATOR.publicKeyRawBase64;

  const mutations = [
    (envelope) => {
      envelope.extra = "x";
    },
    (envelope) => {
      delete envelope.operator;
    },
    (envelope) => {
      delete envelope.operator.keyId;
    },
    (envelope) => {
      envelope.operator.extra = "x";
    },
    (envelope) => {
      envelope.operator.algorithm = "Ed25519";
    },
    (envelope) => {
      envelope.operator.algorithm = "rsa";
    },
    (envelope) => {
      envelope.operator.keyId = "Bad_Key";
    },
    (envelope) => {
      envelope.descriptor.paymentMoved = true;
    },
  ];
  for (const mutate of mutations) {
    const envelope = structuredClone(good);
    mutate(envelope);
    assert.throws(
      () =>
        verifyDescriptorEnvelope(envelope, { repositoryPublicKey }),
      DescriptorError,
      "expected typed rejection",
    );
  }
  for (const invalid of [null, [], "envelope", 42]) {
    assert.throws(
      () =>
        verifyDescriptorEnvelope(invalid, { repositoryPublicKey }),
      DescriptorError,
    );
  }
});

test("a tampered envelope signature is rejected", () => {
  const envelope = structuredClone(
    createSignedEnvelope(clone(), {
      keyId: OPERATOR.keyId,
      privateKeyPem: OPERATOR.privateKeyPem,
    }),
  );
  const bytes = Buffer.from(envelope.operator.signature, "base64");
  bytes[0] ^= 0xff;
  envelope.operator.signature = bytes.toString("base64");
  assert.throws(
    () =>
      verifyDescriptorEnvelope(envelope, {
        repositoryPublicKey: OPERATOR.publicKeyRawBase64,
      }),
    DescriptorSignatureError,
  );
});

test("the repository key argument itself is validated strictly", () => {
  const envelope = createSignedEnvelope(clone(), {
    keyId: OPERATOR.keyId,
    privateKeyPem: OPERATOR.privateKeyPem,
  });
  for (const repositoryPublicKey of [
    undefined,
    null,
    "",
    "AAAA",
    `${OPERATOR.publicKeyRawBase64}\n`,
    ` ${OPERATOR.publicKeyRawBase64}`,
    42,
  ]) {
    assert.throws(
      () =>
        verifyDescriptorEnvelope(envelope, { repositoryPublicKey }),
      DescriptorError,
    );
  }
});

// --- scripts/create-session.mjs -------------------------------------------

const SCRIPT_SHA = "89abcdef0123456789abcdef0123456789abcdef";

function createArguments(root, overrides = {}) {
  const values = {
    "--key-id": "demo-operator-1",
    "--payer-address": PAYER_ADDRESS,
    "--payer-agent-id": "8677",
    "--payer-name": "Billy",
    "--payee-address": PAYEE_ADDRESS,
    "--payee-agent-id": "8678",
    "--payee-name": "Iris",
    "--amounts": "USD:250,USD:100",
    "--mandate-digest": "b".repeat(64),
    "--repository-sha": SCRIPT_SHA,
    "--prompt-sha256": PROMPT_SHA256,
    "--output": join(root, "session-envelope.json"),
    "--request-digest": "c".repeat(64),
    ...overrides,
  };
  return Object.entries(values)
    .filter(([, value]) => value !== undefined)
    .reduce(
      (arguments_, [flag, value]) => [
        ...arguments_,
        flag,
        value,
      ],
      ["create"],
    );
}

function keygenArguments(overrides = {}) {
  const values = {
    "--key-id": "demo-operator-1",
    ...overrides,
  };
  return Object.entries(values)
    .filter(([, value]) => value !== undefined)
    .reduce(
      (arguments_, [flag, value]) => [
        ...arguments_,
        flag,
        value,
      ],
      ["keygen"],
    );
}

function createOptions(root, repositoryPublicKeyFile, overrides = {}) {
  return {
    randomBytes: (size) => {
      assert.equal(size, 16);
      return Buffer.from(SESSION_ID, "hex");
    },
    readRepositoryFileAtSha: async ({
      path,
      repoRoot,
      repositorySha,
    }) => {
      assert.equal(repoRoot, root);
      assert.equal(repositorySha, SCRIPT_SHA);
      assert.equal(
        path,
        "docs/operator-keys/demo-operator-1.pub",
      );
      return repositoryPublicKeyFile;
    },
    resolveHeadSha: () => {
      throw new Error("resolveHeadSha must not run when --repository-sha is given");
    },
    ...overrides,
  };
}

async function makeRoot() {
  return mkdtemp(join(tmpdir(), "bilateral-session-"));
}

async function git(root, ...arguments_) {
  return execFileAsync("git", arguments_, {
    cwd: root,
    encoding: "utf8",
  });
}

async function keygen(root, overrides = {}) {
  return createSession(
    keygenArguments(),
    { repoRoot: root, ...overrides },
  );
}

function privateKeyPath(root) {
  return join(
    root,
    ".context/operator-keys/demo-operator-1.ed25519.pem",
  );
}

const TEST_FILE_SYSTEM = Object.freeze({
  lstat,
  mkdir,
  open,
  readFile,
  realpath,
  unlink,
  writeFile,
});

function instrumentedHandle(handle, {
  failMethod,
  onCall = () => {},
} = {}) {
  return {
    async close() {
      onCall("close");
      return handle.close();
    },
    async readFile(options) {
      onCall("readFile");
      if (failMethod === "readFile") {
        throw new Error("injected read failure");
      }
      return handle.readFile(options);
    },
    async stat() {
      onCall("stat");
      if (failMethod === "stat") {
        throw new Error("injected stat failure");
      }
      return handle.stat();
    },
    async sync() {
      onCall("sync");
      if (failMethod === "sync") {
        throw new Error("injected sync failure");
      }
      return handle.sync();
    },
    async writeFile(contents, options) {
      onCall("writeFile");
      if (failMethod === "writeFile") {
        throw new Error("injected write failure");
      }
      return handle.writeFile(contents, options);
    },
  };
}


























