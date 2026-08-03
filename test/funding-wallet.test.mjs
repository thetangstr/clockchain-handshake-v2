import { test } from "node:test";
import assert from "node:assert/strict";
import {
  createCipheriv,
  createHash,
  scrypt as scryptCallback,
} from "node:crypto";
import { chmod, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

import { keccak256 } from "viem";
import { privateKeyToAccount } from "viem/accounts";

import {
  FUNDING_PASSWORD_ENV,
  FUNDING_PASSWORD_FILE_ENV,
  openFundingWallet,
} from "../src/core/funding/wallet.mjs";

const scrypt = promisify(scryptCallback);
const WALLET_MODULE_PATH = fileURLToPath(
  new URL("../src/core/funding/wallet.mjs", import.meta.url),
);
const CHAIN_ID = 11155111;
const PASSWORD_CANARY = "pw-canary-not-in-output";
const PRIVATE_KEY_CANARY =
  "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const FUNDING_ADDRESS = privateKeyToAccount(PRIVATE_KEY_CANARY)
  .address.toLowerCase();

function hexBuffer(value) {
  return Buffer.from(value.replace(/^0x/u, ""), "hex");
}

async function createKeystore({
  privateKey = PRIVATE_KEY_CANARY,
  password = PASSWORD_CANARY,
  n = 2,
  r = 8,
  p = 1,
  dklen = 32,
  salt = "11".repeat(32),
  iv = "22".repeat(16),
} = {}) {
  const address = privateKeyToAccount(privateKey).address.toLowerCase();
  const derivedKey = await scrypt(password, hexBuffer(salt), dklen, {
    N: n,
    r,
    p,
  });
  const cipherText = createCipheriv(
    "aes-128-ctr",
    derivedKey.subarray(0, 16),
    hexBuffer(iv),
  ).update(hexBuffer(privateKey));
  return {
    version: 3,
    id: "11111111-2222-4333-8444-555555555555",
    address: address.slice(2),
    crypto: {
      ciphertext: cipherText.toString("hex"),
      cipherparams: { iv },
      cipher: "aes-128-ctr",
      kdf: "scrypt",
      kdfparams: { dklen, salt, n, r, p },
      mac: keccak256(
        Buffer.concat([derivedKey.subarray(16, 32), cipherText]),
      ).slice(2),
    },
  };
}

async function writePrivateJson(path, value) {
  await writeFile(path, `${JSON.stringify(value)}\n`, { mode: 0o600 });
  await chmod(path, 0o600);
}

async function writeFixture(t) {
  const keystore = await createKeystore();
  const root = await mkdtemp(join(tmpdir(), "funding-wallet-"));
  t.after(() => rm(root, { force: true, recursive: true }));
  const keystorePath = join(root, "funding-wallet.json");
  const metadataPath = join(root, "funding-wallet.public.json");
  await writePrivateJson(keystorePath, keystore);
  const keystoreBytes = await readFile(keystorePath);
  await writePrivateJson(metadataPath, {
    schemaVersion: 1,
    chainId: CHAIN_ID,
    fundingAddress: `0x${keystore.address}`,
    keystoreSha256: createHash("sha256").update(keystoreBytes).digest("hex"),
    createdAt: "2026-07-28T07:11:27.911Z",
  });
  return { keystorePath, metadataPath, root };
}

// Every test controls both password variables explicitly and restores the
// ambient environment afterwards, so no case can pass by inheriting a
// password from the shell that started the suite.
function configurePassword(t, { file, inline } = {}) {
  const previous = {
    [FUNDING_PASSWORD_ENV]: process.env[FUNDING_PASSWORD_ENV],
    [FUNDING_PASSWORD_FILE_ENV]: process.env[FUNDING_PASSWORD_FILE_ENV],
  };
  t.after(() => {
    for (const [key, value] of Object.entries(previous)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
  });
  for (const [key, value] of [
    [FUNDING_PASSWORD_FILE_ENV, file],
    [FUNDING_PASSWORD_ENV, inline],
  ]) {
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
}

async function writePasswordFile(root, mode, password = PASSWORD_CANARY) {
  const path = join(root, "funding-password.txt");
  await writeFile(path, `${password}\n`, { mode });
  await chmod(path, mode);
  return path;
}

function assertNoSecretLeak(error) {
  for (const secret of [PASSWORD_CANARY, PRIVATE_KEY_CANARY.slice(2)]) {
    assert.doesNotMatch(error.message, new RegExp(secret, "u"));
    assert.doesNotMatch(String(error.stack ?? ""), new RegExp(secret, "u"));
  }
}

test("openFundingWallet reads the password from the environment variable", async (t) => {
  const fixture = await writeFixture(t);
  configurePassword(t, { inline: PASSWORD_CANARY });

  const { account, metadata } = await openFundingWallet({
    keystorePath: fixture.keystorePath,
    metadataPath: fixture.metadataPath,
  });

  assert.equal(account.address.toLowerCase(), FUNDING_ADDRESS);
  assert.equal(metadata.fundingAddress, FUNDING_ADDRESS);
  assert.equal(metadata.chainId, CHAIN_ID);
});

test("openFundingWallet reads the password from a 0600 password file", async (t) => {
  const fixture = await writeFixture(t);
  const passwordPath = await writePasswordFile(fixture.root, 0o600);
  configurePassword(t, { file: passwordPath });

  const { account } = await openFundingWallet({
    keystorePath: fixture.keystorePath,
    metadataPath: fixture.metadataPath,
  });

  assert.equal(account.address.toLowerCase(), FUNDING_ADDRESS);
});

test("openFundingWallet refuses a password file with permissions looser than 0600", async (t) => {
  const fixture = await writeFixture(t);
  const passwordPath = await writePasswordFile(fixture.root, 0o644);
  configurePassword(t, { file: passwordPath, inline: PASSWORD_CANARY });

  const error = await openFundingWallet({
    keystorePath: fixture.keystorePath,
    metadataPath: fixture.metadataPath,
  }).then(
    () => assert.fail("a 0644 password file must be refused"),
    (rejection) => rejection,
  );

  assert.equal(error.name, "FundingPasswordFileError");
  assert.equal(error.code, "BILATERAL_FUNDING_PASSWORD_FILE_INVALID");
  assert.match(error.message, /0600/u);
  assertNoSecretLeak(error);
});

test("openFundingWallet fails closed with a named error when no password is configured", async (t) => {
  const fixture = await writeFixture(t);
  configurePassword(t, {});

  const error = await openFundingWallet({
    keystorePath: fixture.keystorePath,
    metadataPath: fixture.metadataPath,
  }).then(
    () => assert.fail("an unconfigured password must fail closed"),
    (rejection) => rejection,
  );

  assert.equal(error.name, "FundingPasswordNotConfiguredError");
  assert.equal(error.code, "BILATERAL_FUNDING_PASSWORD_NOT_CONFIGURED");
  assert.match(error.message, new RegExp(FUNDING_PASSWORD_FILE_ENV, "u"));
  assert.match(error.message, new RegExp(FUNDING_PASSWORD_ENV, "u"));
  assertNoSecretLeak(error);
});

test("the funding wallet module carries no OS credential-store references", async () => {
  const source = await readFile(WALLET_MODULE_PATH, "utf8");

  for (const forbidden of ["security", "keychain", "keytar"]) {
    assert.doesNotMatch(source, new RegExp(forbidden, "iu"));
  }
  assert.doesNotMatch(source, /child_process/u);
  assert.doesNotMatch(source, /find-generic-password/u);
});
