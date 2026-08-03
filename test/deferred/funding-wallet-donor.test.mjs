// PRUNED from test/funding-wallet-donor.test.mjs during M0.
// Exercises the macOS Keychain password path deleted in v2 (rule 1: no OS credential stores).

// dropped: openFundingWallet decrypts a strict Web3 v3 treasury and returns only public data plus a viem account
test("openFundingWallet decrypts a strict Web3 v3 treasury and returns only public data plus a viem account", async (t) => {
  const fixture = await writeFixture(t);
  const reader = passwordReader();

  const result = await openFundingWallet({
    keystorePath: fixture.keystorePath,
    metadataPath: fixture.metadataPath,
    dependencies: reader,
  });

  assert.deepEqual(passwordCalls.get(reader), [{
    account: FUNDING_KEYCHAIN_ACCOUNT,
    service: FUNDING_KEYCHAIN_SERVICE,
  }]);
  assert.equal(result.account.address.toLowerCase(), ADDRESS);
  assert.equal(typeof result.account.signTransaction, "function");
  assert.deepEqual(Object.keys(result.metadata), PUBLIC_METADATA_KEYS);
  assert.equal(result.metadata.fundingAddress, ADDRESS);
  assert.doesNotMatch(JSON.stringify(result), new RegExp(PASSWORD_CANARY, "u"));
  assert.doesNotMatch(JSON.stringify(result), new RegExp(PRIVATE_KEY_CANARY.slice(2), "u"));
  assert.equal("privateKey" in result, false);
  assert.equal("password" in result, false);
});

// dropped: openFundingWallet uses bounded nofollow reads and the production security command without leaking canaries
test("openFundingWallet uses bounded nofollow reads and the production security command without leaking canaries", async (t) => {
  const fixture = await writeFixture(t);
  const stdout = [];
  const stderr = [];
  const fsCalls = [];

  const result = await openFundingWallet({
    keystorePath: fixture.keystorePath,
    metadataPath: fixture.metadataPath,
    dependencies: {
      stdout: { write: (value) => stdout.push(String(value)) },
      stderr: { write: (value) => stderr.push(String(value)) },
      execFile: async (file, args, options) => {
        assert.equal(file, "/usr/bin/security");
        assert.deepEqual(args, [
          "find-generic-password",
          "-s",
          FUNDING_KEYCHAIN_SERVICE,
          "-a",
          FUNDING_KEYCHAIN_ACCOUNT,
          "-w",
        ]);
        assert.equal(options?.encoding, "utf8");
        assert.equal(options?.maxBuffer <= 4096, true);
        return { stdout: `${PASSWORD_CANARY}\n`, stderr: RPC_CANARY };
      },
      fs: {
        lstat,
        open: async (path, flags) => {
          fsCalls.push({ flags, path });
          return open(path, flags);
        },
      },
    },
  });

  assert.equal(result.account.address.toLowerCase(), ADDRESS);
  assert.ok(
    fsCalls.every(
      ({ flags }) => (flags & constants.O_ACCMODE) === constants.O_RDONLY,
    ),
  );
  if (constants.O_NOFOLLOW !== undefined) {
    assert.ok(fsCalls.every(({ flags }) => (flags & constants.O_NOFOLLOW) !== 0));
  }
  if (constants.O_NONBLOCK !== undefined) {
    assert.ok(fsCalls.every(({ flags }) => (flags & constants.O_NONBLOCK) !== 0));
  }
  const serialized = [
    JSON.stringify(result),
    stdout.join(""),
    stderr.join(""),
  ].join("\n");
  for (const canary of [PASSWORD_CANARY, PRIVATE_KEY_CANARY, RPC_CANARY]) {
    assert.doesNotMatch(serialized, new RegExp(canary.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&"), "u"));
  }

  const failure = await openFundingWallet({
    keystorePath: fixture.keystorePath,
    metadataPath: fixture.metadataPath,
    dependencies: passwordReader("wrong-password-canary"),
  }).then(
    () => assert.fail("wrong password must fail"),
    (error) => error,
  );
  assert.equal(failure.message, "Bilateral funding failed safely.");
  assert.doesNotMatch(failure.message, /wrong-password-canary/u);
  assert.doesNotMatch(failure.message, new RegExp(PRIVATE_KEY_CANARY.slice(2), "u"));
});