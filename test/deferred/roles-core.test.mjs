// PRUNED from test/roles-core.test.mjs during M0.
// Exercises the invitation/CLI layer severed from roles-core (v2 roles are driven by src/roles/* wrappers, M1a).

// dropped: both CLIs require the exact frozen path flags and valueless write acknowledgement
test("both CLIs require the exact frozen path flags and valueless write acknowledgement", async () => {
  assert.deepEqual(ROLE_CLI_ARGUMENTS, [
    "--descriptor",
    "--invitation",
    "--clockchain-token-file",
    "--output",
  ]);
  assert.equal(
    ROLE_RISK_FLAG,
    "--i-understand-this-writes-to-clockchain",
  );
  const arguments_ = [
    "--descriptor",
    "/public/session.json",
    "--invitation",
    "/secret/invitation.json",
    "--clockchain-token-file",
    "/secret/clockchain.token",
    "--output",
    "/evidence/payer",
    ROLE_RISK_FLAG,
  ];
  for (const [main, role, state] of [
    [proposeMain, "payer", "ACKNOWLEDGED"],
    [acceptMain, "payee", "ACCEPTED"],
  ]) {
    const roleArguments = arguments_.map((value, index) => (
      arguments_[index - 1] === "--output" ? `/evidence/${role}` : value
    ));
    const writes = [];
    const seen = [];
    const exitCode = await main(roleArguments, {
      buildRoleInput: async (values, actualRole) => {
        seen.push([values, actualRole]);
        return {};
      },
      runRole: async () => ({
        localVerdict: "LOCAL_OK",
        paymentMoved: false,
        role,
        state,
      }),
      stderr: { write: (value) => writes.push(["err", value]) },
      stdout: { write: (value) => writes.push(["out", value]) },
    });
    assert.equal(exitCode, 0);
    assert.equal(seen[0][1], role);
    assert.deepEqual(seen[0][0], {
      descriptorPath: "/public/session.json",
      invitationPath: "/secret/invitation.json",
      clockchainTokenPath: "/secret/clockchain.token",
      outputDirectory: `/evidence/${role === "payer" ? "payer" : "payee"}`,
    });
    assert.deepEqual(writes, [[
      "out",
      `${JSON.stringify({
        localVerdict: "LOCAL_OK",
        paymentMoved: false,
        role,
        state,
      })}\n`,
    ]]);
  }
});

// dropped: default builder fails provenance closed before secrets, clients, or tokens
test("default builder fails provenance closed before secrets, clients, or tokens", async (t) => {
  const cases = [
    {
      name: "wrong full HEAD",
      override: {
        repositoryStateResolver: async () => ({
          headSha:
            "fedcba9876543210fedcba9876543210fedcba98",
          worktreeStatus: "",
        }),
      },
    },
    {
      name: "dirty worktree",
      override: {
        repositoryStateResolver: async () => ({
          headSha:
            "0123456789abcdef0123456789abcdef01234567",
          worktreeStatus: " M src/bilateral/roles.mjs\n",
        }),
      },
    },
    {
      name: "state resolution failure",
      override: {
        repositoryStateResolver: async () => {
          throw new Error("git failed");
        },
      },
    },
    {
      name: "prompt bundle mismatch",
      override: {
        repositoryPromptResolver: async ({
          repositoryPath,
        }) =>
          Buffer.from(
            repositoryPath.includes("payer")
              ? `${REPOSITORY_PROMPTS.payer}mutated\n`
              : REPOSITORY_PROMPTS.payee,
          ),
      },
    },
    {
      name: "prompt resolution failure",
      override: {
        repositoryPromptResolver: async () => {
          throw new Error("git show failed");
        },
      },
    },
  ];

  for (const scenario of cases) {
    await t.test(scenario.name, async (t) => {
      const fixture = await defaultBuilderFixture(t);
      const calls = {
        clockchainClients: 0,
        identityClients: 0,
        secretReads: 0,
        tokenReads: 0,
      };
      const dependencies = {
        ...fixture.dependencies,
        ...scenario.override,
        createClockchainClient() {
          calls.clockchainClients += 1;
          return {};
        },
        createIdentityClient() {
          calls.identityClients += 1;
          return {};
        },
        fileSystem: {
          async open(path, flags, mode) {
            if (path === fixture.values.clockchainTokenPath) {
              calls.tokenReads += 1;
            }
            return nodeOpen(path, flags, mode);
          },
        },
        async loadInvitation() {
          calls.secretReads += 1;
          throw new Error("must not read invitation");
        },
      };

      await assert.rejects(
        buildDefaultRoleInput(
          fixture.values,
          "payer",
          dependencies,
        ),
        (error) =>
          error instanceof ProtocolFailureError &&
          error.terminalCode === "FAILED",
      );
      assert.deepEqual(calls, {
        clockchainClients: 0,
        identityClients: 0,
        secretReads: 0,
        tokenReads: 0,
      });
    });
  }
});

// dropped: default builder binds the live identity RPC chain before reading protected credential files
test("default builder binds the live identity RPC chain before reading protected credential files", async (t) => {
  for (const chainId of [
    11155112,
    "11155112",
    11155111.5,
    "011155111",
    -1,
    null,
    {},
  ]) {
    await t.test(String(chainId), async (t) => {
      const fixture = await defaultBuilderFixture(t);
      const calls = {
        clockchainClients: 0,
        secretReads: 0,
        tokenReads: 0,
      };
      const dependencies = {
        ...fixture.dependencies,
        createClockchainClient() {
          calls.clockchainClients += 1;
          return {};
        },
        createIdentityClient: () => ({
          async getChainId() {
            return chainId;
          },
          async readContract() {
            return PAYER_ADDRESS;
          },
        }),
        fileSystem: {
          async open(path, flags, mode) {
            if (path === fixture.values.clockchainTokenPath) {
              calls.tokenReads += 1;
            }
            return nodeOpen(path, flags, mode);
          },
        },
        async loadInvitation() {
          calls.secretReads += 1;
          throw new Error("must not read invitation");
        },
      };

      await assert.rejects(
        buildDefaultRoleInput(
          fixture.values,
          "payer",
          dependencies,
        ),
        ProtocolFailureError,
      );
      assert.deepEqual(calls, {
        clockchainClients: 0,
        secretReads: 0,
        tokenReads: 0,
      });
    });
  }
});

// dropped: default builder safely reuses an existing intent directory without live network
test("default builder safely reuses an existing intent directory without live network", async (t) => {
  const fixture = await defaultBuilderFixture(t);
  const first = await buildDefaultRoleInput(
    fixture.values,
    "payer",
    fixture.dependencies,
  );
  const second = await buildDefaultRoleInput(
    fixture.values,
    "payer",
    fixture.dependencies,
  );

  assert.equal(first.outputDirectory, fixture.values.outputDirectory);
  assert.equal(second.outputDirectory, fixture.values.outputDirectory);
  assert.equal(first.client.token, "clockchain-token-canary");
  assert.equal(
    await first.ownerOf({
      agentId: "8677",
      registry:
        "0x8004a818bfb912233c491871b3d84c89a494bd9e",
    }),
    PAYER_ADDRESS,
  );
  assert.ok(first.canaries.includes(fixture.privateKey));
  assert.ok(first.canaries.includes("clockchain-token-canary"));
});

// dropped: default builder emits full-size overlapping canaries for long secrets
test("default builder emits full-size overlapping canaries for long secrets", async (t) => {
  const fragmentExpectation = (secret) => {
    if (secret.length <= 256) {
      return [secret];
    }
    const fragments = [];
    for (let offset = 0; offset + 256 <= secret.length; offset += 256) {
      fragments.push(secret.slice(offset, offset + 256));
    }
    if (secret.length % 256 !== 0) {
      fragments.push(secret.slice(secret.length - 256));
    }
    return fragments;
  };
  const tokenForLength = (length) =>
    length === 257
      ? `${"a".repeat(256)}e`
      : Array.from(
        { length },
        (_value, index) =>
          String.fromCharCode(33 + (index % 90)),
      ).join("");

  for (const length of [256, 257, 4096]) {
    await t.test(`token length ${length}`, async (t) => {
      const fixture = await defaultBuilderFixture(t);
      const invitation = JSON.parse(
        await readFile(fixture.values.invitationPath, "utf8"),
      );
      assert.ok(
        invitation.bundle.crypto.ciphertext.length > 256,
      );
      const token = tokenForLength(length);
      await writeFile(
        fixture.values.clockchainTokenPath,
        length === 4096 ? token : `${token}\n`,
        { mode: 0o600 },
      );

      const input = await buildDefaultRoleInput(
        fixture.values,
        "payer",
        fixture.dependencies,
      );
      const expected = [
        invitation.code,
        invitation.bundle.crypto.ciphertext,
        fixture.privateKey,
        token,
      ].flatMap(fragmentExpectation);
      const tokenFragments = input.canaries.slice(
        -fragmentExpectation(token).length,
      );

      assert.deepEqual(input.canaries, expected);
      assert.ok(tokenFragments.every(
        (fragment) => fragment.length === 256,
      ));
      assert.equal(
        tokenFragments[0], token.slice(0, 256),
      );
      assert.equal(
        tokenFragments.at(-1), token.slice(-256));
      assert.throws(() => assertSecretFree(token, tokenFragments));
      assert.doesNotThrow(() =>
        assertSecretFree("ordinary rendered evidence", tokenFragments),
      );
    });
  }

  await t.test("accepted maximum credential sizes stay within the evidence ceiling", async (t) => {
    const fixture = await defaultBuilderFixture(t);
    const code = "c".repeat(1024);
    const ciphertext = "d".repeat(8192);
    const token = tokenForLength(4096);
    await writeFile(
      fixture.values.clockchainTokenPath,
      token,
      { mode: 0o600 },
    );

    const input = await buildDefaultRoleInput(
      fixture.values,
      "payer",
      {
        ...fixture.dependencies,
        async decryptInvitation() {
          return {
            address: PAYER_ADDRESS,
            privateKey: fixture.privateKey,
          };
        },
        async loadInvitation() {
          return {
            bundle: { crypto: { ciphertext } },
            code,
          };
        },
      },
    );
    const expected = [
      code,
      ciphertext,
      fixture.privateKey,
      token,
    ].flatMap(fragmentExpectation);

    assert.equal(input.canaries.length, 53);
    assert.ok(input.canaries.every(
      (canary) => canary.length > 0 && canary.length <= 256,
    ));
    assert.deepEqual(input.canaries, expected);
  });
});

// dropped: default role builder bounds descriptor and token reads at max plus one
test("default role builder bounds descriptor and token reads at max plus one", async (t) => {
  for (const target of ["descriptor", "token"]) {
    await t.test(target, async (t) => {
      const fixture = await defaultBuilderFixture(t);
      const targetPath =
        target === "descriptor"
          ? fixture.values.descriptorPath
          : fixture.values.clockchainTokenPath;
      let readLength = 0;
      await assert.rejects(
        buildDefaultRoleInput(
          fixture.values,
          "payer",
          {
            ...fixture.dependencies,
            fileSystem: {
              async open(path, flags, mode) {
                const handle = await nodeOpen(path, flags, mode);
                return path === targetPath
                  ? adversarialReadHandle(handle, {
                      onRead(length) {
                        readLength = length;
                      },
                      overflow: true,
                    })
                  : handle;
              },
            },
          },
        ),
        ProtocolFailureError,
      );
      assert.equal(
        readLength,
        target === "descriptor"
          ? (1024 * 1024) + 1
          : 4097,
      );
    });
  }
});

// dropped: default role builder rejects full-metadata races after bounded reads
test("default role builder rejects full-metadata races after bounded reads", async (t) => {
  for (const target of ["descriptor", "token"]) {
    await t.test(target, async (t) => {
      const fixture = await defaultBuilderFixture(t);
      const targetPath =
        target === "descriptor"
          ? fixture.values.descriptorPath
          : fixture.values.clockchainTokenPath;
      const readLengths = [];
      await assert.rejects(
        buildDefaultRoleInput(
          fixture.values,
          "payer",
          {
            ...fixture.dependencies,
            fileSystem: {
              async open(path, flags, mode) {
                const handle = await nodeOpen(path, flags, mode);
                return path === targetPath
                  ? adversarialReadHandle(handle, {
                      metadataField: "ctimeMs",
                      onRead(length) {
                        readLengths.push(length);
                      },
                    })
                  : handle;
              },
            },
          },
        ),
        ProtocolFailureError,
      );
      assert.equal(
        readLengths[0],
        target === "descriptor"
          ? (1024 * 1024) + 1
          : 4097,
      );
      assert.ok(readLengths.length >= 2);
    });
  }
});

// dropped: default builder rejects unsafe output, invitation, token, and duplicate-key inputs before a Clockchain client
test("default builder rejects unsafe output, invitation, token, and duplicate-key inputs before a Clockchain client", async (t) => {
  const fixture = await defaultBuilderFixture(t);
  let clockchainClients = 0;
  const dependencies = {
    ...fixture.dependencies,
    createClockchainClient: () => {
      clockchainClients += 1;
      return {};
    },
  };

  await chmod(fixture.values.outputDirectory, 0o755);
  await assert.rejects(
    buildDefaultRoleInput(
      fixture.values,
      "payer",
      dependencies,
    ),
    ProtocolFailureError,
  );
  await chmod(fixture.values.outputDirectory, 0o700);

  const linkedOutput = join(
    fixture.values.outputDirectory,
    "..",
    "linked-output",
  );
  await symlink(fixture.values.outputDirectory, linkedOutput);
  await assert.rejects(
    buildDefaultRoleInput(
      {
        ...fixture.values,
        outputDirectory: linkedOutput,
      },
      "payer",
      dependencies,
    ),
    ProtocolFailureError,
  );

  const fileOutput = join(
    fixture.values.outputDirectory,
    "..",
    "file-output",
  );
  await writeFile(fileOutput, "not a directory\n", {
    mode: 0o600,
  });
  await assert.rejects(
    buildDefaultRoleInput(
      {
        ...fixture.values,
        outputDirectory: fileOutput,
      },
      "payer",
      dependencies,
    ),
    ProtocolFailureError,
  );

  await chmod(fixture.values.invitationPath, 0o644);
  await assert.rejects(
    buildDefaultRoleInput(
      fixture.values,
      "payer",
      dependencies,
    ),
    ProtocolFailureError,
  );
  await chmod(fixture.values.invitationPath, 0o600);

  await chmod(fixture.values.clockchainTokenPath, 0o644);
  await assert.rejects(
    buildDefaultRoleInput(
      fixture.values,
      "payer",
      dependencies,
    ),
    ProtocolFailureError,
  );
  await chmod(fixture.values.clockchainTokenPath, 0o600);

  await chmod(fixture.values.clockchainTokenPath, 0o400);
  await assert.rejects(
    buildDefaultRoleInput(
      fixture.values,
      "payer",
      dependencies,
    ),
    ProtocolFailureError,
  );
  await chmod(fixture.values.clockchainTokenPath, 0o600);

  const linkedToken = join(
    fixture.values.outputDirectory,
    "..",
    "linked-clockchain.token",
  );
  await symlink(
    fixture.values.clockchainTokenPath,
    linkedToken,
  );
  await assert.rejects(
    buildDefaultRoleInput(
      {
        ...fixture.values,
        clockchainTokenPath: linkedToken,
      },
      "payer",
      dependencies,
    ),
    ProtocolFailureError,
  );

  await assert.rejects(
    buildDefaultRoleInput(
      {
        ...fixture.values,
        clockchainTokenPath: join(
          fixture.values.outputDirectory,
          "..",
          "missing-clockchain.token",
        ),
      },
      "payer",
      dependencies,
    ),
    ProtocolFailureError,
  );

  await writeFile(
    fixture.values.clockchainTokenPath,
    "\n",
    { mode: 0o600 },
  );
  await assert.rejects(
    buildDefaultRoleInput(
      fixture.values,
      "payer",
      dependencies,
    ),
    ProtocolFailureError,
  );

  await writeFile(
    fixture.values.clockchainTokenPath,
    ` ${fixture.token} \n`,
    { mode: 0o600 },
  );
  await assert.rejects(
    buildDefaultRoleInput(
      fixture.values,
      "payer",
      dependencies,
    ),
    ProtocolFailureError,
  );

  await assert.rejects(
    buildDefaultRoleInput(
      {
        ...fixture.values,
        privateKeyPath: join(
          fixture.values.outputDirectory,
          "duplicate-secret.key",
        ),
      },
      "payer",
      dependencies,
    ),
    ProtocolFailureError,
  );
  assert.equal(clockchainClients, 0);
});

// --- second pass: blocks spawning donor CLI binaries (bin/handshake-*.mjs) ---
// v2 drives roles through src/roles/* wrappers (M1a); re-point and re-enable there.

// dropped: role CLIs dispatch through generic protocol runners
test("role CLIs dispatch through generic protocol runners", async () => {
  const files = [
    ["../bin/handshake-propose.mjs", "runPayerRole", "runIrisRole"],
    ["../bin/handshake-accept.mjs", "runPayeeRole", "runBillieRole"],
  ];
  for (const [relative, expected, rejected] of files) {
    const source = await readFile(
      new URL(relative, import.meta.url),
      "utf8",
    );
    assert.match(source, new RegExp(`\\b${expected}\\b`), relative);
    assert.doesNotMatch(source, new RegExp(`\\b${rejected}\\b`), relative);
  }
});

// dropped: role modules and CLIs contain no authorizing verdict literal
test("role modules and CLIs contain no authorizing verdict literal", async () => {
  for (const relative of [
    "../src/core/roles-core.mjs",
    "../bin/handshake-propose.mjs",
    "../bin/handshake-accept.mjs",
  ]) {
    const source = await import("node:fs/promises").then(
      ({ readFile }) =>
        readFile(new URL(relative, import.meta.url), "utf8"),
    );
    assert.equal(
      source.includes(`AUTHOR${"IZED"}`),
      false,
    );
  }
});

// --- third pass: severed CLI surface / donor prompt files ---

// dropped: actual mapped role prompts are canonical Payer and Requestor surfaces
test("actual mapped role prompts are canonical Payer and Requestor surfaces", async () => {
  const paths = Object.freeze({
    payer: "prompts/run-payer-bilateral-demo.md",
    payee: "prompts/run-requestor-bilateral-demo.md",
  });
  const [payer, payee] = await Promise.all([
    readFile(join(ROLE_REPOSITORY_ROOT, paths.payer), "utf8"),
    readFile(join(ROLE_REPOSITORY_ROOT, paths.payee), "utf8"),
  ]);
  assert.match(
    payer,
    /You are the Payer\./,
  );
  assert.match(payer, /\bPROPOSED\b/);
  assert.match(payer, /\bACKNOWLEDGED\b/);
  assert.doesNotMatch(payer, /\bPayer\b[^.\n]*\bpayee\b/i);
  assert.doesNotMatch(payer, /\bRequestor\b[^.\n]*\banchors `PROPOSED`\b/i);

  assert.match(
    payee,
    /You are the Requestor\./,
  );
  assert.match(payee, /\brequestor\b/i);
  assert.match(payee, /\bACCEPTED\b/);
  assert.match(payee, /\bPayer-owned MCP\b/);
  assert.match(payee, /\bHANDSHAKE_REQUIRED\b/);
  assert.doesNotMatch(payee, /\bPayer\b[^.\n]*\bpayee\b/i);
  assert.doesNotMatch(payee, /\bRequestor\b[^.\n]*\banchors `PROPOSED`\b/i);

  await Promise.all(
    Object.values(paths).map((repositoryPath) =>
      execFileAsync("git", [
        "ls-files",
        "--cached",
        "--others",
        "--exclude-standard",
        "--error-unmatch",
        repositoryPath,
      ], { cwd: ROLE_REPOSITORY_ROOT }),
    ),
  );
});

// --- fourth pass: donor CLI entrypoints (proposeMain/acceptMain) ---

// dropped: role CLIs reject missing acknowledgement, extra flags, and secret argv without calling dependencies
test("role CLIs reject missing acknowledgement, extra flags, and secret argv without calling dependencies", async () => {
  let calls = 0;
  const dependencies = {
    buildRoleInput: async () => {
      calls += 1;
    },
    runRole: async () => {
      calls += 1;
    },
    stderr: { write() {} },
    stdout: { write() {} },
  };
  for (const arguments_ of [
    [],
    [
      "--descriptor", "d",
      "--invitation", "i",
      "--clockchain-token-file", "t",
      "--output", "o",
    ],
    [
      "--descriptor", "d",
      "--invitation", "i",
      "--clockchain-token-file", "t",
      "--output", "o",
      "--private-key-file", "k",
      ROLE_RISK_FLAG,
    ],
    [
      "--descriptor", "d",
      "--invitation", "i",
      "--clockchain-token-file", "t",
      "--output", "o",
      "--private-key", "secret",
      ROLE_RISK_FLAG,
    ],
    [
      "--descriptor", "d",
      "--invitation", "i",
      "--clockchain-token-file", "t",
      "--output", "o",
      ROLE_RISK_FLAG,
      "yes",
    ],
  ]) {
    assert.equal(
      await proposeMain(arguments_, dependencies),
      1,
    );
  }
  assert.equal(calls, 0);
});

// dropped: role CLI emits readiness only after valid argv and input construction
test("role CLI emits readiness only after valid argv and input construction", async () => {
  const writes = [];
  let entered = false;
  const arguments_ = [
    "--descriptor", "/public/session.json",
    "--invitation", "/secret/invitation.json",
    "--clockchain-token-file", "/secret/clockchain.token",
    "--output", "/evidence/payer",
    ROLE_RISK_FLAG,
  ];
  const exitCode = await proposeMain(arguments_, {
    buildRoleInput: async () => ({
      notifyReady: () => writes.push("ready"),
    }),
    runRole: async (input) => {
      input.notifyReady();
      entered = true;
      return { localVerdict: "LOCAL_OK", paymentMoved: false, state: "ACKNOWLEDGED" };
    },
    stderr: { write() {} },
    stdout: { write() {} },
  });
  assert.equal(exitCode, 0);
  assert.deepEqual(writes, ["ready"]);
  assert.equal(entered, true);

  writes.length = 0;
  assert.equal(await proposeMain([], {
    buildRoleInput: async () => assert.fail("invalid argv must not build input"),
    runRole: async () => assert.fail("invalid argv must not enter role"),
    stderr: { write() {} },
    stdout: { write() {} },
  }), 1);
  assert.deepEqual(writes, []);
});