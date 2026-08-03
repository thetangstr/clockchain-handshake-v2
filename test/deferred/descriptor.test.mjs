// DEFERRED from test/descriptor.test.mjs during M0.
// Depends on the donor session-creation script; v2 builds descriptors in src/roles/operator.mjs (M1a).
// Re-point at the v2 module and re-enable at the milestone named above.
// Symbols that were imported from scripts/create-session.mjs: SessionCreationError

test("keygen rejects symlink ancestors without writing outside the repository", async () => {
  const cases = [
    {
      ancestor: ".context",
    },
    {
      ancestor: ".context/operator-keys",
      parent: ".context",
      parentMode: 0o700,
    },
    {
      ancestor: "docs",
    },
    {
      ancestor: "docs/operator-keys",
      parent: "docs",
      parentMode: 0o755,
    },
  ];

  for (const setup of cases) {
    const root = await makeRoot();
    const outside = await makeRoot();
    if (setup.parent) {
      await mkdir(join(root, setup.parent), {
        mode: setup.parentMode,
      });
    }
    await symlink(outside, join(root, setup.ancestor));

    await assert.rejects(keygen(root), SessionCreationError);
    assert.deepEqual(await readdir(outside), []);
    await assert.rejects(stat(privateKeyPath(root)), {
      code: "ENOENT",
    });
  }
});

test("keygen revalidates a replaced private-key parent before writing secret bytes", async () => {
  const root = await makeRoot();
  const outside = await makeRoot();
  const stolenDirectory = join(outside, "stolen-operator-keys");
  const routedDirectory = join(outside, "routed-operator-keys");
  await mkdir(routedDirectory, { mode: 0o700 });
  let swapped = false;
  const fileSystem = {
    ...TEST_FILE_SYSTEM,
    open: async (path, flags, mode) => {
      const handle = await open(path, flags, mode);
      if (
        !swapped &&
        path.endsWith("demo-operator-1.ed25519.pem")
      ) {
        swapped = true;
        const parent = join(root, ".context/operator-keys");
        await rename(parent, stolenDirectory);
        await symlink(routedDirectory, parent);
      }
      return handle;
    },
    async unlink() {
      const error = new Error("cleanup denied");
      error.code = "EPERM";
      throw error;
    },
  };

  await assert.rejects(
    keygen(root, { fileSystem }),
    SessionCreationError,
  );
  assert.equal(swapped, true);
  assert.equal(
    await readFile(
      join(stolenDirectory, "demo-operator-1.ed25519.pem"),
      "utf8",
    ),
    "",
  );
  assert.deepEqual(await readdir(routedDirectory), []);
});

test("keygen rejects a permissive operator-keys directory", async () => {
  const root = await makeRoot();
  await mkdir(join(root, ".context"), { mode: 0o755 });
  await mkdir(join(root, ".context/operator-keys"), {
    mode: 0o755,
  });

  await assert.rejects(keygen(root), SessionCreationError);
  await assert.rejects(stat(privateKeyPath(root)), {
    code: "ENOENT",
  });
});

test("keygen removes exclusively created partial files after write or sync failure", async () => {
  for (const failure of [
    { method: "writeFile", suffix: ".ed25519.pem" },
    { method: "sync", suffix: ".pub" },
  ]) {
    const root = await makeRoot();
    const fileSystem = {
      ...TEST_FILE_SYSTEM,
      open: async (path, flags, mode) =>
        instrumentedHandle(
          await open(path, flags, mode),
          {
            failMethod: path.endsWith(failure.suffix)
              ? failure.method
              : undefined,
          },
        ),
    };
    await assert.rejects(
      keygen(root, { fileSystem }),
      SessionCreationError,
    );
    await assert.rejects(stat(privateKeyPath(root)), {
      code: "ENOENT",
    });
    await assert.rejects(
      stat(
        join(
          root,
          "docs/operator-keys/demo-operator-1.pub",
        ),
      ),
      { code: "ENOENT" },
    );
  }
});

test("create requires exact public intent digest flags", async () => {
  const root = await makeRoot();
  const keyReport = await keygen(root);
  const repositoryPublicKeyFile = await readFile(
    keyReport.publicKeyPath,
    "utf8",
  );
  const options = {
    repoRoot: root,
    ...createOptions(root, repositoryPublicKeyFile),
  };
  const accepted = await createSession(
    createArguments(root, {
      "--output": join(root, "accepted.json"),
    }),
    options,
  );
  assert.equal(
    accepted.envelope.descriptor.mandateDigest,
    "b".repeat(64),
  );
  assert.equal(
    accepted.envelope.descriptor.requestDigest, "c".repeat(64));
  for (const [index, overrides] of [
    { "--mandate-digest": undefined },
    { "--request-digest": undefined },
    { "--mandate-digest": "B".repeat(64) },
    { "--request-digest": "c".repeat(63) },
  ].entries()) {
    await assert.rejects(
      createSession(
        createArguments(root, {
          "--output": join(root, `reject-${index}.json`),
          ...overrides,
        }),
        options,
      ),
      SessionCreationError,
    );
  }
  await assert.rejects(
    createSession(
      [
        ...createArguments(root, {
          "--output": join(root, "duplicate.json"),
        }),
        "--mandate-digest",
        "b".repeat(64),
      ],
      options,
    ),
    SessionCreationError,
  );
});

test("create CLI accepts the payer reference boundary and rejects overflow", async () => {
  const root = await makeRoot();
  const keyReport = await keygen(root);
  const repositoryPublicKeyFile = await readFile(
    keyReport.publicKeyPath,
    "utf8",
  );
  let stdout = "";
  const dependencies = {
    repoRoot: root,
    ...createOptions(root, repositoryPublicKeyFile),
    writeStdout(value) {
      stdout += value;
    },
  };

  const accepted = await runCreateSessionCli(
    createArguments(root, {
      "--payer-agent-id": "9".repeat(197),
    }),
    dependencies,
  );
  assert.equal(
    accepted.envelope.descriptor.payer.agentId,
    "9".repeat(197),
  );
  assert.deepEqual(JSON.parse(stdout), accepted.envelope);

  await assert.rejects(
    runCreateSessionCli(
      createArguments(root, {
        "--output": join(root, "overflow-session.json"),
        "--payer-agent-id": "9".repeat(198),
      }),
      dependencies,
    ),
    SessionCreationError,
  );
});

test("create bounds --amounts bytes before splitting operator input", async () => {
  const root = await makeRoot();
  const keyReport = await keygen(root);
  const repositoryPublicKeyFile = await readFile(
    keyReport.publicKeyPath,
    "utf8",
  );
  const oversized = `USD:${"1".repeat(2_084)}`;
  assert.equal(Buffer.byteLength(oversized, "utf8"), 2_088);
  const originalSplit = String.prototype.split;
  String.prototype.split = function guardedSplit(
    separator,
    limit,
  ) {
    if (this.toString() === oversized) {
      throw new Error("oversized amounts reached split");
    }
    return originalSplit.call(this, separator, limit);
  };
  try {
    await assert.rejects(
      createSession(
        createArguments(root, { "--amounts": oversized }),
        {
          repoRoot: root,
          ...createOptions(root, repositoryPublicKeyFile),
        },
      ),
      SessionCreationError,
    );
  } finally {
    String.prototype.split = originalSplit;
  }
});

test("create rejects oversized prompt files before reading their bytes", async () => {
  const root = await makeRoot();
  const keyReport = await keygen(root);
  const repositoryPublicKeyFile = await readFile(
    keyReport.publicKeyPath,
    "utf8",
  );
  const promptPath = join(root, "oversized-prompt.md");
  await writeFile(promptPath, Buffer.alloc(65_537, 0x61));
  let promptReads = 0;
  const fileSystem = {
    ...TEST_FILE_SYSTEM,
    readFile: async (path, ...arguments_) => {
      if (path === promptPath) {
        promptReads += 1;
      }
      return readFile(path, ...arguments_);
    },
  };
  await assert.rejects(
    createSession(
      createArguments(root, {
        "--prompt-file": promptPath,
        "--prompt-sha256": undefined,
      }),
      {
        repoRoot: root,
        ...createOptions(root, repositoryPublicKeyFile, {
          fileSystem,
        }),
      },
    ),
    SessionCreationError,
  );
  assert.equal(promptReads, 0);
});

test("create requires exactly one of --prompt-sha256 and --prompt-file", async () => {
  const root = await makeRoot();
  await assert.rejects(
    createSession(
      createArguments(root, { "--prompt-sha256": undefined }),
      { repoRoot: root },
    ),
    SessionCreationError,
  );
  await assert.rejects(
    createSession(
      createArguments(root, {
        "--prompt-file": join(root, "p.md"),
      }),
      { repoRoot: root },
    ),
    SessionCreationError,
  );
});

test("keygen refuses existing targets without modifying them", async () => {
  const root = await makeRoot();
  const first = await keygen(root);
  const publicBefore = await readFile(first.publicKeyPath, "utf8");
  const privateBefore = await readFile(privateKeyPath(root), "utf8");

  await assert.rejects(keygen(root), SessionCreationError);
  assert.equal(
    await readFile(first.publicKeyPath, "utf8"),
    publicBefore,
  );
  assert.equal(
    await readFile(privateKeyPath(root), "utf8"),
    privateBefore,
  );
});

test("create requires both default key files and refuses existing output", async () => {
  const root = await makeRoot();
  await assert.rejects(
    createSession(
      createArguments(root),
      {
        repoRoot: root,
        ...createOptions(root, ""),
      },
    ),
    SessionCreationError,
  );

  const keyReport = await keygen(root);
  const repositoryPublicKeyFile = await readFile(
    keyReport.publicKeyPath,
    "utf8",
  );
  const options = {
    repoRoot: root,
    ...createOptions(root, repositoryPublicKeyFile),
  };
  await createSession(createArguments(root), options);
  await assert.rejects(
    createSession(createArguments(root), options),
    SessionCreationError,
  );
});

test("create rejects a working-tree public key that mismatches the private key", async () => {
  const root = await makeRoot();
  const keyReport = await keygen(root);
  await writeFile(
    keyReport.publicKeyPath,
    `${IMPOSTOR.publicKeyRawBase64}\n`,
    "utf8",
  );
  let repositoryReads = 0;
  await assert.rejects(
    createSession(
      createArguments(root),
      {
        repoRoot: root,
        ...createOptions(root, `${IMPOSTOR.publicKeyRawBase64}\n`, {
          readRepositoryFileAtSha: async () => {
            repositoryReads += 1;
            return `${IMPOSTOR.publicKeyRawBase64}\n`;
          },
        }),
      },
    ),
    SessionCreationError,
  );
  assert.equal(repositoryReads, 0);
  await assert.rejects(
    stat(join(root, "session-envelope.json")),
    { code: "ENOENT" },
  );
});

test("create rejects a missing or byte-different public key at repositorySha", async () => {
  for (const repositoryRead of [
    async () => {
      throw new Error("missing at repository SHA");
    },
    async () => `${IMPOSTOR.publicKeyRawBase64}\n`,
  ]) {
    const root = await makeRoot();
    await keygen(root);
    await assert.rejects(
      createSession(
        createArguments(root),
        {
          repoRoot: root,
          ...createOptions(root, "", {
            readRepositoryFileAtSha: repositoryRead,
          }),
        },
      ),
      SessionCreationError,
    );
    await assert.rejects(
      stat(join(root, "session-envelope.json")),
      { code: "ENOENT" },
    );
  }
});

test("default git-show provenance accepts the committed key and rejects wrong SHA or key", async () => {
  const root = await makeRoot();
  await git(root, "init", "--quiet");
  await writeFile(join(root, ".gitignore"), ".context/\n", "utf8");
  const keyReport = await keygen(root);
  const originalPublicKeyFile = await readFile(
    keyReport.publicKeyPath,
    "utf8",
  );
  await git(
    root,
    "add",
    ".gitignore",
    "docs/operator-keys/demo-operator-1.pub",
  );
  await git(
    root,
    "-c",
    "user.name=Handshake Test",
    "-c",
    "user.email=handshake@example.invalid",
    "commit",
    "--quiet",
    "--no-gpg-sign",
    "-m",
    "pin public operator key",
  );
  const { stdout: goodShaOutput } = await git(
    root,
    "rev-parse",
    "HEAD",
  );
  const goodSha = goodShaOutput.trim();
  const deterministicOptions = {
    randomBytes: (size) => {
      assert.equal(size, 16);
      return Buffer.from(SESSION_ID, "hex");
    },
    repoRoot: root,
  };
  const good = await createSession(
    createArguments(root, {
      "--repository-sha": goodSha,
    }),
    deterministicOptions,
  );
  verifyDescriptorEnvelope(good.envelope, {
    repositoryPublicKey: originalPublicKeyFile.trim(),
  });
  const { stdout: trackedPrivate } = await git(
    root,
    "ls-files",
    ".context",
  );
  assert.equal(trackedPrivate, "");

  await assert.rejects(
    createSession(
      createArguments(root, {
        "--output": join(root, "wrong-sha.json"),
        "--repository-sha": "0".repeat(40),
      }),
      deterministicOptions,
    ),
    SessionCreationError,
  );

  await writeFile(
    keyReport.publicKeyPath,
    `${IMPOSTOR.publicKeyRawBase64}\n`,
    "utf8",
  );
  await git(
    root,
    "add",
    "docs/operator-keys/demo-operator-1.pub",
  );
  await git(
    root,
    "-c",
    "user.name=Handshake Test",
    "-c",
    "user.email=handshake@example.invalid",
    "commit",
    "--quiet",
    "--no-gpg-sign",
    "-m",
    "pin wrong public key",
  );
  const { stdout: wrongKeyShaOutput } = await git(
    root,
    "rev-parse",
    "HEAD",
  );
  await writeFile(
    keyReport.publicKeyPath,
    originalPublicKeyFile,
    "utf8",
  );
  await assert.rejects(
    createSession(
      createArguments(root, {
        "--output": join(root, "wrong-key.json"),
        "--repository-sha": wrongKeyShaOutput.trim(),
      }),
      deterministicOptions,
    ),
    SessionCreationError,
  );
});

test("create fails closed on malformed modes and arguments", async () => {
  const root = await makeRoot();
  const cases = [
    [],
    ["unknown", "--key-id", "demo-operator-1"],
    ["keygen"],
    [...keygenArguments(), "--unknown", "x"],
    [...keygenArguments(), "--key-id", "twice"],
    createArguments(root, { "--key-id": "Bad_Key" }),
    createArguments(root, {
      "--payer-address": PAYER_ADDRESS.toUpperCase(),
    }),
    createArguments(root, { "--payer-agent-id": "007" }),
    createArguments(root, { "--amounts": "" }),
    createArguments(root, { "--amounts": "USD:100,USD:100" }),
    createArguments(root, { "--amounts": "usd:100" }),
    createArguments(root, { "--amounts": "USD:0.50" }),
    createArguments(root, {
      "--amounts": Array.from(
        { length: 9 },
        (_, i) => `USD:${i + 1}00`,
      ).join(","),
    }),
    createArguments(root, { "--repository-sha": "abc" }),
    [...createArguments(root), "--unknown", "x"],
    [
      ...createArguments(root),
      "--output",
      join(root, "twice.json"),
    ],
    createArguments(root).slice(0, -2),
    [...createArguments(root), "--private-key", privateKeyPath(root)],
    [
      ...createArguments(root),
      "--private-key-out",
      join(root, "leak.pem"),
    ],
  ];
  for (const args of cases) {
    await assert.rejects(
      createSession(args, { repoRoot: root }),
      SessionCreationError,
      `expected rejection for ${JSON.stringify(args)}`,
    );
  }
});

test("create rejects identical payer and payee identities", async () => {
  const root = await makeRoot();
  await assert.rejects(
    createSession(
      createArguments(root, { "--payee-address": PAYER_ADDRESS }),
      { repoRoot: root },
    ),
    SessionCreationError,
  );
  await assert.rejects(
    createSession(
      createArguments(root, { "--payee-agent-id": "8677" }),
      { repoRoot: root },
    ),
    SessionCreationError,
  );
});

// --- second pass: blocks referencing createSession ---

test("create emits a pinned verifiable envelope without private metadata", async () => {
  const root = await makeRoot();
  const keyReport = await keygen(root);
  const repositoryPublicKeyFile = await readFile(
    keyReport.publicKeyPath,
    "utf8",
  );
  const report = await createSession(
    createArguments(root),
    {
      repoRoot: root,
      ...createOptions(root, repositoryPublicKeyFile),
    },
  );

  assert.deepEqual(Object.keys(report).sort(), [
    "dSession",
    "envelope",
  ]);
  assert.ok(!JSON.stringify(report).includes("privateKey"));
  assert.ok(!JSON.stringify(report).includes(".context"));

  const envelope = report.envelope;
  assert.deepEqual(
    envelope,
    JSON.parse(
      await readFile(join(root, "session-envelope.json"), "utf8"),
    ),
  );
  const { dSession: digest } = verifyDescriptorEnvelope(envelope, {
    repositoryPublicKey: repositoryPublicKeyFile.trim(),
  });
  assert.equal(report.dSession, digest);
  assert.equal(envelope.operator.keyId, "demo-operator-1");
  assert.equal(envelope.descriptor.repositorySha, SCRIPT_SHA);
  assert.equal(envelope.descriptor.promptSha256, PROMPT_SHA256);
  assert.equal(envelope.descriptor.mandateDigest, "b".repeat(64));
  assert.equal(envelope.descriptor.requestDigest, "c".repeat(64));
  assert.equal(envelope.descriptor.sessionId, SESSION_ID);
  assert.deepEqual(envelope.descriptor.amountOptions, [
    { currency: "USD", value: "100" },
    { currency: "USD", value: "250" },
  ]);
  assert.equal(envelope.descriptor.paymentMoved, false);
  assert.equal(envelope.descriptor.settlement, "not-executed");
});

test("create verifies repository bytes before invoking the injected output seam", async () => {
  const root = await makeRoot();
  const keyReport = await keygen(root);
  const repositoryPublicKeyFile = await readFile(
    keyReport.publicKeyPath,
    "utf8",
  );
  const events = [];
  let writtenEnvelope;

  const report = await createSession(
    createArguments(root),
    {
      repoRoot: root,
      ...createOptions(root, repositoryPublicKeyFile, {
        readRepositoryFileAtSha: async (request) => {
          events.push("repository");
          assert.equal(request.repositorySha, SCRIPT_SHA);
          return repositoryPublicKeyFile;
        },
        writeSessionOutput: async ({ envelope, path }) => {
          events.push("output");
          assert.equal(path, join(root, "session-envelope.json"));
          writtenEnvelope = envelope;
        },
      }),
    },
  );
  assert.deepEqual(events, ["repository", "output"]);
  assert.deepEqual(writtenEnvelope, report.envelope);
  await assert.rejects(
    stat(join(root, "session-envelope.json")),
    { code: "ENOENT" },
  );
});

test("create reads both operator key files through no-follow descriptors", async () => {
  const root = await makeRoot();
  const keyReport = await keygen(root);
  const repositoryPublicKeyFile = await readFile(
    keyReport.publicKeyPath,
    "utf8",
  );
  const keyReads = [];
  const fileSystem = {
    ...TEST_FILE_SYSTEM,
    open: async (path, flags, mode) => {
      if (
        path.endsWith(".ed25519.pem") ||
        path.endsWith(".pub")
      ) {
        keyReads.push({ flags, path });
      }
      return instrumentedHandle(await open(path, flags, mode));
    },
  };
  await createSession(
    createArguments(root),
    {
      repoRoot: root,
      ...createOptions(root, repositoryPublicKeyFile, {
        fileSystem,
      }),
    },
  );
  assert.equal(keyReads.length, 2);
  for (const { flags } of keyReads) {
    if (fsConstants.O_NOFOLLOW !== undefined) {
      assert.ok(flags & fsConstants.O_NOFOLLOW);
    }
  }
});

test("create computes promptSha256 from --prompt-file when given", async () => {
  const root = await makeRoot();
  const keyReport = await keygen(root);
  const repositoryPublicKeyFile = await readFile(
    keyReport.publicKeyPath,
    "utf8",
  );
  const promptPath = join(root, "payer-prompt.md");
  const promptBody = "# payer prompt\nno secrets here\n";
  await writeFile(promptPath, promptBody, "utf8");
  const expected = createHash("sha256")
    .update(Buffer.from(promptBody, "utf8"))
    .digest("hex");

  const report = await createSession(
    createArguments(root, {
      "--prompt-sha256": undefined,
      "--prompt-file": promptPath,
    }),
    {
      repoRoot: root,
      ...createOptions(root, repositoryPublicKeyFile),
    },
  );
  assert.equal(report.envelope.descriptor.promptSha256, expected);
});

test("create defaults repositorySha to the injected HEAD resolver", async () => {
  const root = await makeRoot();
  const keyReport = await keygen(root);
  const repositoryPublicKeyFile = await readFile(
    keyReport.publicKeyPath,
    "utf8",
  );
  const report = await createSession(
    createArguments(root, { "--repository-sha": undefined }),
    {
      repoRoot: root,
      ...createOptions(root, repositoryPublicKeyFile, {
        resolveHeadSha: async () => SCRIPT_SHA,
      }),
    },
  );
  assert.equal(report.envelope.descriptor.repositorySha, SCRIPT_SHA);
});

// --- third pass: blocks invoking the donor session CLI as a subprocess ---

test("keygen writes one fixed operator keypair and returns public metadata only", async () => {
  const root = await makeRoot();
  const report = await keygen(root);

  assert.deepEqual(Object.keys(report).sort(), [
    "keyId",
    "publicKey",
    "publicKeyPath",
  ]);
  assert.equal(report.keyId, "demo-operator-1");
  assert.equal(
    report.publicKeyPath,
    join(root, "docs/operator-keys/demo-operator-1.pub"),
  );
  assert.equal(
    (await readFile(report.publicKeyPath, "utf8")).trim(),
    report.publicKey,
  );
  publicKeyPemFromRawBase64(report.publicKey);

  const privatePath = privateKeyPath(root);
  const keyStat = await stat(privatePath);
  assert.equal(keyStat.mode & 0o777, 0o600);
  const privatePem = await readFile(privatePath, "utf8");
  assert.match(privatePem, /BEGIN PRIVATE KEY/);
  const reportText = JSON.stringify(report);
  assert.ok(!reportText.includes("PRIVATE KEY"));
  assert.ok(!reportText.includes(".context"));
  assert.ok(!reportText.includes("privateKey"));
  assert.ok(
    !reportText.includes(
      privatePem.replace(/-----[^-]+-----|\s/g, "").slice(0, 16),
    ),
  );
});

test("keygen accepts a contained 0755 .context and creates operator-keys as 0700", async () => {
  const root = await makeRoot();
  await mkdir(join(root, ".context"), { mode: 0o755 });

  await keygen(root);

  assert.equal(
    (await stat(join(root, ".context"))).mode & 0o777,
    0o755,
  );
  assert.equal(
    (
      await stat(join(root, ".context/operator-keys"))
    ).mode & 0o777,
    0o700,
  );
  assert.equal(
    (await stat(privateKeyPath(root))).mode & 0o777,
    0o600,
  );
});

test("keygen uses no-follow exclusive descriptors and syncs before close", async () => {
  const root = await makeRoot();
  const opened = [];
  const calls = [];
  const fileSystem = {
    ...TEST_FILE_SYSTEM,
    open: async (path, flags, mode) => {
      opened.push({ flags, mode, path });
      return instrumentedHandle(
        await open(path, flags, mode),
        {
          onCall: (method) => calls.push({ method, path }),
        },
      );
    },
  };

  await keygen(root, { fileSystem });
  const keyOpens = opened.filter(
    ({ path }) =>
      path.endsWith(".ed25519.pem") || path.endsWith(".pub"),
  );
  assert.equal(keyOpens.length, 2);
  for (const { flags } of keyOpens) {
    assert.ok(flags & fsConstants.O_EXCL);
    if (fsConstants.O_NOFOLLOW !== undefined) {
      assert.ok(flags & fsConstants.O_NOFOLLOW);
    }
  }
  for (const { path } of keyOpens) {
    assert.deepEqual(
      calls
        .filter((call) => call.path === path)
        .map((call) => call.method),
      ["stat", "writeFile", "sync", "close"],
    );
  }
});

test("keygen CLI stdout contains only public key metadata", async () => {
  const root = await makeRoot();
  let stdout = "";
  await runCreateSessionCli(
    keygenArguments(),
    {
      repoRoot: root,
      writeStdout: (value) => {
        stdout += value;
      },
    },
  );
  const payload = JSON.parse(stdout);
  assert.deepEqual(Object.keys(payload).sort(), [
    "keyId",
    "publicKey",
    "publicKeyPath",
  ]);
  assert.ok(!stdout.includes("PRIVATE KEY"));
  assert.ok(!stdout.includes(".context"));
  assert.ok(!stdout.includes("privateKey"));
});

test("create CLI stdout is the signed public envelope only", async () => {
  const root = await makeRoot();
  const keyReport = await keygen(root);
  const repositoryPublicKeyFile = await readFile(
    keyReport.publicKeyPath,
    "utf8",
  );
  let stdout = "";
  await runCreateSessionCli(
    createArguments(root),
    {
      repoRoot: root,
      ...createOptions(root, repositoryPublicKeyFile),
      writeStdout: (value) => {
        stdout += value;
      },
    },
  );
  const envelope = JSON.parse(stdout);
  assert.deepEqual(Object.keys(envelope).sort(), [
    "descriptor",
    "operator",
  ]);
  assert.ok(!stdout.includes("dSession"));
  assert.ok(!stdout.includes("privateKey"));
  assert.ok(!stdout.includes(".context"));
  verifyDescriptorEnvelope(envelope, {
    repositoryPublicKey: repositoryPublicKeyFile.trim(),
  });
});