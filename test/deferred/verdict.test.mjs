// DEFERRED from test/verdict.test.mjs during M0.
// Depends on the donor verifier CLI; v2 rebuilds it as src/verifier/run.mjs (M1a step 12).
// Re-point at the v2 module and re-enable at the milestone named above.
// Symbols that were imported from scripts/verify-bilateral-results.mjs: CLI_ARGUMENTS

test("default verifier builder authenticates local provenance and chain before creating Clockchain", async (t) => {
  const {
    VERIFIER_REPOSITORY_ROOT,
    buildDefaultVerifierInput,
  } = await import("../scripts/verify-bilateral-results.mjs");
  assert.equal(typeof buildDefaultVerifierInput, "function");
  assert.equal(
    VERIFIER_REPOSITORY_ROOT,
    dirname(dirname(fileURLToPath(import.meta.url))),
  );
  const harness = await defaultBuilderHarness(t);
  const input = await buildDefaultVerifierInput(
    harness.values,
    harness.dependencies(),
  );
  assert.equal(
    await input.repositoryPublicKeyResolver({
      keyId: harness.fixture.descriptorEnvelope.operator.keyId,
      repositoryPath:
        "docs/operator-keys/verdict-test-operator.pub",
      repositorySha:
        harness.fixture.descriptor.repositorySha,
    }),
    harness.fixture.repositoryPublicKey,
  );
  assert.deepEqual(harness.metrics.events, [
    "git:show 0123456789abcdef0123456789abcdef01234567:docs/operator-keys/verdict-test-operator.pub",
    "git:rev-parse --verify HEAD",
    "git:status --porcelain=v1 --untracked-files=all",
    "rpc:create",
    "rpc:getChainId",
    "clockchain:create",
  ]);
  assert.equal(
    await input.ownerOf({
      agentId: harness.fixture.descriptor.payer.agentId,
      registry: harness.fixture.descriptor.registry,
    }),
    harness.fixture.descriptor.payer.address,
  );
  assert.equal(harness.metrics.ownerReads, 1);
});

test("a 4096-byte token survives the default builder-to-verifier contract", async (t) => {
  const { buildDefaultVerifierInput } =
    await import("../scripts/verify-bilateral-results.mjs");
  const token = "t".repeat(4096);
  const harness = await defaultBuilderHarness(t, { token });
  const input = await buildDefaultVerifierInput(
    harness.values,
    harness.dependencies(),
  );
  assert.deepEqual(input.canaries, [token]);
  const verdict = await verifyBilateralAuthorization(input);
  assert.equal(verdict.outcome, "AUTHORIZED");
});

test("default verifier builder bounds descriptor, token, and intent reads and rejects races", async (t) => {
  const { buildDefaultVerifierInput } =
    await import("../scripts/verify-bilateral-results.mjs");
  for (const target of [
    "descriptor",
    "token",
    "payer mandate",
    "payment request",
  ]) {
    for (const scenario of [
      { metadataField: undefined, overflow: true },
      { metadataField: "ctimeMs", overflow: false },
      { truncate: true },
    ]) {
      await t.test(
        `${target} ${
          scenario.overflow
            ? "growth"
            : scenario.truncate
              ? "truncation"
              : "metadata"
        }`,
        async (t) => {
          const harness = await defaultBuilderHarness(t);
          const targetPath =
            target === "descriptor"
              ? harness.descriptorPath
              : target === "token"
                ? harness.tokenPath
                : target === "payer mandate"
                  ? harness.mandatePath
                  : harness.requestPath;
          let readLength = 0;
          await assert.rejects(
            buildDefaultVerifierInput(
              harness.values,
              harness.dependencies({
                fileSystem: {
                  async open(path, flags) {
                    const handle = await open(path, flags);
                    return path === targetPath
                      ? adversarialVerdictReadHandle(handle, {
                          ...scenario,
                          onRead(length) {
                            readLength = Math.max(
                              readLength,
                              length,
                            );
                          },
                        })
                      : handle;
                  },
                },
              }),
            ),
            BilateralVerdictError,
          );
          assert.equal(
            readLength,
            target === "descriptor"
              ? (1024 * 1024) + 1
              : target === "token"
                ? 4097
                : 65_537,
          );
        },
      );
    }
  }
});

test("default verifier CLI rejects unsafe local state and wrong chain before Clockchain without leaking secrets", async (t) => {
  const { buildDefaultVerifierInput } =
    await import("../scripts/verify-bilateral-results.mjs");
  const scenarios = [
    {
      name: "wrong full HEAD",
      overrides: { head: "f".repeat(40) },
    },
    {
      name: "dirty worktree",
      overrides: { status: " M README.md\n" },
    },
    {
      name: "wrong RPC chain",
      overrides: { chainId: 1 },
    },
    {
      async setup(harness) {
        const target = join(harness.fixture.root, "descriptor-target.json");
        await writeFile(
          target,
          await readFile(harness.descriptorPath),
          { mode: 0o600 },
        );
        await rm(harness.descriptorPath);
        await symlink(target, harness.descriptorPath);
      },
      name: "symlinked descriptor",
    },
    {
      async setup(harness) {
        const target = join(harness.fixture.root, "mandate-target.json");
        await writeFile(target, await readFile(harness.mandatePath), {
          mode: 0o600,
        });
        await rm(harness.mandatePath);
        await symlink(target, harness.mandatePath);
      },
      name: "symlinked payer mandate",
    },
    {
      async setup(harness) {
        const target = join(harness.fixture.root, "request-target.json");
        await writeFile(target, await readFile(harness.requestPath), {
          mode: 0o600,
        });
        await rm(harness.requestPath);
        await symlink(target, harness.requestPath);
      },
      name: "symlinked payment request",
    },
    {
      async setup(harness) {
        await rm(harness.tokenPath);
        await execFileAsync("mkfifo", [harness.tokenPath]);
      },
      name: "FIFO token",
    },
    {
      async setup(harness) {
        await rm(harness.mandatePath);
        await execFileAsync("mkfifo", [harness.mandatePath]);
      },
      name: "FIFO payer mandate",
    },
    {
      async setup(harness) {
        await rm(harness.requestPath);
        await execFileAsync("mkfifo", [harness.requestPath]);
      },
      name: "FIFO payment request",
    },
    {
      async setup(harness) {
        await rm(harness.mandatePath);
        await mkdir(harness.mandatePath, { mode: 0o700 });
      },
      name: "directory payer mandate path",
    },
    {
      async setup(harness) {
        await rm(harness.requestPath);
        await mkdir(harness.requestPath, { mode: 0o700 });
      },
      name: "directory payment request path",
    },
    {
      async setup(harness) {
        await chmod(harness.tokenPath, 0o644);
      },
      name: "permissive token mode",
    },
    {
      async setup(harness) {
        const defaultOpen = open;
        harness.overrides = {
          fileSystem: {
            async open(path, flags) {
              const handle = await defaultOpen(path, flags);
              if (path !== harness.descriptorPath) {
                return handle;
              }
              let statCalls = 0;
              return {
                close: () => handle.close(),
                read: (...args) => handle.read(...args),
                async stat() {
                  const metadata = await handle.stat();
                  statCalls += 1;
                  if (statCalls === 1) {
                    return metadata;
                  }
                  return {
                    ...metadata,
                    isFile: () => true,
                    mtimeMs: metadata.mtimeMs + 1,
                  };
                },
              };
            },
          },
        };
      },
      name: "changed descriptor metadata",
    },
    {
      async setup(harness) {
        harness.overrides = {
          fileSystem: adversarialBuilderFileSystem(
            harness.mandatePath,
            { metadataField: "ctimeMs" },
          ),
        };
      },
      name: "changed payer mandate metadata",
    },
    {
      async setup(harness) {
        harness.overrides = {
          fileSystem: adversarialBuilderFileSystem(
            harness.requestPath,
            { truncate: true },
          ),
        };
      },
      name: "truncated payment request",
    },
    {
      async setup(harness) {
        await writeFile(harness.mandatePath, "{", { mode: 0o600 });
      },
      name: "malformed payer mandate JSON",
    },
    {
      async setup(harness) {
        await writeFile(harness.requestPath, "{", { mode: 0o600 });
      },
      name: "malformed payment request JSON",
    },
    {
      async setup(harness) {
        await writeFile(
          harness.mandatePath,
          Buffer.concat([
            canonicalBytes(harness.fixture.mandateEnvelope),
            Buffer.from("\n", "utf8"),
          ]),
          { mode: 0o600 },
        );
      },
      name: "noncanonical payer mandate JSON",
    },
    {
      async setup(harness) {
        await writeFile(
          harness.requestPath,
          Buffer.concat([
            canonicalBytes(harness.fixture.requestEnvelope),
            Buffer.from("\n", "utf8"),
          ]),
          { mode: 0o600 },
        );
      },
      name: "noncanonical payment request JSON",
    },
  ];

  for (const scenario of scenarios) {
    await t.test(scenario.name, async (t) => {
      const harness = await defaultBuilderHarness(t);
      await scenario.setup?.(harness);
      const stdout = captureStream();
      const stderr = captureStream();
      let verifierCalls = 0;
      const exitCode = await runVerifierCli(harness.arguments_, {
        buildVerifierInput: (values) =>
          buildDefaultVerifierInput(
            values,
            harness.dependencies({
              ...scenario.overrides,
              ...harness.overrides,
            }),
          ),
        async verify() {
          verifierCalls += 1;
          throw new Error("unreachable");
        },
        stderr,
        stdout,
      });
      assert.equal(exitCode, 1);
      assert.equal(verifierCalls, 0);
      assert.equal(harness.metrics.clockchainCreates, 0);
      assert.equal(
        stdout.value,
        '{"outcome":"FAILED","paymentMoved":false,"schema":"clockchain.bilateral-authorization-verdict/v2"}\n',
      );
      assert.equal(stderr.value, "BILATERAL_VERDICT_FAILED\n");
      assert.equal(stdout.value.includes(harness.token), false);
      assert.equal(stderr.value.includes(harness.token), false);
      await assert.rejects(() => lstat(harness.output), {
        code: "ENOENT",
      });
    });
  }
});

test("pins the exact verifier CLI and publishes a hashed completion marker before stdout", async (t) => {
  const fixture = await completeFixture(t);
  const output = join(fixture.root, "verdict-output");
  const stdout = captureStream();
  const stderr = captureStream();
  const arguments_ = [
    "--clockchain-token-file",
    "clockchain.token",
    "--descriptor",
    "descriptor.json",
    "--output",
    output,
    "--payer-mandate",
    "payer-mandate.json",
    "--payee-results",
    fixture.payeeDirectory,
    "--payer-results",
    fixture.payerDirectory,
    "--payment-request",
    "payment-request.json",
    "--rpc-url",
    "https://rpc.example",
  ];

  assert.deepEqual([...CLI_ARGUMENTS], [
    "--clockchain-token-file",
    "--descriptor",
    "--output",
    "--payer-mandate",
    "--payee-results",
    "--payer-results",
    "--payment-request",
    "--rpc-url",
  ]);
  const exitCode = await runVerifierCli(arguments_, {
    async buildVerifierInput(values) {
      assert.deepEqual(values, {
        clockchainTokenFile: "clockchain.token",
        descriptor: "descriptor.json",
        output,
        payerMandate: "payer-mandate.json",
        payeeResults: fixture.payeeDirectory,
        payerResults: fixture.payerDirectory,
        paymentRequest: "payment-request.json",
        rpcUrl: "https://rpc.example",
      });
      return fixture.input;
    },
    stderr,
    stdout,
  });

  assert.equal(exitCode, 0);
  assert.equal(stdout.value, "AUTHORIZED\n");
  assert.equal(stderr.value, "");
  const json = await readFile(
    join(output, "bilateral-verdict.json"),
    "utf8",
  );
  const markdown = await readFile(
    join(output, "BILATERAL-VERDICT.md"),
    "utf8",
  );
  const marker = JSON.parse(
    await readFile(
      join(output, ".bilateral-verdict.complete.json"),
      "utf8",
    ),
  );
  assert.equal(
    markdown,
    renderBilateralVerdictMarkdown(JSON.parse(json)),
  );
  assert.deepEqual(marker, {
    jsonSha256: createHash("sha256")
      .update(json)
      .digest("hex"),
    markdownSha256: createHash("sha256")
      .update(markdown)
      .digest("hex"),
    schema:
      "clockchain.bilateral-authorization-verdict-completion/v2",
  });
});

// --- second pass: blocks referencing runVerifierCli ---

test("runs a fresh-task publication gate after the durable verdict marker and before authorizing stdout", async (t) => {
  const fixture = await completeFixture(t);
  const output = join(
    fixture.root,
    "fresh-task-publication-gate",
  );
  const stdout = captureStream();
  const order = [];
  const arguments_ = [
    "--clockchain-token-file",
    "clockchain.token",
    "--descriptor",
    "descriptor.json",
    "--output",
    output,
    "--payer-mandate",
    "payer-mandate.json",
    "--payee-results",
    fixture.payeeDirectory,
    "--payer-results",
    fixture.payerDirectory,
    "--payment-request",
    "payment-request.json",
    "--rpc-url",
    "https://rpc.example",
  ];
  const exitCode = await runVerifierCli(arguments_, {
    async beforeAuthorizationOutput(value) {
      assert.equal(value.output, output);
      assert.equal(value.verdict.paymentMoved, false);
      assert.equal(
        await readFile(
          join(
            output,
            ".bilateral-verdict.complete.json",
          ),
          "utf8",
        ).then((bytes) => bytes.length > 0),
        true,
      );
      assert.equal(stdout.value, "");
      order.push("gate");
    },
    async buildVerifierInput() {
      return fixture.input;
    },
    stderr: captureStream(),
    stdout: {
      write(value) {
        order.push("stdout");
        stdout.write(value);
      },
    },
  });
  assert.equal(exitCode, 0);
  assert.deepEqual(order, ["gate", "stdout"]);
  assert.equal(stdout.value, "AUTHORIZED\n");

  const rejectedOutput = join(
    fixture.root,
    "fresh-task-publication-rejected",
  );
  const rejectedStdout = captureStream();
  assert.equal(
    await runVerifierCli(
      arguments_.map((value) =>
        value === output ? rejectedOutput : value),
      {
        async beforeAuthorizationOutput() {
          throw new Error("publication rejected");
        },
        async buildVerifierInput() {
          return fixture.input;
        },
        stderr: captureStream(),
        stdout: rejectedStdout,
      },
    ),
    1,
  );
  assert.equal(
    rejectedStdout.value.includes("AUTHORIZED"),
    false,
  );
  await assert.rejects(
    lstat(
      join(
        rejectedOutput,
        ".bilateral-verdict.complete.json",
      ),
    ),
    { code: "ENOENT" },
  );
});

test("every aggregate publication-step failure removes marker authority and suppresses authorizing stdout", async (t) => {
  const fixture = await completeFixture(t);
  const argumentsFor = (output) => [
    "--clockchain-token-file",
    "clockchain.token",
    "--descriptor",
    "descriptor.json",
    "--output",
    output,
    "--payer-mandate",
    "payer-mandate.json",
    "--payee-results",
    fixture.payeeDirectory,
    "--payer-results",
    fixture.payerDirectory,
    "--payment-request",
    "payment-request.json",
    "--rpc-url",
    "https://rpc.example",
  ];
  const successfulOutput = join(fixture.root, "publication-trace");
  const trace = [];
  assert.equal(
    await runVerifierCli(argumentsFor(successfulOutput), {
      async buildVerifierInput() {
        return fixture.input;
      },
      fileSystem: publicationFileSystem(trace),
      stderr: captureStream(),
      stdout: captureStream(),
    }),
    0,
  );
  assert.ok(
    trace.includes("rename:.bilateral-verdict.complete.json"),
  );
  assert.ok(
    trace.indexOf("rename:.bilateral-verdict.complete.json") >
      trace.indexOf("rename:BILATERAL-VERDICT.md"),
  );
  assert.ok(
    trace.lastIndexOf("sync:publication-trace") >
      trace.indexOf("rename:.bilateral-verdict.complete.json"),
  );

  for (let failAfter = 1; failAfter <= trace.length; failAfter += 1) {
    const output = join(
      fixture.root,
      `publication-failure-${failAfter}`,
    );
    const stdout = captureStream();
    const stderr = captureStream();
    const exitCode = await runVerifierCli(argumentsFor(output), {
      async buildVerifierInput() {
        return fixture.input;
      },
      fileSystem: publicationFileSystem([], failAfter),
      stderr,
      stdout,
    });
    assert.equal(exitCode, 1, trace[failAfter - 1]);
    assert.equal(
      stdout.value.includes("AUTHORIZED"),
      false,
      trace[failAfter - 1],
    );
    await assert.rejects(
      () =>
        lstat(
          join(
            output,
            ".bilateral-verdict.complete.json",
          ),
        ),
      { code: "ENOENT" },
    );
  }
});

test("an authorizing stdout crash revokes the completion marker", async (t) => {
  const fixture = await completeFixture(t);
  const output = join(fixture.root, "stdout-crash");
  const stdout = {
    value: "",
    write(chunk) {
      if (chunk === "AUTHORIZED\n") {
        throw new Error("stdout crashed");
      }
      this.value += chunk;
    },
  };
  const exitCode = await runVerifierCli(
    [
      "--clockchain-token-file",
      "clockchain.token",
      "--descriptor",
      "descriptor.json",
      "--output",
      output,
      "--payee-results",
      fixture.payeeDirectory,
      "--payer-results",
      fixture.payerDirectory,
      "--rpc-url",
      "https://rpc.example",
    ],
    {
      async buildVerifierInput() {
        return fixture.input;
      },
      stderr: captureStream(),
      stdout,
    },
  );
  assert.equal(exitCode, 1);
  assert.equal(stdout.value.includes("AUTHORIZED"), false);
  await assert.rejects(
    () =>
      lstat(
        join(output, ".bilateral-verdict.complete.json"),
      ),
    { code: "ENOENT" },
  );
});

test("CLI failures emit only a fixed non-authorizing terminal result and no artifacts", async (t) => {
  const fixture = await completeFixture(t);
  const output = join(fixture.root, "failed-output");
  const stdout = captureStream();
  const stderr = captureStream();
  const arguments_ = [
    "--clockchain-token-file",
    "clockchain.token",
    "--descriptor",
    "descriptor.json",
    "--output",
    output,
    "--payer-mandate",
    "payer-mandate.json",
    "--payee-results",
    fixture.payeeDirectory,
    "--payer-results",
    fixture.payerDirectory,
    "--payment-request",
    "payment-request.json",
    "--rpc-url",
    "https://rpc.example",
  ];

  const exitCode = await runVerifierCli(arguments_, {
    async buildVerifierInput() {
      throw new BilateralVerdictError("EXPIRED");
    },
    stderr,
    stdout,
  });
  assert.equal(exitCode, 1);
  assert.equal(
    stdout.value,
    '{"outcome":"EXPIRED","paymentMoved":false,"schema":"clockchain.bilateral-authorization-verdict/v2"}\n',
  );
  assert.equal(stderr.value, "BILATERAL_VERDICT_FAILED\n");
  await assert.rejects(() => readFile(output), {
    code: "ENOENT",
  });
});

test("CLI rejects missing, duplicate, and unknown arguments before dependency calls", async () => {
  let calls = 0;
  const dependencies = {
    async buildVerifierInput() {
      calls += 1;
      throw new Error("unreachable");
    },
    stderr: captureStream(),
    stdout: captureStream(),
  };
  for (const arguments_ of [
    [],
    ["--descriptor", "one", "--descriptor", "two"],
    ["--unknown", "value"],
  ]) {
    assert.equal(
      await runVerifierCli(arguments_, dependencies),
      1,
    );
  }
  assert.equal(calls, 0);
});