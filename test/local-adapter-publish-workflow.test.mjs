// The adapter publish workflow sets npm dist-tags explicitly: a tag push
// publishes under next, a manual dispatch under its dist_tag input, and latest
// moves only through the separate set_latest_version dispatch input, which
// publishes nothing.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmod, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

const WORKFLOW_URL = new URL("../.github/workflows/local-adapter-publish.yml", import.meta.url);
const PACKAGE = "@d4d.group/local-adapter";
const PUBLISH_STEP = "Publish with provenance under an explicit dist-tag";
const SET_LATEST_STEP = "Move the latest dist-tag to the named version";

function indentOf(line) {
  return line.length - line.trimStart().length;
}

// The lines of the step named `name`, its env mapping and its run script.
function step(workflow, name) {
  const lines = workflow.split("\n");
  const start = lines.findIndex((line) => line.trim() === `- name: ${name}`);
  assert.ok(start >= 0, `step "${name}" is missing`);
  const keyIndent = lines[start].indexOf("-") + 2;
  const body = [];
  for (const line of lines.slice(start + 1)) {
    if (line.trim() !== "" && indentOf(line) < keyIndent) break;
    body.push(line);
  }
  const block = (key) => {
    const at = body.findIndex((line) => indentOf(line) === keyIndent && line.trim().startsWith(`${key}:`));
    if (at < 0) return null;
    const out = [];
    for (const line of body.slice(at + 1)) {
      if (line.trim() !== "" && indentOf(line) <= keyIndent) break;
      out.push(line);
    }
    return { header: body[at].trim(), lines: out };
  };
  const envBlock = block("env");
  const env = {};
  for (const line of envBlock?.lines ?? []) {
    if (line.trim() === "" || line.trim().startsWith("#")) continue;
    const match = /^\s*([A-Z_][A-Z0-9_]*):\s*(.*?)\s*(?:#.*)?$/.exec(line);
    assert.ok(match, `unreadable env line: ${line}`);
    env[match[1]] = match[2];
  }
  const runBlock = block("run");
  assert.ok(runBlock && runBlock.header === "run: |", `step "${name}" has no run block`);
  const scriptLines = runBlock.lines;
  const scriptIndent = Math.min(...scriptLines.filter((line) => line.trim() !== "").map(indentOf));
  const script = scriptLines.map((line) => line.slice(scriptIndent)).join("\n");
  const shell = body.find((line) => indentOf(line) === keyIndent && line.trim().startsWith("shell:"));
  return { env, script, shell: shell?.trim() ?? null };
}

// Resolves the step's env expressions for one event.
function resolveEnv(env, inputs) {
  const resolved = {};
  for (const [key, value] of Object.entries(env)) {
    const input = /^\$\{\{ inputs\.([a-z_]+) \}\}$/.exec(value);
    if (input) {
      resolved[key] = inputs[input[1]] ?? "";
      continue;
    }
    assert.match(value, /^\$\{\{ secrets\.NODE_AUTH_TOKEN \}\}$/, `unexpected env value for ${key}`);
    resolved[key] = "";
  }
  return resolved;
}

// Runs a step script under bash with a stub npm that records its arguments.
async function runStep(t, workflowStep, { event, inputs = {}, viewVersion = "" }) {
  const directory = await mkdtemp(join(tmpdir(), "adapter-publish-workflow-"));
  t.after(() => rm(directory, { force: true, recursive: true }));
  const calls = join(directory, "npm-calls.txt");
  const npm = join(directory, "npm");
  await writeFile(npm, [
    "#!/usr/bin/env bash",
    'printf "%s\\n" "$*" >> "$NPM_CALLS"',
    'if [ "$1" = "view" ]; then printf "%s\\n" "$NPM_VIEW_VERSION"; fi',
    "exit 0",
    "",
  ].join("\n"));
  await chmod(npm, 0o755);
  await writeFile(calls, "");
  const script = join(directory, "step.sh");
  await writeFile(script, workflowStep.script);
  const result = spawnSync("bash", ["--noprofile", "--norc", "-eo", "pipefail", script], {
    cwd: directory,
    encoding: "utf8",
    env: {
      ...resolveEnv(workflowStep.env, inputs),
      GITHUB_EVENT_NAME: event,
      HOME: directory,
      NPM_CALLS: calls,
      NPM_VIEW_VERSION: viewVersion,
      PATH: `${directory}:${process.env.PATH}`,
    },
  });
  const npmCalls = (await readFile(calls, "utf8")).split("\n").filter(Boolean);
  return { npmCalls, status: result.status, output: `${result.stdout}${result.stderr}` };
}

test("every npm publish in the adapter workflow names its dist-tag", async () => {
  const workflow = await readFile(WORKFLOW_URL, "utf8");
  const publishLines = workflow.split("\n").filter((line) =>
    /\bnpm publish\b/.test(line) &&
    !line.trim().startsWith("#") &&
    !/^(?:description|- name|name):/.test(line.trim()));
  assert.ok(publishLines.length > 0);
  for (const line of publishLines) {
    assert.match(line, /--tag "\$DIST_TAG"/, line.trim());
  }
});

test("manual dispatch takes a dist_tag input defaulting to next and a separate set_latest_version input", async () => {
  const workflow = await readFile(WORKFLOW_URL, "utf8");
  const dispatch = workflow.slice(workflow.indexOf("workflow_dispatch:"), workflow.indexOf("\npermissions:"));
  assert.match(dispatch, /\n {6}dist_tag:\n(?: {8}.*\n)*? {8}default: next\n/);
  assert.match(dispatch, /\n {6}set_latest_version:\n(?: {8}.*\n)*? {8}type: string\n/);
  assert.match(dispatch, /\n {6}set_latest_version:\n(?: {8}.*\n)*? {8}default: ""\n/);
  // Inputs reach step scripts only through env, never as interpolated text.
  for (const name of [PUBLISH_STEP, SET_LATEST_STEP]) {
    assert.equal(step(workflow, name).script.includes("${{"), false, name);
  }
  // latest is moved by one step only, and a dispatch that moves it publishes
  // nothing.
  const commandLines = workflow.split("\n").filter((line) => !line.trim().startsWith("#"));
  assert.equal(commandLines.filter((line) => line.includes("npm dist-tag add")).length, 1);
  assert.match(step(workflow, SET_LATEST_STEP).script, /npm dist-tag add "\$PACKAGE@\$LATEST_VERSION" latest/);
  assert.match(workflow, /\n {2}pack-and-verify:\n {4}if: github\.event_name == 'push' \|\| inputs\.set_latest_version == ''\n/);
  assert.match(workflow, /\n {2}publish:\n(?: {4}.*\n)*? {4}needs: pack-and-verify\n/);
  assert.match(workflow, /\n {2}set-latest:\n {4}if: github\.event_name == 'workflow_dispatch' && inputs\.set_latest_version != ''\n/);
});

test("a tag push publishes under next, whatever the dispatch inputs say", async (t) => {
  const workflow = await readFile(WORKFLOW_URL, "utf8");
  const publish = step(workflow, PUBLISH_STEP);
  assert.equal(publish.shell, "shell: bash");
  for (const inputs of [{}, { dist_tag: "latest" }, { dist_tag: "beta" }]) {
    const run = await runStep(t, publish, { event: "push", inputs });
    assert.equal(run.status, 0, run.output);
    assert.deepEqual(run.npmCalls, ["publish --provenance --access public --tag next"], JSON.stringify(inputs));
  }
});

test("a manual dispatch publishes under its dist_tag input, and refuses latest or a malformed tag", async (t) => {
  const workflow = await readFile(WORKFLOW_URL, "utf8");
  const publish = step(workflow, PUBLISH_STEP);
  for (const [inputs, expected] of [
    [{ dist_tag: "next", dry_run: "true" }, "publish --provenance --access public --tag next --dry-run"],
    [{ dist_tag: "next", dry_run: "false" }, "publish --provenance --access public --tag next"],
    [{ dist_tag: "beta", dry_run: "false" }, "publish --provenance --access public --tag beta"],
  ]) {
    const run = await runStep(t, publish, { event: "workflow_dispatch", inputs });
    assert.equal(run.status, 0, run.output);
    assert.deepEqual(run.npmCalls, [expected], JSON.stringify(inputs));
  }
  for (const distTag of ["latest", "", "Next", "1.2.3", "next --tag latest", "next;latest", "-latest"]) {
    const run = await runStep(t, publish, { event: "workflow_dispatch", inputs: { dist_tag: distTag, dry_run: "false" } });
    assert.notEqual(run.status, 0, distTag);
    assert.deepEqual(run.npmCalls, [], distTag);
  }
});

test("latest moves only to an exact version npm already serves, and not on a dry run", async (t) => {
  const workflow = await readFile(WORKFLOW_URL, "utf8");
  const setLatest = step(workflow, SET_LATEST_STEP);
  assert.equal(setLatest.shell, "shell: bash");
  const moved = await runStep(t, setLatest, {
    event: "workflow_dispatch",
    inputs: { dry_run: "false", set_latest_version: "2.3.0" },
    viewVersion: "2.3.0",
  });
  assert.equal(moved.status, 0, moved.output);
  assert.ok(moved.npmCalls.includes(`view ${PACKAGE}@2.3.0 version`), moved.npmCalls.join("\n"));
  assert.deepEqual(moved.npmCalls.filter((call) => call.startsWith("dist-tag add")), [`dist-tag add ${PACKAGE}@2.3.0 latest`]);
  assert.equal(moved.npmCalls.some((call) => call.startsWith("publish")), false);

  const dryRun = await runStep(t, setLatest, {
    event: "workflow_dispatch",
    inputs: { dry_run: "true", set_latest_version: "2.3.0" },
    viewVersion: "2.3.0",
  });
  assert.equal(dryRun.status, 0, dryRun.output);
  assert.equal(dryRun.npmCalls.some((call) => call.startsWith("dist-tag add")), false);

  const unpublished = await runStep(t, setLatest, {
    event: "workflow_dispatch",
    inputs: { dry_run: "false", set_latest_version: "2.3.0" },
    viewVersion: "",
  });
  assert.notEqual(unpublished.status, 0);
  assert.equal(unpublished.npmCalls.some((call) => call.startsWith("dist-tag add")), false);

  for (const version of ["", "latest", "2.3", "v2.3.0", "2.3.0-rc.1", "02.3.0", "2.3.0 latest"]) {
    const run = await runStep(t, setLatest, {
      event: "workflow_dispatch",
      inputs: { dry_run: "false", set_latest_version: version },
      viewVersion: version,
    });
    assert.notEqual(run.status, 0, version);
    assert.deepEqual(run.npmCalls, [], version);
  }
});
