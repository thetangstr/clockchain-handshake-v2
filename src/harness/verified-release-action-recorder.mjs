import { execFile } from "node:child_process";
import { createHash, generateKeyPairSync, randomBytes, randomUUID, sign as signBytes } from "node:crypto";
import { chmod, lstat, mkdir, unlink, writeFile } from "node:fs/promises";
import { readFileSync, writeFileSync } from "node:fs";
import { createServer } from "node:net";
import { basename, isAbsolute, join, relative, resolve } from "node:path";
import { promisify, types } from "node:util";

import { rawEd25519PublicKey } from "../agent-handshake/v2/host-key-certificate.mjs";
import { localPolicyDigest, validateLocalPolicy } from "../agent-handshake/v2/policy.mjs";
import { writePrivateFile } from "../core/private-path.mjs";

const RELEASE_PREFIX = "https://github.com/thetangstr/clockchain-handshake-v2/releases/download/v2.1.3/";
const SHA256 = /^[0-9a-f]{64}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const BASE64URL = /^[A-Za-z0-9_-]+$/;
const ROLES = Object.freeze(["initiator", "responder"]);
const OPERATIONS = Object.freeze(["init", "policy", "inspect", "register", "sign", "verify-certificate"]);
const SIGNING_OPERATIONS = Object.freeze(["identity_claim", "proposal", "acceptance", "evidence"]);
const MAX_RESULT_BYTES = 64 * 1024;
const MAX_SOCKET_PATH_BYTES = 96;
// Completion can include bounded MCP/A2A commits. It must dominate the 15-second
// workflow-client deadline and leave room for exact acknowledgment-only retry.
const COMPLETION_SOCKET_DEADLINE_MS = 60_000;
const EMPTY_DIGEST = createHash("sha256").update("").digest("hex");
const RECORDER_FAILURE_STAGES = Object.freeze([
  "construction-options", "construction-room", "construction-paths", "construction-platform",
  "release-manifest-fetch", "release-helper-fetch", "release-assets", "adapter-layout", "completion-socket",
  "execution-launch", "execution-command-mismatch", "execution-action-expired", "execution-action-replayed",
  "execution-helper-launch", "execution-helper-failed", "execution-output-invalid", "execution-completion-failed",
  "execution-output", "execution-public-result",
]);
const RECORDER_FAILURES = new WeakMap();
const execFileAsync = promisify(execFile);

export const VERIFIED_RELEASE_HELPER_BOOTSTRAP = 'const fs=require("node:fs");const crypto=require("node:crypto");const Module=require("node:module");const argv=process.argv.slice(1);const expected=argv.shift();const manifestPath=argv.shift();const helperPath=argv.shift();const manifestBytes=fs.readFileSync(manifestPath);const manifestDigest=crypto.createHash("sha256").update(manifestBytes).digest("hex");if(manifestDigest!==expected)process.exit(86);const manifest=JSON.parse(manifestBytes);if(manifest.schema!=="clockchain.agent-handshake-release-manifest/v1"||manifest.version!=="2.1.3"||!/^24\\./.test(manifest.nodeRuntime)||!/^24\\./.test(process.versions.node)||!Array.isArray(manifest.assets)||manifest.assets.length!==1)process.exit(86);const asset=manifest.assets[0];if(asset.filename!=="clockchain-agent-handshake.cjs"||asset.url!=="https://github.com/thetangstr/clockchain-handshake-v2/releases/download/v2.1.3/clockchain-agent-handshake.cjs"||typeof asset.sha256!=="string"||!/^[0-9a-f]{64}$/.test(asset.sha256))process.exit(86);const helperBytes=fs.readFileSync(helperPath);const helperDigest=crypto.createHash("sha256").update(helperBytes).digest("hex");if(helperDigest!==asset.sha256)process.exit(86);process.argv=[process.execPath].concat(helperPath).concat(argv);const loaded=new Module(helperPath);loaded.filename=helperPath;loaded.paths=[];const compile=loaded._compile.bind(loaded);compile(...[helperBytes.toString("utf8")].concat(helperPath));';

function fail() {
  throw new Error("Verified release action recorder failed safely.");
}

function stagedFailure(stage) {
  if (!RECORDER_FAILURE_STAGES.includes(stage)) fail();
  const error = new Error("Verified release action recorder failed safely.");
  RECORDER_FAILURES.set(error, stage);
  return error;
}

export function verifiedReleaseActionRecorderFailureStage(error) {
  return RECORDER_FAILURES.get(error) ?? null;
}

function restage(error, stage) {
  if (verifiedReleaseActionRecorderFailureStage(error) !== null) throw error;
  throw stagedFailure(stage);
}

function snapshotObject(value, allowedKeys, requiredKeys = allowedKeys) {
  if (
    value === null || typeof value !== "object" || Array.isArray(value) || types.isProxy(value) ||
    ![Object.prototype, null].includes(Object.getPrototypeOf(value))
  ) fail();
  let descriptors;
  try { descriptors = Object.getOwnPropertyDescriptors(value); } catch { fail(); }
  const keys = Reflect.ownKeys(descriptors);
  if (keys.some((key) => typeof key !== "string" || !allowedKeys.includes(key))) fail();
  for (const key of requiredKeys) if (!Object.hasOwn(descriptors, key)) fail();
  const result = {};
  for (const key of keys) {
    const descriptor = descriptors[key];
    if (!descriptor.enumerable || !Object.hasOwn(descriptor, "value")) fail();
    result[key] = descriptor.value;
  }
  return result;
}

function absolute(value) {
  if (typeof value !== "string" || !isAbsolute(value)) fail();
  return resolve(value);
}

function descendant(root, value) {
  const cleanRoot = absolute(root);
  const cleanValue = absolute(value);
  const offset = relative(cleanRoot, cleanValue);
  if (offset === "" || offset.startsWith("..") || isAbsolute(offset)) fail();
  return cleanValue;
}

async function privateDirectory(path) {
  await mkdir(path, { recursive: false, mode: 0o700 });
  await chmod(path, 0o700);
  const stat = await lstat(path);
  if (!stat.isDirectory() || stat.isSymbolicLink() || (stat.mode & 0o777) !== 0o700) fail();
}

async function ensurePrivateSocketRoot(path) {
  try {
    await mkdir(path, { recursive: false, mode: 0o700 });
    await chmod(path, 0o700);
  } catch (error) {
    if (error?.code !== "EEXIST") throw error;
  }
  const stat = await lstat(path);
  const uid = process.getuid?.();
  if (
    !stat.isDirectory() || stat.isSymbolicLink() || (stat.mode & 0o777) !== 0o700 ||
    (Number.isSafeInteger(uid) && stat.uid !== uid)
  ) fail();
}

function parseLiteralShellWords(value) {
  if (typeof value !== "string" || value.length < 1 || value.length > 1024 * 1024) fail();
  const words = [];
  let quote = null;
  let word = "";
  let started = false;
  for (let index = 0; index < value.length; index += 1) {
    const char = value[index];
    if (quote === "single") {
      if (char === "'") quote = null;
      else word += char;
      continue;
    }
    if (quote === "double") {
      if (char === '"') quote = null;
      else {
        if (char === "\\" || char === "`" || char === "\r") fail();
        word += char;
      }
      continue;
    }
    if (char === "\\" && value[index + 1] === "\n") {
      index += 1;
      continue;
    }
    if (/\s/.test(char)) {
      if (started) {
        words.push(word);
        word = "";
        started = false;
      }
      continue;
    }
    if (char === "'") {
      quote = "single";
      started = true;
      continue;
    }
    if (char === '"') {
      quote = "double";
      started = true;
      continue;
    }
    if (char === "\\" || /[;&|<>`()[\]{}*?!#~$]/.test(char)) fail();
    word += char;
    started = true;
  }
  if (quote !== null) fail();
  if (started) words.push(word);
  return words;
}

function normalizeHelperStep(step) {
  const allowed = ["approvalCommand", "commandLength", "commandSha256", "operation", "policyDigest", "role", "sessionId", "shellCommand"];
  const item = snapshotObject(step, allowed, allowed.filter((key) => key !== "policyDigest"));
  const shellCommand = item.shellCommand;
  if (typeof shellCommand !== "string" || shellCommand.length < 1) fail();
  const argv = parseLiteralShellWords(shellCommand);
  const commandLength = Buffer.byteLength(shellCommand);
  const commandSha256 = createHash("sha256").update(shellCommand).digest("hex");
  if (
    item.commandLength !== commandLength || item.commandSha256 !== commandSha256 ||
    item.approvalCommand !== `clockchain-agent-authorize ${commandSha256}` ||
    !OPERATIONS.includes(item.operation) || !ROLES.includes(item.role) ||
    !UUID.test(item.sessionId) || (item.policyDigest !== undefined && !SHA256.test(item.policyDigest))
  ) fail();
  return Object.freeze({
    approvalCommand: item.approvalCommand,
    argv: Object.freeze(argv),
    commandLength,
    commandSha256,
    operation: item.operation,
    policyDigest: item.policyDigest ?? null,
    role: item.role,
    sessionId: item.sessionId,
    shellCommand,
  });
}

function requestBinding(expected) {
  const payloadIndex = expected.argv.indexOf("--payload-base64url");
  if (payloadIndex === -1) {
    const bytes = Buffer.from(expected.shellCommand, "utf8");
    return Object.freeze({ digest: createHash("sha256").update(bytes).digest("hex"), length: bytes.length, policyDigest: null });
  }
  if (payloadIndex !== expected.argv.length - 2 || !BASE64URL.test(expected.argv[payloadIndex + 1])) fail();
  const bytes = Buffer.from(expected.argv[payloadIndex + 1], "base64url");
  if (bytes.length < 1 || bytes.toString("base64url") !== expected.argv[payloadIndex + 1]) fail();
  let record;
  try { record = JSON.parse(bytes.toString("utf8")); } catch { fail(); }
  if (expected.operation === "policy") {
    let policy;
    try { policy = validateLocalPolicy(record); } catch { fail(); }
    if (policy.role !== expected.role) fail();
    return Object.freeze({
      digest: createHash("sha256").update(bytes).digest("hex"),
      length: bytes.length,
      policyDigest: localPolicyDigest(policy),
    });
  }
  if (
    record === null || typeof record !== "object" || Array.isArray(record) ||
    (expected.operation === "sign"
      ? !SIGNING_OPERATIONS.includes(record.operation)
      : record.operation !== expected.operation) ||
    record.role !== expected.role ||
    record.sessionId !== expected.sessionId ||
    (expected.policyDigest !== null && record.policyDigest !== expected.policyDigest)
  ) fail();
  return Object.freeze({
    digest: createHash("sha256").update(bytes).digest("hex"),
    length: bytes.length,
    policyDigest: SHA256.test(record.policyDigest) ? record.policyDigest : null,
  });
}

function validateHelperArgv(argv, workspace, manifestDigest) {
  if (!Array.isArray(argv) || argv.length < 8 || argv.some((entry) => typeof entry !== "string")) fail();
  if (
    argv[0] !== "node" || argv[1] !== "--input-type=commonjs" || argv[2] !== "--eval" ||
    argv[3] !== VERIFIED_RELEASE_HELPER_BOOTSTRAP || argv[4] !== manifestDigest || !SHA256.test(manifestDigest)
  ) fail();
  const manifestPath = descendant(workspace, argv[5]);
  const helperPath = descendant(workspace, argv[6]);
  if (basename(manifestPath) !== "manifest.json" || basename(helperPath) !== "clockchain-agent-handshake.cjs") fail();
  if (!OPERATIONS.includes(argv[7]) || argv[8] !== "--state-dir") fail();
  descendant(workspace, argv[9]);
  if (argv.length === 10) return;
  if (argv.length !== 12 || argv[10] !== "--payload-base64url" || !BASE64URL.test(argv[11])) fail();
}

function validateExpectedArgvBinding(argv, expected) {
  if (argv[7] !== expected.operation) fail();
  const stateSuffix = `/.clockchain/handshakes/${expected.sessionId}/${expected.role}`;
  if (!argv[9].endsWith(stateSuffix)) fail();
}

async function fetchReleaseAsset(fetchImpl, url, maxBytes, stage) {
  try {
    const response = await fetchImpl(url);
    if (response?.ok !== true || typeof response.arrayBuffer !== "function") fail();
    const bytes = Buffer.from(await response.arrayBuffer());
    if (bytes.length < 1 || bytes.length > maxBytes) fail();
    return bytes;
  } catch {
    throw stagedFailure(stage);
  }
}

export async function preloadVerifiedReleaseAssets({ fetchImpl, manifestDigest, workspace }) {
  if (typeof fetchImpl !== "function" || !SHA256.test(manifestDigest)) fail();
  const manifestBytes = await fetchReleaseAsset(fetchImpl, `${RELEASE_PREFIX}manifest.json`, 64 * 1024, "release-manifest-fetch");
  if (createHash("sha256").update(manifestBytes).digest("hex") !== manifestDigest) fail();
  let manifest;
  try { manifest = JSON.parse(manifestBytes.toString("utf8")); } catch { fail(); }
  if (
    manifest?.schema !== "clockchain.agent-handshake-release-manifest/v1" || manifest?.version !== "2.1.3" ||
    typeof manifest?.nodeRuntime !== "string" || !/^24\./.test(manifest.nodeRuntime) ||
    !Array.isArray(manifest?.assets) || manifest.assets.length !== 1
  ) fail();
  const asset = manifest.assets[0];
  const helperUrl = `${RELEASE_PREFIX}clockchain-agent-handshake.cjs`;
  if (asset?.filename !== "clockchain-agent-handshake.cjs" || asset?.url !== helperUrl || !SHA256.test(asset?.sha256)) fail();
  const helperBytes = await fetchReleaseAsset(fetchImpl, helperUrl, 1024 * 1024, "release-helper-fetch");
  if (createHash("sha256").update(helperBytes).digest("hex") !== asset.sha256) fail();
  await writeFile(join(workspace, "manifest.json"), manifestBytes, { mode: 0o600 });
  await writeFile(join(workspace, "clockchain-agent-handshake.cjs"), helperBytes, { mode: 0o600 });
}

function adapterExecutable(runtimeExecPath, publicKeyDer, completionDeadlineMs) {
  return `#!${runtimeExecPath}\n` + String.raw`"use strict";
const { spawnSync }=require("node:child_process");
const { createHash,createPublicKey,verify }=require("node:crypto");
const { createConnection }=require("node:net");
const { mkdirSync,readFileSync,renameSync,rmSync,writeFileSync }=require("node:fs");
const { dirname,join,resolve }=require("node:path");
const SHA=/^[0-9a-f]{64}$/;const ROLES=new Set(["initiator","responder"]);const OPS=new Set(["init","policy","inspect","register","sign","verify-certificate"]);const MAX=65536;const COMPLETION_DEADLINE=${completionDeadlineMs};const COMPLETION_ATTEMPT=Math.max(1000,Math.floor(COMPLETION_DEADLINE/2));
function stop(code="HELPER_COMMAND_MISMATCH"){try{process.stderr.write(JSON.stringify({code})+"\n")}catch{}process.exit(86)}
function exact(v,keys){if(!v||typeof v!=="object"||Array.isArray(v)||Object.keys(v).sort().join(",")!==keys.slice().sort().join(","))stop();return v}
function envelope(path,digest){const e=JSON.parse(readFileSync(path,"utf8"));if(!e||Object.keys(e).sort().join(",")!=="body,schema,signature"||e.schema!=="clockchain.agent-harness-bound-action/v1")stop();const bytes=Buffer.from(JSON.stringify(e.body));const key=createPublicKey({key:Buffer.from("${publicKeyDer}","base64"),format:"der",type:"spki"});if(!verify(null,bytes,key,Buffer.from(e.signature,"base64")))stop();const b=exact(e.body,["actionId","actionNonce","args","commandLength","commandSha256","completionRequired","completionSocket","cwd","expiresAtMs","file","manifestDigest","operation","policyDigest","requestDigest","requestLength","role","schema","sessionId","stateDir"]);if(b.schema!=="clockchain.agent-harness-bound-action-body/v2"||b.commandSha256!==digest||!Number.isSafeInteger(b.commandLength)||b.commandLength<1||!SHA.test(b.manifestDigest)||!(b.policyDigest===null||SHA.test(b.policyDigest))||!SHA.test(b.requestDigest)||!Number.isSafeInteger(b.requestLength)||b.requestLength<1||!OPS.has(b.operation)||!ROLES.has(b.role)||!Number.isSafeInteger(b.expiresAtMs)||typeof b.actionId!=="string"||typeof b.actionNonce!=="string"||typeof b.completionRequired!=="boolean"||typeof b.completionSocket!=="string")stop();if(Date.now()>b.expiresAtMs)stop("HELPER_ACTION_EXPIRED");if(b.file!==process.execPath||b.cwd!==process.cwd()||!Array.isArray(b.args)||b.args.some(v=>typeof v!=="string"))stop();const tmp=resolve(process.env.TMPDIR||"");const state=resolve(b.stateDir);if(!tmp||!state.startsWith(tmp+"/"))stop();return b}
function assets(b){const a=b.args;if(a.length<9||a[0]!=="--input-type=commonjs"||a[1]!=="--eval"||a[3]!==b.manifestDigest||a[6]!==b.operation)stop();const mb=readFileSync(a[4]);if(createHash("sha256").update(mb).digest("hex")!==b.manifestDigest)stop();const m=JSON.parse(mb);if(m.schema!=="clockchain.agent-handshake-release-manifest/v1"||m.version!=="2.1.3"||!Array.isArray(m.assets)||m.assets.length!==1)stop();const x=m.assets[0];if(x.filename!=="clockchain-agent-handshake.cjs"||!SHA.test(x.sha256))stop();if(createHash("sha256").update(readFileSync(a[5])).digest("hex")!==x.sha256)stop()}
function completeOnce(b,result){return new Promise((ok,bad)=>{const s=createConnection(b.completionSocket);let out="";const timer=setTimeout(()=>{s.destroy();bad(new Error("transport"))},COMPLETION_ATTEMPT);s.setEncoding("utf8");s.on("connect",()=>s.write(JSON.stringify({actionId:b.actionId,actionNonce:b.actionNonce,commandSha256:b.commandSha256,requestDigest:b.requestDigest,result})+"\n"));s.on("data",c=>{out+=c;if(Buffer.byteLength(out)>MAX){s.destroy();bad(new Error("rejected"))}});s.on("end",()=>{clearTimeout(timer);try{const a=exact(JSON.parse(out),["accepted"]);a.accepted===true?ok():bad(new Error("rejected"))}catch{bad(new Error("rejected"))}});s.on("error",()=>{clearTimeout(timer);bad(new Error("transport"))})})}
async function complete(b,result){const started=Date.now();for(let attempt=0;attempt<3&&Date.now()-started<COMPLETION_DEADLINE;attempt++){try{return await completeOnce(b,result)}catch(e){if(e&&e.message==="rejected")throw e}if(attempt<2)await new Promise(r=>setTimeout(r,100))}throw new Error("completion")}
async function main(){const digest=process.argv.length===3?process.argv[2]:"";if(!SHA.test(digest))stop();const root=dirname(dirname(__filename));const pending=join(root,"pending",digest+".json"),running=join(root,"running",digest+"."+process.pid+".json"),consumed=join(root,"consumed",digest+".json");let b;try{try{readFileSync(consumed);stop("HELPER_ACTION_REPLAYED")}catch(e){if(e&&e.code!=="ENOENT")stop()}b=envelope(pending,digest);assets(b);try{renameSync(pending,running)}catch{try{readFileSync(consumed);stop("HELPER_ACTION_REPLAYED")}catch{}stop()}writeFileSync(consumed,JSON.stringify({schema:"clockchain.agent-harness-consumed-action/v1",commandSha256:b.commandSha256})+"\n",{encoding:"utf8",flag:"wx",mode:0o600});mkdirSync(resolve(b.stateDir),{recursive:true,mode:0o700});const child=spawnSync(b.file,b.args,{cwd:b.cwd,env:process.env,encoding:"utf8",maxBuffer:MAX});if(child.error||!Number.isSafeInteger(child.status))stop("HELPER_EXECUTION_LAUNCH_FAILED");if(child.status!==0)stop("HELPER_OPERATION_FAILED");if(typeof child.stdout!=="string"||Buffer.byteLength(child.stdout)<2||Buffer.byteLength(child.stdout)>MAX||!child.stdout.endsWith("\n")||child.stdout.slice(0,-1).includes("\n"))stop("HELPER_OUTPUT_INVALID");let result;try{result=JSON.parse(child.stdout)}catch{stop("HELPER_OUTPUT_INVALID")}if(!result||typeof result!=="object"||Array.isArray(result))stop("HELPER_OUTPUT_INVALID");if(b.completionRequired){try{await complete(b,result)}catch{stop("HELPER_COMPLETION_FAILED")}}process.stdout.write(child.stdout)}catch{stop()}finally{try{rmSync(running,{force:true})}catch{}}}
main();
`;
}

function executionFailureStage(error) {
  const stderr = error?.stderr;
  if (typeof stderr !== "string" || Buffer.byteLength(stderr) < 2 || Buffer.byteLength(stderr) > 256) return "execution-launch";
  let parsed;
  try { parsed = JSON.parse(stderr.trim()); } catch { return "execution-launch"; }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed) || Object.keys(parsed).join(",") !== "code") return "execution-launch";
  return Object.freeze({
    HELPER_COMMAND_MISMATCH: "execution-command-mismatch",
    HELPER_ACTION_EXPIRED: "execution-action-expired",
    HELPER_ACTION_REPLAYED: "execution-action-replayed",
    HELPER_EXECUTION_LAUNCH_FAILED: "execution-helper-launch",
    HELPER_OPERATION_FAILED: "execution-helper-failed",
    HELPER_OUTPUT_INVALID: "execution-output-invalid",
    HELPER_COMPLETION_FAILED: "execution-completion-failed",
  })[parsed.code] ?? "execution-launch";
}

async function createCompletionSocket({ deadlineMs, platform, socketRoot }) {
  if (!["darwin", "linux"].includes(platform) || !Number.isSafeInteger(deadlineMs) || deadlineMs < 1) fail();
  const root = absolute(socketRoot);
  await ensurePrivateSocketRoot(root);
  const socketPath = join(root, "completion.sock");
  if (Buffer.byteLength(socketPath) > MAX_SOCKET_PATH_BYTES) fail();
  try {
    const collision = await lstat(socketPath);
    const uid = process.getuid?.();
    if (
      !collision.isSocket() || collision.isSymbolicLink() ||
      (Number.isSafeInteger(uid) && collision.uid !== uid)
    ) fail();
    await unlink(socketPath);
  } catch (error) {
    if (error?.code !== "ENOENT") throw error;
  }
  const actions = new Map();
  const sockets = new Set();
  let handler = null;
  let closing = false;
  const server = createServer((socket) => {
    sockets.add(socket);
    socket.setEncoding("utf8");
    socket.setTimeout(deadlineMs, () => socket.destroy());
    let input = "";
    let handled = false;
    socket.on("data", (chunk) => {
      if (handled) return;
      input += chunk;
      if (Buffer.byteLength(input) > MAX_RESULT_BYTES || (input.includes("\n") && !input.endsWith("\n"))) {
        handled = true;
        socket.end('{"accepted":false}\n');
        return;
      }
      if (!input.endsWith("\n")) return;
      handled = true;
      void (async () => {
        try {
          const value = JSON.parse(input.slice(0, -1));
          if (value === null || typeof value !== "object" || Array.isArray(value) ||
              JSON.stringify(Object.keys(value).sort()) !== JSON.stringify(["actionId", "actionNonce", "commandSha256", "requestDigest", "result"].sort())) fail();
          const action = actions.get(value.actionId);
          if (!action || value.actionNonce !== action.actionNonce ||
              value.commandSha256 !== action.commandSha256 || value.requestDigest !== action.requestDigest || handler === null) fail();
          const completionResultDigest = createHash("sha256").update(JSON.stringify(value.result)).digest("hex");
          if (action.completionResultDigest !== null && action.completionResultDigest !== completionResultDigest) fail();
          if (action.state === "pending") {
            action.state = "active";
            action.completionResultDigest = completionResultDigest;
            action.completion = (async () => {
              let handlerTimer;
              try {
                const accepted = await Promise.race([
                  Promise.resolve(handler(Object.freeze({
                    actionId: value.actionId,
                    commandSha256: value.commandSha256,
                    operation: action.operation,
                    requestDigest: value.requestDigest,
                    result: value.result,
                    role: action.role,
                    sessionId: action.sessionId,
                  }))),
                  new Promise((_, reject) => { handlerTimer = setTimeout(reject, deadlineMs); }),
                ]);
                if (accepted?.accepted !== true) fail();
                action.state = "consumed";
              } catch (error) {
                action.state = "failed";
                throw error;
              } finally {
                clearTimeout(handlerTimer);
              }
            })();
          }
          if (action.state === "failed" || action.completion === null) fail();
          await action.completion;
          socket.end('{"accepted":true}\n');
        } catch {
          socket.end('{"accepted":false}\n');
        }
      })();
    });
    socket.on("close", () => sockets.delete(socket));
    socket.on("error", () => {});
  });
  await new Promise((resolveListen, rejectListen) => {
    server.once("error", rejectListen);
    server.listen(socketPath, () => {
      server.off("error", rejectListen);
      resolveListen();
    });
  });
  server.unref();
  const stat = await lstat(socketPath);
  if (!stat.isSocket() || stat.isSymbolicLink()) fail();
  return Object.freeze({
    actions,
    root,
    socketPath,
    setHandler(value) {
      if (closing || typeof value !== "function") fail();
      handler = value;
    },
    async close() {
      if (closing) return;
      closing = true;
      for (const socket of sockets) socket.destroy();
      await new Promise((resolveClose) => server.close(() => resolveClose()));
      try {
        const owned = await lstat(socketPath);
        if (!owned.isSocket() || owned.isSymbolicLink()) fail();
        await unlink(socketPath);
      } catch (error) {
        if (error?.code !== "ENOENT") throw error;
      }
    },
  });
}

export async function createVerifiedReleaseActionRecorder(input = {}) {
  let options;
  try {
    options = snapshotObject(input, [
      "actionTtlMs", "completionDeadlineMs", "fetchImpl", "manifestDigest", "platform",
      "room", "runtimeExecPath", "socketRoot",
    ], ["manifestDigest", "room", "socketRoot"]);
  } catch (error) { restage(error, "construction-options"); }
  const actionTtlMs = options.actionTtlMs ?? 5 * 60_000;
  const completionDeadlineMs = options.completionDeadlineMs ?? COMPLETION_SOCKET_DEADLINE_MS;
  const fetchImpl = options.fetchImpl ?? globalThis.fetch;
  const manifestDigest = options.manifestDigest;
  const platform = options.platform ?? process.platform;
  let room;
  try {
    room = snapshotObject(options.room, ["cache", "home", "root", "state", "tmp", "workspace"], ["tmp", "workspace"]);
  } catch (error) { restage(error, "construction-room"); }
  const runtimeExecPath = options.runtimeExecPath ?? process.execPath;
  const socketRoot = options.socketRoot;
  if (
    !SHA256.test(manifestDigest) || room === null || typeof room !== "object" || Array.isArray(room) ||
    !Number.isSafeInteger(actionTtlMs) || actionTtlMs < 1 || actionTtlMs > 10 * 60_000 ||
    !Number.isSafeInteger(completionDeadlineMs) || completionDeadlineMs < 1 || completionDeadlineMs > 60_000
  ) throw stagedFailure("construction-options");
  let workspace;
  let tmp;
  let runtime;
  try {
    workspace = absolute(room.workspace);
    tmp = descendant(workspace, room.tmp);
    runtime = absolute(runtimeExecPath);
  } catch (error) { restage(error, "construction-paths"); }
  if (!["darwin", "linux"].includes(platform)) throw stagedFailure("construction-platform");
  try { await preloadVerifiedReleaseAssets({ fetchImpl, manifestDigest, workspace }); }
  catch (error) { restage(error, "release-assets"); }
  const root = join(workspace, ".clockchain-adapter");
  const bin = join(root, "bin");
  const pending = join(root, "pending");
  const running = join(root, "running");
  const consumed = join(root, "consumed");
  try {
    for (const path of [root, bin, pending, running, consumed]) await privateDirectory(path);
  } catch (error) { restage(error, "adapter-layout"); }
  let completion;
  try { completion = await createCompletionSocket({ deadlineMs: completionDeadlineMs, platform, socketRoot }); }
  catch (error) { restage(error, "completion-socket"); }
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const publicKeyDer = publicKey.export({ type: "spki", format: "der" }).toString("base64");
  const trustedAdapterPublicKey = rawEd25519PublicKey(publicKey);
  const executable = join(bin, "clockchain-agent-authorize");
  await writePrivateFile({ path: executable, bytes: Buffer.from(adapterExecutable(runtime, publicKeyDer, completionDeadlineMs), "utf8") });
  await chmod(executable, 0o500);
  let completionHandlerSet = false;
  const retainedByCommand = new Map();

  function recordRetainedAction(value) {
    if (!completionHandlerSet) fail();
    const expected = normalizeHelperStep(value);
    const argv = [...expected.argv];
    if (argv[0] !== "node") fail();
    argv[5] = isAbsolute(argv[5]) ? descendant(workspace, argv[5]) : descendant(workspace, resolve(workspace, argv[5]));
    argv[6] = isAbsolute(argv[6]) ? descendant(workspace, argv[6]) : descendant(workspace, resolve(workspace, argv[6]));
    if (typeof argv[9] !== "string" || !argv[9].startsWith("$TMPDIR/")) fail();
    argv[9] = descendant(tmp, resolve(tmp, argv[9].slice("$TMPDIR/".length)));
    validateHelperArgv(argv, workspace, manifestDigest);
    validateExpectedArgvBinding(argv, expected);
    const request = requestBinding(expected);
    const prior = retainedByCommand.get(expected.commandSha256);
    if (prior !== undefined) {
      if (
        prior.operation !== expected.operation || prior.requestDigest !== request.digest ||
        prior.requestLength !== request.length || prior.role !== expected.role ||
        prior.sessionId !== expected.sessionId || prior.policyDigest !== (expected.policyDigest ?? request.policyDigest ?? EMPTY_DIGEST)
      ) fail();
      return prior;
    }
    const issuedAtMs = Date.now();
    const actionId = randomUUID();
    const actionNonce = randomBytes(32).toString("base64url");
    const effectivePolicyDigest = expected.policyDigest ?? request.policyDigest;
    const policyDigest = effectivePolicyDigest ?? EMPTY_DIGEST;
    const unsigned = Object.freeze({
      schema: "clockchain.retained-local-action/v1",
      sessionId: expected.sessionId,
      role: expected.role,
      actionId,
      operation: expected.operation,
      requestDigest: request.digest,
      requestLength: request.length,
      commandSha256: expected.commandSha256,
      commandLength: expected.commandLength,
      policyDigest,
      issuedAtMs,
      expiresAtMs: issuedAtMs + actionTtlMs,
    });
    const actionBytes = Buffer.from(JSON.stringify(unsigned));
    const action = Object.freeze({
      ...unsigned,
      adapterRecordDigest: createHash("sha256").update(actionBytes).digest("hex"),
      adapterSignature: signBytes(null, actionBytes, privateKey).toString("base64"),
      adapterPublicKey: trustedAdapterPublicKey,
    });
    const body = Object.freeze({
      schema: "clockchain.agent-harness-bound-action-body/v2",
      actionId,
      actionNonce,
      commandSha256: expected.commandSha256,
      commandLength: expected.commandLength,
      operation: expected.operation,
      manifestDigest,
      policyDigest: effectivePolicyDigest,
      requestDigest: request.digest,
      requestLength: request.length,
      role: expected.role,
      sessionId: expected.sessionId,
      expiresAtMs: unsigned.expiresAtMs,
      file: runtime,
      args: Object.freeze(argv.slice(1)),
      cwd: workspace,
      stateDir: argv[9],
      completionRequired: true,
      completionSocket: completion.socketPath,
    });
    const signature = signBytes(null, Buffer.from(JSON.stringify(body)), privateKey).toString("base64");
    const bytes = `${JSON.stringify({ schema: "clockchain.agent-harness-bound-action/v1", body, signature })}\n`;
    const target = join(pending, `${expected.commandSha256}.json`);
    try { writeFileSync(target, bytes, { encoding: "utf8", flag: "wx", mode: 0o600 }); }
    catch (error) { if (error?.code !== "EEXIST" || readFileSync(target, "utf8") !== bytes) fail(); }
    completion.actions.set(actionId, {
      actionNonce,
      commandSha256: expected.commandSha256,
      operation: expected.operation,
      requestDigest: request.digest,
      role: expected.role,
      sessionId: expected.sessionId,
      state: "pending",
      completion: null,
      completionResultDigest: null,
    });
    retainedByCommand.set(expected.commandSha256, action);
    return action;
  }

  async function executeAuthorizedAction(value) {
    const input = snapshotObject(value, ["actionId", "commandSha256", "role", "sessionId"]);
    if (
      typeof input.actionId !== "string" || !SHA256.test(input.commandSha256) ||
      !ROLES.includes(input.role) || !UUID.test(input.sessionId)
    ) fail();
    const action = retainedByCommand.get(input.commandSha256);
    if (
      action === undefined || action.actionId !== input.actionId || action.role !== input.role ||
      action.sessionId !== input.sessionId
    ) fail();
    let stdout;
    try {
      ({ stdout } = await execFileAsync(runtime, [executable, input.commandSha256], {
        cwd: workspace,
        encoding: "utf8",
        env: { ...process.env, PATH: `${bin}:${process.env.PATH ?? ""}`, TMPDIR: tmp },
        maxBuffer: MAX_RESULT_BYTES,
      }));
    } catch (error) { throw stagedFailure(executionFailureStage(error)); }
    if (
      typeof stdout !== "string" || Buffer.byteLength(stdout) < 2 ||
      Buffer.byteLength(stdout) > MAX_RESULT_BYTES || !stdout.endsWith("\n") ||
      stdout.slice(0, -1).includes("\n")
    ) throw stagedFailure("execution-output");
    let publicResult;
    try { publicResult = JSON.parse(stdout.slice(0, -1)); } catch { throw stagedFailure("execution-public-result"); }
    if (
      publicResult === null || typeof publicResult !== "object" || Array.isArray(publicResult) ||
      types.isProxy(publicResult) || ![Object.prototype, null].includes(Object.getPrototypeOf(publicResult))
    ) throw stagedFailure("execution-public-result");
    return Object.freeze({
      actionId: action.actionId,
      commandSha256: action.commandSha256,
      executed: true,
      operation: action.operation,
      publicResult,
      role: action.role,
      sessionId: action.sessionId,
    });
  }

  return Object.freeze({
    actionRecorder: Object.freeze({ executeAuthorizedAction, record: recordRetainedAction }),
    bin,
    consumed,
    pending,
    record: recordRetainedAction,
    recordRetainedAction,
    executeAuthorizedAction,
    root,
    trustedAdapterPublicKey,
    setCompletionHandler(handler) {
      if (completionHandlerSet) fail();
      completion.setHandler(handler);
      completionHandlerSet = true;
    },
    close: completion.close,
  });
}
