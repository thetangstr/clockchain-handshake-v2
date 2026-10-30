// Upstream tool-result handling for the local adapter (H-REQ-06). Pure: no
// I/O and no state, so it can be carried to another adapter line unchanged.
//
// A hosted tool result may present the same data twice: as JSON inside a text
// content item and as structuredContent. Clients may read either one, so both
// are treated as views of one value:
//   - content must be an array of text items; any other item type is refused;
//   - every text item must hold a JSON object, with one exception: the
//     coordinator's MCP server reports a request it could not run as an error
//     result whose only item is plain text starting "MCP error <code>: ". That
//     shape is accepted, but its text is never forwarded: the client sees
//     "MCP error <code>: " with the parsed integer code and a fixed local
//     text. Any other plain text is refused;
//   - structuredContent, when present, must be a plain object, and every JSON
//     text view must be deep-equal to it;
//   - an executable field (shellCommand, shellCommandFetch,
//     stateDirectoryCommand) must hold a string; any other value is refused;
//   - helper steps are collected from every view, and executable fields are
//     withheld from every view;
//   - a walk that would go below MAX_WALK_DEPTH refuses instead of stopping;
//   - the exposed result is rebuilt from the parsed and checked values of
//     content, structuredContent and isError only; every other field
//     (including _meta) is dropped, and JSON text is re-serialized.
// Every refusal throws; callers map it to their own refusal text. An upstream
// JSON-RPC error is reduced to its numeric code and a generic message.

import { isDeepStrictEqual, types } from "node:util";

export const MAX_WALK_DEPTH = 32;

// Coordinator responses embed runnable shell (shellCommand, the digest-bound
// shellCommandFetch download-and-exec chain, stateDirectoryCommand) for
// adapter-less clients. Under the adapter those bytes are staged privately and
// executed through authorize_local_action, so the agent-visible copy must not
// carry them. commandSha256/commandLength stay — they attest to the staged
// step without being executable.
export const WITHHELD_COMMAND =
  "[withheld by clockchain-local-adapter: this digest-bound step is staged " +
  "privately; execute it by calling authorize_local_action]";
const EXECUTABLE_KEYS = Object.freeze(new Set([
  "shellCommand", "shellCommandFetch", "stateDirectoryCommand",
]));

// The coordinator's plain-text error: the MCP SDK's own error result text.
// Only its numeric code is kept; the message is replaced by WITHHELD_ERROR_TEXT.
const PLAIN_ERROR = /^MCP error (-?[0-9]{1,6}): /;
export const WITHHELD_ERROR_TEXT =
  "[withheld by clockchain-local-adapter: upstream error text]";

// Upstream JSON-RPC errors keep only their numeric code; the message is kept
// only when it is one of the JSON-RPC standard messages.
export const UPSTREAM_ERROR_MESSAGE = "Clockchain local adapter upstream request failed.";
const STANDARD_RPC_ERROR_MESSAGES = Object.freeze(new Set([
  "Parse error", "Invalid Request", "Method not found", "Invalid params", "Internal error",
]));

function refuse() {
  throw new Error("Upstream tool result refused.");
}

function isPlainObject(value) {
  return (
    value !== null && typeof value === "object" && !Array.isArray(value) &&
    !types.isProxy(value) &&
    [Object.prototype, null].includes(Object.getPrototypeOf(value))
  );
}

function ownData(object, key) {
  const descriptor = Object.getOwnPropertyDescriptor(object, key);
  if (descriptor === undefined) return { present: false, value: undefined };
  if (descriptor.enumerable !== true || !Object.hasOwn(descriptor, "value")) refuse();
  return { present: true, value: descriptor.value };
}

function defineOwn(target, key, value) {
  // defineProperty keeps a "__proto__" key an ordinary own property.
  Object.defineProperty(target, key, {
    value, enumerable: true, writable: true, configurable: true,
  });
}

// Deep-copies a JSON value into fresh, frozen plain data. Refuses anything that
// is not JSON data and any object or array deeper than MAX_WALK_DEPTH, so later
// walks see a bounded tree.
function copyJsonTree(value, depth) {
  if (value === null || typeof value === "string" || typeof value === "boolean") return value;
  if (typeof value === "number") {
    if (!Number.isFinite(value)) refuse();
    return value;
  }
  if (typeof value !== "object" || depth > MAX_WALK_DEPTH) refuse();
  if (Array.isArray(value)) {
    if (types.isProxy(value)) refuse();
    const copy = [];
    for (let index = 0; index < value.length; index += 1) {
      const entry = ownData(value, String(index));
      if (!entry.present) refuse();
      copy.push(copyJsonTree(entry.value, depth + 1));
    }
    return Object.freeze(copy);
  }
  if (!isPlainObject(value)) refuse();
  const copy = {};
  for (const key of Reflect.ownKeys(value)) {
    if (typeof key !== "string") refuse();
    const entry = copyJsonTree(ownData(value, key).value, depth + 1);
    if (EXECUTABLE_KEYS.has(key) && typeof entry !== "string") refuse();
    defineOwn(copy, key, entry);
  }
  return Object.freeze(copy);
}

function parseJsonText(text) {
  try {
    return { json: true, value: JSON.parse(text) };
  } catch {
    return { json: false, value: undefined };
  }
}

// Validates an upstream tools/call result and returns a frozen normalized form:
// { items: [{ text, json?, value? }], hasStructured, structuredContent, isError }.
export function normalizeUpstreamToolResult(result) {
  if (!isPlainObject(result)) refuse();
  const content = ownData(result, "content");
  if (!content.present || !Array.isArray(content.value) || types.isProxy(content.value)) refuse();
  const items = [];
  for (let index = 0; index < content.value.length; index += 1) {
    const entry = ownData(content.value, String(index));
    if (!entry.present || !isPlainObject(entry.value)) refuse();
    const type = ownData(entry.value, "type").value;
    const text = ownData(entry.value, "text").value;
    if (type !== "text" || typeof text !== "string") refuse();
    const parsed = parseJsonText(text);
    if (parsed.json && !isPlainObject(parsed.value)) refuse();
    items.push(Object.freeze(parsed.json
      ? { text, json: true, value: copyJsonTree(parsed.value, 0) }
      : { text, json: false }));
  }
  const structured = ownData(result, "structuredContent");
  let structuredContent;
  if (structured.present) {
    if (!isPlainObject(structured.value)) refuse();
    structuredContent = copyJsonTree(structured.value, 0);
    for (const item of items) {
      if (item.json && !isDeepStrictEqual(item.value, structuredContent)) refuse();
    }
  }
  const isError = ownData(result, "isError");
  if (isError.present && typeof isError.value !== "boolean") refuse();
  if (
    items.some((item) => !item.json) && (
      isError.value !== true || items.length !== 1 || structured.present ||
      !PLAIN_ERROR.test(items[0].text)
    )
  ) refuse();
  return Object.freeze({
    items: Object.freeze(items),
    hasStructured: structured.present,
    structuredContent,
    isError: isError.present ? isError.value : undefined,
  });
}

function collectFrom(value, depth, out) {
  if (value === null || typeof value !== "object") return;
  if (depth > MAX_WALK_DEPTH) refuse();
  if (Array.isArray(value)) {
    for (const entry of value) collectFrom(entry, depth + 1, out);
    return;
  }
  if (Object.hasOwn(value, "helperStep")) out.push(value.helperStep);
  if (Object.hasOwn(value, "helperSteps")) {
    if (!Array.isArray(value.helperSteps)) refuse();
    for (const entry of value.helperSteps) out.push(entry);
  }
  for (const key of Object.keys(value)) collectFrom(value[key], depth + 1, out);
}

// Every helperStep / helperSteps candidate in every view, in view order. The
// same step mirrored in two views appears twice; staging deduplicates.
export function collectHelperStepCandidates(normalized) {
  const out = [];
  for (const item of normalized.items) if (item.json) collectFrom(item.value, 0, out);
  if (normalized.hasStructured) collectFrom(normalized.structuredContent, 0, out);
  return Object.freeze(out);
}

// Returns a fresh copy with every executable field withheld (normalization
// has already refused any that is not a string), and whether anything changed.
function withholdExecutableFields(value, depth) {
  if (value === null || typeof value !== "object") return { value, changed: false };
  if (depth > MAX_WALK_DEPTH) refuse();
  let changed = false;
  if (Array.isArray(value)) {
    const copy = value.map((entry) => {
      const next = withholdExecutableFields(entry, depth + 1);
      changed = next.changed || changed;
      return next.value;
    });
    return { value: copy, changed };
  }
  const copy = {};
  for (const key of Object.keys(value)) {
    if (EXECUTABLE_KEYS.has(key)) {
      if (typeof value[key] !== "string") refuse();
      defineOwn(copy, key, WITHHELD_COMMAND);
      changed = true;
    } else {
      const next = withholdExecutableFields(value[key], depth + 1);
      changed = next.changed || changed;
      defineOwn(copy, key, next.value);
    }
  }
  return { value: copy, changed };
}

// The plain-text error a client sees: the parsed integer code and a fixed
// local text. No upstream message text is forwarded.
function exposePlainError(text) {
  const code = Number(PLAIN_ERROR.exec(text)[1]);
  return `MCP error ${code}: ${WITHHELD_ERROR_TEXT}`;
}

// The result a client sees: rebuilt from the parsed values of content,
// structuredContent and isError only, with executable fields withheld from
// every view. JSON text is always re-serialized from its parsed value, so the
// client never sees bytes that parsing dropped.
export function exposeToolResult(normalized) {
  const content = normalized.items.map((item) => {
    if (!item.json) return Object.freeze({ type: "text", text: exposePlainError(item.text) });
    return Object.freeze({
      type: "text",
      text: JSON.stringify(withholdExecutableFields(item.value, 0).value),
    });
  });
  const exposed = { content: Object.freeze(content) };
  if (normalized.hasStructured) {
    exposed.structuredContent = withholdExecutableFields(normalized.structuredContent, 0).value;
  }
  if (normalized.isError !== undefined) exposed.isError = normalized.isError;
  return Object.freeze(exposed);
}

// The error a client sees for an upstream JSON-RPC error: the upstream numeric
// code when it is an integer (otherwise -32603), and the upstream message only
// when it is a JSON-RPC standard message. data and any other text are dropped.
export function sanitizeUpstreamError(error) {
  const fields = isPlainObject(error) ? error : {};
  const code = Object.hasOwn(fields, "code") && Number.isSafeInteger(fields.code)
    ? fields.code
    : -32603;
  const message = Object.hasOwn(fields, "message") &&
    typeof fields.message === "string" &&
    STANDARD_RPC_ERROR_MESSAGES.has(fields.message)
    ? fields.message
    : UPSTREAM_ERROR_MESSAGE;
  return Object.freeze({ code, message });
}
