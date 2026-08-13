const START_MARKER = "start-fresh-demo";
const MAX_BODY_BYTES = 128;

function sendJson(response, statusCode, value, origin = null) {
  const body = Buffer.from(JSON.stringify(value), "utf8");
  response.writeHead(statusCode, {
    "cache-control": "no-store",
    "content-length": String(body.length),
    "content-type": "application/json; charset=utf-8",
    ...(origin === null ? {} : { "access-control-allow-origin": origin, vary: "Origin" }),
  });
  response.end(body);
}

async function readEmptyObject(request) {
  const chunks = [];
  let length = 0;
  for await (const chunk of request) {
    length += chunk.length;
    if (length > MAX_BODY_BYTES) return false;
    chunks.push(chunk);
  }
  if (length === 0) return true;
  try {
    const value = JSON.parse(Buffer.concat(chunks).toString("utf8"));
    return value !== null && typeof value === "object" && !Array.isArray(value) && Object.keys(value).length === 0;
  } catch {
    return false;
  }
}

export function createFacilitatorDemoControlHandler({ allowedOrigins, launchDemo }) {
  if (!Array.isArray(allowedOrigins) || allowedOrigins.length === 0 ||
      allowedOrigins.some((origin) => typeof origin !== "string" || origin.length === 0)) {
    throw new TypeError("allowedOrigins must contain at least one origin.");
  }
  if (typeof launchDemo !== "function") {
    throw new TypeError("launchDemo must be a function.");
  }

  const trustedOrigins = new Set(allowedOrigins);
  let starting = false;

  return async function facilitatorDemoControl(request, response) {
    const origin = typeof request.headers.origin === "string" ? request.headers.origin : null;
    const trustedOrigin = origin !== null && trustedOrigins.has(origin);
    const url = new URL(request.url ?? "/", "http://127.0.0.1");

    if (!trustedOrigin) {
      sendJson(response, 403, { code: "FORBIDDEN", ok: false });
      return;
    }

    if (request.method === "OPTIONS") {
      if (url.pathname !== "/control/start") {
        sendJson(response, 404, { code: "NOT_FOUND", ok: false }, origin);
        return;
      }
      response.writeHead(204, {
        "access-control-allow-headers": "content-type,x-clockchain-facilitator",
        "access-control-allow-methods": "POST,OPTIONS",
        "access-control-allow-origin": origin,
        "access-control-allow-private-network": "true",
        "cache-control": "no-store",
        vary: "Origin, Access-Control-Request-Method, Access-Control-Request-Headers",
      });
      response.end();
      return;
    }

    if (request.method === "GET" && url.pathname === "/control/status") {
      sendJson(response, 200, {
        ok: true,
        ready: !starting,
        state: starting ? "starting" : "ready",
      }, origin);
      return;
    }

    if (request.method !== "POST" || url.pathname !== "/control/start") {
      sendJson(response, 404, { code: "NOT_FOUND", ok: false }, origin);
      return;
    }

    if (request.headers["x-clockchain-facilitator"] !== START_MARKER) {
      sendJson(response, 403, { code: "FORBIDDEN", ok: false }, origin);
      return;
    }
    if (!(await readEmptyObject(request))) {
      sendJson(response, 400, { code: "MALFORMED_BODY", ok: false }, origin);
      return;
    }
    if (starting) {
      sendJson(response, 409, {
        code: "DEMO_START_IN_PROGRESS",
        ok: false,
        state: "starting",
      }, origin);
      return;
    }

    starting = true;
    try {
      await launchDemo();
      sendJson(response, 202, { ok: true, state: "started" }, origin);
    } catch {
      sendJson(response, 500, {
        code: "DEMO_START_FAILED",
        ok: false,
        state: "ready",
      }, origin);
    } finally {
      starting = false;
    }
  };
}
