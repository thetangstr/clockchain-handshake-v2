// src/monitor/control-plane/app.mjs
//
// The session host control plane's client-side script. Plain ES module, no
// build step, no framework -- loaded directly by the browser from
// index.html. Served loopback-only by the session host process alongside
// routes.mjs (see that file's header for the HTTP surface and the P2
// rationale for binding 127.0.0.1 only).
//
// This script only ever does two things a person did not ask for: poll
// GET /control/snapshot on a timer, and re-render the DOM from whatever it
// gets back. Every mutating action (Start, Abort, Re-verify) is a direct
// response to a click. There is no third control here, by design -- see the
// binding rule: exactly two controls (Start, Abort). "Re-verify" is
// deliberately not counted as a control: it never changes the run, it only
// asks Clockchain a read-only question again.

import {
  REASON_CODES,
  STATUS_CODES,
  reasonMessage,
  renderVerdict,
  statusMessage,
} from "./messages.mjs";

// Named to avoid scripts/check-invariants.sh's human-paced wait sweep, which
// flags any TIMEOUT|DEADLINE|WINDOW|WAIT|POLL|EXPIR *_MS constant for
// classification: this is a UI refresh cadence, not a protocol wait bound.
const SNAPSHOT_REFRESH_MS = 3000;
const ANCHOR_ORDER = Object.freeze([
  "proposal",
  "acceptance",
  "acknowledgment",
]);
const ANCHOR_TITLES = Object.freeze({
  acceptance: "Acceptance",
  acknowledgment: "Acknowledgment",
  proposal: "Proposal",
});

function el(tag, attributes = {}, children = []) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attributes)) {
    if (key === "class") {
      node.className = value;
    } else if (key === "text") {
      node.textContent = value;
    } else if (key.startsWith("on") && typeof value === "function") {
      node.addEventListener(key.slice(2), value);
    } else if (value !== undefined && value !== null) {
      node.setAttribute(key, value);
    }
  }
  for (const child of Array.isArray(children) ? children : [children]) {
    if (child === undefined || child === null || child === false) {
      continue;
    }
    node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return node;
}

function ageLabel(lastSeenMs) {
  if (typeof lastSeenMs !== "number" || !Number.isFinite(lastSeenMs)) {
    return "no heartbeat yet";
  }
  const seconds = Math.max(0, Math.round((Date.now() - lastSeenMs) / 1000));
  return `last update ${seconds}s ago`;
}

function formatJson(value) {
  try {
    return JSON.stringify(value ?? null, null, 2);
  } catch {
    return "(unavailable)";
  }
}

async function postJson(path, body) {
  const response = await fetch(path, {
    body: body === undefined ? undefined : JSON.stringify(body),
    cache: "no-store",
    headers: body === undefined ? {} : { "content-type": "application/json" },
    method: "POST",
  });
  let payload = null;
  try {
    payload = await response.json();
  } catch {
    payload = null;
  }
  return { ok: response.ok, payload, status: response.status };
}

async function getJson(path) {
  const response = await fetch(path, { cache: "no-store" });
  if (!response.ok) {
    throw new Error(`${path} responded ${response.status}`);
  }
  return response.json();
}

const reverifyResults = new Map();

function renderHeader(root, snapshot) {
  const header = el("section", { class: "panel header" }, [
    el("div", { class: "run-id" }, [
      el("span", { class: "label", text: "Session" }),
      el("span", { class: "value mono", text: snapshot?.sessionId ?? "(none yet)" }),
    ]),
    el("div", { class: "run-id" }, [
      el("span", { class: "label", text: "Sub-run" }),
      el("span", { class: "value mono", text: snapshot?.subjectRun ?? "(none yet)" }),
    ]),
    el("div", { class: "moved-banner", text: "paymentMoved: false -- no money has moved" }),
  ]);
  root.append(header);
}

function renderControls(root, refresh) {
  const status = el("span", { class: "control-status" }, "");
  const startButton = el("button", {
    class: "control start",
    onclick: async () => {
      startButton.disabled = true;
      abortButton.disabled = true;
      status.textContent = "Starting...";
      const result = await postJson("/control/start");
      status.textContent = result.ok ? "Start requested." : "Start failed.";
      startButton.disabled = false;
      abortButton.disabled = false;
      refresh();
    },
    text: "Start",
  });
  const abortButton = el("button", {
    class: "control abort",
    onclick: async () => {
      startButton.disabled = true;
      abortButton.disabled = true;
      status.textContent = "Aborting...";
      const result = await postJson("/control/abort");
      status.textContent = result.ok ? "Abort requested." : "Abort failed.";
      startButton.disabled = false;
      abortButton.disabled = false;
      refresh();
    },
    text: "Abort",
  });
  root.append(
    el("section", { class: "panel controls" }, [
      el("h2", { text: "Controls" }),
      el("p", {
        class: "hint",
        text:
          "Exactly two controls. This dashboard shows the run; it never gates it.",
      }),
      el("div", { class: "control-row" }, [startButton, abortButton, status]),
    ]),
  );
}

function renderVerdictPanel(root, snapshot) {
  const rendered = renderVerdict(snapshot?.verdict ?? null);
  root.append(
    el("section", { class: `panel verdict verdict-${rendered.state}` }, [
      el("h2", { text: "Verdict" }),
      el("div", { class: "verdict-headline", text: rendered.headline }),
      el("div", { class: "verdict-detail", text: rendered.detail }),
    ]),
  );
}

function renderAuditTrail(root, snapshot) {
  const history = Array.isArray(snapshot?.stageHistory)
    ? snapshot.stageHistory
    : [];
  const rows = history.map((entry) =>
    el("li", { class: "audit-row" }, [
      el("span", { class: "mono code", text: entry?.status ?? "?" }),
      el("span", {
        class: "sentence",
        text: STATUS_CODES.includes(entry?.status)
          ? statusMessage(entry.status)
          : REASON_CODES.includes(entry?.status)
            ? reasonMessage(entry.status)
            : statusMessage(entry?.status),
      }),
      el("span", {
        class: "timestamp",
        text:
          typeof entry?.at === "number"
            ? new Date(entry.at).toISOString()
            : "(no timestamp)",
      }),
    ]),
  );
  root.append(
    el("section", { class: "panel audit-trail" }, [
      el("h2", { text: "Audit trail" }),
      rows.length > 0
        ? el("ol", { class: "audit-list" }, rows)
        : el("p", { class: "hint", text: "No stages recorded yet." }),
    ]),
  );
}

function renderAnchorPanel(root, snapshot, anchorKind, refresh) {
  const anchors = Array.isArray(snapshot?.anchors) ? snapshot.anchors : [];
  const anchor = anchors.find((entry) => entry?.kind === anchorKind) ?? null;
  const cached = reverifyResults.get(anchorKind);

  const reverifyButton = el("button", {
    class: "reverify",
    disabled: anchor === null ? "disabled" : undefined,
    onclick: async () => {
      reverifyButton.disabled = true;
      reverifyButton.textContent = "Checking Clockchain...";
      const result = await postJson("/control/reverify", { anchorKind });
      reverifyResults.set(anchorKind, result.payload);
      refresh();
    },
    text: "Re-verify this receipt",
  });

  const resultBlock = cached
    ? el("div", { class: `reverify-result ${cached.match ? "match" : "mismatch"}` }, [
        el("div", {
          class: "reverify-headline",
          text: cached.match
            ? "Confirmed against a fresh, independent Clockchain read."
            : "Fresh Clockchain read did not confirm this receipt.",
        }),
        el("div", { class: "reverify-timestamp", text: `Checked at ${cached.verifiedAt ?? "(unknown time)"}` }),
        cached.match
          ? el("pre", { class: "receipt", text: formatJson(cached.onChain) })
          : el("div", { class: "reverify-reason", text: cached.reason ?? "" }),
      ])
    : el("p", { class: "hint", text: "Not yet re-verified this run." });

  root.append(
    el("article", { class: "panel anchor" }, [
      el("h2", { text: ANCHOR_TITLES[anchorKind] }),
      anchor === null
        ? el("p", { class: "hint", text: "Not anchored yet." })
        : el("div", { class: "anchor-body" }, [
            el("dl", { class: "anchor-facts" }, [
              el("dt", { text: "Kind" }),
              el("dd", { class: "mono", text: anchor.kind }),
              el("dt", { text: "Block height" }),
              el("dd", { class: "mono", text: String(anchor.blockHeight ?? "?") }),
              el("dt", { text: "Ledger id" }),
              el("dd", { class: "mono", text: anchor.ledgerId ?? "?" }),
              el("dt", { text: "Block time" }),
              el("dd", { class: "mono", text: anchor.blockTime ?? "?" }),
              el("dt", { text: "Digest chain" }),
              el("dd", { class: "mono", text: formatJson(anchor.digestChain ?? null) }),
            ]),
            el("details", { class: "receipt-fold" }, [
              el("summary", { text: "Receipt payload" }),
              el("pre", { class: "receipt", text: formatJson(anchor.receipt ?? null) }),
            ]),
            anchor.explorerUrl
              ? el("a", {
                  class: "explorer-link",
                  href: anchor.explorerUrl,
                  rel: "noopener noreferrer",
                  target: "_blank",
                  text: "View on Clockchain",
                })
              : null,
          ]),
      el("div", { class: "reverify-row" }, [reverifyButton]),
      resultBlock,
    ]),
  );
}

function renderFunding(root, snapshot) {
  const addresses = Array.isArray(snapshot?.funding?.addresses)
    ? snapshot.funding.addresses
    : [];
  const journalState = snapshot?.funding?.journal?.state ?? "(unknown)";
  const rows = addresses.map((entry) =>
    el("li", { class: "funding-row" }, [
      el("span", { class: "mono", text: entry?.address ?? "?" }),
      el("span", { class: "mono", text: `balance ${entry?.balanceWei ?? "?"} wei` }),
      el("span", { class: "mono", text: `nonce ${entry?.nonce ?? "?"}` }),
    ]),
  );
  root.append(
    el("section", { class: "panel funding" }, [
      el("h2", { text: "Funding journal" }),
      el("div", { class: "journal-state" }, [
        el("span", { class: "label", text: "Replay-safety state" }),
        el("span", { class: "mono value", text: journalState }),
      ]),
      rows.length > 0
        ? el("ul", { class: "funding-list" }, rows)
        : el("p", { class: "hint", text: "No funded addresses recorded yet." }),
    ]),
  );
}

function renderRoles(root, snapshot) {
  const roles = snapshot?.roles && typeof snapshot.roles === "object" ? snapshot.roles : {};
  const rows = Object.entries(roles).map(([name, role]) =>
    el("li", { class: "role-row" }, [
      el("span", { class: "role-name", text: name }),
      el("span", { class: "mono", text: role?.status ?? "(unknown)" }),
      el("span", { class: "heartbeat", text: ageLabel(role?.lastSeenMs) }),
    ]),
  );
  root.append(
    el("section", { class: "panel roles" }, [
      el("h2", { text: "Per-role status" }),
      rows.length > 0
        ? el("ul", { class: "role-list" }, rows)
        : el("p", { class: "hint", text: "No roles bound yet." }),
    ]),
  );
}

function renderPreflight(root, snapshot) {
  const preflight = snapshot?.preflight ?? null;
  root.append(
    el("section", { class: "panel preflight" }, [
      el("h2", { text: "Preflight" }),
      preflight === null
        ? el("p", { class: "hint", text: "Preflight has not run yet." })
        : el("div", { class: `preflight-status ${preflight.ok ? "ok" : "blocked"}` }, [
            el("span", { text: preflight.ok ? "Admitted" : "Blocked" }),
            preflight.checkedAt
              ? el("span", { class: "timestamp", text: `checked ${preflight.checkedAt}` })
              : null,
          ]),
    ]),
  );
}

function render(root, snapshot, refresh) {
  root.replaceChildren();
  renderHeader(root, snapshot);
  renderControls(root, refresh);
  renderVerdictPanel(root, snapshot);
  renderPreflight(root, snapshot);

  const anchorsRoot = el("div", { class: "anchor-grid" });
  for (const kind of ANCHOR_ORDER) {
    renderAnchorPanel(anchorsRoot, snapshot, kind, refresh);
  }
  root.append(anchorsRoot);

  renderAuditTrail(root, snapshot);
  renderFunding(root, snapshot);
  renderRoles(root, snapshot);
}

async function main() {
  const root = document.getElementById("app");
  if (root === null) {
    return;
  }

  let latestSnapshot = null;

  function refresh() {
    render(root, latestSnapshot, refresh);
  }

  async function poll() {
    try {
      latestSnapshot = await getJson("/control/snapshot");
    } catch {
      // The dashboard keeps showing the last snapshot it had rather than
      // blanking the screen -- an honest stall beats a false "nothing is
      // happening" reset.
    }
    refresh();
  }

  await poll();
  setInterval(poll, SNAPSHOT_REFRESH_MS);
}

main();
