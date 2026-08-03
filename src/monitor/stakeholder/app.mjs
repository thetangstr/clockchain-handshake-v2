// The stakeholder audience page. Polls the relay's snapshot endpoint and
// renders it. All narration logic lives in messages.mjs (pure, testable);
// this file is the thin DOM-binding layer on top of it.
//
// paymentMoved is always false in this system. If the relay cannot be
// reached, this page says so plainly rather than silently freezing on a
// stale render — a frozen page during a slow Clockchain write is how an
// audience loses confidence in something that is actually working.

import {
  ANCHOR_KINDS,
  msSinceUpdate,
  validateSnapshot,
} from "../snapshot.mjs";
import {
  buildStakeholderView,
  isSnapshotStale,
  NO_MONEY_MOVED_SENTENCE,
  RECEIPT_CARDS,
} from "./messages.mjs";

const POLL_INTERVAL_MS = 2000;
const REQUEST_TIMEOUT_MS = 5000;
const STALE_SNAPSHOT_MS = 30000;

const params = new URLSearchParams(window.location.search);
const sessionId = params.get("sid") ?? "";
const relayBase = (params.get("relay") ?? "").replace(/\/+$/, "");

function snapshotUrl() {
  const path = `/v1/sessions/${encodeURIComponent(sessionId)}/snapshot`;
  return relayBase ? `${relayBase}${path}` : path;
}

const el = {
  connectionBanner: document.getElementById("connection-banner"),
  failureCard: document.getElementById("failure-card"),
  failureNoMoney: document.getElementById("failure-no-money"),
  failureSentence: document.getElementById("failure-sentence"),
  freshness: document.getElementById("freshness"),
  noMoneyBanner: document.getElementById("no-money-banner"),
  receipts: document.getElementById("receipts"),
  sessionId: document.getElementById("session-id"),
  technicalJson: document.getElementById("technical-json"),
  timeline: document.getElementById("timeline"),
  verdictSentence: document.getElementById("verdict-sentence"),
  verdictCard: document.getElementById("verdict-card"),
};

const STATE_ICON = Object.freeze({
  done: "✓",
  active: "●",
  pending: "○",
  failed: "✕",
});

function setConnectionBanner(message) {
  if (message === null) {
    el.connectionBanner.hidden = true;
    el.connectionBanner.textContent = "";
    return;
  }
  el.connectionBanner.hidden = false;
  el.connectionBanner.textContent = message;
}

function renderTimeline(view) {
  el.timeline.textContent = "";
  for (const row of view.timeline) {
    const li = document.createElement("li");
    li.className = `timeline-step state-${row.state}`;

    const icon = document.createElement("span");
    icon.className = "step-icon";
    icon.setAttribute("aria-hidden", "true");
    icon.textContent = STATE_ICON[row.state] ?? "○";

    const label = document.createElement("span");
    label.className = "step-label";
    label.textContent = row.label;

    li.append(icon, label);
    el.timeline.append(li);
  }
}

function renderFreshness(view) {
  if (view.freshness) {
    el.freshness.hidden = false;
    el.freshness.textContent = view.freshness;
  } else {
    el.freshness.hidden = true;
    el.freshness.textContent = "";
  }
}

function renderVerdict(view) {
  el.verdictSentence.textContent = view.verdict.sentence;
  el.verdictCard.classList.toggle(
    "verdict-published",
    view.verdict.state === "published",
  );
}

function renderFailure(view) {
  if (!view.failure) {
    el.failureCard.hidden = true;
    return;
  }
  el.failureCard.hidden = false;
  el.failureSentence.textContent = view.failure.sentence;
  el.failureNoMoney.textContent = view.failure.noMoneyMoved;
}

function anchorCardBody(anchor) {
  const body = document.createElement("div");
  if (anchor === null) {
    const pending = document.createElement("p");
    pending.className = "receipt-pending";
    pending.textContent = "Not yet recorded.";
    body.append(pending);
    return body;
  }

  const block = document.createElement("p");
  block.className = "receipt-line";
  block.textContent = `Block #${anchor.blockHeight}`;

  const when = document.createElement("p");
  when.className = "receipt-line receipt-when";
  when.textContent = new Date(anchor.blockTime).toLocaleString();

  const link = document.createElement("a");
  link.className = "receipt-link";
  link.href = anchor.explorerUrl;
  link.target = "_blank";
  link.rel = "noopener noreferrer";
  link.textContent = "View on Clockchain →";

  body.append(block, when, link);
  return body;
}

function renderReceipts(snapshot) {
  el.receipts.textContent = "";
  for (const card of RECEIPT_CARDS) {
    const anchor = snapshot.anchors[card.kind];
    const wrapper = document.createElement("article");
    wrapper.className = `receipt-card${anchor ? "" : " receipt-card-pending"}`;

    const title = document.createElement("h3");
    title.textContent = card.title;

    wrapper.append(title, anchorCardBody(anchor));
    el.receipts.append(wrapper);
  }
}

function renderTechnical(snapshot) {
  el.technicalJson.textContent = JSON.stringify(snapshot, null, 2);
}

function render(snapshot, nowMs) {
  const view = buildStakeholderView(snapshot, nowMs);

  el.sessionId.textContent = view.sessionId;
  el.noMoneyBanner.textContent = view.noMoneyMoved;

  renderTimeline(view);
  renderFreshness(view);
  renderVerdict(view);
  renderFailure(view);
  renderReceipts(snapshot);
  renderTechnical(snapshot);

  if (isSnapshotStale(snapshot, nowMs, STALE_SNAPSHOT_MS)) {
    const seconds = Math.floor(msSinceUpdate(snapshot, nowMs) / 1000);
    setConnectionBanner(
      `The run hasn't updated in ${seconds} seconds. Still trying to reach it.`,
    );
  } else {
    setConnectionBanner(null);
  }
}

function renderUnreachable() {
  el.noMoneyBanner.textContent = NO_MONEY_MOVED_SENTENCE;
  setConnectionBanner("Cannot reach the run right now. Retrying…");
}

async function fetchSnapshot() {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
  try {
    const response = await fetch(snapshotUrl(), { signal: controller.signal });
    if (!response.ok) {
      throw new Error(`snapshot endpoint returned ${response.status}`);
    }
    const snapshot = await response.json();
    validateSnapshot(snapshot);
    return snapshot;
  } finally {
    clearTimeout(timeout);
  }
}

async function tick() {
  try {
    const snapshot = await fetchSnapshot();
    render(snapshot, Date.now());
  } catch {
    renderUnreachable();
  }
}

function assertAnchorKindsWired() {
  // Defensive: keep RECEIPT_CARDS in sync with the schema's anchor kinds.
  const cardKinds = RECEIPT_CARDS.map((c) => c.kind).sort();
  const schemaKinds = [...ANCHOR_KINDS].sort();
  if (JSON.stringify(cardKinds) !== JSON.stringify(schemaKinds)) {
    throw new Error("RECEIPT_CARDS is out of sync with ANCHOR_KINDS");
  }
}

function start() {
  assertAnchorKindsWired();
  if (!sessionId) {
    el.noMoneyBanner.textContent = NO_MONEY_MOVED_SENTENCE;
    setConnectionBanner(
      "No session id given. Open this page with ?sid=<sessionId>.",
    );
    return;
  }
  tick();
  setInterval(tick, POLL_INTERVAL_MS);
}

start();
