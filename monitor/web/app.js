"use strict";
// Dashboard script. Text is only ever inserted with textContent (never innerHTML), so
// wallet addresses, notes and explanations from the engine cannot inject markup.

const REFRESH_MS = 10000;
const SEV_ORDER = ["critical", "high", "medium"];
const SEV_LABEL = { critical: "Critical", high: "High", medium: "Medium", low: "Low" };
const SVG_NS = "http://www.w3.org/2000/svg";

const state = { config: null, summary: null, openWallet: null, detail: null };
const $ = (id) => document.getElementById(id);

// ---------------------------------------------------------------- DOM helpers
function el(tag, props, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(props || {})) {
    if (k === "class") node.className = v;
    else if (k === "text") node.textContent = v;
    else if (k.startsWith("on")) node.addEventListener(k.slice(2), v);
    else if (v !== false && v != null) node.setAttribute(k, v === true ? "" : v);
  }
  for (const c of children.flat()) if (c != null) node.append(c);
  return node;
}
function svg(tag, attrs, text) {
  const node = document.createElementNS(SVG_NS, tag);
  for (const [k, v] of Object.entries(attrs || {})) node.setAttribute(k, v);
  if (text != null) node.textContent = text;
  return node;
}
const clear = (node) => node.replaceChildren();
const fmt = (n) => Number(n || 0).toLocaleString();
const short = (a) => (a ? `${a.slice(0, 8)}…${a.slice(-4)}` : "");
const shortHash = (h) => (h ? `${h.slice(0, 10)}…${h.slice(-6)}` : "");

function ago(ts, now) {
  const s = Math.max(0, (now || Date.now() / 1000) - ts);
  if (s < 90) return `${Math.round(s)}s ago`;
  if (s < 5400) return `${Math.round(s / 60)}m ago`;
  if (s < 129600) return `${Math.round(s / 3600)}h ago`;
  return `${Math.round(s / 86400)}d ago`;
}
const clock = (ts) => new Date(ts * 1000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
const full = (ts) => new Date(ts * 1000).toLocaleString();

function toast(message) {
  const t = $("toast");
  t.textContent = message;
  t.hidden = false;
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => (t.hidden = true), 4000);
}

// tooltip shared by all charts
function attachTip(node, text) {
  const tip = $("tip");
  const show = (e) => {
    tip.textContent = text;
    tip.hidden = false;
    const x = e.clientX ?? node.getBoundingClientRect().left;
    const y = e.clientY ?? node.getBoundingClientRect().top;
    tip.style.left = `${Math.min(x + 12, window.innerWidth - 270)}px`;
    tip.style.top = `${y + 14}px`;
  };
  node.addEventListener("mousemove", show);
  node.addEventListener("focus", show);
  node.addEventListener("mouseleave", () => (tip.hidden = true));
  node.addEventListener("blur", () => (tip.hidden = true));
}

// ------------------------------------------------------------------------ API
async function api(path, body) {
  const opts = body === undefined
    ? {}
    : { method: "POST", headers: { "Content-Type": "application/json", "X-Requested-With": "fetch" }, body: JSON.stringify(body) };
  const res = await fetch(path, opts);
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || `request failed (${res.status})`);
  return data;
}

const explorer = () => state.config && state.config.contract ? state.config.contract.explorer : "https://sepolia.etherscan.io";
const isLive = () => state.config && state.config.mode === "live";
// Real mainnet links only make sense for live data; demo transactions are simulated.
function mainnetLink(kind, value, text, cls = "link mono") {
  if (!isLive()) return el("span", { class: "mono", text });
  return el("a", { class: cls, href: `https://etherscan.io/${kind}/${value}`, target: "_blank", rel: "noopener noreferrer", text });
}

// -------------------------------------------------------------------- header
function renderHeader() {
  const { config: cfg, summary: s } = state;
  const mode = $("mode");
  mode.className = `pill ${cfg.mode}`;
  mode.textContent = cfg.mode === "live" ? "Live: Ethereum mainnet" : cfg.mode === "demo" ? "Demo: simulated data" : "Stored data";

  let fresh = "";
  if (cfg.mode === "live" && s.last_poll_ts) fresh = `Block ${fmt(s.last_block)} · updated ${ago(Number(s.last_poll_ts), s.server_time)}`;
  else if (s.latest_tx_ts) fresh = `Latest transfer ${ago(s.latest_tx_ts, s.server_time)}`;
  $("fresh").textContent = fresh;

  const c = $("contract");
  if (cfg.contract) {
    c.hidden = false;
    c.href = `${cfg.contract.explorer}/address/${cfg.contract.address}`;
    c.textContent = `RiskRegistry on ${cfg.contract.network} · ${short(cfg.contract.address)} ↗`;
  }
}

function renderKpis() {
  const s = state.summary;
  const high = s.severity.critical + s.severity.high;
  const items = [
    ["Transactions monitored", fmt(s.transactions), state.config.mode === "live" ? "Real mainnet transfers" : "Simulated transfers"],
    ["Alerts raised", fmt(s.alerts), `Score ≥ ${state.config.alert_threshold}`],
    ["Active cases", fmt(s.active_cases), `${fmt(s.open_cases)} open · ${fmt(s.escalated_cases)} escalated`],
    ["High-risk cases", fmt(high), `${fmt(s.severity.critical)} critical · ${fmt(s.severity.high)} high`],
    ["Anchored on-chain", fmt(s.anchored_cases), s.pending_sync ? `${fmt(s.pending_sync)} waiting to sync` : "Audit trail up to date"],
  ];
  const box = $("kpis");
  clear(box);
  for (const [label, value, note] of items) {
    box.append(el("div", { class: "kpi" }, el("div", { class: "label", text: label }), el("div", { class: "value", text: value }), el("div", { class: "note", text: note })));
  }
}

// -------------------------------------------------------------------- charts
function dataTable(headers, rows) {
  const t = el("table", {}, el("thead", {}, el("tr", {}, headers.map((h) => el("th", { text: h })))),
    el("tbody", {}, rows.map((r) => el("tr", {}, r.map((c) => el("td", { text: String(c) }))))));
  return el("details", { class: "data" }, el("summary", { text: "View data as table" }), t);
}
const nodata = (msg) => el("p", { class: "nodata", text: msg });

function renderTimeChart() {
  const box = $("chart-time");
  const tl = state.summary.timeline;
  clear(box);
  if (!tl.length || tl.every((b) => b.alerts === 0)) {
    box.append(nodata("No alerts yet"));
    $("time-sub").textContent = "";
    return;
  }
  const W = 560, H = 190, L = 34, R = 6, T = 8, B = 24;
  const max = Math.max(...tl.map((b) => b.alerts));
  const top = Math.max(4, Math.ceil(max / 4) * 4);
  const bw = (W - L - R) / tl.length;
  const y = (v) => T + (H - T - B) * (1 - v / top);
  const root = svg("svg", { viewBox: `0 0 ${W} ${H}`, role: "img", "aria-label": `Alerts per time bucket, peak ${max}` });

  for (const f of [0, 0.5, 1]) {
    const v = Math.round(top * f);
    root.append(svg("line", { class: "grid", x1: L, x2: W - R, y1: y(v), y2: y(v) }));
    root.append(svg("text", { class: "axis", x: L - 6, y: y(v) + 4, "text-anchor": "end" }, String(v)));
  }
  tl.forEach((b, i) => {
    const h = (H - T - B) * (b.alerts / top);
    const x = L + i * bw + 1;
    const w = Math.max(2, bw - 2);
    const bar = svg("rect", { class: "bar bar-1", x, y: H - B - h, width: w, height: Math.max(h, b.alerts ? 2 : 0), rx: Math.min(4, w / 2), tabindex: 0 });
    attachTip(bar, `${clock(b.t)}: ${fmt(b.alerts)} alerts of ${fmt(b.txs)} transfers`);
    root.append(bar);
  });
  const mid = tl[Math.floor(tl.length / 2)].t;
  [[0, tl[0].t, "start"], [Math.floor(tl.length / 2), mid, "middle"], [tl.length - 1, tl[tl.length - 1].t, "end"]].forEach(([i, t, anchor]) => {
    root.append(svg("text", { class: "axis", x: L + i * bw + bw / 2, y: H - 6, "text-anchor": anchor }, clock(t)));
  });
  box.append(root, dataTable(["Time", "Alerts", "Transfers"], tl.map((b) => [clock(b.t), b.alerts, b.txs])));
  $("time-sub").textContent = `Peak ${fmt(max)} per bucket · ${fmt(tl.reduce((a, b) => a + b.alerts, 0))} total`;
}

function hbars(box, rows, { color, label }) {
  clear(box);
  if (!rows.length || rows.every((r) => r.value === 0)) {
    box.append(nodata("Nothing to show yet"));
    return;
  }
  const W = 360, rowH = 30, L = 150, R = 40;
  const H = rows.length * rowH + 6;
  const max = Math.max(...rows.map((r) => r.value));
  const root = svg("svg", { viewBox: `0 0 ${W} ${H}`, role: "img", "aria-label": label });
  rows.forEach((r, i) => {
    const yy = i * rowH + 4;
    const w = Math.max(r.value ? 3 : 0, ((W - L - R) * r.value) / max);
    root.append(svg("text", { class: "lbl", x: L - 8, y: yy + 15, "text-anchor": "end" }, r.label.length > 24 ? `${r.label.slice(0, 23)}…` : r.label));
    const bar = svg("rect", { class: `bar ${r.cls || "bar-1"}`, x: L, y: yy + 3, width: w, height: 18, rx: 4, tabindex: 0, fill: color ? color(r) : null });
    if (!color) bar.removeAttribute("fill");
    attachTip(bar, `${r.label}: ${fmt(r.value)} cases`);
    root.append(bar, svg("text", { class: "lbl-strong", x: L + w + 6, y: yy + 16 }, fmt(r.value)));
  });
  box.append(root, dataTable(["Item", "Cases"], rows.map((r) => [r.label, r.value])));
}

function renderSeverityChart() {
  const sev = state.summary.severity;
  const colours = { critical: "var(--critical)", high: "var(--serious)", medium: "var(--warning)" };
  const shapes = { critical: "◆", high: "▲", medium: "●" };
  hbars($("chart-sev"), SEV_ORDER.map((k) => ({ key: k, label: `${shapes[k]} ${SEV_LABEL[k]}`, value: sev[k] || 0 })), {
    color: (r) => colours[r.key],
    label: "Active cases by severity",
  });
}

function renderSignalsChart() {
  const rows = state.summary.signals.slice(0, 8).map((s) => ({ label: s.title, value: s.cases }));
  hbars($("chart-signals"), rows, { label: "Cases by risk signal" });
}

// --------------------------------------------------------------------- cases
function sevNode(sev) {
  return el("span", { class: `sev sev-${sev}` }, el("span", { class: "shape", "aria-hidden": "true" }), SEV_LABEL[sev] || sev);
}
function chainCell(c) {
  if (c.anchored && !c.queued) return "✓ Anchored";
  if (c.queued) return c.anchored ? "⟳ Sync pending" : "⏳ Queued";
  return "—";
}

async function loadCases() {
  const q = new URLSearchParams({ status: $("f-status").value, min_score: $("f-score").value, q: $("f-q").value.trim() });
  const data = await api(`/api/cases?${q}`);
  const body = $("cases-body");
  clear(body);
  for (const c of data.cases) {
    const tr = el("tr", { tabindex: 0, "aria-label": `Case ${c.subject}, ${c.severity}, score ${c.top_score}` },
      el("td", {}, sevNode(c.severity)),
      el("td", { class: "wallet" }, short(c.subject), c.likely_service ? el("span", { class: "tag", text: "possible exchange/bot" }) : null),
      el("td", { class: "num" }, el("b", { text: String(c.top_score) })),
      el("td", {}, el("div", { class: "chips" }, c.reasons.slice(0, 3).map((r) => el("span", { class: "chip", text: state.config.typologies[r] || r })),
        c.reasons.length > 3 ? el("span", { class: "chip", text: `+${c.reasons.length - 3}` }) : null)),
      el("td", { class: "num", text: fmt(c.alert_count) }),
      el("td", { title: full(c.last_seen), text: ago(c.last_seen, state.summary && state.summary.server_time) }),
      el("td", { class: "status", text: c.status }),
      el("td", { text: chainCell(c) }),
    );
    const open = () => openCase(c.subject);
    tr.addEventListener("click", open);
    tr.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); open(); } });
    body.append(tr);
  }
  $("cases-empty").hidden = data.cases.length > 0;
  $("cases-count").textContent = data.total > data.cases.length ? `Showing ${data.cases.length} of ${fmt(data.total)} cases` : `${fmt(data.total)} case(s)`;
}

// -------------------------------------------------------------------- drawer
function closeDrawer() {
  state.openWallet = null;
  $("drawer").hidden = true;
  $("scrim").hidden = true;
}

async function openCase(wallet) {
  state.openWallet = wallet;
  try {
    state.detail = await api(`/api/cases/${wallet}`);
  } catch (err) {
    toast(err.message);
    return closeDrawer();
  }
  renderDrawer();
  $("scrim").hidden = false;
  $("drawer").hidden = false;
  $("drawer").focus();
}

async function act(path, body, message) {
  try {
    await api(path, body);
    toast(message);
    await refresh();
  } catch (err) {
    toast(err.message);
  }
}

function chainBox(c) {
  const box = el("div", { class: "chain" });
  if (c.anchored) {
    box.append(el("div", {}, el("b", { text: `Anchored on-chain as alert #${c.alert_id}` })));
    if (c.anchor_tx) box.append(el("div", {}, "Transaction: ", el("a", { class: "link", href: `${explorer()}/tx/${c.anchor_tx}`, target: "_blank", rel: "noopener noreferrer" }, el("code", { text: shortHash(c.anchor_tx) }), " ↗")));
    if (c.anchor_gas) box.append(el("div", { class: "muted", text: `Gas used: ${fmt(c.anchor_gas)}` }));
  } else {
    box.append(el("div", { text: "Not anchored yet. Anchoring writes this alert to the RiskRegistry smart contract so it cannot be altered later." }));
  }
  if (c.queued) box.append(el("div", { class: "notice", text: "Waiting for sync. In a terminal, run: npm run anchor" }));
  return box;
}

function renderDrawer() {
  const { case: c, typologies, alerts, recent_transfers: recent } = state.detail;
  const d = $("drawer");
  clear(d);

  const canMove = (to) => (c.status === "open" && to !== "open") || (c.status === "reviewed" && (to === "escalated" || to === "dismissed"));
  const note = el("input", { class: "note-in", id: "note", placeholder: "Optional note for the audit trail", maxlength: "200", "aria-label": "Note" });
  const move = (to, label) => el("button", { class: "btn", disabled: !canMove(to), text: label, onclick: () => act(`/api/cases/${c.subject}/status`, { status: to, note: note.value }, `Case ${to}`) });

  d.append(
    el("div", { class: "d-head" },
      el("div", {}, el("div", { class: "muted small", text: "Wallet" }), el("div", { class: "d-wallet", text: c.subject }),
        isLive() ? mainnetLink("address", c.subject, "View on Etherscan ↗", "link small") : null),
      el("button", { class: "d-close", "aria-label": "Close", text: "✕", onclick: closeDrawer })),
    el("div", { class: "d-score" }, el("span", { class: "big", text: String(c.top_score) }), sevNode(c.severity),
      el("span", { class: "muted status", text: `${c.status} · ${fmt(c.alert_count)} alerts` })),
  );

  if (c.likely_service) {
    d.append(el("div", { class: "notice", text: "High-volume pattern with no structuring, round-trip or watchlist signal. Wallets like this are often exchanges or bots. Check who owns it before escalating, and allowlist it if it is legitimate infrastructure." }));
  }

  d.append(el("div", { class: "section" }, el("h3", { text: "Why this was flagged" }),
    typologies.map((t) => el("div", { class: "typo" }, el("b", { text: t.title }), el("p", { text: t.meaning }),
      el("p", {}, el("span", { class: "k", text: "Why it matters: " }), t.why_it_matters),
      el("p", {}, el("span", { class: "k", text: "Next step: " }), t.next_step)))));

  d.append(el("div", { class: "section" }, el("h3", { text: "Review" }),
    note,
    el("div", { class: "actions" }, move("reviewed", "Mark reviewed"), move("escalated", "Escalate"), move("dismissed", "Dismiss"),
      el("button", { class: "btn", text: "Allowlist wallet", title: "Known exchange or service: stop alerting on it", onclick: () => {
        if (confirm("Treat this wallet as known infrastructure? Future behaviour-based alerts will be suppressed for it.")) act(`/api/cases/${c.subject}/allowlist`, { note: note.value }, "Wallet allowlisted");
      } })),
    c.note ? el("p", { class: "muted small", text: `Last note: ${c.note}` }) : null));

  d.append(el("div", { class: "section" }, el("h3", { text: "On-chain audit trail" }), chainBox(c),
    el("div", { class: "actions" }, el("button", { class: "btn primary", text: c.queued ? "Remove from sync queue" : c.anchored ? "Queue status sync" : "Queue for on-chain anchoring",
      onclick: () => act(`/api/cases/${c.subject}/queue`, { queued: !c.queued }, c.queued ? "Removed from queue" : "Queued. Run npm run anchor") }))));

  d.append(el("div", { class: "section" }, el("h3", { text: "Evidence: highest-scoring alerts" }),
    alerts.slice(0, 6).map((a) => el("div", { class: "ev" },
      el("div", { class: "row" }, mainnetLink("tx", a.tx_hash, shortHash(a.tx_hash), "link mono"), el("span", { text: `score ${a.score}` })),
      el("div", { class: "muted", text: `${full(a.timestamp)} · ${a.value_eth.toFixed(4)} ETH → ${short(a.receiver)}` }),
      el("ul", {}, a.reasons.map((r) => el("li", { text: r.detail })))))));

  d.append(el("div", { class: "section" }, el("h3", { text: "Recent transfers" }),
    el("table", { class: "mini" },
      el("thead", {}, el("tr", {}, ["Time", "From", "To", "ETH"].map((h) => el("th", { text: h })))),
      el("tbody", {}, recent.map((t) => el("tr", {}, el("td", { text: clock(t.timestamp) }), el("td", { class: "mono", text: short(t.sender) }),
        el("td", { class: "mono", text: short(t.receiver) }), el("td", { class: "num", text: t.value_eth.toFixed(3) })))))));
}

// ------------------------------------------------------------------- refresh
let refreshing = false;
async function refresh() {
  if (refreshing) return;
  refreshing = true;
  try {
    state.summary = await api("/api/summary");
    renderHeader();
    renderKpis();
    renderTimeChart();
    renderSeverityChart();
    renderSignalsChart();
    await loadCases();
    if (state.openWallet) {
      state.detail = await api(`/api/cases/${state.openWallet}`);
      if (!$("drawer").contains(document.activeElement) || document.activeElement.tagName !== "INPUT") renderDrawer();
    }
  } catch (err) {
    toast(`Cannot reach the dashboard server: ${err.message}`);
  } finally {
    refreshing = false;
  }
}

async function init() {
  state.config = await api("/api/config");
  $("scrim").addEventListener("click", closeDrawer);
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") closeDrawer(); });
  for (const id of ["f-status", "f-score"]) $(id).addEventListener("change", loadCases);
  let timer;
  $("f-q").addEventListener("input", () => { clearTimeout(timer); timer = setTimeout(loadCases, 250); });
  await refresh();
  setInterval(refresh, REFRESH_MS);
}

init().catch((err) => toast(`Startup failed: ${err.message}`));
