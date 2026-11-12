// Actaeon UI. All data from the server (and above all tool output) is untrusted:
// it is only ever set with textContent, never parsed as HTML.
"use strict";
const $ = (s, el = document) => el.querySelector(s);
// Pages render into `main`; route() points it at an off-screen container and swaps it in when
// the page is ready, so the screen never goes blank between pages or after an action.
const mainEl = $("#main");
let main = mainEl;
let navToken = 0;

function h(tag, attrs, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === null || v === undefined || v === false) continue;
    if (k === "class") el.className = v;
    else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else if (k === "value") el.value = v;
    else el.setAttribute(k, v === true ? "" : String(v));
  }
  for (const kid of kids.flat()) {
    if (kid === null || kid === undefined || kid === false) continue;
    el.append(kid instanceof Node ? kid : document.createTextNode(String(kid)));
  }
  return el;
}
// Like el.replaceChildren, but flattens arrays and skips null/false (as h() does).
function fill(el, ...kids) {
  el.replaceChildren(...kids.flat(Infinity).filter((k) => k !== null && k !== undefined && k !== false)
    .map((k) => (k instanceof Node ? k : document.createTextNode(String(k)))));
  return el;
}
const icon = (n) => h("span", { class: "mdi mdi-" + n });
const badge = (v) => h("span", { class: "badge b-" + (v || "none") }, (v || "none").replace(/_/g, " "));
const section = (title, ic, ...kids) => h("section", {}, h("h2", {}, icon(ic), title), ...kids);

function toast(msg, ms = 3500) {
  const t = $("#toast"); t.textContent = msg; t.classList.remove("hidden");
  clearTimeout(toast._t); toast._t = setTimeout(() => t.classList.add("hidden"), ms);
}
async function api(url, body, method) {
  const opt = body === undefined && !method ? {} : { method: method || "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body || {}) };
  const r = await fetch(url, opt);
  let data = null;
  try { data = await r.json(); } catch (e) { data = null; }
  if (!r.ok) {
    const msg = (data && data.error) || (r.status === 403 ? "Not allowed for your role." : `Request failed (${r.status})`);
    toast(msg); throw new Error(msg);
  }
  return data;
}
// Actions always POST, even with no body (api() with no body is a GET).
const post = (url, body) => api(url, body || {}, "POST");
const when = (s) => (s || "").replace("T", " ").slice(0, 16);

let poll = null;
function route() {
  clearInterval(poll); poll = null;
  const [tab, arg] = (location.hash.slice(1) || "leads").split("/");
  const navTab = { hunt: "hunts", lead: "leads" }[tab] || tab;
  document.querySelectorAll("#nav a").forEach((a) => a.classList.toggle("on", a.dataset.tab === navTab));
  const pages = { leads, lead: () => leadDetail(arg), hunts, hunt: () => huntDetail(arg), ask, library, intel,
    coverage, reports, connectors, settings };
  const token = ++navToken;
  const view = h("div");
  main = view;
  const done = () => { if (token === navToken) { fill(mainEl, view); main = mainEl; } };
  (pages[tab] || leads)().then(done, (e) => { view.append(h("p", { class: "bad" }, String(e.message || e))); done(); });
}
window.addEventListener("hashchange", route);

// ---------------- Who am I ----------------
let ME = { user: "", role: "viewer" };
const meReady = api("/api/me").then((m) => { ME = m; fill(document.getElementById("me"), icon("account-circle-outline"), " ", m.name || m.user, " ",
  h("span", { class: "badge" }, m.role)); }).catch(() => {});
const SEV = (s) => h("span", { class: "sev sev-" + s }, s);
const STATUS = (s) => h("span", { class: "badge st-" + s }, s.replace("_", " "));
const RES = { true_positive: "True positive", benign_true_positive: "Benign true positive", false_positive: "False positive",
  duplicate: "Duplicate", other: "Other" };
const ago = (t) => { if (!t) return "-"; const m = (Date.now() - new Date(t).getTime()) / 60000;
  return m < 60 ? `${Math.max(1, Math.round(m))} min ago` : m < 2880 ? `${Math.round(m / 60)} h ago` : `${Math.round(m / 1440)} d ago`; };
const mins = (m) => (m === null || m === undefined ? "-" : m < 120 ? `${m} min` : `${(m / 60).toFixed(1)} h`);

// ---------------- Leads ----------------
async function leads() {
  const st = await api("/api/leads/stats");
  const kpi = (n, l, cls, hash) => h("a", { class: "kpi-card " + (cls || ""), href: hash || "#leads" }, h("b", {}, n), h("span", {}, l));
  const mine = await api("/api/leads?assignee=me&open=1");
  main.append(h("div", { class: "kpi-row" },
    kpi(st.open, "open leads"), kpi(st.new, "new, not acknowledged", st.new ? "warn-card" : ""),
    kpi(mine.length, "assigned to me"), kpi((st.by_severity_open.critical || 0) + (st.by_severity_open.high || 0), "critical + high open", "bad-card"),
    kpi(mins(st.mean_minutes_to_acknowledge), "avg time to acknowledge"), kpi(mins(st.mean_minutes_to_close), "avg time to close")));
  const filt = { view: "open", severity: "" };
  const body = h("tbody");
  const bar = h("div", { class: "row" },
    ...[["open", "Open"], ["new", "New"], ["mine", "Mine"], ["closed", "Closed"], ["all", "All"]].map(([v, l]) =>
      h("button", { class: "ghost seg" + (v === filt.view ? " on" : ""), "data-view": v, onclick: (e) => { filt.view = v;
        bar.querySelectorAll(".seg").forEach((b) => b.classList.toggle("on", b.dataset.view === v)); load(); } }, l)),
    h("select", { onchange: (e) => { filt.severity = e.target.value; load(); } },
      h("option", { value: "" }, "Any severity"), ["critical", "high", "medium", "low"].map((x) => h("option", { value: x }, x))));
  const load = async () => {
    const q = new URLSearchParams();
    if (filt.view === "open") q.set("open", "1");
    if (filt.view === "new") q.set("status", "new");
    if (filt.view === "closed") q.set("status", "closed");
    if (filt.view === "mine") { q.set("assignee", "me"); q.set("open", "1"); }
    if (filt.severity) q.set("severity", filt.severity);
    const rows = await api("/api/leads?" + q.toString());
    fill(body, rows.length ? rows.map((c) => h("tr", { class: "click", onclick: () => (location.hash = "#lead/" + c.id) },
      h("td", {}, `#${c.id}`), h("td", {}, SEV(c.severity)), h("td", {}, STATUS(c.status)),
      h("td", {}, c.title, h("div", { class: "muted small" }, c.origin || "")),
      h("td", {}, c.assignee || h("span", { class: "muted" }, "unassigned")),
      h("td", { class: "small" }, c.status === "closed" ? (RES[c.resolution] || c.resolution) : ago(c.created)))) :
      h("tr", {}, h("td", { colspan: 6, class: "muted" }, "No leads here.")));
  };
  main.append(section("Leads", "briefcase-outline",
    h("p", { class: "muted small" }, "A lead opens for every threat or result that needs review. Everyone can see every lead."),
    bar, h("table", {}, h("thead", {}, h("tr", {}, ["Lead", "Severity", "Status", "Title", "Assignee", "Opened / resolution"].map((x) => h("th", {}, x)))), body)));
  await load();
  poll = setInterval(load, 15000);
}

async function leadDetail(id) {
  const c = await api("/api/leads/" + encodeURIComponent(id));
  const hu = c.hunt || {};
  const v = hu.verdict || {};
  const can = ME.role !== "viewer";
  const act = async (action, body) => { await post(`/api/leads/${c.id}/${action}`, body); toast("Saved."); route(); };
  const comment = h("textarea", { placeholder: "Add a comment (visible to everyone)" });
  const resSel = h("select", {}, Object.entries(RES).map(([k, l]) => h("option", { value: k }, l)));
  const closeNote = h("input", { class: "grow", placeholder: "Why? (required)" });
  const assignSel = h("select", {}, h("option", { value: "" }, "Assign to..."));
  const open = c.status !== "closed";
  if (can && open) api("/api/users").then((us) => us.forEach((u) => assignSel.append(h("option", { value: u.user }, u.name ? `${u.name} (${u.user})` : u.user)))).catch(() => {});
  main.append(section(`Lead #${c.id}`, "briefcase-outline",
    h("h3", { class: "lead-title" }, c.title),
    h("div", { class: "row" }, SEV(c.severity), STATUS(c.status),
      h("span", { class: "small" }, "Assignee: ", h("b", {}, c.assignee || "unassigned")),
      c.resolution ? h("span", { class: "badge st-closed" }, RES[c.resolution] || c.resolution) : null,
      h("span", { class: "muted small" }, `opened ${when(c.created)}`)),
    can ? h("div", { class: "row actions" },
      open && (c.assignee !== ME.user || c.status === "new") ? h("button", { onclick: () => act("acknowledge") }, icon("hand-back-right-outline"), "Acknowledge (assign to me)") : null,
      open && c.status !== "in_progress" && c.status !== "new" ? h("button", { class: "ghost", onclick: () => act("status", { status: "in_progress" }) }, icon("progress-wrench"), "In progress") : null,
      open ? [assignSel, h("button", { class: "ghost", onclick: () => assignSel.value ? act("assign", { to: assignSel.value }) : toast("Pick someone first.") }, icon("account-arrow-right-outline"), "Assign")] : null,
      !open ? h("button", { class: "ghost", onclick: () => act("reopen", { comment: comment.value }) }, icon("restore"), "Reopen") : null) :
      h("p", { class: "muted small" }, "Read-only: your role is viewer."),
    can && open ? h("div", { class: "row close-row" }, h("span", { class: "small" }, "Close as"), resSel, closeNote,
      h("button", { class: "danger", onclick: () => closeNote.value.trim() ? act("close", { resolution: resSel.value, comment: closeNote.value }) : toast("Write why you are closing it.") },
        icon("check-decagram-outline"), "Close lead")) : null,
    h("div", { class: "row" },
      h("a", { href: `/api/leads/${c.id}/report.pdf` }, h("button", { class: "ghost" }, icon("file-pdf-box"), "PDF")),
      h("a", { href: `/api/leads/${c.id}/report.docx` }, h("button", { class: "ghost" }, icon("file-word-box"), "Word")),
      h("a", { href: "#hunt/" + hu.id }, h("button", { class: "ghost" }, icon("target"), "Open the hunt")))));
  main.append(section("What was found", "magnify-scan",
    h("p", {}, hu.hypothesis || ""), h("div", { class: "row" }, badge(hu.outcome), h("span", {}, `confidence ${v.confidence ?? "-"}`),
      v.verification ? h("span", { class: "badge" }, icon("check-all"), " second look: " + v.verification.result) : null),
    h("p", {}, v.summary || ""),
    (v.findings || []).length ? h("ul", {}, v.findings.map((f) => h("li", {}, f.claim, h("span", { class: "muted" }, ` (${f.evidence.join(", ")})`)))) : null,
    v.verification && v.verification.reason ? h("p", { class: "small muted" }, "Second look: " + v.verification.reason) : null));
  main.append(section("Activity", "history",
    h("ul", { class: "events" }, c.events.slice().reverse().map((e) => h("li", {},
      h("span", { class: "muted small" }, `${when(e.ts)}  `), h("b", {}, e.user), ` ${e.action.replace("_", " ")}`,
      e.detail ? h("div", { class: "pre small" }, e.detail) : null))),
    can ? [comment, h("div", { class: "row" }, h("button", { class: "ghost", onclick: () => comment.value.trim() ? act("comment", { text: comment.value }) : null }, icon("comment-plus-outline"), "Comment"))] : null));
}

// ---------------- Ask ----------------
async function ask() {
  const convs = await api("/api/assistant");
  let current = null;
  const list = h("div", { class: "conv-list" });
  const log = h("div", { class: "conv-log" });
  const input = h("textarea", { placeholder: "Ask anything: \"has anything talked to 203.0.113.66 this week?\", \"hunt for password spraying in the last 3 days\", \"what are my open leads?\"" });
  const drawList = (cs) => fill(list, h("button", { class: "ghost", onclick: () => { current = null; fill(log, h("p", { class: "muted" }, "New conversation.")); } }, icon("plus"), "New"),
    cs.map((c) => h("a", { href: "#", class: "conv" + (current === c.id ? " on" : ""), onclick: (e) => { e.preventDefault(); show(c.id); } },
      h("div", {}, c.title.slice(0, 60)), h("div", { class: "muted small" }, `${c.user}  ${ago(c.updated)}`))));
  const show = async (cid) => {
    current = cid;
    const d = await api("/api/assistant/" + cid);
    fill(log, d.messages.map((m) => h("div", { class: "chat " + (m.role === "user" ? "me" : "bot") },
      h("div", { class: "muted small" }, m.role === "user" ? m.user : "Actaeon", "  ", when(m.ts)),
      h("div", { class: "pre" }, m.content),
      (m.links.hunts || []).length || (m.links.cases || []).length ? h("div", { class: "row small" },
        (m.links.hunts || []).map((x) => h("a", { href: "#hunt/" + x }, h("span", { class: "badge" }, icon("target"), " hunt " + x))),
        (m.links.cases || []).map((x) => h("a", { href: "#lead/" + x }, h("span", { class: "badge" }, icon("briefcase-outline"), " lead #" + x)))) : null)));
    drawList(await api("/api/assistant"));
    return d.messages.length;
  };
  const send = async () => {
    if (!input.value.trim()) return;
    const r = await post("/api/assistant", { message: input.value, conversation_id: current });
    input.value = "";
    const before = current === r.conversation_id ? (await api("/api/assistant/" + r.conversation_id)).messages.length : 0;
    current = r.conversation_id;
    toast("Working on it. Hunts can take a few minutes.", 6000);
    let tries = 0;
    clearInterval(poll);
    poll = setInterval(async () => { tries++; const n = await show(current); if (n >= before + 2 || tries > 300) { clearInterval(poll); poll = null; } }, 3000);
    await show(current);
  };
  drawList(convs);
  fill(log, h("p", { class: "muted" }, "Ask a question or ask for a hunt. Hunts started here are stored like any other hunt, with their evidence."));
  main.append(section("Ask Actaeon", "chat-question-outline", h("div", { class: "ask-grid" }, list,
    h("div", {}, log, input, h("div", { class: "row" }, h("button", { onclick: send }, icon("send"), "Send"),
      h("span", { class: "muted small" }, "Uses the analyst model. It can search records, look up intel and run read-only hunts."))))));
}

// ---------------- Reports ----------------
async function reports() {
  const days = h("select", {}, [7, 30, 90, 365].map((d) => h("option", { value: d }, `Last ${d} days`)));
  const dl = (fmt) => () => { location.href = `/api/reports/summary.${fmt}?days=${days.value}`; };
  main.append(section("Summary report", "file-chart-outline",
    h("p", { class: "muted small" }, "Hunts by outcome and origin, leads opened and closed, resolutions, time to acknowledge and close, open leads, threats found and top ATT&CK techniques."),
    h("div", { class: "row" }, days,
      h("button", { onclick: dl("pdf") }, icon("file-pdf-box"), "PDF"),
      h("button", { class: "ghost", onclick: dl("docx") }, icon("file-word-box"), "Word"),
      h("button", { class: "ghost", onclick: dl("md") }, icon("language-markdown-outline"), "Markdown"))));
  const cs = await api("/api/leads");
  main.append(section("Lead reports", "briefcase-outline",
    h("table", {}, h("tbody", {}, cs.slice(0, 50).map((c) => h("tr", {},
      h("td", {}, h("a", { href: "#lead/" + c.id }, `#${c.id}`)), h("td", {}, SEV(c.severity)), h("td", {}, STATUS(c.status)), h("td", {}, c.title),
      h("td", {}, h("a", { href: `/api/leads/${c.id}/report.pdf` }, "PDF"), " ", h("a", { href: `/api/leads/${c.id}/report.docx` }, "Word"))))))));
}

// ---------------- Hunts ----------------
async function hunts() {
  const lib = await api("/api/library").catch(() => ({ starters: [] }));
  const hyp = h("textarea", { placeholder: "Hypothesis, for example: an Office app started encoded PowerShell on any host in the last 7 days" });
  const steps = h("input", { type: "number", min: 1, max: 100, placeholder: "max steps" });
  const pick = h("select", { onchange: () => { if (pick.value) hyp.value = pick.value; } },
    h("option", { value: "" }, "Starter hypotheses..."),
    lib.starters.map((s) => h("option", { value: s.hypothesis }, `${s.name} (${s.attack.join(", ")})`)));
  const start = async () => {
    if (!hyp.value.trim()) return toast("Write a hypothesis first.");
    const r = await api("/api/hunts", { hypothesis: hyp.value, max_steps: steps.value ? +steps.value : undefined });
    location.hash = "#hunt/" + r.hunt_id;
  };
  main.append(section("New hunt", "target", hyp,
    h("div", { class: "row" }, pick, steps, h("button", { onclick: start }, icon("play"), "Start hunt"))));
  const sug = h("div");
  main.append(section("Autopilot", "robot-outline",
    h("p", { class: "muted small" }, "Proposes hypotheses from new advisories, coverage gaps and follow-ups. Nothing starts until you choose."),
    h("div", { class: "row" },
      h("button", { class: "ghost", onclick: async (e) => {
        e.target.disabled = true; fill(sug, h("p", { class: "muted" }, "Asking the planner..."));
        try {
          const r = await api("/api/autopilot", { dry_run: true });
          fill(sug, 
            r.note ? h("p", { class: "warn" }, r.note) : null,
            ...r.hypotheses.map((x) => h("div", { class: "row" }, h("span", { class: "grow" }, x.hypothesis,
              h("div", { class: "muted small" }, `${x.source}  ${x.attack.join(", ")}  ${x.why}`)),
              h("button", { onclick: async () => { const s = await api("/api/hunts", { hypothesis: x.hypothesis, context: "Proposed by autopilot: " + x.why }); location.hash = "#hunt/" + s.hunt_id; } }, icon("play"), "Hunt"))),
            ...(r.rejected || []).map((x) => h("p", { class: "muted small" }, `skipped: ${x.hypothesis} (${x.rejected})`)));
        } finally { e.target.disabled = false; }
      } }, icon("lightbulb-on-outline"), "Suggest hypotheses"),
      h("button", { class: "ghost", onclick: async () => { const r = await api("/api/autopilot", { dry_run: false }); toast("Autopilot queued (job " + r.job_id + "); its hunts appear below."); } }, icon("play-circle-outline"), "Run autopilot now"),
      h("button", { class: "ghost", onclick: async () => { const r = await post("/api/intel/web/pull"); toast("Web intel pull queued (job " + r.job_id + ")."); } }, icon("web"), "Pull web intel")),
    sug));
  const list = h("tbody");
  main.append(section("Recent hunts", "history",
    h("table", {}, h("thead", {}, h("tr", {}, h("th", {}, "Started"), h("th", {}, "Status"), h("th", {}, "Outcome"),
      h("th", {}, "Hypothesis"), h("th", {}, "Origin"))), list)));
  const load = async () => {
    const rows = await api("/api/hunts?limit=100");
    fill(list, ...rows.map((r) => h("tr", { class: "click", onclick: () => (location.hash = "#hunt/" + r.id) },
      h("td", {}, when(r.created)), h("td", {}, badge(r.status)), h("td", {}, badge(r.outcome)),
      h("td", {}, r.hypothesis.slice(0, 140)), h("td", { class: "muted small" }, r.origin))));
    if (!rows.length) list.append(h("tr", {}, h("td", { colspan: 5, class: "muted" }, "No hunts yet.")));
  };
  await load();
  poll = setInterval(load, 5000);
}

async function huntDetail(id) {
  const box = h("div");
  main.append(box);
  // Re-draw only while the hunt runs; a finished hunt is drawn once, so its panels
  // (chat, detection draft, timeline filters) keep their state.
  const draw = async () => {
    const hu = await api("/api/hunts/" + encodeURIComponent(id));
    fill(box, renderHunt(hu));
    const live = ["queued", "running"].includes(hu.status);
    if (!live && poll) { clearInterval(poll); poll = null; }
    return live;
  };
  if (await draw()) poll = setInterval(draw, 2000);
}

function renderHunt(hu) {
  const v = hu.verdict || {};
  const running = ["queued", "running"].includes(hu.status);
  const act = (a) => async () => { await post(`/api/hunts/${hu.id}/${a}`); toast(a + " requested"); };
  const head = section(hu.hypothesis, "target",
    h("div", { class: "row" }, badge(hu.status), badge(hu.outcome),
      hu.lead ? h("a", { href: "#lead/" + hu.lead.id }, h("span", { class: "badge" }, icon("briefcase-outline"), ` lead #${hu.lead.id} ${hu.lead.status}${hu.lead.assignee ? " - " + hu.lead.assignee : ""}`)) : null,
      h("span", { class: "muted small" },
      `started ${when(hu.created)}  origin ${hu.origin}  ${hu.actor ? "by " + hu.actor : ""}`)),
    h("div", { class: "row" },
      running && h("button", { class: "ghost", onclick: act("pause") }, icon("pause"), "Pause"),
      running && h("button", { class: "ghost", onclick: act("resume") }, icon("play"), "Resume"),
      running && h("button", { class: "danger", onclick: act("stop") }, icon("stop"), "Stop"),
      h("a", { href: `/api/hunts/${hu.id}/report.pdf` }, h("button", { class: "ghost" }, icon("file-pdf-box"), "PDF")),
      h("a", { href: `/api/hunts/${hu.id}/report.docx` }, h("button", { class: "ghost" }, icon("file-word-box"), "Word")),
      h("a", { href: `/api/hunts/${hu.id}/report.md` }, h("button", { class: "ghost" }, icon("file-document"), "Markdown")),
      h("a", { href: `/api/hunts/${hu.id}/export.json` }, h("button", { class: "ghost" }, icon("code-json"), "JSON")),
      h("a", { href: `/api/hunts/${hu.id}/export.csv` }, h("button", { class: "ghost" }, icon("file-delimited"), "CSV"))),
    hu.error && h("p", { class: "warn" }, hu.error));
  const out = [head];
  if (hu.verdict) {
    const vs = section("Verdict", "gavel",
      h("div", { class: "row" }, badge(v.outcome), h("span", {}, `confidence ${v.confidence}`),
        v.verification ? h("span", { class: "badge" }, icon("check-all"), " second look: " + v.verification.result) : null,
        v.needs_review && h("span", { class: "badge b-logs_missing" }, icon("eye"), "needs review")),
      h("p", {}, v.summary || ""),
      v.verification && v.verification.reason ? h("p", { class: "small muted" }, "Second look: " + v.verification.reason) : null,
      (v.findings || []).length ? [h("h3", {}, "Findings"), h("ul", {}, v.findings.map((f, i) =>
        h("li", {}, f.claim, " ", f.evidence.map((e) => h("a", { href: "#", onclick: (ev) => { ev.preventDefault(); const t = document.getElementById("step-" + e); if (t) { t.open = true; t.scrollIntoView(); } } }, `[${e}] `)),
          feedbackButtons(hu, i))))] : null,
      (hu.feedback || []).length ? [h("h3", {}, "Analyst feedback"), h("ul", {}, hu.feedback.map((f) =>
        h("li", { class: "small" }, `${f.kind.replace("_", " ")}: ${f.claim}`, f.comment ? ` (${f.comment})` : "", f.by ? ` by ${f.by}` : "")))] : null,
      (v.unsupported_claims || []).length ? [h("h3", { class: "warn" }, "Claims without evidence (not verified)"),
        h("ul", {}, v.unsupported_claims.map((f) => h("li", { class: "muted" }, f.claim)))] : null,
      (v.attack || []).length ? h("p", {}, "ATT&CK: ", v.attack.join(", ")) : null,
      list("Gaps", v.gaps), list("Next steps", v.next_steps), list("Checks applied", v.checks));
    out.push(vs);
    if (!running) out.push(saveBox(hu), narrativeBox(hu), detectionBox(hu));
  }
  if (hu.plan) {
    out.push(section("Plan", "map-outline", h("p", {}, hu.plan.summary || ""),
      h("ul", {}, (hu.plan.steps || []).map((s) => h("li", {}, h("span", { class: "muted" }, `[${s.role}] `), s.goal))),
      (hu.plan.missing_roles || []).length ? h("p", { class: "warn" }, "No connector for: " + hu.plan.missing_roles.join(", ")) : null));
  }
  if (!running) out.push(chatBox(hu), timelineBox(hu));
  out.push(section("Steps", "format-list-numbered", (hu.steps || []).filter((s) => s.kind !== "verdict").map(stepView)));
  return h("div", {}, out);
}
function feedbackButtons(hu, i) {
  const send = (kind) => async () => {
    const comment = prompt(kind === "confirmed" ? "Comment (optional)" : "Why is this benign? This is saved to memory for future hunts.") ;
    if (comment === null) return;
    await api(`/api/hunts/${hu.id}/feedback`, { finding: i, kind, comment });
    toast(kind === "confirmed" ? "Marked as confirmed." : "Saved; related hunts will see this note.");
    route();
  };
  return h("span", { class: "fb" },
    h("button", { class: "ghost small", title: "Known benign", onclick: send("benign") }, icon("check-circle-outline"), "Benign"),
    h("button", { class: "ghost small", title: "False positive", onclick: send("false_positive") }, icon("close-circle-outline"), "False positive"),
    h("button", { class: "ghost small", title: "Confirmed", onclick: send("confirmed") }, icon("alert-circle-outline"), "Confirmed"));
}
const list = (title, items) => (items && items.length ? [h("h3", {}, title), h("ul", {}, items.map((x) => h("li", {}, x)))] : null);

function stepView(s) {
  const cls = s.kind === "blocked" ? "blocked" : s.kind === "call" ? (s.ok ? "good" : "fail") : "";
  const title = s.kind === "call" ? `E${s.n}  ${s.connector}.${s.tool}` : `${s.kind}`;
  return h("details", { class: "step " + cls, id: "step-E" + s.n },
    h("summary", {}, title, "  ", s.kind === "call" ? h("span", { class: s.ok ? "ok" : "bad" }, s.ok ? "ok" : "failed") : null,
      "  ", h("span", { class: "muted small" }, (s.note || s.why || "").slice(0, 160))),
    s.why && h("p", { class: "small" }, "Why: ", s.why),
    s.arguments && h("pre", {}, JSON.stringify(s.arguments, null, 1)),
    s.result && h("pre", {}, s.result));
}

function timelineBox(hu) {
  const box = h("div", {}, h("p", { class: "muted small" }, "Loading..."));
  let filter = null;
  const draw = (t) => {
    const rows = t.events.filter((r) => !filter || r[filter[0]] === filter[1]);
    const chips = Object.entries(t.entities).filter(([, v]) => v.length).map(([k, v]) =>
      h("div", { class: "row small" }, h("span", { class: "muted" }, k + ":"),
        v.slice(0, 12).map((x) => h("button", { class: "ghost small" + (filter && filter[1] === x.value ? " on" : ""),
          onclick: () => { filter = filter && filter[1] === x.value ? null : [k, x.value]; draw(t); } }, `${x.value} (${x.count})`))));
    fill(box, 
      h("p", { class: "muted small" }, t.total ? `${t.total} events, ${when(t.first)} to ${when(t.last)}` + (t.no_time ? `  (${t.no_time} without a time left out)` : "") : "No timestamped events in the evidence."),
      ...chips,
      h("table", {}, h("thead", {}, h("tr", {}, ["Time", "Host", "User", "What", "State", "Ev"].map((x) => h("th", {}, x)))),
        h("tbody", {}, rows.slice(0, 300).map((r) => h("tr", {}, h("td", { class: "small" }, when(r.time)), h("td", {}, r.host),
          h("td", {}, r.user), h("td", { class: "small" }, [r.what, r.process && `${r.parent ? r.parent + " -> " : ""}${r.process}`, r.command && r.command.slice(0, 140), r.destination && "to " + r.destination].filter(Boolean).join("  ")),
          h("td", { class: "small " + (r.state === "executed" ? "bad" : r.state === "blocked" ? "ok" : "muted") }, r.state), h("td", {}, r.evidence))))));
  };
  api(`/api/hunts/${hu.id}/timeline`).then(draw);
  return section("Timeline", "timeline-clock-outline", box);
}

function detectionBox(hu) {
  const box = h("div");
  const show = (d) => fill(box, 
    h("p", { class: "warn small" }, "DRAFT: review and test before deploying. Status is set to experimental."),
    (d.problems || []).length ? h("ul", {}, d.problems.map((p) => h("li", { class: "warn small" }, p))) : null,
    d.sigma ? [h("h3", {}, "Sigma draft"), h("pre", {}, d.sigma)] : null,
    d.notes ? h("p", { class: "small" }, d.notes) : null,
    (d.native || []).length ? [h("h3", {}, "Queries that found data (exactly as they ran)"),
      ...d.native.map((q) => h("div", {}, h("div", { class: "muted small" }, `${q.evidence}  ${q.connector}.${q.tool}  hits ${q.hits ?? "?"}`), h("pre", {}, q.query)))] : null);
  api(`/api/hunts/${hu.id}/detection`).then((ds) => { if (ds.length) show(ds[0]); });
  return section("Detection draft", "shield-check-outline",
    h("button", { class: "ghost", onclick: async (e) => { e.target.disabled = true; try { show(await post(`/api/hunts/${hu.id}/detection`)); } finally { e.target.disabled = false; } } },
      icon("file-code-outline"), "Draft a detection rule"), box);
}

function chatBox(hu) {
  const log = h("div");
  const input = h("input", { class: "grow", placeholder: "Ask about this hunt, or say what to check next (for example: check the other hosts)" });
  const draw = async () => {
    const msgs = await api(`/api/hunts/${hu.id}/chat`);
    fill(log, ...msgs.map((m) => h("div", { class: "chat " + (m.role === "analyst" ? "me" : "bot") },
      h("div", { class: "muted small" }, m.role === "analyst" ? (m.author || "you") : "Actaeon", "  ", when(m.ts)),
      h("div", { class: "pre" }, m.content), m.evidence.length ? h("div", { class: "small" }, "Evidence: " + m.evidence.join(", ")) : null)));
    return msgs.length;
  };
  draw();
  const send = async () => {
    if (!input.value.trim()) return;
    const before = await draw();
    await api(`/api/hunts/${hu.id}/chat`, { message: input.value });
    input.value = ""; toast("Thinking... answers can take a minute.");
    let tries = 0;
    const t = setInterval(async () => { tries++; const n = await draw(); if (n >= before + 2 || tries > 90) { clearInterval(t); } }, 2000);
  };
  input.addEventListener("keydown", (e) => { if (e.key === "Enter") send(); });
  return section("Ask Actaeon", "chat-outline",
    h("p", { class: "muted small" }, "Answers cite evidence. New searches run read-only and are added to this hunt."),
    log, h("div", { class: "row" }, input, h("button", { onclick: send }, icon("send"), "Send")));
}

function saveBox(hu) {
  const name = h("input", { class: "grow", placeholder: "Name", value: hu.hypothesis.slice(0, 80) });
  const every = h("input", { type: "number", min: 0, placeholder: "replay every N minutes (0 = manual)" });
  const esc = h("input", { type: "checkbox" });
  return section("Save to library", "bookmark-plus",
    h("div", { class: "row" }, name, every, h("label", {}, esc, " start a full hunt when a replay finds matches"),
      h("button", { onclick: async () => {
        const r = await api("/api/library", { hunt_id: hu.id, name: name.value, interval_minutes: +every.value || 0, escalate: esc.checked });
        toast(`Saved with ${r.calls.length} call(s).` + (r.warnings.length ? " " + r.warnings.join(" ") : ""), 6000);
      } }, icon("content-save"), "Save")));
}

function narrativeBox(hu) {
  const p = h("pre", { class: hu.narrative ? "" : "hidden" }, hu.narrative || "");
  return section("Narrative", "text-box-outline",
    h("p", { class: "muted small" }, "Optional summary written by the reporter model. Check it against the record."),
    h("button", { class: "ghost", onclick: async (e) => {
      e.target.disabled = true;
      try { const r = await post(`/api/hunts/${hu.id}/narrative`); p.textContent = r.narrative; p.classList.remove("hidden"); }
      finally { e.target.disabled = false; }
    } }, icon("robot-outline"), hu.narrative ? "Rewrite" : "Write"), p);
}

// ---------------- Library ----------------
async function library() {
  const d = await api("/api/library");
  const rows = d.saved.map((s) => {
    const every = h("input", { type: "number", min: 0, value: s.interval_minutes, class: "small" });
    return h("tr", {},
      h("td", {}, s.name, h("div", { class: "muted small" }, s.attack.join(", "))),
      h("td", {}, every),
      h("td", {}, h("input", { type: "checkbox", checked: s.enabled, onchange: (e) => api(`/api/library/${s.id}`, { enabled: e.target.checked }) })),
      h("td", { class: "small" }, when(s.last_run) || "-", s.last_hunt_id ? [" ", h("a", { href: "#hunt/" + s.last_hunt_id }, "view")] : null),
      h("td", {}, s.last_hits === null ? "-" : s.last_hits),
      h("td", {}, h("div", { class: "row" },
        h("button", { class: "ghost", onclick: async () => { await api(`/api/library/${s.id}`, { interval_minutes: +every.value || 0 }); toast("Saved"); } }, icon("content-save")),
        h("button", { class: "ghost", onclick: async () => { await post(`/api/library/${s.id}/run`); toast("Replay queued"); } }, icon("replay")),
        h("button", { class: "danger", onclick: async () => { if (confirm("Delete this saved hunt?")) { await post(`/api/library/${s.id}/delete`); route(); } } }, icon("delete")))));
  });
  main.append(section("Saved hunts", "bookshelf",
    h("p", { class: "muted small" }, "Replays run the saved searches again without a model and flag matches for review."),
    h("table", {}, h("thead", {}, h("tr", {}, ["Name", "Every (min)", "On", "Last run", "Hits", ""].map((x) => h("th", {}, x)))),
      h("tbody", {}, rows.length ? rows : h("tr", {}, h("td", { colspan: 6, class: "muted" }, "Nothing saved yet. Open a finished hunt and save it."))))));
  main.append(section("Starter hypotheses", "lightbulb-outline",
    h("table", {}, h("tbody", {}, d.starters.map((s) => h("tr", {},
      h("td", {}, h("b", {}, s.name), h("div", { class: "small" }, s.hypothesis)),
      h("td", { class: "small muted" }, s.attack.join(", "), h("div", {}, (s.roles || []).join(", "))),
      h("td", {}, h("button", { onclick: async () => { const r = await api("/api/hunts", { hypothesis: s.hypothesis }); location.hash = "#hunt/" + r.hunt_id; } }, icon("play"), "Hunt"))))))));
}

// ---------------- Intel ----------------
async function intel() {
  const st = await api("/api/intel/stats");
  const title = h("input", { class: "wide", placeholder: "Advisory title (optional: saves the text as an advisory)" });
  const text = h("textarea", { placeholder: "Paste indicators or a whole advisory. Defanged values (hxxp, [.]) are handled." });
  const conf = h("input", { type: "number", min: 0, max: 100, value: 50, title: "confidence 0-100" });
  const tags = h("input", { class: "grow", placeholder: "tags, comma separated" });
  const out = h("pre", { class: "hidden" });
  const show = (x) => { out.textContent = typeof x === "string" ? x : JSON.stringify(x, null, 1); out.classList.remove("hidden"); };
  main.append(section("Add intel", "shield-plus",
    h("p", { class: "muted small" }, `${st.indicators} indicators, ${st.advisories} advisories. Review the preview: extraction is pattern-based.`),
    title, text, h("div", { class: "row" }, conf, tags,
      h("button", { class: "ghost", onclick: async () => show((await api("/api/intel/indicators", { text: text.value, preview: true })).found) }, icon("eye"), "Preview"),
      h("button", { onclick: async () => {
        if (!text.value.trim()) return;
        const body = { text: text.value, confidence: +conf.value, tags: tags.value };
        const r = title.value.trim() ? await api("/api/intel/advisories", { ...body, title: title.value }) : await api("/api/intel/indicators", body);
        show(`Added: ${r.new} new, ${r.updated} updated` + (r.advisory_id ? ` (advisory ${r.advisory_id})` : ""));
        text.value = ""; title.value = "";
      } }, icon("plus"), "Add")), out));
  const url = h("input", { class: "grow", placeholder: "Advisory URL (web page or PDF)" });
  const file = h("input", { type: "file", accept: ".pdf,.txt,.html,.htm,.md" });
  const imp = h("pre", { class: "hidden" });
  const done = (r) => { imp.textContent = `Advisory ${r.advisory_id} "${r.title}": ${r.new} new, ${r.updated} updated indicators`; imp.classList.remove("hidden"); };
  main.append(section("Import an advisory", "file-import",
    h("div", { class: "row" }, url, h("button", { onclick: async () => { if (url.value.trim()) done(await api("/api/intel/advisories/import", { url: url.value })); } }, icon("web"), "Fetch")),
    h("div", { class: "row" }, file, h("button", { class: "ghost", onclick: async () => {
      if (!file.files.length) return toast("Choose a file first.");
      const fd = new FormData(); fd.append("file", file.files[0]);
      const r = await fetch("/api/intel/advisories/import", { method: "POST", body: fd });
      const d = await r.json(); if (!r.ok) return toast(d.error || "Import failed"); done(d);
    } }, icon("upload"), "Upload")), imp));
  const enc = h("textarea", { placeholder: "Paste an obfuscated command line or script. It is decoded as text and never run." });
  const decOut = h("pre", { class: "hidden" });
  main.append(section("Decode", "lock-open-variant-outline", enc, h("div", { class: "row" }, h("button", { class: "ghost", onclick: async () => {
    const r = await api("/api/decode", { text: enc.value });
    decOut.textContent = (r.layers.length ? r.layers.map((l) => `[${l.depth}] ${l.method}\n${l.decoded}`).join("\n\n") : "No known encoding found.") +
      (r.keywords.length ? "\n\nKeywords: " + r.keywords.join(", ") : "") + (r.urls.length ? "\nURLs: " + r.urls.join(", ") : "") + (r.ips.length ? "\nIPs: " + r.ips.join(", ") : "");
    decOut.classList.remove("hidden");
  } }, icon("lock-open-variant-outline"), "Decode")), decOut));
  const q = h("input", { class: "grow", placeholder: "Look up a value" });
  const res = h("pre", { class: "hidden" });
  main.append(section("Look up", "magnify", h("div", { class: "row" }, q, h("button", { onclick: async () => {
    const r = await api("/api/intel/lookup?value=" + encodeURIComponent(q.value));
    res.textContent = r.found ? JSON.stringify(r.matches, null, 1) : "Not in the intel store." + (r.related.length ? " Related: " + r.related.map((x) => x.value).join(", ") : "");
    res.classList.remove("hidden");
  } }, icon("magnify"))), res));
  const actors = await api("/api/intel/actors");
  const an = h("input", { placeholder: "Actor name" }), aa = h("input", { class: "grow", placeholder: "aliases, comma separated" });
  const at = h("input", { class: "grow", placeholder: "ATT&CK IDs, comma separated" }), atl = h("input", { class: "grow", placeholder: "tools / malware, comma separated" });
  const ad = h("textarea", { placeholder: "Description and indicators (paste a report; defanged values are fine)" });
  main.append(section("Threat actors", "account-alert-outline",
    h("table", {}, h("tbody", {}, actors.length ? actors.map((x) => h("tr", {},
      h("td", {}, h("b", {}, x.name), h("div", { class: "muted small" }, (x.aliases || []).join(", "))),
      h("td", { class: "small" }, x.techniques.join(", ") || "-", h("div", { class: "muted" }, x.tools.join(", "))),
      h("td", {}, `${x.indicator_count} indicators`),
      h("td", {}, h("button", { onclick: async () => { const r = await post(`/api/intel/actors/${encodeURIComponent(x.slug)}/hunt`); toast("Campaign started" + (r.sweep_job ? " (with an indicator sweep)" : "")); location.hash = "#hunt/" + r.hunt_id; } }, icon("play"), "Hunt this actor")))) :
      h("tr", {}, h("td", { class: "muted" }, "No actors yet.")))),
    h("details", {}, h("summary", {}, "Add or update an actor"),
      h("div", { class: "row" }, an, aa), h("div", { class: "row" }, at, atl), ad,
      h("div", { class: "row" }, h("button", { onclick: async () => {
        const r = await api("/api/intel/actors", { name: an.value, aliases: aa.value, techniques: at.value, tools: atl.value, description: ad.value, indicators: ad.value });
        toast(`Saved ${r.name}: ${r.indicators_added} indicator(s) added`); route();
      } }, icon("content-save"), "Save actor")))));
  const advs = await api("/api/intel/advisories");
  main.append(section("Advisories", "file-document-outline", h("table", {}, h("tbody", {}, advs.length ? advs.map((a) => h("tr", {},
    h("td", {}, a.title, h("div", { class: "muted small" }, `${when(a.added)}  ${a.indicator_count} indicators  ${a.techniques.join(", ")}`)),
    h("td", {}, h("button", { onclick: async () => { const r = await post(`/api/hunts/advisory/${a.id}`); location.hash = "#hunt/" + r.hunt_id; } }, icon("play"), "Hunt this")))) :
    h("tr", {}, h("td", { class: "muted" }, "No advisories yet."))))));
  const inds = await api("/api/intel/indicators?limit=100");
  main.append(section("Indicators", "format-list-bulleted",
    h("div", { class: "row" }, h("button", { class: "ghost", onclick: async () => { const r = await post("/api/intel/sweep"); toast("Sweep queued (job " + r.job_id + "); it appears under Hunts."); } }, icon("radar"), "Sweep logs for new or changed indicators")),
    h("table", {}, h("thead", {}, h("tr", {}, ["Type", "Value", "Conf", "Seen", "Last seen", "Source", ""].map((x) => h("th", {}, x)))),
      h("tbody", {}, inds.map((i) => h("tr", {}, h("td", {}, i.type), h("td", {}, i.value), h("td", {}, i.confidence),
        h("td", {}, i.seen_count), h("td", { class: "small" }, when(i.last_seen)), h("td", { class: "small muted" }, i.source),
        h("td", {}, h("button", { class: "ghost", title: "Deactivate", onclick: async () => { await post(`/api/intel/indicators/${i.id}/deactivate`); route(); } }, icon("cancel")))))))));
}

// ---------------- Coverage ----------------
async function coverage() {
  const c = await api("/api/coverage");
  const s = c.summary;
  const kpi = (n, l) => h("div", { class: "kpi" }, h("b", {}, n), h("span", { class: "muted small" }, l));
  main.append(section("ATT&CK coverage", "grid",
    h("div", { class: "kpis" }, kpi(s.techniques, "techniques seen"), kpi(s.hunted, "hunted"), kpi(s.data_missing, "data missing"),
      kpi(s.not_hunted, "not hunted yet"), kpi(s.scheduled, "on a schedule")),
    h("p", { class: "muted small" }, "Built from your hunts, saved hunts and the starter list. 'Hunted' means at least one hunt searched data for it; it does not mean detection coverage."),
    h("div", { class: "grid" }, c.techniques.map((t) => h("div", { class: "cell " + t.state.replace(" ", "-"), title: JSON.stringify(t.outcomes) },
      h("div", { class: "tid" }, t.technique), h("div", { class: "small" }, t.name || ""),
      h("div", { class: "small muted" }, `${t.state}  ${t.hunts} hunt(s)${t.scheduled ? "  scheduled" : ""}`),
      t.last && h("div", { class: "small muted" }, "last " + when(t.last)))))));
  main.append(section("Data roles", "database-search",
    h("p", {}, "Connected: ", c.roles.connected.join(", ") || "none"),
    c.roles.missing.length ? h("p", { class: "warn" }, "Used by starter hunts but not connected: " + c.roles.missing.join(", ")) : null,
    Object.keys(c.roles.missing_in_hunts).length ? h("p", { class: "warn" }, "Needed by past hunt plans: " +
      Object.entries(c.roles.missing_in_hunts).map(([r, n]) => `${r} (${n})`).join(", ")) : null));
}

// ---------------- Connectors ----------------
async function connectors() {
  const cs = await api("/api/connectors");
  const tools = h("div");
  main.append(section("Connectors", "connection",
    h("p", { class: "muted small" }, "Add connectors under connectors: in config.yaml. Tools are read-only unless allowed otherwise."),
    h("table", {}, h("tbody", {}, cs.map((c) => {
      const res = h("span", { class: "small" });
      return h("tr", {}, h("td", {}, h("b", {}, c.name), h("div", { class: "muted small" }, c.description || "")),
        h("td", {}, c.roles.join(", ")), h("td", {}, c.transport), h("td", {}, c.enabled ? "on" : "off"),
        h("td", {}, h("div", { class: "row" },
          h("button", { class: "ghost", onclick: async () => { res.textContent = "..."; const r = await post(`/api/connectors/${c.name}/test`); res.textContent = r.ok ? `${r.allowed}/${r.tools} tools allowed, ${r.ms} ms` : r.error; res.className = r.ok ? "ok small" : "bad small"; } }, icon("lan-check"), "Test"),
          h("button", { class: "ghost", onclick: async () => { const t = await api(`/api/connectors/${c.name}/tools`); fill(tools, section(c.name + " tools", "tools",
            h("table", {}, h("tbody", {}, t.map((x) => h("tr", {}, h("td", {}, x.name), h("td", {}, x.allowed ? h("span", { class: "ok" }, "allowed") : h("span", { class: "bad" }, "blocked")),
              h("td", { class: "small muted" }, x.reason), h("td", { class: "small" }, x.description.slice(0, 160)))))))); } }, icon("tools"), "Tools"), res)));
    })))));
  main.append(tools);
  const f = {};
  const inp = (k, ph, cls) => (f[k] = h("input", { class: cls || "grow", placeholder: ph }));
  const transport = h("select", {}, h("option", { value: "http" }, "HTTP (remote MCP server)"), h("option", { value: "stdio" }, "stdio (local command)"));
  const authType = h("select", {}, ["none", "bearer", "api_key", "oauth_client_credentials"].map((x) => h("option", { value: x }, x)));
  const roles = ["log_search", "endpoint", "identity", "email", "asset", "network", "cloud", "intel", "analysis"].map((r) =>
    h("label", { class: "small chk" }, h("input", { type: "checkbox", value: r }), " " + r));
  const out = h("pre", { class: "hidden" });
  const build = () => {
    const c = { name: f.name.value.trim(), roles: roles.map((l) => l.firstChild).filter((x) => x.checked).map((x) => x.value),
      transport: transport.value, dialect: f.dialect.value.trim(), query_notes_file: f.notes.value.trim() };
    if (c.transport === "http") c.url = f.url.value.trim(); else { c.command = f.command.value.trim(); c.args = f.args.value.trim() ? f.args.value.trim().split(/\s+/) : []; }
    const a = authType.value;
    if (a !== "none") c.auth = { type: a, ...(a === "bearer" ? { token_env: f.secret.value.trim() } : a === "api_key" ? { api_key_env: f.secret.value.trim() } :
      { client_secret_env: f.secret.value.trim(), token_url: f.token_url.value.trim(), client_id: f.client_id.value.trim() }) };
    return c;
  };
  const go = async (preview) => {
    try { const r = await post("/api/settings/connectors", { connector: build(), preview });
      out.textContent = r.diff || "No change."; out.classList.remove("hidden"); if (!preview) { toast("Saved."); route(); } } catch (e) { /* toast shown */ }
  };
  main.append(section("Add or update a connector", "plus-network-outline",
    h("p", { class: "muted small" }, "Admins only. Secrets are never typed here: give the NAME of the environment variable that holds them (in .env)."),
    h("div", { class: "row" }, inp("name", "name (lowercase, e.g. logs)", ""), transport),
    h("div", { class: "row" }, ...roles),
    h("div", { class: "row" }, inp("url", "https://mcp-server.example/mcp")),
    h("div", { class: "row" }, inp("command", "command (stdio), e.g. actaeon", ""), inp("args", "arguments, e.g. bridge search-index --url ${LOGS_URL} --index logs-*")),
    h("div", { class: "row" }, authType, inp("secret", "env var with the token / key / client secret", ""), inp("client_id", "client id (oauth)", ""), inp("token_url", "token URL (oauth)")),
    h("div", { class: "row" }, inp("dialect", "query language name (optional)", ""), inp("notes", "query notes file path (optional)")),
    h("div", { class: "row" }, h("button", { class: "ghost", onclick: () => go(true) }, icon("eye"), "Preview change"),
      h("button", { onclick: () => go(false) }, icon("content-save"), "Save to config.yaml")), out));
}

// ---------------- Settings ----------------
async function settings() {
  const s = await api("/api/settings/llm");
  const rows = Object.entries(s.roles).map(([r, c]) => {
    const sel = h("select", { "data-role": r }, s.providers.map((p) => h("option", { value: p, selected: p === (c.provider || "ollama") }, p)));
    const model = h("input", { class: "grow", "data-model": r, placeholder: "model (blank = provider default)", value: c.model || "" });
    return h("div", { class: "row" }, h("span", { class: "grow" }, r), sel, model);
  });
  const diff = h("pre", { class: "hidden" });
  const testOut = h("pre", { class: "hidden" });
  const collect = () => Object.fromEntries([...document.querySelectorAll("[data-role]")].map((e) => [e.dataset.role, { provider: e.value, model: $(`[data-model="${e.dataset.role}"]`).value }]));
  main.append(section("Models", "brain", h("p", { class: "muted small" }, "One provider and model per role. Keys stay in .env. Admins only."), rows,
    h("div", { class: "row" }, h("button", { onclick: async () => {
      const p = await api("/api/settings/llm", { roles: collect(), preview: true });
      if (!p.changed) return toast("No changes.");
      diff.textContent = p.diff; diff.classList.remove("hidden");
      if (!confirm("Apply this change to config.yaml?")) return;
      await api("/api/settings/llm", { roles: collect() }); toast("Saved."); diff.classList.add("hidden");
    } }, icon("content-save"), "Save"),
      h("button", { class: "ghost", onclick: async (e) => {
        e.target.disabled = true; testOut.textContent = "Testing each role..."; testOut.classList.remove("hidden");
        try { const r = await post("/api/settings/llm/test");
          testOut.textContent = r.map((x) => `${x.ok ? "OK  " : "FAIL"} ${x.role}  ${x.provider}/${x.model}  ${x.ok ? x.ms + " ms" : x.error}`).join("\n");
        } finally { e.target.disabled = false; }
      } }, icon("lan-check"), "Test models")), diff, testOut));
  const note = h("input", { class: "grow", placeholder: "Note, for example: the backup agent uploads to cloud storage from backup01 nightly" });
  const ntags = h("input", { placeholder: "tags" });
  const notes = await api("/api/memory/notes");
  main.append(section("Memory notes", "note-text-outline",
    h("p", { class: "muted small" }, "Notes are added to the context of related hunts. Only people write them."),
    h("div", { class: "row" }, note, ntags, h("button", { onclick: async () => { await api("/api/memory/notes", { text: note.value, tags: ntags.value.split(",").map((x) => x.trim()).filter(Boolean) }); route(); } }, icon("plus"), "Add")),
    h("table", {}, h("tbody", {}, notes.map((n) => h("tr", {}, h("td", { class: n.active ? "" : "muted" }, n.text), h("td", { class: "small muted" }, n.tags.join(", ")),
      h("td", {}, n.active && h("button", { class: "ghost", onclick: async () => { await post(`/api/memory/notes/${n.id}/retire`); route(); } }, icon("archive")))))))));
  const audit = h("div", {}, h("button", { class: "ghost", onclick: async () => {
    const rows = await api("/api/audit?limit=100");
    fill(audit, h("table", {}, h("thead", {}, h("tr", {}, ["Time", "Connector", "Tool", "Status", "Decision", "ms"].map((x) => h("th", {}, x)))),
      h("tbody", {}, rows.map((r) => h("tr", {}, h("td", { class: "small" }, when(r.ts)), h("td", {}, r.connector), h("td", {}, r.tool),
        h("td", {}, h("span", { class: r.status === "ok" ? "ok" : "bad" }, r.status)), h("td", { class: "small muted" }, r.decision), h("td", {}, r.duration_ms))))));
  } }, icon("clipboard-text-clock"), "Show audit log (admin)"));
  main.append(section("Audit log", "clipboard-text-clock", audit));
  const doc = h("div");
  main.append(section("Health check", "stethoscope", h("p", { class: "muted small" }, "Checks config, login, models, every connector (reads from each source), outputs, intel and schedules. Admins only."),
    h("button", { class: "ghost", onclick: async (e) => { e.target.disabled = true; fill(doc, h("p", { class: "muted" }, "Checking...")); try {
      const rows = await api("/api/doctor");
      fill(doc, h("table", {}, h("tbody", {}, rows.map((r) => h("tr", {}, h("td", {}, h("span", { class: "badge " + (r.level === "OK" ? "st-closed" : r.level === "WARN" ? "b-logs_missing" : "b-threat") }, r.level)),
        h("td", { class: "small" }, r.area), h("td", {}, r.message, r.hint ? h("div", { class: "muted small" }, r.hint) : null))))));
    } finally { e.target.disabled = false; } } }, icon("stethoscope"), "Run health check"), doc));
}

meReady.then(route);
