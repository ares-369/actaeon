// Alert triage pages (cases, approvals, alerts, dashboard, tuning). Loaded before app.js, which owns the
// router and the shared helpers (h, fill, icon, section, api, post, toast, when, ago, main, poll, ME).
// All server data (alerts and tool output above all) is untrusted: it is only ever set as text.
"use strict";
window.SOC_PAGES = (() => {
const SVGNS = "http://www.w3.org/2000/svg";
function s(tag, attrs, ...kids) {
  const el = document.createElementNS(SVGNS, tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === null || v === undefined || v === false) continue;
    if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else el.setAttribute(k, v === true ? "" : String(v));
  }
  for (const kid of kids.flat()) {
    if (kid === null || kid === undefined || kid === false) continue;
    el.append(kid instanceof Node ? kid : document.createTextNode(String(kid)));
  }
  return el;
}
// Widths are set through the style object (allowed by the strict content security policy), not a style attribute.
function barFill(pct) { const b = h("div", { class: "hbar-fill" }); b.style.width = pct + "%"; return b; }
const SUB = [["cases", "Cases", "format-list-bulleted"], ["approvals", "Approvals", "gavel"], ["socalerts", "Alerts", "alert-circle-outline"],
  ["socdash", "Dashboard", "file-chart-outline"], ["tuning", "Tuning", "progress-wrench"]];
const subnav = (on) => h("div", { class: "row subnav" }, SUB.map(([k, label, ic]) =>
  h("a", { class: "button ghost seg" + (k === on ? " on" : ""), href: "#" + k }, icon(ic), label)));

// ---- verdict and severity labels (always text + icon, never colour alone) ----
const VERDICT = {
  true_positive: ["True positive", "alert-circle-outline"], false_positive: ["False positive", "close-circle-outline"],
  benign: ["Benign", "check-circle-outline"], needs_analyst: ["Needs analyst", "hand-back-right-outline"],
  logs_missing: ["Logs missing", "database-search"],
};
const verdictBadge = (v) => v ? h("span", { class: "badge v-" + v }, icon((VERDICT[v] || [])[1] || "label"), (VERDICT[v] || [v])[0])
  : h("span", { class: "badge muted" }, "not triaged");
const SEV = (label) => h("span", { class: "sev sev-" + (label || "low") }, label || "low");
const STATUS = (st) => h("span", { class: "badge st-" + st }, String(st || "").replace("_", " "));
const VERDICT_OPTIONS = Object.keys(VERDICT);

// ---- tooltip shared by charts and the graph ----
const tipEl = () => document.getElementById("tip");
function tipShow(evt, lines) {
  const el = tipEl();
  fill(el, lines.map((l, i) => h("div", { class: i ? "" : "tip-h" }, l)));
  el.classList.remove("hidden");
  const x = Math.min(window.innerWidth - el.offsetWidth - 12, evt.clientX + 14);
  const y = Math.min(window.innerHeight - el.offsetHeight - 12, evt.clientY + 14);
  el.style.left = x + "px"; el.style.top = y + "px";
}
const tipHide = () => tipEl().classList.add("hidden");

// ---------------- Queue ----------------
async function queue(filter) {
  filter = filter || "open";
  const q = { open: "?open=1", needs_analyst: "?status=needs_analyst", triaged: "?status=triaged", closed: "?status=closed",
    true_positive: "?verdict=true_positive", all: "" }[filter] || "?open=1";
  const [cases, st, m] = await Promise.all([api("/api/cases" + q), api("/api/soc/status"), api("/api/soc/metrics?days=1")]);
  const kpi = (label, value, href, cls) => h("a", { class: "kpi-card " + (cls || ""), href }, h("b", {}, value ?? "-"), h("span", {}, label));
  const open = (m.status && Object.entries(m.status).filter(([k]) => k !== "closed").reduce((a, [, v]) => a + v, 0)) || 0;
  main.append(subnav("cases"));
  main.append(h("div", { class: "kpi-row" },
    kpi("Open cases", open, "#cases/open"),
    kpi("Need an analyst", (m.status || {}).needs_analyst || 0, "#cases/needs_analyst", (m.status || {}).needs_analyst ? "warn-card" : ""),
    kpi("Waiting for approval", m.pending_actions, "#approvals", m.pending_actions ? "warn-card" : ""),
    kpi("True positives (24 h)", (m.ai_verdicts || {}).true_positive || 0, "#cases/true_positive",
      (m.ai_verdicts || {}).true_positive ? "bad-card" : ""),
    kpi("Median minutes to triage", (m.minutes_to_triage || {}).median, "#socdash")));
  const seg = (k, label) => h("button", { class: "ghost seg" + (k === filter ? " on" : ""), onclick: () => { location.hash = "cases/" + k; } }, label);
  const tools = h("div", { class: "row" },
    seg("open", "Open"), seg("needs_analyst", "Needs analyst"), seg("triaged", "AI triaged"), seg("true_positive", "True positives"),
    seg("closed", "Closed"), seg("all", "All"), h("span", { class: "grow" }),
    h("span", { class: "muted small" }, `Response: ${st.response_mode}. Auto triage ${st.auto_triage ? "on" : "off"}.`),
    st.intake_sources.length ? h("button", { class: "ghost", "data-need": "op", onclick: async () => {
      const r = await post("/api/intake/poll"); toast(`Polled ${r.polled.length} source(s), queued ${r.queued.length} case(s)`); route();
    } }, icon("replay"), "Poll now") : null);
  const rows = cases.map((c) => h("tr", { class: "click", onclick: () => { location.hash = "case/" + c.id; } },
    h("td", {}, SEV(c.severity_label)),
    h("td", {}, c.status === "triaging" ? h("span", { class: "badge" }, icon("progress-wrench"), "investigating") : verdictBadge(c.verdict)),
    h("td", { class: "num" }, c.verdict ? String(c.confidence) : ""),
    h("td", {}, c.title, c.pending_actions ? h("span", { class: "badge warn small", title: "actions waiting for approval" },
      icon("gavel"), c.pending_actions) : null),
    h("td", { class: "num" }, String(c.alert_count)),
    h("td", {}, STATUS(c.status)),
    h("td", { class: "muted small" }, ago(c.last_alert || c.created))));
  main.append(section("Cases", "format-list-bulleted", tools,
    cases.length ? h("table", { class: "cases" }, h("thead", {}, h("tr", {}, ["Severity", "AI verdict", "Conf.", "Case", "Alerts", "Status", "Last alert"].map((x) => h("th", {}, x)))),
      h("tbody", {}, rows)) : h("p", { class: "muted" }, "No cases here. Alerts arrive through POST /api/alerts, a polled source, or haymdhal alerts import.")));
  if (cases.some((c) => c.status === "triaging" || c.status === "new")) poll = setInterval(() => { if (!document.hidden) route(); }, 5000);
}

// ---------------- Case ----------------
async function caseDetail(id) {
  const c = await api("/api/cases/" + encodeURIComponent(id));
  await meReady;
  const r = c.report || {};
  const head = section(c.title, "shield-search",
    h("div", { class: "row" }, SEV(c.severity_label), verdictBadge(c.verdict),
      c.verdict ? h("span", { class: "muted" }, `confidence ${c.confidence}`) : null, STATUS(c.status),
      c.analyst_verdict ? h("span", { class: "badge" }, icon("account-circle-outline"), "analyst: ", (VERDICT[c.analyst_verdict] || [c.analyst_verdict])[0]) : null,
      h("span", { class: "grow" }),
      h("span", { class: "muted small" }, `${c.alerts.length} alert(s), ${when(c.first_alert)} to ${when(c.last_alert)}`)),
    h("div", { class: "row" },
      h("button", { class: "ghost", "data-need": "op", disabled: c.status === "triaging",
        onclick: async () => { await post(`/api/cases/${c.id}/triage`); toast("Investigation started"); route(); } },
        icon("replay"), c.verdict ? "Investigate again" : "Investigate now"),
      c.status === "triaging" ? h("button", { class: "ghost", "data-need": "op", onclick: async () => { await post(`/api/cases/${c.id}/stop`); route(); } }, icon("stop"), "Stop") : null,
      h("button", { class: "ghost", "data-need": "op", onclick: async () => { await post(`/api/cases/${c.id}/assign`, { assignee: ME.user }); route(); } },
        icon("account-arrow-left-outline"), c.assignee ? `Assigned: ${c.assignee}` : "Assign to me"),
      h("button", { class: "ghost", "data-need": "op", title: "Start a full hunt for the same activity elsewhere",
        onclick: async () => { const r = await post(`/api/cases/${c.id}/hunt`); toast("Hunt started"); location.hash = "hunt/" + r.hunt_id; } },
        icon("target"), "Hunt this"),
      h("a", { class: "button ghost", href: `/api/cases/${c.id}/report.md` }, icon("language-markdown-outline"), "Report"),
      h("a", { class: "button ghost", href: `/api/cases/${c.id}/evidence.json`, title: "Sealed evidence bundle (JSON)" }, icon("lock"), "Evidence")),
    c.error ? h("p", { class: "bad" }, c.error) : null);
  main.append(head);
  if (c.status === "triaging") {
    main.append(section("Investigating", "progress-wrench", h("p", { class: "muted" }, "The AI is working on this case; the page refreshes."),
      stepsList(c.steps)));
    poll = setInterval(() => { if (!document.hidden) route(); }, 4000);
  }
  if (c.verdict) {
    const checks = (r.checks || []);
    main.append(section("What happened", "text-box-outline",
      h("p", { class: "pre lead" }, c.summary || ""),
      r.findings && r.findings.length ? h("ul", { class: "findings" }, r.findings.map((f) => h("li", {}, f.text, " ",
        (f.evidence || []).map((e) => h("a", { class: "ev", href: "#", onclick: (ev) => { ev.preventDefault(); openEvidence(e); } }, e))))) : null,
      r.contradicting && r.contradicting.length ? h("div", { class: "handoff" }, h("h4", {}, icon("compare-horizontal"), " Points against this verdict"),
        h("ul", {}, r.contradicting.map((f) => h("li", {}, f.text, " ", (f.evidence || []).map((e) => h("a", { class: "ev", href: "#", onclick: (ev) => { ev.preventDefault(); openEvidence(e); } }, e)))))) : null,
      r.missing && r.missing.length ? h("div", { class: "handoff" }, h("h4", {}, icon("chat-question-outline"), " Could not establish"),
        h("ul", {}, r.missing.map((m) => h("li", { class: "small" }, m)))) : null,
      r.verification ? h("p", { class: "small" }, icon("check-decagram-outline"), " Second look: ", h("b", {}, r.verification.result), ". ",
        r.verification.reason || "", " ", (r.verification.evidence || []).map((e) => h("a", { class: "ev", href: "#", onclick: (ev) => { ev.preventDefault(); openEvidence(e); } }, e))) : null,
      checks.length ? h("div", { class: "handoff" }, h("h4", {}, icon("check-decagram-outline"), " Checks on the AI verdict"),
        h("ul", {}, checks.map((x) => h("li", { class: "small" }, x)))) : null,
      r.injection && r.injection.length ? h("div", { class: "handoff bad-border" }, h("h4", {}, icon("alert-circle-outline"), " Text that tries to instruct the AI"),
        h("ul", {}, r.injection.map((x) => h("li", { class: "small" }, x)))) : null,
      r.gaps && r.gaps.length ? h("details", {}, h("summary", {}, "Not checked"), h("ul", {}, r.gaps.map((x) => h("li", {}, x)))) : null,
      r.next_steps && r.next_steps.length ? h("details", { open: true }, h("summary", {}, "Next steps for the analyst"), h("ul", {}, r.next_steps.map((x) => h("li", {}, x)))) : null));
    main.append(fixSection(c));
  }
  main.append(actionsSection(c));
  main.append(section("Entity graph", "graph-outline", graphView(c.graph, r)));
  main.append(section("Timeline", "timeline-clock-outline", timelineView(c.timeline)));
  if (c.chain && c.chain.length) main.append(section("ATT&CK chain", "map-outline", chainView(c.chain)));
  main.append(section("Alerts", "alert-circle-outline", alertTable(c.alerts, false)));
  if (c.first_look && Object.keys(c.first_look).length) {
    const fl = c.first_look;
    main.append(section("First look", "lightbulb-on-outline",
      fl.error ? h("p", { class: "bad" }, fl.error) : h("div", {},
        h("p", {}, h("b", {}, fl.priority || ""), " likely ", (fl.likely || "").replace("_", " "), ". ", fl.reason || ""),
        h("ol", {}, (fl.questions || []).map((q) => h("li", {}, q))),
        (c.steps || []).filter((x) => x.kind === "playbook").map((x) => h("p", { class: "muted small" }, icon("bookshelf"), " Playbook: ", x.note)))));
  }
  main.append(section("Evidence", "database-search", stepsList(c.steps)));
  if (c.related && c.related.length) main.append(section("Related cases", "compare-horizontal",
    h("table", {}, h("tbody", {}, c.related.map((x) => h("tr", { class: "click", onclick: () => { location.hash = "case/" + x.id; } },
      h("td", {}, verdictBadge(x.analyst_verdict || x.verdict)), h("td", {}, x.title), h("td", { class: "muted small" }, x.shared_values)))))));
  main.append(notesSection(c));
  main.append(closeSection(c));
  if (c.usage && c.usage.calls) main.append(h("p", { class: "muted small" },
    `Model use: ${c.usage.calls} calls, ${c.usage.tokens_in} tokens in, ${c.usage.tokens_out} out, ${c.usage.seconds} s.`));
}

function openEvidence(eid) {
  const el = document.getElementById("ev-" + eid);
  if (el) { el.open = true; el.scrollIntoView({ behavior: "smooth", block: "center" }); }
}

function stepsList(steps) {
  const calls = (steps || []).filter((x) => x.kind === "call");
  if (!calls.length) return h("p", { class: "muted" }, "No tool calls yet.");
  return h("div", {}, calls.map((x) => h("details", { class: "step " + (x.ok ? "good" : "fail"), id: "ev-E" + x.n },
    h("summary", {}, h("b", {}, "E" + x.n), " ", `${x.connector}.${x.tool}`, " ", h("span", { class: x.ok ? "ok" : "bad" }, x.ok ? "ok" : "failed"),
      x.note ? h("span", { class: "muted small" }, " " + x.note) : null),
    x.why ? h("p", { class: "muted small" }, x.why) : null,
    h("pre", {}, JSON.stringify(x.arguments, null, 1)),
    h("pre", {}, x.result || ""))));
}

function fixSection(c) {
  const fx = (c.report || {}).fix || {};
  const t = fx.tuning;
  const kids = [];
  if (fx.steps && fx.steps.length) kids.push(h("ol", {}, fx.steps.map((x) => h("li", {}, x))));
  if (t) {
    const days = h("input", { type: "number", value: 30, min: 1, max: 365, class: "w5" });
    kids.push(h("div", { class: "close-row" }, h("b", {}, "Tuning proposal: "),
      `suppress rule ${t.rule || "(this case's rule)"}`, t.entity_type ? ` for ${t.entity_type} ${t.entity_value}` : " for every entity",
      t.reason ? h("span", { class: "muted" }, ` - ${t.reason}`) : null,
      h("div", { class: "row" }, "for", days, "days",
        h("button", { "data-need": "op", onclick: async () => { const r = await post(`/api/cases/${c.id}/tuning`, { days: Number(days.value) });
          toast(`Suppression ${r.suppression_id} added`); route(); } }, icon("progress-wrench"), "Apply tuning"))));
  }
  if (!kids.length) kids.push(h("p", { class: "muted" }, "No fix proposed."));
  return section(fx.type === "tuning" ? "Fix: tune the detection" : fx.type === "remediation" ? "Fix: remediation" : "Fix", "tools", kids);
}

function actionsSection(c) {
  const acts = c.actions || [];
  const rows = acts.map((a) => h("div", { class: "action-card st-" + a.status },
    h("div", { class: "row" }, h("b", {}, a.name.replace(/_/g, " ")), h("code", {}, a.target), STATUS(a.status),
      a.stale ? h("span", { class: "badge warn" }, icon("alert-circle-outline"), "case changed since proposed") : null,
      h("span", { class: "muted small" }, { reversible: "undo: reversible", compensating: "undo: partial (a follow-up action, not a full restore)", none: "no undo" }[a.undo_kind || "none"]),
      h("span", { class: "grow" }),
      a.status === "proposed" ? [
        h("button", { "data-need": "op", onclick: async () => { const r = await post(`/api/actions/${a.id}/approve`); toast(r.waiting_for ? "Waiting for a second approver" : `Action ${r.status}`); route(); } }, icon("check-all"), "Approve"),
        h("button", { class: "ghost", "data-need": "op", onclick: async () => { await post(`/api/actions/${a.id}/reject`); route(); } }, icon("cancel"), "Reject")] : null,
      (a.status === "executed" || a.status === "dry_run") && a.undo ? h("button", { class: "ghost", "data-need": "op",
        onclick: async () => { await post(`/api/actions/${a.id}/undo`); toast("Undone"); route(); } }, icon("restore"), "Undo") : null),
    a.reason ? h("div", { class: "small" }, a.reason) : null,
    h("div", { class: "muted small" }, `${a.connector}.${a.tool} ${JSON.stringify(a.arguments)}`,
      a.approvers && a.approvers.length ? ` - approved by ${a.approvers.join(", ")}` : "", a.result ? ` - ${a.result}` : "")));
  const cat = c.catalogue || [];
  let adder = null;
  if (cat.length) {
    const sel = h("select", {}, cat.map((x) => h("option", { value: x.name }, `${x.name} (${x.entity})`)));
    const tgt = h("select", {});
    const refresh = () => { const kind = (cat.find((x) => x.name === sel.value) || {}).entity;
      fill(tgt, (c.entities || []).filter((e) => e.type === kind).map((e) => h("option", { value: e.value }, e.value))); };
    sel.addEventListener("change", refresh); refresh();
    adder = h("div", { class: "row", "data-need": "op" }, icon("plus"), "Propose", sel, "on", tgt,
      h("button", { class: "ghost", onclick: async () => { if (!tgt.value) return toast("No matching entity in this case");
        await post(`/api/cases/${c.id}/actions`, { name: sel.value, target: tgt.value }); route(); } }, "Add"));
  }
  return section("Response actions", "gavel", h("p", { class: "muted small" }, `Mode: ${c.response_mode}. The AI proposes; a person approves.`),
    rows.length ? rows : h("p", { class: "muted" }, c.verdict === "true_positive" ? "No configured action fits this case. See the fix steps."
      : "No actions proposed."), adder);
}

function notesSection(c) {
  const ta = h("textarea", { placeholder: "Add a note for the team" });
  return section("Notes", "note-text-outline",
    h("ul", { class: "events" }, (c.notes || []).map((n) => h("li", {}, h("span", { class: "muted small" }, when(n.ts) + " " + n.author + ": "), n.text))),
    h("div", { "data-need": "op" }, ta, h("button", { class: "ghost", onclick: async () => { if (!ta.value.trim()) return;
      await post(`/api/cases/${c.id}/notes`, { text: ta.value }); route(); } }, icon("comment-plus-outline"), "Add note")));
}

function closeSection(c) {
  if (c.status === "closed") return section("Closed", "check-circle-outline",
    h("p", {}, `Closed by ${c.closed_by || "-"} ${when(c.closed_at)} as `, verdictBadge(c.analyst_verdict || c.verdict), c.analyst_note ? ` - ${c.analyst_note}` : ""),
    h("button", { class: "ghost", "data-need": "op", onclick: async () => { await post(`/api/cases/${c.id}/reopen`); route(); } }, icon("lock-open-variant-outline"), "Reopen"));
  const sel = h("select", {}, VERDICT_OPTIONS.map((v) => h("option", { value: v, selected: v === c.verdict }, VERDICT[v][0])));
  const note = h("input", { class: "grow", placeholder: "Why (optional)" });
  return section("Your decision", "gavel", h("div", { class: "row close-row", "data-need": "op" }, "Close as", sel, note,
    h("button", { onclick: async () => { await post(`/api/cases/${c.id}/close`, { verdict: sel.value, note: note.value }); toast("Case closed"); route(); } },
      icon("lock"), "Close case")),
  h("p", { class: "muted small" }, "Your verdict is stored next to the AI's; disagreements show on the dashboard."));
}

// ---- entity graph: columns by kind, curves for links, click a node to focus it ----
const COLS = [["alert"], ["user", "host"], ["process", "file", "hash"], ["ip", "domain", "url", "entity"]];
const COL_NAMES = ["Alerts", "Users and hosts", "Processes and files", "Network and indicators"];
function graphView(g, report) {
  if (!g || !g.nodes.length) return h("p", { class: "muted" }, "No entities.");
  const colOf = (n) => Math.max(0, COLS.findIndex((c) => c.includes(n.type)));
  const cols = COLS.map(() => []);
  g.nodes.forEach((n) => cols[colOf(n)].push(n));
  cols.forEach((c) => c.sort((a, b) => (b.role === "attacker") - (a.role === "attacker") || (b.role === "victim") - (a.role === "victim") || (b.alerts || 0) - (a.alerts || 0)));
  const W = 980, colW = W / 4, rowH = 40, top = 34, nodeW = colW - 34;
  const H = top + Math.max(...cols.map((c) => c.length)) * rowH + 10;
  const pos = {};
  cols.forEach((c, ci) => c.forEach((n, i) => { pos[n.id] = { x: ci * colW + 14, y: top + i * rowH }; }));
  const svg = s("svg", { viewBox: `0 0 ${W} ${H}`, class: "egraph", role: "img", "aria-label": "Entity graph of this case" });
  COL_NAMES.forEach((name, i) => svg.append(s("text", { x: i * colW + 14, y: 16, class: "eg-col" }, name)));
  const edgeEls = [];
  const nodeEls = {};
  g.edges.forEach((e) => {
    const a = pos[e.source], b = pos[e.target];
    if (!a || !b) return;
    const ax = a.x + (a.x < b.x ? nodeW : 0), bx = b.x + (a.x < b.x ? 0 : nodeW);
    const ay = a.y + 13, by = b.y + 13;
    const mx = (ax + bx) / 2;
    const d = a.x === b.x ? `M${a.x + nodeW},${ay} C${a.x + nodeW + 40},${ay} ${b.x + nodeW + 40},${by} ${b.x + nodeW},${by}`
      : `M${ax},${ay} C${mx},${ay} ${mx},${by} ${bx},${by}`;
    const el = s("path", { d, class: "eg-edge" + (e.type === "in alert" ? "" : " rel") });
    el.addEventListener("mousemove", (ev) => tipShow(ev, [e.type, `${label(e.source)} to ${label(e.target)}`, e.count > 1 ? `${e.count} times` : ""]));
    el.addEventListener("mouseleave", tipHide);
    edgeEls.push([el, e]);
    svg.append(el);
  });
  function label(id) { const n = g.nodes.find((x) => x.id === id); return n ? `${n.type} ${n.label}` : id; }
  let focus = null;
  function setFocus(id) {
    focus = focus === id ? null : id;
    const near = new Set([focus]);
    edgeEls.forEach(([, e]) => { if (e.source === focus || e.target === focus) { near.add(e.source); near.add(e.target); } });
    edgeEls.forEach(([el, e]) => el.classList.toggle("dim", !!focus && !(e.source === focus || e.target === focus)));
    Object.entries(nodeEls).forEach(([nid, el]) => el.classList.toggle("dim", !!focus && !near.has(nid)));
  }
  g.nodes.forEach((n) => {
    const p = pos[n.id];
    const grp = s("g", { class: "eg-node role-" + (n.role || "none") + " t-" + n.type, transform: `translate(${p.x},${p.y})`, tabindex: 0 });
    grp.append(s("rect", { width: nodeW, height: 26, rx: 6 }));
    const kind = n.type === "alert" ? (n.severity >= 65 ? "!" : "") : n.type;
    grp.append(s("text", { x: 8, y: 17, class: "eg-kind" }, kind));
    const txt = n.label.length > 30 ? n.label.slice(0, 29) + "..." : n.label;
    grp.append(s("text", { x: n.type === "alert" ? 18 : 8 + kind.length * 6.6 + 6, y: 17 }, txt));
    grp.addEventListener("mousemove", (ev) => tipShow(ev, [`${n.type}: ${n.value}`, n.role ? `role: ${n.role}` : "", n.alerts ? `in ${n.alerts} alert(s)` : "",
      n.first ? `seen ${when(n.first)}${n.last && n.last !== n.first ? " to " + when(n.last) : ""}` : ""].filter(Boolean)));
    grp.addEventListener("mouseleave", tipHide);
    grp.addEventListener("click", () => setFocus(n.id));
    grp.addEventListener("keydown", (ev) => { if (ev.key === "Enter") setFocus(n.id); });
    nodeEls[n.id] = grp;
    svg.append(grp);
  });
  const legend = h("div", { class: "legend small" },
    h("span", {}, h("i", { class: "sw sw-attacker" }), "attacker side"), h("span", {}, h("i", { class: "sw sw-victim" }), "affected"),
    h("span", {}, h("i", { class: "sw sw-none" }), "related"), h("span", {}, h("i", { class: "sw sw-rel" }), "link found by the investigation"),
    h("span", { class: "muted" }, "Click a node to show only its links."));
  const table = h("details", {}, h("summary", {}, "Links as a table"),
    h("table", {}, h("thead", {}, h("tr", {}, ["From", "Link", "To"].map((x) => h("th", {}, x)))),
      h("tbody", {}, g.edges.map((e) => h("tr", {}, h("td", {}, label(e.source)), h("td", {}, e.type), h("td", {}, label(e.target)))))));
  return h("div", {}, h("div", { class: "egraph-wrap" }, svg), legend, g.truncated ? h("p", { class: "muted small" }, "Graph cut at 150 nodes.") : null, table);
}

function timelineView(items) {
  if (!items || !items.length) return h("p", { class: "muted" }, "Nothing yet.");
  const ic = { alert: "alert-circle-outline", finding: "magnify-scan", action: "gavel", note: "comment", verdict: "robot-outline", closed: "lock" };
  return h("ul", { class: "timeline" }, items.map((t) => h("li", { class: "tl-" + t.kind },
    h("span", { class: "tl-time muted small" }, t.time ? when(t.time) : "(time not given)"), icon(ic[t.kind] || "label"),
    h("span", { class: "tl-kind small" }, t.kind), " ", t.text,
    (t.evidence || []).map((e) => h("a", { class: "ev", href: "#", onclick: (ev) => { ev.preventDefault(); openEvidence(e); } }, e)))));
}

function chainView(chain) {
  return h("div", { class: "chain" }, chain.map((c, i) => h("div", { class: "tactic" },
    h("div", { class: "tactic-h" }, `${i + 1}. ${c.tactic.replace(/-/g, " ")}`),
    c.techniques.map((t) => h("div", { class: "tech" }, h("b", {}, t.id), " ", t.name)))));
}

function alertTable(alerts, withCase) {
  if (!alerts.length) return h("p", { class: "muted" }, "No alerts.");
  return h("table", {}, h("thead", {}, h("tr", {}, ["Time", "Sev.", "Alert", "Rule", "Entities", withCase ? "Case" : "Raw"].map((x) => h("th", {}, x)))),
    h("tbody", {}, alerts.map((a) => h("tr", {},
      h("td", { class: "small" }, when(a.ts)), h("td", { class: "num" }, String(a.severity)),
      h("td", {}, a.title, a.dup_count ? h("span", { class: "muted small" }, ` (+${a.dup_count} repeats)`) : null,
        a.status === "suppressed" ? h("span", { class: "badge small" }, "suppressed") : null),
      h("td", { class: "small" }, a.rule_id || ""),
      h("td", { class: "small" }, (a.entities || []).slice(0, 6).map((e) => `${e.type}=${e.value}`).join(", ")),
      withCase ? h("td", {}, a.case_id ? h("a", { href: "#case/" + a.case_id }, a.case_id) : "-")
        : h("td", {}, h("details", {}, h("summary", {}, "json"), h("pre", {}, JSON.stringify(a.raw, null, 1))))))));
}

// ---------------- Approvals ----------------
async function approvals() {
  const [pending, all, st] = await Promise.all([api("/api/actions?status=proposed"), api("/api/actions"), api("/api/soc/status")]);
  const card = (a) => h("tr", { class: "click", onclick: () => { location.hash = "case/" + a.case_id; } },
    h("td", {}, h("b", {}, a.name.replace(/_/g, " "))), h("td", {}, h("code", {}, a.target)), h("td", {}, a.reason || ""),
    h("td", {}, STATUS(a.status)), h("td", { class: "muted small" }, when(a.decided_at || a.proposed_at)));
  main.append(subnav("approvals"));
  main.append(section("Waiting for approval", "gavel", h("p", { class: "muted small" }, `Mode: ${st.response_mode}. Open a case to approve or reject.`),
    pending.length ? h("table", {}, h("tbody", {}, pending.map(card))) : h("p", { class: "muted" }, "Nothing waiting.")));
  const done = all.filter((a) => a.status !== "proposed");
  main.append(section("History", "history", done.length ? h("table", {}, h("tbody", {}, done.map(card))) : h("p", { class: "muted" }, "No decisions yet.")));
}

// ---------------- Alerts ----------------
async function alerts() {
  const q = h("input", { placeholder: "search title, rule or entity", class: "grow" });
  const box = h("div");
  const load = async () => fill(box, alertTable(await api("/api/alerts?limit=300&q=" + encodeURIComponent(q.value)), true));
  q.addEventListener("change", load);
  await load();
  const ta = h("textarea", { placeholder: '[{"rule": {"id": "R1", "name": "...", "level": 10}, "host": {"name": "..."}, "@timestamp": "..."}]' });
  main.append(subnav("socalerts"), section("Alerts", "alert-circle-outline", h("div", { class: "row" }, q, h("button", { class: "ghost", onclick: load }, icon("magnify"), "Search")), box));
  main.append(section("Send alerts", "upload", h("p", { class: "muted small" }, "Paste one alert object or a list. Other systems POST the same JSON to /api/alerts."),
    h("div", { "data-need": "op" }, ta, h("button", { onclick: async () => {
      let data; try { data = JSON.parse(ta.value); } catch (e) { return toast("That is not valid JSON"); }
      const r = await post("/api/alerts?source=paste", data);
      toast(`${r.new} new, ${r.duplicates} duplicates, ${r.suppressed} suppressed; ${r.cases_opened.length} case(s) opened`); route();
    } }, icon("send"), "Send"))));
}

// ---------------- Dashboard ----------------
const GROUPS = [["true_positive", "True positive", "c-tp"], ["needs", "Needs a person", "c-need"], ["clear", "Not a threat", "c-clear"]];
function groupOf(d) {
  return { true_positive: d.true_positive || 0, needs: (d.needs_analyst || 0) + (d.logs_missing || 0) + (d.untriaged || 0),
    clear: (d.false_positive || 0) + (d.benign || 0) };
}
async function dashboard() {
  const days = Number(sessionStorage.getItem("hd-days") || 14);
  const m = await api("/api/soc/metrics?days=" + days);
  const pick = h("div", { class: "row" }, [7, 14, 30, 90].map((d) => h("button", { class: "ghost seg" + (d === days ? " on" : ""),
    onclick: () => { sessionStorage.setItem("hd-days", d); route(); } }, `${d} days`)));
  const pct = (x) => (x === null || x === undefined ? "-" : Math.round(x * 100) + "%");
  main.append(subnav("socdash"));
  main.append(pick);
  main.append(h("div", { class: "kpi-row" },
    tile("Cases", m.cases), tile("Alerts received", m.alerts), tile("AI and analyst agree", pct(m.agreement.rate),
      `${m.agreement.agree} of ${m.agreement.agree + m.agreement.disagree} closed by an analyst`),
    tile("Median minutes to triage", m.minutes_to_triage.median), tile("Median minutes to close", m.minutes_to_close.median),
    tile("Median tokens per case", m.tokens_per_case.median)));
  main.append(section("Cases per day by verdict", "chart-timeline-variant", stackedBars(m.per_day)));
  const rows = Object.entries(m.ai_verdicts).map(([k, v]) => ({ label: (VERDICT[k] || [k.replace("_", " ")])[0], value: v }));
  main.append(section("AI verdicts", "robot-outline", hbars(rows, "cases")));
  main.append(section("Noisiest rules (false positive or benign)", "progress-wrench", noisyTable(m.noisy_rules),
    h("p", { class: "muted small" }, "Rules that keep producing cases nobody needs: tune them from a case's fix, or on the Tuning page.")));
  main.append(section("Model tokens per day", "brain", hbars(m.tokens_per_day.map((d) => ({ label: d.day, value: d.tokens })), "tokens")));
  if (m.agreement.matrix.length) main.append(section("Where the analyst disagreed", "compare-horizontal",
    h("table", {}, h("thead", {}, h("tr", {}, ["AI said", "Analyst said", "Cases"].map((x) => h("th", {}, x)))),
      h("tbody", {}, m.agreement.matrix.filter((x) => x.ai !== x.analyst).map((x) => h("tr", {}, h("td", {}, verdictBadge(x.ai)), h("td", {}, verdictBadge(x.analyst)), h("td", { class: "num" }, String(x.count))))))));
  main.append(h("p", {}, h("a", { href: "/api/soc/shift.md?hours=12" }, icon("file-document-outline"), " Shift report (last 12 hours, markdown)")));
}
function tile(label, value, sub) {
  return h("div", { class: "kpi-card" }, h("b", {}, value === null || value === undefined ? "-" : String(value)), h("span", {}, label), sub ? h("span", { class: "small" }, sub) : null);
}
function niceMax(v) { if (v <= 5) return 5; const p = Math.pow(10, Math.floor(Math.log10(v))); return Math.ceil(v / p) * p; }
function stackedBars(perDay) {
  if (!perDay.length) return h("p", { class: "muted" }, "No cases in this period.");
  const data = perDay.map((d) => ({ day: d.day, ...groupOf(d) }));
  const W = 900, H = 220, L = 34, B = 24, T = 8;
  const max = niceMax(Math.max(...data.map((d) => d.true_positive + d.needs + d.clear)));
  const bw = Math.min(42, (W - L) / data.length - 6);
  const step = (W - L) / data.length;
  const y = (v) => T + (H - T - B) * (1 - v / max);
  const svg = s("svg", { viewBox: `0 0 ${W} ${H}`, class: "chart", role: "img", "aria-label": "Cases per day by verdict group" });
  [0, max / 2, max].forEach((v) => { svg.append(s("line", { x1: L, x2: W, y1: y(v), y2: y(v), class: v ? "grid" : "axis" }));
    svg.append(s("text", { x: L - 6, y: y(v) + 4, class: "tick", "text-anchor": "end" }, String(v))); });
  data.forEach((d, i) => {
    const x = L + i * step + (step - bw) / 2;
    let base = 0;
    const segs = GROUPS.filter(([k]) => d[k] > 0);
    segs.forEach(([k, , cls], si) => {
      const y0 = y(base), y1 = y(base + d[k]);
      const top = si === segs.length - 1;
      const hgt = Math.max(0, y0 - y1 - (si ? 2 : 0));
      const yy = y1;
      const r = top ? Math.min(4, hgt, bw / 2) : 0;
      const p = `M${x},${yy + hgt} V${yy + r} Q${x},${yy} ${x + r},${yy} H${x + bw - r} Q${x + bw},${yy} ${x + bw},${yy + r} V${yy + hgt} Z`;
      svg.append(s("path", { d: p, class: "bar " + cls }));
      base += d[k];
    });
    const hit = s("rect", { x: L + i * step, y: T, width: step, height: H - T - B, class: "hit" });
    hit.addEventListener("mousemove", (ev) => tipShow(ev, [d.day, ...GROUPS.map(([k, lbl]) => `${lbl}: ${d[k]}`)]));
    hit.addEventListener("mouseleave", tipHide);
    svg.append(hit);
    if (data.length <= 16 || i % Math.ceil(data.length / 12) === 0) svg.append(s("text", { x: x + bw / 2, y: H - 6, class: "tick", "text-anchor": "middle" }, d.day.slice(5)));
  });
  const legend = h("div", { class: "legend small" }, GROUPS.map(([, lbl, cls]) => h("span", {}, h("i", { class: "sw " + cls }), lbl)));
  const table = h("details", {}, h("summary", {}, "Show as a table"), h("table", {}, h("thead", {}, h("tr", {}, ["Day", ...GROUPS.map((g) => g[1])].map((x) => h("th", {}, x)))),
    h("tbody", {}, data.map((d) => h("tr", {}, h("td", {}, d.day), GROUPS.map(([k]) => h("td", { class: "num" }, String(d[k]))))))));
  return h("div", {}, legend, svg, table);
}
function hbars(rows, unit) {
  if (!rows.length) return h("p", { class: "muted" }, "Nothing in this period.");
  const max = Math.max(...rows.map((r) => r.value), 1);
  return h("div", { class: "hbars" }, rows.map((r) => {
    const bar = barFill(Math.max(0.5, (r.value / max) * 100));
    const row = h("div", { class: "hbar" }, h("span", { class: "hbar-l" }, r.label), h("div", { class: "hbar-t" }, bar), h("span", { class: "hbar-v num" }, r.value.toLocaleString()));
    row.addEventListener("mousemove", (ev) => tipShow(ev, [r.label, `${r.value.toLocaleString()} ${unit}`]));
    row.addEventListener("mouseleave", tipHide);
    return row;
  }));
}
function noisyTable(rows) {
  if (!rows.length) return h("p", { class: "muted" }, "No closed or triaged cases yet.");
  return h("table", {}, h("thead", {}, h("tr", {}, ["Rule", "Cases", "True positive", "Not a threat", "Noise"].map((x) => h("th", {}, x)))),
    h("tbody", {}, rows.map((r) => h("tr", {}, h("td", {}, r.rule), h("td", { class: "num" }, String(r.cases)), h("td", { class: "num" }, String(r.true_positive)),
      h("td", { class: "num" }, String(r.noise)), h("td", {}, h("div", { class: "hbar-t sm" }, barFill(r.noise_rate * 100)),
        h("span", { class: "small" }, ` ${Math.round(r.noise_rate * 100)}%`))))));
}

// ---------------- Tuning ----------------
async function tuning() {
  const rows = await api("/api/suppressions?all=1");
  const rule = h("input", { placeholder: "rule id or name (wildcards *)" });
  const et = h("select", {}, ["", "host", "user", "ip", "process", "domain", "hash", "file", "url"].map((x) => h("option", { value: x }, x || "any entity")));
  const ev = h("input", { placeholder: "entity value (wildcards *)" });
  const reason = h("input", { class: "grow", placeholder: "reason" });
  const days = h("input", { type: "number", value: 30, class: "w5" });
  main.append(subnav("tuning"));
  const warn = rows.filter((x) => x.enabled && x.high_hits);
  if (warn.length) main.append(section("Check these suppressions", "alert-circle-outline",
    h("p", { class: "small" }, "These suppressions hid high or critical alerts. Make sure that is still what you want."),
    h("ul", {}, warn.map((x) => h("li", {}, `${x.rule}${x.entity_type ? ` (${x.entity_type}=${x.entity_value})` : ""}: `,
      `${x.high_hits} high-severity alert(s) hidden, last ${when(x.last_hit)}`)))));
  main.append(section("Suppressions", "progress-wrench", h("p", { class: "muted small" }, "Matching alerts are stored as suppressed and never open a case. They expire."),
    h("div", { class: "row", "data-need": "op" }, rule, et, ev, reason, days, "days", h("button", { onclick: async () => {
      await post("/api/suppressions", { rule: rule.value, entity_type: et.value, entity_value: ev.value, reason: reason.value, days: Number(days.value) }); route(); } }, icon("plus"), "Add")),
    rows.length ? h("table", {}, h("thead", {}, h("tr", {}, ["Rule", "Entity", "Reason", "Hits", "Expires", "By", ""].map((x) => h("th", {}, x)))),
      h("tbody", {}, rows.map((x) => h("tr", { class: x.enabled ? "" : "muted" }, h("td", {}, x.rule), h("td", {}, x.entity_type ? `${x.entity_type}=${x.entity_value}` : "any"),
        h("td", {}, x.reason || "", x.case_id ? h("a", { href: "#case/" + x.case_id }, " (case)") : null), h("td", { class: "num" }, String(x.hits)),
        h("td", { class: "small" }, when(x.expires)), h("td", { class: "small" }, x.created_by || ""),
        h("td", {}, x.enabled ? h("button", { class: "ghost", "data-need": "op", onclick: async () => { await post(`/api/suppressions/${x.id}/disable`); route(); } }, "Disable") : "off"))))) : h("p", { class: "muted" }, "None yet.")));
}


const page = (fn) => () => { tipHide(); main.classList.add("soc"); return fn(location.hash.slice(1).split("/")[1]); };
return { cases: page(queue), case: page(caseDetail), approvals: page(approvals), socalerts: page(alerts),
  socdash: page(dashboard), tuning: page(tuning) };
})();
