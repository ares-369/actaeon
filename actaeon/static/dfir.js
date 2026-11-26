// Offline investigation pages (DFIR): case list, overview with evidence and analyzers, timeline, story.
// Loaded before app.js, which owns the router and the shared helpers (h, fill, icon, section, api, post, toast,
// when, ago, main, route). Evidence and model text are untrusted: they are only ever set as text.
"use strict";
window.DFIR_PAGES = (() => {
const LV = { critical: "badge-red", high: "badge-orange", medium: "badge-blue", low: "badge-neutral", informational: "muted" };
const LVN = ["", "informational", "low", "medium", "high", "critical"];
const lvBadge = (lv) => h("span", { class: "badge " + (LV[lv] || "") }, lv);
const busy = (fn) => async (e) => { const b = e.currentTarget; b.disabled = true; try { await fn(e); } finally { b.disabled = false; } };
const off = () => section("Investigations are off", "folder-search-outline",
  h("p", {}, "Set dfir.enabled: true in config.yaml to load evidence files (event logs, JSON lines, CSV, syslog, zip collections) into a case, build one timeline and run Sigma rules over it."),
  h("p", { class: "muted small" }, "See docs/dfir.md."));
const short = (s) => (s || "").slice(0, 12);
const sub = (cid, on) => h("div", { class: "row subnav" }, [["", "Overview", "file-chart-outline"], ["timeline", "Timeline", "timeline-clock-outline"],
  ["story", "Story", "note-text-outline"]].map(([k, label, ic]) =>
  h("a", { class: "button ghost seg" + (k === on ? " on" : ""), href: `#inv/${cid}${k ? "/" + k : ""}` }, icon(ic), label)));
// Long tables show their first rows; a button reveals the rest (cases can have hundreds of files or rules).
function capped(rows, n, label) {
  if (rows.length <= n) return rows;
  const rest = rows.slice(n);
  rest.forEach((r) => r.classList.add("hidden"));
  const btn = h("button", { class: "ghost", onclick: () => { rest.forEach((r) => r.classList.remove("hidden")); btn.remove(); } },
    `Show all ${rows.length} ${label}`);
  return [...rows, h("tr", {}, h("td", { colspan: 9 }, btn))];
}
const evLink = (cid, seq) => h("a", { class: "badge", href: `#inv/${cid}/timeline?focus=${seq}` }, "E" + seq);

// ---------------- list ----------------
async function list() {
  const st = await api("/api/dfir/status");
  if (!st.enabled) { main.append(off()); return; }
  const cases = await api("/api/dfir/cases");
  const title = h("input", { class: "grow", placeholder: "title, e.g. Web server breach November", "aria-label": "Investigation title" });
  const desc = h("textarea", { rows: 3, placeholder: "scope, what is known so far (optional)", "aria-label": "Description" });
  main.append(section("Investigations", "folder-search-outline",
    h("p", { class: "muted small" }, "Load evidence files into a case and work offline: nothing is queried or changed on any system."),
    cases.length ? h("table", {}, h("thead", {}, h("tr", {}, ["Investigation", "Status", "Events", "Updated"].map((x) => h("th", {}, x)))),
      h("tbody", {}, cases.map((c) => h("tr", { class: "click", onclick: () => { location.hash = "inv/" + c.id; } },
        h("td", {}, h("a", { href: "#inv/" + c.id }, c.title)), h("td", { class: "small" }, c.status),
        h("td", { class: "num" }, String(c.events)), h("td", { class: "small" }, ago(c.updated))))))
      : h("p", { class: "muted" }, "No investigations yet."),
    st.evtx ? null : h("p", { class: "warn small" }, "Event log files (.evtx) need the dfir extra: pip install 'actaeon[dfir]'. Other formats work now.")));
  main.append(section("New investigation", "plus", h("div", { "data-need": "op" }, title, desc,
    h("button", { onclick: busy(async () => { const c = await post("/api/dfir/cases", { title: title.value, description: desc.value }); location.hash = "inv/" + c.id; }) },
      icon("plus"), "Create"))));
}

// ---------------- overview ----------------
function workBanner(o) {
  const w = o.work;
  if (!w) return null;
  if (w.running) return h("p", { class: "warn" }, icon("progress-wrench"), ` ${w.what}... this page refreshes by itself.`);
  if (w.error) return h("p", { class: "bad" }, icon("alert-circle-outline"), ` ${w.what} failed: ${w.error}`);
  return null;
}

async function overview(cid) {
  const o = await api("/api/dfir/cases/" + cid);
  if (o.work && o.work.running) poll = setInterval(async () => {
    const x = await api("/api/dfir/cases/" + cid).catch(() => null);
    if (x && !(x.work && x.work.running)) route();
  }, 3000);
  const sp = o.span || {};
  const kpi = (n, label, href) => h(href ? "a" : "div", { class: "kpi-card", href }, h("b", {}, n ?? "-"), h("span", {}, label));
  main.append(sub(cid, ""), section(o.title, "folder-search-outline", o.description ? h("p", {}, o.description) : null,
    workBanner(o), h("div", { class: "kpi-row" }, kpi(o.events, "Events", `#inv/${cid}/timeline`), kpi(o.hosts.filter((x) => x.host).length, "Hosts"),
      kpi(o.detections.reduce((a, d) => a + d.n, 0), "Detections", `#inv/${cid}/timeline?detected=1`), kpi(o.sources.length, "Evidence files")),
    h("p", { class: "small muted" }, `From ${when(sp.first) || "-"} to ${when(sp.last) || "-"} (UTC).`,
      o.attack.length ? `  ATT&CK: ${o.attack.join(", ")}` : "")));

  const files = h("input", { type: "file", multiple: true, "aria-label": "Evidence files" });
  main.append(section("Evidence", "upload",
    h("p", { class: "muted small" }, "Windows event logs (.evtx), JSON or JSON lines (Velociraptor, Hayabusa, osquery, exported event logs), CSV (Plaso, Hayabusa, any with a time column), syslog and auth.log, .gz, and .zip collections. Each file's SHA-256 is recorded before it is read; the same file twice is skipped."),
    h("div", { class: "row", "data-need": "op" }, files, h("button", { disabled: !!(o.work && o.work.running), onclick: busy(async () => {
      if (!files.files.length) { toast("Choose one or more files"); return; }
      const fd = new FormData(); for (const f of files.files) fd.append("files", f);
      const r = await fetch(`/api/dfir/cases/${cid}/upload`, { method: "POST", body: fd });
      const j = await r.json().catch(() => ({}));
      if (!r.ok) { toast(j.error || `Upload failed (${r.status})`); return; }
      toast(`Importing ${j.files.length} file(s)`); route(); }) }, icon("upload"), "Upload and import")),
    o.sources.length ? h("table", {}, h("thead", {}, h("tr", {}, ["File", "Kind", "Events", "Unreadable", "SHA-256", "Status"].map((x) => h("th", {}, x)))),
      h("tbody", {}, capped(o.sources.map((s) => h("tr", {}, h("td", {}, s.name, h("div", { class: "muted small" }, (s.hosts || []).slice(0, 4).join(", "))),
        h("td", { class: "small" }, s.kind), h("td", { class: "num" }, String(s.events)),
        h("td", { class: "num", title: (s.error_samples || []).join("\n") }, String(s.errors)),
        h("td", { class: "small mono", title: s.sha256 }, short(s.sha256)),
        h("td", { class: "small " + (s.status === "failed" ? "bad" : "") }, s.status, s.note ? h("div", { class: "muted" }, s.note) : null))), 8, "files"))) : null));

  const an = o.analysis || {};
  const sig = an.sigma;
  main.append(section("Detections", "shield-search",
    h("div", { class: "row", "data-need": "op" }, h("button", { disabled: !o.events || !!(o.work && o.work.running), onclick: busy(async () => {
      await post(`/api/dfir/cases/${cid}/analyze`); toast("Analyzers started"); route(); }) }, icon("play"), o.analyzed ? "Run the analyzers again" : "Run the analyzers"),
      o.analyzed ? h("span", { class: "small muted" }, `last run ${when(o.analyzed)}`) : null),
    sig ? h("p", { class: "small muted" }, `${sig.rules} Sigma rules run (rule library, built-in checks and rule folders), ${sig.matched_rules} matched; ${sig.imported} detections came with the evidence; ${sig.skipped_count} rule(s) could not be evaluated.`) : null,
    o.detections.length ? h("table", {}, h("thead", {}, h("tr", {}, ["Level", "Rule", "Events", "Hosts", "First", "Last"].map((x) => h("th", {}, x)))),
      h("tbody", {}, capped(o.detections.map((d) => h("tr", { class: "click", onclick: () => { location.hash = `inv/${cid}/timeline?rule=${encodeURIComponent(d.rule_key)}`; } },
        h("td", {}, lvBadge(d.level)), h("td", {}, d.title, h("div", { class: "muted small" }, d.origin + (d.attack.length ? "  " + d.attack.join(", ") : ""))),
        h("td", { class: "num" }, String(d.n)), h("td", { class: "num" }, String(d.hosts)), h("td", { class: "small" }, when(d.first)), h("td", { class: "small" }, when(d.last)))), 25, "rules")))
      : h("p", { class: "muted" }, o.analyzed ? "No rule matched." : "Run the analyzers to tag events with Sigma rules.")));

  if (an.stacking) {
    const st = an.stacking;
    const stack = (label, rows) => rows && rows.length ? [h("h3", {}, label), h("table", {}, h("tbody", {}, rows.slice(0, 12).map((x) =>
      h("tr", {}, h("td", { class: "num" }, String(x.count)), h("td", { class: "small mono" }, x.value), h("td", {}, x.sample ? evLink(cid, x.sample) : null)))))] : null;
    main.append(section("Least frequent (stacking)", "format-list-numbered",
      h("p", { class: "muted small" }, "Rare values across the case are often where an intrusion stands out."),
      stack("Processes", st.processes), stack("Parent and child", st.parent_child), stack("Services installed", st.services),
      stack("Scheduled tasks", st.tasks), stack("Logon sources", st.logon_sources)));
  }
  if (an.logons && an.logons.length) {
    main.append(section("Logons", "login", h("table", {}, h("thead", {}, h("tr", {}, ["Account", "Source", "OK", "Failed", "Types", "First", "Last"].map((x) => h("th", {}, x)))),
      h("tbody", {}, capped(an.logons.slice(0, 200).map((x) => h("tr", {}, h("td", { class: "small" }, x.account), h("td", { class: "small" }, x.source || "-"),
        h("td", { class: "num" }, String(x.ok)), h("td", { class: "num " + (x.failed > 9 ? "warn" : "") }, String(x.failed)),
        h("td", { class: "small" }, Object.entries(x.types || {}).map(([k, v]) => `${k}:${v}`).join(" ")), h("td", { class: "small" }, when(x.first)), h("td", { class: "small" }, when(x.last)))), 15, "accounts")))));
  }
  main.append(section("Report and export", "export-variant", h("div", { class: "row" },
    h("a", { class: "button ghost", href: `/api/dfir/cases/${cid}/report.md`, download: "" }, icon("language-markdown-outline"), "Report (Markdown)"),
    h("a", { class: "button ghost", href: `/api/dfir/cases/${cid}/export.csv`, download: "" }, icon("file-delimited"), "Timeline (CSV)"),
    h("a", { class: "button ghost", href: `/api/dfir/cases/${cid}/export.csv?detected=1`, download: "" }, icon("file-delimited"), "Detections only (CSV)")),
    h("div", { class: "row", "data-need": "op" }, h("button", { class: "ghost", onclick: busy(async () => {
      if (!confirm("Delete this investigation and all its events?")) return;
      await post(`/api/dfir/cases/${cid}/delete`); location.hash = "dfir"; }) }, icon("delete"), "Delete investigation"))));
}

// ---------------- timeline ----------------
function detail(cid, e, onSave) {
  const tags = h("input", { class: "grow", value: (e.tags || []).join(", "), placeholder: "tags, comma separated", "aria-label": "Tags" });
  const comment = h("textarea", { rows: 2, placeholder: "comment", "aria-label": "Comment" }); comment.value = e.comment || "";
  const rows = Object.entries(e.data || {}).map(([k, v]) => h("tr", {}, h("td", { class: "small mono" }, k), h("td", { class: "small mono val" }, typeof v === "string" ? v : JSON.stringify(v))));
  return h("div", { class: "card" },
    h("div", { class: "row" }, h("b", {}, "E" + e.seq), h("span", { class: "small" }, when(e.ts)), h("span", { class: "small" }, e.host),
      (e.detections || []).flatMap((d) => [lvBadge(d.level), h("span", { class: "small" }, d.title)])),
    h("table", {}, h("tbody", {}, rows)),
    h("div", { "data-need": "op" }, h("div", { class: "row" }, tags), comment, h("button", { class: "ghost", onclick: busy(async () => {
      await post(`/api/dfir/cases/${cid}/events/${e.seq}`, { tags: tags.value.split(",").map((t) => t.trim()).filter(Boolean), comment: comment.value });
      toast("Saved"); if (onSave) onSave(); }) }, icon("content-save"), "Save tags and comment")));
}

async function timeline(cid) {
  const P = window.ROUTE_QUERY || new URLSearchParams();
  const o = await api("/api/dfir/cases/" + cid);
  const q = new URLSearchParams();
  for (const k of ["q", "host", "since", "until", "rule", "starred", "detected", "tag", "event_id", "order", "offset"]) if (P.get(k)) q.set(k, P.get(k));
  q.set("limit", "100");
  const res = await api(`/api/dfir/cases/${cid}/events?${q}`);
  const go = (changes) => { const n = new URLSearchParams(q); n.delete("limit"); n.delete("focus");
    for (const [k, v] of Object.entries(changes)) { if (v === "" || v === null || v === false) n.delete(k); else n.set(k, v); }
    location.hash = `inv/${cid}/timeline?${n}`; };
  const qi = h("input", { class: "grow", placeholder: "words, or field:value (e.g. Image:powershell)", value: P.get("q") || "", "aria-label": "Search" });
  const host = h("select", { "aria-label": "Host" }, h("option", { value: "" }, "all hosts"), o.hosts.filter((x) => x.host).map((x) => h("option", { value: x.host, selected: x.host === P.get("host") }, `${x.host} (${x.n})`)));
  const since = h("input", { placeholder: "from 2026-11-01T00:00", value: P.get("since") || "", class: "w12", "aria-label": "From (UTC)" });
  const until = h("input", { placeholder: "to", value: P.get("until") || "", class: "w12", "aria-label": "Until (UTC)" });
  const det = h("input", { type: "checkbox", checked: P.get("detected") === "1", "aria-label": "Only detections" });
  const star = h("input", { type: "checkbox", checked: P.get("starred") === "1", "aria-label": "Only starred" });
  const apply = () => go({ q: qi.value, host: host.value, since: since.value, until: until.value, detected: det.checked ? "1" : "", starred: star.checked ? "1" : "", offset: "" });
  qi.addEventListener("keydown", (e) => { if (e.key === "Enter") apply(); });
  const focusBox = h("div");
  if (P.get("focus")) api(`/api/dfir/cases/${cid}/events/${P.get("focus")}`).then((e) => fill(focusBox, h("h3", {}, "Cited event"), detail(cid, e))).catch(() => {});
  const rule = P.get("rule");
  main.append(sub(cid, "timeline"), section("Timeline", "timeline-clock-outline",
    h("div", { class: "row" }, qi, host), h("div", { class: "row" }, since, until, h("label", { class: "small" }, det, " detections"),
      h("label", { class: "small" }, star, " starred"), h("button", { onclick: apply }, icon("magnify"), "Search"),
      h("a", { class: "button ghost", href: `/api/dfir/cases/${cid}/export.csv?${q}`, download: "" }, icon("file-delimited"), "CSV")),
    rule ? h("p", { class: "small" }, "Rule: ", h("b", {}, (o.detections.find((d) => d.rule_key === rule) || {}).title || rule), "  ",
      h("a", { href: "#", onclick: (e) => { e.preventDefault(); go({ rule: "" }); } }, "clear")) : null,
    focusBox));
  const off = Number(P.get("offset") || 0);
  const table = h("table", { class: "timeline" }, h("thead", {}, h("tr", {}, ["", "Time (UTC)", "Host", "Log / id", "What"].map((x) => h("th", {}, x)))),
    h("tbody", {}, res.events.flatMap((e) => {
      const box = h("td", { colspan: 5 }); const extra = h("tr", { class: "hidden" }, box);
      const starBtn = h("button", { class: "ghost", "data-need": "op", "aria-label": e.star ? "Remove star" : "Star this event", title: "Star", onclick: async (ev) => {
        ev.stopPropagation(); e.star = !e.star; await post(`/api/dfir/cases/${cid}/events/${e.seq}`, { star: e.star }); fill(starBtn, icon(e.star ? "star" : "star-outline")); } },
        icon(e.star ? "star" : "star-outline"));
      return [h("tr", { class: "click" + (e.level >= 4 ? " bad-border" : ""), onclick: () => {
        if (extra.classList.toggle("hidden")) return; fill(box, detail(cid, e)); } },
        h("td", {}, starBtn), h("td", { class: "small mono" }, when(e.ts) + (e.ts ? e.ts.slice(16, 23) : "")), h("td", { class: "small" }, e.host),
        h("td", { class: "small" }, `${e.channel || ""}${e.event_id ? " / " + e.event_id : ""}`),
        h("td", {}, h("span", { class: "small" }, e.summary), (e.detections || []).map((d) => h("span", { class: "small", title: d.title }, " ", lvBadge(d.level), " ", d.title)),
          e.comment ? h("div", { class: "small muted" }, icon("comment"), " ", e.comment) : null, (e.tags || []).map((t) => h("span", { class: "badge" }, t)))), extra];
    })));
  main.append(section(`${res.total} event(s)` + (res.total > 100 ? `, showing ${off + 1}-${Math.min(off + 100, res.total)}` : ""), "format-list-bulleted",
    res.events.length ? table : h("p", { class: "muted" }, "No events match."),
    h("div", { class: "row" }, off > 0 ? h("button", { class: "ghost", onclick: () => go({ offset: String(Math.max(0, off - 100)) }) }, "Earlier") : null,
      off + 100 < res.total ? h("button", { class: "ghost", onclick: () => go({ offset: String(off + 100) }) }, "Later") : null)));
}

// ---------------- story ----------------
async function story(cid) {
  const [o, s] = await Promise.all([api("/api/dfir/cases/" + cid), api(`/api/dfir/cases/${cid}/story`)]);
  const kind = h("select", { "aria-label": "Note kind" }, ["hypothesis", "question", "finding", "note"].map((k) => h("option", { value: k }, k)));
  const text = h("input", { class: "grow", placeholder: "e.g. The attacker came in through RDP on WEB01", "aria-label": "Note" });
  const evs = h("input", { class: "w8", placeholder: "E12, E40", "aria-label": "Events (optional)" });
  main.append(sub(cid, "story"), section("Hypotheses, questions and findings", "lightbulb-on-outline",
    o.notes.length ? h("table", {}, h("tbody", {}, o.notes.map((n) => h("tr", {}, h("td", { class: "small" }, n.kind), h("td", {}, n.text, h("div", {}, (n.events || []).map((x) => evLink(cid, x)))),
      h("td", { class: "small muted" }, n.author || ""), h("td", {}, h("select", { "data-need": "op", "aria-label": "Status", onchange: async (e) => { await post(`/api/dfir/cases/${cid}/notes/${n.id}/status`, { status: e.target.value }); } },
        ["open", "confirmed", "refuted", "answered", "closed"].map((x) => h("option", { value: x, selected: x === n.status }, x)))))))) : h("p", { class: "muted" }, "Write down what you think happened and what you still need to know. The model sees these."),
    h("div", { class: "row", "data-need": "op" }, kind, text, evs, h("button", { onclick: busy(async () => {
      await post(`/api/dfir/cases/${cid}/notes`, { kind: kind.value, text: text.value, events: (evs.value.match(/\d+/g) || []).map(Number) }); route(); }) }, icon("plus"), "Add"))));

  const latest = (s.stories || [])[0];
  const b = latest && latest.body;
  main.append(section("What happened", "robot-outline",
    h("p", { class: "muted small" }, "The model reads the starred events, events with detections, the analyzer results and your notes, and must cite event ids. Citations are checked: a part with no valid citation is marked."),
    h("div", { class: "row", "data-need": "op" }, h("button", { onclick: busy(async () => { toast("Writing the story, this can take a few minutes...", 120000);
      await post(`/api/dfir/cases/${cid}/story`); toast("Done"); route(); }) }, icon("robot-outline"), b ? "Write it again" : "Write the story")),
    b ? [h("p", { class: "small muted" }, `Written ${when(latest.ts)} by ${latest.model}, from ${b.events_given} events` +
        (b.events_left_out ? ` (${b.events_left_out} more left out to fit the model's context)` : "") + `. Confidence: ${b.confidence || "-"}.` +
        (b.citations_removed ? ` ${b.citations_removed} citation(s) to events it was not shown were removed.` : "")),
      h("p", {}, b.summary),
      h("ol", {}, (b.phases || []).map((p) => h("li", {}, h("b", {}, p.phase), p.when ? h("span", { class: "small muted" }, "  " + p.when) : null, h("div", {}, p.what),
        p.uncited ? h("div", { class: "warn small" }, icon("alert-circle-outline"), " Not supported by a cited event.") : h("div", {}, p.events.map((x) => evLink(cid, x)))))),
      ...((b.open_questions || []).length ? [h("h3", {}, "Open questions"), h("ul", {}, b.open_questions.map((x) => h("li", {}, x)))] : []),
      ...((b.next_steps || []).length ? [h("h3", {}, "Next steps"), h("ul", {}, b.next_steps.map((x) => h("li", {}, x)))] : [])] : null));

  const qn = h("input", { class: "grow", placeholder: "e.g. Which account ran mimikatz, and from where?", "aria-label": "Question" });
  const out = h("div");
  const ask = busy(async () => { if (!qn.value.trim()) return; fill(out, h("p", { class: "muted small" }, "Thinking...")); const r = await post(`/api/dfir/cases/${cid}/ask`, { question: qn.value }).catch((e) => { fill(out); throw e; });
    fill(out, h("p", {}, r.answer), h("div", {}, r.events.map((x) => evLink(cid, x))), r.searches.length ? h("p", { class: "small muted" }, "Searched: " + r.searches.map((x) => `"${x.q}" (${x.found})`).join(", ")) : null); });
  qn.addEventListener("keydown", (e) => { if (e.key === "Enter") ask(e); });
  main.append(section("Ask about this case", "chat-question-outline", h("div", { class: "row", "data-need": "op" }, qn, h("button", { onclick: ask }, icon("send"), "Ask")), out,
    (s.answers || []).length ? [h("h3", {}, "Earlier questions"), h("ul", {}, s.answers.map((a) => h("li", {}, h("b", {}, a.body.question), h("div", { class: "small" }, a.body.answer), h("div", {}, (a.body.events || []).map((x) => evLink(cid, x))))))] : null));
}

document.addEventListener("DOMContentLoaded", () => api("/api/dfir/status").then((s) => {
  const a = document.querySelector('#nav a[data-tab="dfir"]');
  if (a) a.classList.toggle("hidden", !s.enabled);
}).catch(() => {}));

const inv = async () => {
  const parts = location.hash.slice(1).split("?")[0].split("/");
  const st = await api("/api/dfir/status");
  if (!st.enabled) { main.append(off()); return; }
  return ({ timeline, story }[parts[2]] || overview)(parts[1]);
};
return { dfir: list, inv };
})();
