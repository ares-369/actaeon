// Detection rule library pages (rules, rule detail, rule coverage). Loaded before app.js, which owns the router
// and the shared helpers (h, fill, icon, section, api, post, toast, when, ago, main, ME).
// Rule text, test events and notes can come from logs or a model: they are only ever set as text.
"use strict";
window.RULES_ON = false;
window.RULES_PAGES = (() => {
const STATUS_CLS = { draft: "badge-neutral", testing: "badge-blue", ready: "badge-green", retired: "muted" };
const STATUS_ICON = { draft: "file-code-outline", testing: "flask-outline", ready: "check-decagram-outline", retired: "archive" };
const stBadge = (s) => h("span", { class: "badge " + (STATUS_CLS[s] || "") }, icon(STATUS_ICON[s] || "label"), s);
const LINT_ICON = { error: "close-circle-outline", warning: "alert-circle-outline" };
const SUB = [["rules", "Rules", "shield-check-outline"], ["rulecov", "Coverage", "grid"]];
const subnav = (on) => h("div", { class: "row subnav" }, SUB.map(([k, label, ic]) =>
  h("a", { class: "button ghost seg" + (k === on ? " on" : ""), href: "#" + k }, icon(ic), label)));
const runText = (r) => !r ? "not run" : r.unsupported ? "cannot test locally" : r.total ? `${r.passed}/${r.total} pass` : "no tests";
const runCls = (r) => !r ? "muted" : r.unsupported ? "warn" : r.ok ? "ok" : r.total ? "bad" : "muted";
const off = () => section("Rule library is off", "shield-check-outline",
  h("p", {}, "Set rules.enabled: true in config.yaml to keep detection rules here, test them against sample events and see ATT&CK coverage."),
  h("p", { class: "muted small" }, "See docs/rules.md."));
const busy = (fn) => async (e) => { const b = e.currentTarget; b.disabled = true; try { await fn(e); } finally { b.disabled = false; } };

// ---------------- list ----------------
async function list() {
  const st = await api("/api/rules/status");
  if (!st.enabled) { main.append(off()); return; }
  const f = (window.ROUTE_QUERY && window.ROUTE_QUERY.get("status")) || "";
  const q = (window.ROUTE_QUERY && window.ROUTE_QUERY.get("q")) || "";
  const rows = await api("/api/rules?" + new URLSearchParams({ status: f, q }));
  const c = st.counts || {};
  const kpi = (n, label, href) => h("a", { class: "kpi-card", href }, h("b", {}, n || 0), h("span", {}, label));
  main.append(subnav("rules"), h("div", { class: "kpi-row" }, kpi(c.ready, "Ready", "#rules?status=ready"),
    kpi(c.testing, "Testing", "#rules?status=testing"), kpi(c.draft, "Draft", "#rules?status=draft"),
    kpi(c.retired, "Retired", "#rules?status=retired")));
  const search = h("input", { class: "grow", placeholder: "search title or id", value: q, "aria-label": "Search rules" });
  search.addEventListener("keydown", (e) => { if (e.key === "Enter") location.hash = "rules?" + new URLSearchParams({ status: f, q: search.value }); });
  const filters = h("div", { class: "row" }, ["", "draft", "testing", "ready", "retired"].map((s) =>
    h("a", { class: "button ghost seg" + (s === f ? " on" : ""), href: "#rules" + (s ? "?status=" + s : "") }, s || "all")), search);
  const table = rows.length ? h("table", {}, h("thead", {}, h("tr", {}, ["Status", "Rule", "ATT&CK", "Ver.", "Tests", "Updated"].map((x) => h("th", {}, x)))),
    h("tbody", {}, rows.map((r) => h("tr", { class: "click", onclick: () => { location.hash = "rule/" + r.id; } },
      h("td", {}, stBadge(r.status)), h("td", {}, h("a", { href: "#rule/" + r.id }, r.title || r.id), r.level ? h("span", { class: "muted small" }, "  " + r.level) : null),
      h("td", { class: "small" }, (r.attack || []).join(", ")), h("td", { class: "num" }, String(r.version)),
      h("td", { class: "small " + runCls(r.last_run) }, runText(r.last_run)), h("td", { class: "small" }, ago(r.updated))))))
    : h("p", { class: "muted" }, f || q ? "No rules match." : "No rules yet. Add one below, import Sigma files, or draft one from a coverage gap or a hunt.");
  main.append(section("Rules", "shield-check-outline", filters, table,
    h("div", { class: "row" }, h("a", { class: "button ghost", href: "/api/rules/export.zip?status=ready", download: "actaeon-rules.zip" },
      icon("export-variant"), "Export ready rules (zip)"), h("span", { class: "muted small" }, "Actaeon never deploys rules; the zip is for your own review and deployment."))));
  const text = h("textarea", { class: "mono", rows: 12, placeholder: "Paste one Sigma rule (new rule), or several documents separated by --- (import)", "aria-label": "Sigma YAML" });
  main.append(section("Add or import", "file-import", h("div", { "data-need": "op" }, text, h("div", { class: "row" },
    h("button", { onclick: busy(async () => { const r = await post("/api/rules", { sigma: text.value }); location.hash = "rule/" + r.id; }) }, icon("plus"), "Add as a new rule"),
    h("button", { class: "ghost", onclick: busy(async () => {
      const r = await post("/api/rules/import", { text: text.value });
      toast(`created ${r.created.length}, updated ${r.updated.length}, unchanged ${r.unchanged.length}, errors ${r.errors.length}`, 6000);
      if (r.errors.length) main.append(h("ul", {}, r.errors.map((x) => h("li", { class: "warn small" }, x)))); else route();
    }) }, icon("file-import"), "Import (several rules)")))));
}

// ---------------- one rule ----------------
async function detail(id) {
  const st = await api("/api/rules/status");
  if (!st.enabled) { main.append(off()); return; }
  const r = await api("/api/rules/" + encodeURIComponent(id));
  const act = (action, label, ic, cls) => h("button", { class: cls || "ghost", "data-need": "op", onclick: busy(async () => {
    await post(`/api/rules/${r.id}/status`, { action }); route(); }) }, icon(ic), label);
  const actions = {
    draft: [act("submit", "Submit for testing", "flask-outline", ""), act("retire", "Retire", "archive")],
    testing: [act("approve", "Mark ready", "check-decagram-outline", ""), act("back", "Back to draft", "restore"), act("retire", "Retire", "archive")],
    ready: [act("back", "Back to draft", "restore"), act("retire", "Retire", "archive")],
    retired: [act("reopen", "Reopen as draft", "restore")],
  }[r.status] || [];
  if (r.status === "draft" || r.status === "retired") actions.push(h("button", { class: "ghost", "data-need": "op", onclick: busy(async () => {
    if (!confirm("Delete this rule, its versions and its tests?")) return;
    await post(`/api/rules/${r.id}/delete`); location.hash = "rules"; }) }, icon("delete"), "Delete"));
  const src = r.source || {};
  main.append(subnav("rules"), section(r.title || r.id, "shield-check-outline",
    h("div", { class: "row" }, stBadge(r.status), h("span", { class: "small" }, `version ${r.version}`),
      h("span", { class: "small muted" }, (r.attack || []).join(", ")),
      src.kind === "hunt" ? h("a", { class: "small", href: "#hunt/" + src.ref }, "from hunt " + src.ref) :
        src.kind ? h("span", { class: "small muted" }, "source: " + src.kind + (src.ref ? " " + src.ref : "") + (src.model ? " (model draft)" : "")) : null,
      r.approved_by ? h("span", { class: "small ok" }, `approved by ${r.approved_by} ${when(r.approved_at)}`) : null),
    r.notes ? h("p", { class: "small" }, r.notes) : null,
    h("div", { class: "row" }, actions),
    r.status === "testing" && r.ready_problems.length ? [h("h3", {}, "Before it can be marked ready"),
      h("ul", {}, r.ready_problems.map((p) => h("li", { class: "small warn" }, p)))] : null,
    (r.lint || []).length ? [h("h3", {}, "Checks"), h("ul", {}, r.lint.map((x) => h("li", { class: "small " + (x.level === "error" ? "bad" : "warn") },
      icon(LINT_ICON[x.level] || "alert-circle-outline"), " ", x.text)))] : h("p", { class: "small ok" }, icon("check-circle-outline"), " No problems found by the checks.")));

  const editor = h("textarea", { class: "mono", rows: 22, "aria-label": "Sigma rule" });
  editor.value = r.sigma;
  const note = h("input", { class: "grow", placeholder: "what changed (optional)", "aria-label": "Change note" });
  const conv = h("div");
  main.append(section("Sigma rule", "file-code-outline", editor, h("div", { class: "row", "data-need": "op" },
    note, h("button", { disabled: r.status === "retired", onclick: busy(async () => {
      await post("/api/rules/" + r.id, { sigma: editor.value, note: note.value }); toast("Saved as a new version"); route(); }) }, icon("content-save"), "Save new version"),
    h("button", { class: "ghost", onclick: busy(async (e) => {
      fill(conv, h("p", { class: "muted small" }, "Converting" + (e.shiftKey ? "" : " and counting matches over 14 days") + "..."));
      const res = await post(`/api/rules/${r.id}/convert`, { backtest: true, days: 14 }).catch((err) => { fill(conv); throw err; });
      fill(conv, res.converted.map((c) => h("div", {}, h("div", { class: "muted small" }, `${c.connector} (${c.backend})` +
        (c.backtest ? (c.backtest.error ? `  backtest: ${c.backtest.error}` : `  ${c.backtest.matches ?? "?"} match(es) in ${c.backtest.days} days`) : "")),
        c.error ? h("p", { class: "warn small" }, c.error) : (c.queries || []).map((q) => h("pre", {}, typeof q === "string" ? q : JSON.stringify(q, null, 1))))));
    }) }, icon("compare-horizontal"), "Convert and count matches")), conv));

  const results = {};
  ((r.last_run_full || {}).results || []).forEach((x) => { results[x.test_id] = x; });
  const stale = r.last_run_full && r.last_run_full.version !== r.version;
  const lr = r.last_run_full;
  const name = h("input", { placeholder: "name", "aria-label": "Test name" });
  const expect = h("select", { "aria-label": "Expected result" }, h("option", { value: "match" }, "must match"), h("option", { value: "no_match" }, "must not match"));
  const origin = h("select", { "aria-label": "Where the event comes from" }, h("option", { value: "real" }, "real event from logs"), h("option", { value: "synthetic" }, "written by hand or a model"));
  const ev = h("textarea", { class: "mono", rows: 8, placeholder: '{"Image": "C:\\\\Windows\\\\System32\\\\cmd.exe", "CommandLine": "..."}  (one event, or a JSON list of events)', "aria-label": "Event JSON" });
  main.append(section("Tests", "flask-outline",
    h("p", { class: "muted small" }, "Each test is an event the rule must or must not match, checked locally (no log platform needed). Only real events count towards ready."),
    lr ? h("p", { class: "small " + (stale ? "warn" : runCls(lr)) }, `Last run ${when(lr.ts)}: ${runText(lr)}` + (stale ? " (for an older version)" : ""),
      lr.unsupported ? " - " + lr.unsupported : "") : null,
    r.tests.length ? h("table", {}, h("thead", {}, h("tr", {}, ["Result", "Test", "Expect", "Origin", "Matched on", ""].map((x) => h("th", {}, x)))),
      h("tbody", {}, r.tests.flatMap((t) => { const x = results[t.id]; const evPre = h("pre", { class: "hidden" }, JSON.stringify(t.event, null, 1));
        return [h("tr", {},
          h("td", { class: x ? (x.ok ? "ok" : "bad") : "muted" }, x ? icon(x.ok ? "check-circle-outline" : "close-circle-outline") : "-", x ? (x.ok ? " pass" : " fail") : " not run"),
          h("td", {}, h("a", { href: "#", onclick: (e) => { e.preventDefault(); evPre.classList.toggle("hidden"); } }, t.name), h("div", { class: "muted small" }, t.source || "")),
          h("td", { class: "small" }, t.expect === "match" ? "must match" : "must not match"),
          h("td", { class: "small" }, t.origin), h("td", { class: "small" }, x && x.fields ? Object.entries(x.fields).map(([k, v]) => `${k} = ${v}`).join(", ") : "", x && x.error ? h("div", { class: "warn" }, x.error) : null),
          h("td", {}, h("button", { class: "ghost", "data-need": "op", "aria-label": "Delete test", onclick: busy(async () => { await post(`/api/rules/${r.id}/tests/${t.id}/delete`); route(); }) }, icon("delete")))),
        h("tr", {}, h("td", { colspan: 6 }, evPre))]; }))) : h("p", { class: "muted" }, "No tests yet."),
    h("div", { class: "row", "data-need": "op" }, h("button", { onclick: busy(async () => { await post(`/api/rules/${r.id}/run`); route(); }) }, icon("play"), "Run tests")),
    h("h3", {}, "Add a test"), h("div", { "data-need": "op" }, h("div", { class: "row" }, name, expect, origin), ev,
      h("button", { class: "ghost", onclick: busy(async () => {
        let event; try { event = JSON.parse(ev.value); } catch (err) { toast("The event is not valid JSON"); return; }
        await post(`/api/rules/${r.id}/tests`, { name: name.value, expect: expect.value, origin: origin.value, event }); route(); }) }, icon("plus"), "Add test"))));

  main.append(section("History", "history", h("table", {}, h("tbody", {}, r.versions.flatMap((v) => {
    const pre = h("pre", { class: "hidden" }, v.sigma);
    return [h("tr", {}, h("td", {}, h("a", { href: "#", onclick: (e) => { e.preventDefault(); pre.classList.toggle("hidden"); } }, "v" + v.version)),
      h("td", { class: "small" }, when(v.ts)), h("td", { class: "small" }, v.author || ""), h("td", { class: "small" }, v.note || "")),
      h("tr", {}, h("td", { colspan: 4 }, pre))];
  })))));
}

// ---------------- coverage ----------------
async function coverage() {
  const st = await api("/api/rules/status");
  if (!st.enabled) { main.append(off()); return; }
  const cov = await api("/api/rules/coverage");
  const ctx = h("textarea", { rows: 4, placeholder: "Optional: notes or an advisory for the model (what to look for, your tools, known benign activity)", "aria-label": "Context for the model" });
  const tech = h("input", { placeholder: "T1059.001", class: "w8", "aria-label": "Technique id" });
  const draft = async (t) => { toast("Drafting with the model, this can take a minute...", 60000);
    const r = await post("/api/rules/draft", { technique: t, context: ctx.value }); toast("Draft ready"); location.hash = "rule/" + r.id; };
  main.append(subnav("rulecov"), h("div", { class: "kpi-row" },
    h("div", { class: "kpi-card" }, h("b", {}, cov.ready), h("span", {}, "Techniques with a ready rule")),
    h("div", { class: "kpi-card warn-card" }, h("b", {}, cov.gaps), h("span", {}, "Gaps"))));
  main.append(section("Draft a rule with the model", "robot-outline", h("div", { "data-need": "op" },
    h("p", { class: "muted small" }, "The model sees the technique, your environment profile, field names from your data and events from hunts that found it. Its example events are marked synthetic and never count as real tests."),
    ctx, h("div", { class: "row" }, tech, h("button", { onclick: busy(() => draft(tech.value.trim())) }, icon("file-code-outline"), "Draft")))));
  const rows = cov.techniques;
  main.append(section("ATT&CK coverage by rules", "grid", h("p", { class: "muted small" }, cov.note),
    rows.length ? h("table", {}, h("thead", {}, h("tr", {}, ["Technique", "Rules", "Why it matters", ""].map((x) => h("th", {}, x)))),
      h("tbody", {}, rows.map((x) => h("tr", {},
        h("td", {}, h("b", {}, x.technique), " ", x.name, h("div", { class: "muted small" }, (x.tactics || []).join(", "))),
        h("td", { class: "small" }, x.ready ? h("span", { class: "ok" }, `${x.ready} ready `) : h("span", { class: x.gap ? "bad" : "muted" }, "none ready "),
          x.testing ? `${x.testing} testing ` : "", x.draft ? `${x.draft} draft` : "",
          h("div", {}, (x.rules || []).slice(0, 4).map((r) => h("a", { class: "small", href: "#rule/" + r.id }, r.title + "  ")))),
        h("td", { class: "small" }, (x.reasons || []).join("; ") || h("span", { class: "muted" }, "-")),
        h("td", {}, x.gap ? h("button", { class: "ghost", "data-need": "op", onclick: busy(() => draft(x.technique)) }, icon("robot-outline"), "Draft") : null)))))
      : h("p", { class: "muted" }, "Nothing yet. Rules tagged with techniques, hunts and true-positive cases fill this table; rules.priorities adds techniques you want covered.")));
}

// app.js (with api()) loads after this file: ask once the page is ready, then show the nav entry if the library is on.
document.addEventListener("DOMContentLoaded", () => api("/api/rules/status").then((s) => {
  window.RULES_ON = !!s.enabled;
  const a = document.querySelector('#nav a[data-tab="rules"]');
  if (a) a.classList.toggle("hidden", !s.enabled);
}).catch(() => {}));

const page = (fn) => () => fn(location.hash.slice(1).split("?")[0].split("/")[1]);
return { rules: page(list), rule: page(detail), rulecov: page(coverage) };
})();
