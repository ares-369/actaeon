// Actaeon UI. All data from the server (and above all tool output) is untrusted:
// it is only ever set with textContent, never parsed as HTML.
"use strict";
const $ = (s, el = document) => el.querySelector(s);
const main = $("#main");

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
const when = (s) => (s || "").replace("T", " ").slice(0, 16);

let poll = null;
function route() {
  clearInterval(poll); poll = null;
  const [tab, arg] = (location.hash.slice(1) || "hunts").split("/");
  document.querySelectorAll("#nav a").forEach((a) => a.classList.toggle("on", a.dataset.tab === (tab === "hunt" ? "hunts" : tab)));
  main.replaceChildren();
  const pages = { hunts, hunt: () => huntDetail(arg), library, intel, coverage, connectors, settings };
  (pages[tab] || hunts)().catch((e) => main.append(h("p", { class: "bad" }, String(e.message || e))));
}
window.addEventListener("hashchange", route);

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
        e.target.disabled = true; sug.replaceChildren(h("p", { class: "muted" }, "Asking the planner..."));
        try {
          const r = await api("/api/autopilot", { dry_run: true });
          sug.replaceChildren(
            r.note ? h("p", { class: "warn" }, r.note) : null,
            ...r.hypotheses.map((x) => h("div", { class: "row" }, h("span", { class: "grow" }, x.hypothesis,
              h("div", { class: "muted small" }, `${x.source}  ${x.attack.join(", ")}  ${x.why}`)),
              h("button", { onclick: async () => { const s = await api("/api/hunts", { hypothesis: x.hypothesis, context: "Proposed by autopilot: " + x.why }); location.hash = "#hunt/" + s.hunt_id; } }, icon("play"), "Hunt"))),
            ...(r.rejected || []).map((x) => h("p", { class: "muted small" }, `skipped: ${x.hypothesis} (${x.rejected})`)));
        } finally { e.target.disabled = false; }
      } }, icon("lightbulb-on-outline"), "Suggest hypotheses"),
      h("button", { class: "ghost", onclick: async () => { const r = await api("/api/autopilot", { dry_run: false }); toast("Autopilot queued (job " + r.job_id + "); its hunts appear below."); } }, icon("play-circle-outline"), "Run autopilot now"),
      h("button", { class: "ghost", onclick: async () => { const r = await api("/api/intel/web/pull"); toast("Web intel pull queued (job " + r.job_id + ")."); } }, icon("web"), "Pull web intel")),
    sug));
  const list = h("tbody");
  main.append(section("Recent hunts", "history",
    h("table", {}, h("thead", {}, h("tr", {}, h("th", {}, "Started"), h("th", {}, "Status"), h("th", {}, "Outcome"),
      h("th", {}, "Hypothesis"), h("th", {}, "Origin"))), list)));
  const load = async () => {
    const rows = await api("/api/hunts?limit=100");
    list.replaceChildren(...rows.map((r) => h("tr", { class: "click", onclick: () => (location.hash = "#hunt/" + r.id) },
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
  const draw = async () => {
    const hu = await api("/api/hunts/" + encodeURIComponent(id));
    box.replaceChildren(renderHunt(hu));
    if (!["queued", "running"].includes(hu.status)) { clearInterval(poll); poll = null; }
  };
  await draw();
  poll = setInterval(draw, 2000);
}

function renderHunt(hu) {
  const v = hu.verdict || {};
  const running = ["queued", "running"].includes(hu.status);
  const act = (a) => async () => { await api(`/api/hunts/${hu.id}/${a}`); toast(a + " requested"); };
  const head = section(hu.hypothesis, "target",
    h("div", { class: "row" }, badge(hu.status), badge(hu.outcome), h("span", { class: "muted small" },
      `started ${when(hu.created)}  origin ${hu.origin}  ${hu.actor ? "by " + hu.actor : ""}`)),
    h("div", { class: "row" },
      running && h("button", { class: "ghost", onclick: act("pause") }, icon("pause"), "Pause"),
      running && h("button", { class: "ghost", onclick: act("resume") }, icon("play"), "Resume"),
      running && h("button", { class: "danger", onclick: act("stop") }, icon("stop"), "Stop"),
      h("a", { href: `/api/hunts/${hu.id}/report.md` }, h("button", { class: "ghost" }, icon("file-document"), "Report")),
      h("a", { href: `/api/hunts/${hu.id}/export.json` }, h("button", { class: "ghost" }, icon("code-json"), "JSON")),
      h("a", { href: `/api/hunts/${hu.id}/export.csv` }, h("button", { class: "ghost" }, icon("file-delimited"), "CSV"))),
    hu.error && h("p", { class: "warn" }, hu.error));
  const out = [head];
  if (hu.verdict) {
    const vs = section("Verdict", "gavel",
      h("div", { class: "row" }, badge(v.outcome), h("span", {}, `confidence ${v.confidence}`),
        v.needs_review && h("span", { class: "badge b-logs_missing" }, icon("eye"), "needs review")),
      h("p", {}, v.summary || ""),
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
    if (!running) out.push(saveBox(hu), narrativeBox(hu));
  }
  if (hu.plan) {
    out.push(section("Plan", "map-outline", h("p", {}, hu.plan.summary || ""),
      h("ul", {}, (hu.plan.steps || []).map((s) => h("li", {}, h("span", { class: "muted" }, `[${s.role}] `), s.goal))),
      (hu.plan.missing_roles || []).length ? h("p", { class: "warn" }, "No connector for: " + hu.plan.missing_roles.join(", ")) : null));
  }
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
      try { const r = await api(`/api/hunts/${hu.id}/narrative`); p.textContent = r.narrative; p.classList.remove("hidden"); }
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
        h("button", { class: "ghost", onclick: async () => { await api(`/api/library/${s.id}/run`); toast("Replay queued"); } }, icon("replay")),
        h("button", { class: "danger", onclick: async () => { if (confirm("Delete this saved hunt?")) { await api(`/api/library/${s.id}/delete`); route(); } } }, icon("delete")))));
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
  const advs = await api("/api/intel/advisories");
  main.append(section("Advisories", "file-document-outline", h("table", {}, h("tbody", {}, advs.length ? advs.map((a) => h("tr", {},
    h("td", {}, a.title, h("div", { class: "muted small" }, `${when(a.added)}  ${a.indicator_count} indicators  ${a.techniques.join(", ")}`)),
    h("td", {}, h("button", { onclick: async () => { const r = await api(`/api/hunts/advisory/${a.id}`); location.hash = "#hunt/" + r.hunt_id; } }, icon("play"), "Hunt this")))) :
    h("tr", {}, h("td", { class: "muted" }, "No advisories yet."))))));
  const inds = await api("/api/intel/indicators?limit=100");
  main.append(section("Indicators", "format-list-bulleted",
    h("div", { class: "row" }, h("button", { class: "ghost", onclick: async () => { const r = await api("/api/intel/sweep"); toast("Sweep queued (job " + r.job_id + "); it appears under Hunts."); } }, icon("radar"), "Sweep logs for new or changed indicators")),
    h("table", {}, h("thead", {}, h("tr", {}, ["Type", "Value", "Conf", "Seen", "Last seen", "Source", ""].map((x) => h("th", {}, x)))),
      h("tbody", {}, inds.map((i) => h("tr", {}, h("td", {}, i.type), h("td", {}, i.value), h("td", {}, i.confidence),
        h("td", {}, i.seen_count), h("td", { class: "small" }, when(i.last_seen)), h("td", { class: "small muted" }, i.source),
        h("td", {}, h("button", { class: "ghost", title: "Deactivate", onclick: async () => { await api(`/api/intel/indicators/${i.id}/deactivate`); route(); } }, icon("cancel")))))))));
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
          h("button", { class: "ghost", onclick: async () => { res.textContent = "..."; const r = await api(`/api/connectors/${c.name}/test`); res.textContent = r.ok ? `${r.allowed}/${r.tools} tools allowed, ${r.ms} ms` : r.error; res.className = r.ok ? "ok small" : "bad small"; } }, icon("lan-check"), "Test"),
          h("button", { class: "ghost", onclick: async () => { const t = await api(`/api/connectors/${c.name}/tools`); tools.replaceChildren(section(c.name + " tools", "tools",
            h("table", {}, h("tbody", {}, t.map((x) => h("tr", {}, h("td", {}, x.name), h("td", {}, x.allowed ? h("span", { class: "ok" }, "allowed") : h("span", { class: "bad" }, "blocked")),
              h("td", { class: "small muted" }, x.reason), h("td", { class: "small" }, x.description.slice(0, 160)))))))); } }, icon("tools"), "Tools"), res)));
    })))));
  main.append(tools);
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
  const collect = () => Object.fromEntries([...document.querySelectorAll("[data-role]")].map((e) => [e.dataset.role, { provider: e.value, model: $(`[data-model="${e.dataset.role}"]`).value }]));
  main.append(section("Models", "brain", h("p", { class: "muted small" }, "One provider and model per role. Keys stay in .env. Admins only."), rows,
    h("div", { class: "row" }, h("button", { onclick: async () => {
      const p = await api("/api/settings/llm", { roles: collect(), preview: true });
      if (!p.changed) return toast("No changes.");
      diff.textContent = p.diff; diff.classList.remove("hidden");
      if (!confirm("Apply this change to config.yaml?")) return;
      await api("/api/settings/llm", { roles: collect() }); toast("Saved."); diff.classList.add("hidden");
    } }, icon("content-save"), "Save")), diff));
  const note = h("input", { class: "grow", placeholder: "Note, for example: the backup agent uploads to cloud storage from backup01 nightly" });
  const ntags = h("input", { placeholder: "tags" });
  const notes = await api("/api/memory/notes");
  main.append(section("Memory notes", "note-text-outline",
    h("p", { class: "muted small" }, "Notes are added to the context of related hunts. Only people write them."),
    h("div", { class: "row" }, note, ntags, h("button", { onclick: async () => { await api("/api/memory/notes", { text: note.value, tags: ntags.value.split(",").map((x) => x.trim()).filter(Boolean) }); route(); } }, icon("plus"), "Add")),
    h("table", {}, h("tbody", {}, notes.map((n) => h("tr", {}, h("td", { class: n.active ? "" : "muted" }, n.text), h("td", { class: "small muted" }, n.tags.join(", ")),
      h("td", {}, n.active && h("button", { class: "ghost", onclick: async () => { await api(`/api/memory/notes/${n.id}/retire`); route(); } }, icon("archive")))))))));
  const audit = h("div", {}, h("button", { class: "ghost", onclick: async () => {
    const rows = await api("/api/audit?limit=100");
    audit.replaceChildren(h("table", {}, h("thead", {}, h("tr", {}, ["Time", "Connector", "Tool", "Status", "Decision", "ms"].map((x) => h("th", {}, x)))),
      h("tbody", {}, rows.map((r) => h("tr", {}, h("td", { class: "small" }, when(r.ts)), h("td", {}, r.connector), h("td", {}, r.tool),
        h("td", {}, h("span", { class: r.status === "ok" ? "ok" : "bad" }, r.status)), h("td", { class: "small muted" }, r.decision), h("td", {}, r.duration_ms))))));
  } }, icon("clipboard-text-clock"), "Show audit log (admin)"));
  main.append(section("Audit log", "clipboard-text-clock", audit));
}

route();
