"""Deterministic evidence collection for an alert case: no model involved.

Before any model sees a case (and when no model is used at all), the collector runs fixed, read-only
steps chosen from the alert's own fields and the matching playbooks:

  decode     decode an obfuscated command line (never runs it)
  intel      look external addresses, domains, URLs and hashes up in the intel connectors
  context    events on the same host in a window around the alert
  inventory  what runs, listens and which accounts exist on the host now (snapshot connectors)
  auth       for sign-in alerts: how many accounts the source tried, and whether any sign-in succeeded
  spread     which other hosts show the same process, destination or domain

Field names are found, not assumed: for each connector the collector reads ``get_fields`` once and picks
the first name it knows for each kind of value (``host``, ``user``, ``src_ip``, ...). A connector can name
them itself with ``fields: {host: agent.name, ...}`` in its config. Queries use query_string syntax, so
steps only run on connectors whose dialect is query_string/Lucene (the search-index bridge and the demo).

Each result is stored on the case as evidence E<n>, like a model's call. The results are then read by
plain rules into signals (an intel match, a download piped into a shell, a process running from a
temporary path, a second account with user id 0, ...), each citing the evidence it came from. Signals
feed the verdict checks, and with ``soc.analysis: rules`` they make the verdict themselves.
"""

from __future__ import annotations

import json
import re
from datetime import timedelta
from typing import Any

from ..connectors.hub import ToolCallError
from .util import iso, parse_iso, payload

# kind of value -> field names it is commonly found under (first one present wins)
CANDIDATES: dict[str, list[str]] = {
    "host": ["host.name", "agent.name", "hostname", "host.hostname", "computer", "device.name"],
    "user": ["user.name", "data.srcuser", "data.dstuser", "data.win.eventdata.targetUserName",
             "data.win.eventdata.subjectUserName", "user"],
    "process": ["process.name", "data.process.name", "data.win.eventdata.image", "process.executable"],
    "command_line": ["process.command_line", "data.process.command_line", "data.win.eventdata.commandLine",
                     "data.command"],
    "parent": ["process.parent.name", "data.win.eventdata.parentImage"],
    "src_ip": ["source.ip", "data.srcip", "srcip", "client.ip"],
    "dst_ip": ["destination.ip", "data.dstip", "dstip"],
    "domain": ["destination.domain", "dns.question.name", "url.domain"],
    "outcome": ["event.outcome", "data.status", "event.action"],
    "uid": ["user.id", "data.uid"],
    "listen_port": ["source.port", "data.port"],
    "state": ["interface.state"],
}
SIGNAL_LEVELS = ("high", "medium", "info")
_TEMP = re.compile(r"(?i)(^|[\s\"'=/\\])(/dev/shm/|/tmp/|/var/tmp/|/run/user/|\\appdata\\local\\temp\\|"
                   r"\\users\\public\\|\\windows\\temp\\)")
_PIPE_SHELL = re.compile(r"(?i)\b(curl|wget|fetch)\b[^|;\n]{0,300}\|\s*(sudo\s+)?(ba|z|da)?sh\b")
_DOWNLOAD = re.compile(r"(?i)downloadstring|downloadfile|invoke-webrequest|\biwr\b|net\.webclient|start-bitstransfer|"
                       r"certutil\s+-urlcache|bitsadmin\s+/transfer")
_ENCODED = re.compile(r"(?i)\s-(e|en|enc|encodedcommand)\s+[A-Za-z0-9+/=]{20,}")
_OFFICE = ("winword", "excel", "powerpnt", "outlook", "onenote", "msaccess", "mspub")
_SHELLS = ("powershell", "pwsh", "cmd.exe", "wscript", "cscript", "mshta", "rundll32", "regsvr32", "bash", "sh")
_AUTH = re.compile(r"(?i)sign-?in|log[- ]?on|login|authentication|password|brute|spray")
DEFAULT_STEPS = ("decode", "intel", "context", "inventory", "auth", "spread")
COLLECT_BYTES = 2_000_000


def _q(v: str) -> str:
    return '"' + str(v).replace("\\", "\\\\").replace('"', '\\"') + '"'


def _rows(content: str) -> tuple[list[dict], Any]:
    try:
        data = json.loads(payload(content))
    except ValueError:
        return [], None
    if isinstance(data, dict):
        common = data.get("common") if isinstance(data.get("common"), dict) else {}
        for k in ("hits", "buckets", "results", "items", "new", "matches"):
            if isinstance(data.get(k), list):
                return [{**common, **r} if isinstance(r, dict) else {"value": r} for r in data[k]], data
        return [], data
    if isinstance(data, list):
        return [r for r in data if isinstance(r, dict)], data
    return [], data


def _base(name: str) -> str:
    return re.split(r"[\\/]", str(name or ""))[-1].lower()


class Collector:
    def __init__(self, hub, tools: list[dict], store, case_id: str, *, start_n: int = 0, max_calls: int = 12,
                 environment: dict | None = None, window_min: int = 30):
        self.hub, self.store, self.case_id = hub, store, case_id
        self.n = start_n
        self.max_calls = max_calls
        self.calls = 0
        self.window = timedelta(minutes=window_min)
        self.environment = environment or {}
        self.steps: list[dict] = []          # what was run: {n, connector, tool, role, ok, hits, args, why}
        self.signals: list[dict] = []
        self.done: dict[str, str] = {}       # call key -> evidence id
        self._alert_text = ""
        self._alert_ids: list[str] = []
        self._fields: dict[str, set[str]] = {}
        self._indices: dict[str, list[str]] = {}
        self.tools = {(t["connector"], t["name"]): t for t in tools}
        self.connectors = sorted({t["connector"] for t in tools})

    # ---- plumbing ----
    def _has(self, conn: str, tool: str) -> bool:
        return (conn, tool) in self.tools

    def _lucene(self, conn: str) -> bool:
        spec = self.hub.specs.get(conn)
        d = (getattr(spec, "dialect", "") or self.tools.get((conn, "search"), {}).get("dialect", "")).lower()
        return "query_string" in d or "lucene" in d or conn.startswith("demo")

    def _snapshot(self, conn: str) -> bool:
        props = ((self.tools.get((conn, "search")) or {}).get("inputSchema") or {}).get("properties") or {}
        return "time_from" not in props

    def _call(self, conn: str, tool: str, args: dict, why: str, *, evidence: bool = True) -> tuple[bool, str]:
        key = json.dumps([conn, tool, args], sort_keys=True, default=str)
        if evidence and key in self.done:
            return True, ""
        if evidence and self.calls >= self.max_calls:
            return False, ""
        hid = "case:" + self.case_id
        try:
            # no model reads this result whole: the rules parse it, so it is not cut to the size used for prompts
            out = self.hub.call(conn, tool, args, actor="collector", hunt_id=hid, max_bytes=COLLECT_BYTES)
            ok, content = not out.get("is_error"), out["content"]
        except ToolCallError as exc:
            ok, content = False, f"call failed: {exc}"
        if not evidence:
            return ok, content
        self.calls += 1
        self.n += 1
        rows, data = _rows(content) if ok else ([], None)
        hits = None
        if isinstance(data, dict):
            for k in ("total", "count"):
                if isinstance(data.get(k), int):
                    hits = data[k]
                    break
            if hits is None and data.get("found") is not None:
                hits = int(bool(data.get("found")))
        if hits is None and ok:
            hits = len(rows)
        role = (self.tools.get((conn, tool)) or {}).get("role", "")
        self.store.add_step(self.case_id, self.n, "call", connector=conn, tool=tool, role=role, arguments=args,
                            why=f"collected (no model): {why}", ok=ok, result=content,
                            note=(f"hits={hits}; " if hits is not None else "") + "collected")
        eid = f"E{self.n}"
        self.done[key] = eid
        self.steps.append({"n": self.n, "connector": conn, "tool": tool, "role": role, "ok": ok, "hits": hits,
                           "why": why, "rows": rows, "data": data})
        return ok, eid

    def fields(self, conn: str, index: str | None) -> set[str]:
        k = f"{conn}|{index or ''}"
        if k not in self._fields:
            got: set[str] = set()
            if self._has(conn, "get_fields"):
                ok, content = self._call(conn, "get_fields", {"index": index} if index else {}, "field names",
                                         evidence=False)
                if ok:
                    try:
                        f = json.loads(payload(content)).get("fields")
                        got = set(f) if isinstance(f, (dict, list)) else set()
                    except (ValueError, AttributeError):
                        got = set()
            self._fields[k] = got
        return self._fields[k]

    def field(self, conn: str, index: str | None, kind: str) -> str | None:
        own = (getattr(self.hub.specs.get(conn), "raw_fields", None) or {}).get(kind)
        if own:
            return own
        have = self.fields(conn, index)
        return next((f for f in CANDIDATES.get(kind, []) if f in have), None)

    def indices(self, conn: str) -> list[str]:
        if conn not in self._indices:
            pats: list[str] = []
            if self._has(conn, "list_indices"):
                ok, content = self._call(conn, "list_indices", {}, "indices", evidence=False)
                if ok:
                    try:
                        d = json.loads(payload(content))
                        pats = [str(p) for p in d.get("allowed_patterns") or []] or [
                            str(i.get("index")) for i in d.get("indices") or [] if isinstance(i, dict)]
                    except (ValueError, AttributeError):
                        pats = []
            self._indices[conn] = pats
        return self._indices[conn]

    def _signal(self, name: str, level: str, text: str, eid: str) -> None:
        if not eid:
            return
        for s in self.signals:
            if s["name"] == name and s["text"] == text:
                if eid not in s["evidence"]:
                    s["evidence"].append(eid)
                return
        self.signals.append({"name": name, "level": level, "text": text[:300], "evidence": [eid]})

    # ---- the run ----
    def run(self, alerts: list[dict], steps: tuple[str, ...] = DEFAULT_STEPS) -> list[dict]:
        a0 = alerts[0] if alerts else {}
        values: dict[str, set[str]] = {}
        for a in alerts:
            for e in a.get("entities") or []:
                key = {"ip": e.get("field") or "ip"}.get(e["type"], e["type"])
                if e["type"] == "ip" and not e.get("field"):
                    key = "ip_text"
                values.setdefault(key, set()).add(e["value"])
        times = sorted(parse_iso(a["ts"]) for a in alerts if a.get("ts"))
        t0 = (times[0] - self.window) if times else None
        t1 = (times[-1] + self.window) if times else None
        text = " ".join(f"{a.get('title', '')} {a.get('rule_name', '')} {a.get('description', '')}" for a in alerts)
        cmds = [a.get("command_line") for a in alerts if a.get("command_line")]
        cmds += [str(v) for a in alerts for k, v in _flat(a.get("raw") or {}).items()
                 if k.endswith(("command_line", "commandLine", "full_log", "cmdline")) and isinstance(v, str)]
        self._alert_ids = sorted({v.lower() for k in ("process", "user", "command_line", "file", "hash", "dst_ip",
                                                     "domain", "url") for v in values.get(k, set())
                                  if (len(v) > 3 and not _internal(v)) or k in ("process", "user", "command_line")}
                                 | {_base(v) for v in values.get("process", set()) if len(_base(v)) > 3})
        self._alert_text = (text + " " + " ".join(cmds) + " " + " ".join(
            v for k in ("process", "user", "command_line", "file", "hash") for v in values.get(k, set()))).lower()
        for c in cmds:
            self._text_signals(c, "")
        logs = [c for c in self.connectors if self._has(c, "search") and self._lucene(c) and not self._snapshot(c)]
        snaps = [c for c in self.connectors if self._has(c, "search") and self._lucene(c) and self._snapshot(c)]
        intel = [c for c in self.connectors if self._has(c, "lookup")]
        decoder = next((c for c in self.connectors if self._has(c, "decode_command")), None)
        hosts = sorted(values.get("host", set()))[:2]

        if "decode" in steps and decoder:
            for c in dict.fromkeys(c for c in cmds if _ENCODED.search(c) or re.search(r"(?i)frombase64|char\(", c)):
                ok, eid = self._call(decoder, "decode_command", {"text": c[:4000]}, "decode the command line")
                if ok and eid:
                    data = self.steps[-1]["data"] or {}
                    final = str(data.get("final") or "")
                    self._text_signals(final, eid, decoded=True)
                    for u in data.get("urls") or []:
                        values.setdefault("url", set()).add(u)
        if "intel" in steps and intel:
            lookups = sorted(v for k in ("dst_ip", "src_ip", "ip_text", "domain", "url", "hash")
                             for v in values.get(k, set()) if not _internal(v))[:6]
            for v in lookups:
                ok, eid = self._call(intel[0], "lookup", {"value": v}, f"is {v} in the intel store")
                if ok and eid and (self.steps[-1]["data"] or {}).get("found"):
                    m = ((self.steps[-1]["data"] or {}).get("matches") or [{}])[0]
                    self._signal("intel_match", "high", f"{v} is a known indicator"
                                 + (f" ({', '.join(m.get('tags') or [])})" if m.get("tags") else ""), eid)
        if "inventory" in steps and hosts:
            for conn in snaps:
                self._inventory(conn, hosts[0])
        if "context" in steps and hosts and t0:
            for conn in logs[:1]:
                idx = ",".join(p for p in self.indices(conn) if not _is_state(p))[:300] or None
                hf = self.field(conn, idx.split(",")[0] if idx else None, "host")
                if hf and idx:
                    ok, eid = self._call(conn, "search", {"index": idx, "query": f"{hf}:{_q(hosts[0])}",
                                                          "time_from": iso(t0), "time_to": iso(t1), "size": 30},
                                         f"what else happened on {hosts[0]} around the alert")
                    if ok and eid:
                        for r in self.steps[-1]["rows"]:
                            self._row_signals(r, eid)
        if "auth" in steps and values.get("src_ip") and t0 and _AUTH.search(text):
            src = sorted(values["src_ip"])[0]
            for conn in logs[:1]:
                idx = ",".join(p for p in self.indices(conn) if not _is_state(p))[:300] or None
                first = idx.split(",")[0] if idx else None
                sf, uf, of = (self.field(conn, first, k) for k in ("src_ip", "user", "outcome"))
                if not (sf and uf and idx):
                    continue
                win = {"time_from": iso(t0 - timedelta(hours=12)), "time_to": iso(t1 + timedelta(hours=1))}
                ok, eid = self._call(conn, "top_values", {"index": idx, "query": f"{sf}:{_q(src)}", "field": uf,
                                                          "size": 50, **win}, f"accounts tried from {src}")
                n_users = len(self.steps[-1]["rows"]) if ok and eid else 0
                if n_users >= 10:   # password spraying: an attack attempt, whether or not it got in
                    self._signal("many_accounts", "high", f"{src} tried {n_users} different accounts", eid)
                if of:
                    ok, eid = self._call(conn, "count", {"index": idx, "query": f"{sf}:{_q(src)} AND {of}:success",
                                                         **win}, f"successful sign-ins from {src}")
                    hits = self.steps[-1]["hits"] if ok and eid else None
                    if hits:
                        self._signal("success_after_failures", "high", f"{src} also signed in successfully "
                                     f"({hits} times)", eid)
                    elif hits == 0 and n_users >= 10:
                        self._signal("no_success", "info", f"no successful sign-in from {src}", eid)
        if "spread" in steps and t0:
            for conn in logs[:1]:
                idx = ",".join(p for p in self.indices(conn) if not _is_state(p))[:300] or None
                first = idx.split(",")[0] if idx else None
                hf = self.field(conn, first, "host")
                for kind in ("dst_ip", "domain"):
                    vs = [v for v in sorted(values.get(kind, set())) if not _internal(v)][:1]
                    f = self.field(conn, first, kind)
                    if not (vs and f and hf and idx):
                        continue
                    ok, eid = self._call(conn, "top_values", {"index": idx, "query": f"{f}:{_q(vs[0])}", "field": hf,
                                                              "size": 20, "time_from": iso(t0 - timedelta(days=6)),
                                                              "time_to": iso(t1)}, f"which hosts talked to {vs[0]}")
                    if ok and eid and len(self.steps[-1]["rows"]) > 1:
                        self._signal("spread", "medium", f"{len(self.steps[-1]['rows'])} hosts contacted {vs[0]}", eid)
        good = [str(k) for k in self.environment.get("known_good") or []]
        blob = (text + " " + " ".join(cmds) + " " + " ".join(v for s in values.values() for v in s)).lower()
        for k in good:
            # a note matches when every identifier in it (a name with a dot, digit or underscore, such as an
            # account or a host) appears in the case; notes with no identifier never match on their own
            ids = [w.strip(".-") for w in re.findall(r"[\w.\-]+", k.lower()) if re.search(r"[._\d]", w.strip(".-"))]
            if ids and all(w in blob for w in ids):
                self.signals.append({"name": "known_good", "level": "info", "text": f"matches the known-good note: {k}"[:300],
                                     "evidence": []})
        _ = a0
        return self.signals

    def _related(self, *values) -> bool:
        """Does an inventory finding concern what the alert is about (its process, account, command or file)?"""
        vals = [str(v).lower() for v in values if v and len(str(v)) > 2]
        return any(v in self._alert_text or _base(v) in self._alert_text for v in vals)

    def _host_signal(self, name: str, level: str, text: str, eid: str, *values) -> None:
        if self._related(*values):
            self._signal(name, level, text, eid)
        else:      # true of the host, not of this alert: worth a person's look, not the alert's verdict
            self._signal("host_" + name, "medium", f"the host also shows: {text}", eid)

    def _inventory(self, conn: str, host: str) -> None:
        pats = self.indices(conn)
        for kind in ("process", "port", "user"):
            idx = next((p for p in pats if kind in p.lower()), None)
            if not idx:
                continue
            hf = self.field(conn, idx, "host")
            if not hf:
                continue
            ok, eid = self._call(conn, "search", {"index": idx, "query": f"{hf}:{_q(host)}", "size": 200},
                                 f"{kind}es on {host} now" if kind == "process" else f"{kind}s on {host} now")
            if not (ok and eid):
                continue
            for r in self.steps[-1]["rows"]:
                if kind == "process":
                    cmd = str(r.get("process.command_line") or r.get("process.executable") or "")
                    name = str(r.get("process.name") or "")
                    if _TEMP.search(" " + cmd):
                        self._host_signal("temp_path_exec", "high", f"{name or cmd} runs from a temporary path: "
                                          f"{cmd[:120]}", eid, name, cmd)
                    elif name.startswith(".") and len(name) > 2:
                        self._host_signal("hidden_process", "medium", f"process with a hidden name: {name}", eid, name)
                elif kind == "port":
                    name = str(r.get("process.name") or "")
                    state = str(r.get("interface.state") or "")
                    port = r.get("source.port") or r.get("local.port")
                    if name.startswith(".") and state in ("listening", "") and port:
                        self._host_signal("hidden_listener", "high", f"hidden-name process {name} listens on port "
                                          f"{port}", eid, name, f"port {port}", str(port))
                elif kind == "user":
                    uid, name = str(r.get("user.id", "")), str(r.get("user.name", ""))
                    if uid == "0" and name and name != "root":
                        self._host_signal("uid0_non_root", "high", f"account {name} has user id 0 (root)", eid, name)

    def _mentions(self, text: str) -> bool:
        """Does a log row name something the alert is about (its process, account, command, address, domain)?"""
        t = text.lower()
        return any(v in t for v in self._alert_ids)

    def _row_signals(self, r: dict, eid: str) -> None:
        text = " ".join(str(v) for k, v in r.items() if isinstance(v, (str, int))
                        and any(s in k for s in ("command", "full_log", "message", "process", "parent")))
        whole = " ".join(str(v) for v in r.values() if isinstance(v, (str, int)))
        if self._mentions(whole):
            self._text_signals(text, eid)
        else:      # the same host around the same time, but not this alert's activity
            before = len(self.signals)
            self._text_signals(text, eid)
            for sig in self.signals[before:]:
                if sig["level"] == "high" and eid in sig["evidence"] and not sig["name"].startswith("host_"):
                    sig.update(name="host_" + sig["name"], level="medium", text="the host also shows: " + sig["text"])
        parent = _base(r.get("process.parent.name") or r.get("data.win.eventdata.parentImage") or "")
        child = _base(r.get("process.name") or r.get("data.win.eventdata.image") or "")
        if any(o in parent for o in _OFFICE) and any(child.startswith(s) for s in _SHELLS):
            self._signal("office_spawns_shell", "medium", f"{parent} started {child}", eid)

    def _text_signals(self, text: str, eid: str, *, decoded: bool = False) -> None:
        if not text:
            return
        if _PIPE_SHELL.search(text):
            self._signal("download_piped_to_shell", "high", f"a download is piped into a shell: "
                         f"{_PIPE_SHELL.search(text).group(0)[:120]}", eid or "alert")
        if decoded and _DOWNLOAD.search(text):
            self._signal("decoded_download", "high", f"the decoded command downloads and runs code: {text[:150]}", eid)
        if _TEMP.search(" " + text) and re.search(r"(?i)\b(exec|run|start|chmod|nohup|\./)", text):
            self._signal("temp_path_exec", "high", f"something is run from a temporary path: {text[:120]}", eid or "alert")
        if not decoded and _ENCODED.search(text):
            self._signal("encoded_command", "medium", "an encoded command line", eid or "alert")


def _flat(d: dict, prefix: str = "") -> dict:
    out = {}
    for k, v in (d or {}).items():
        key = f"{prefix}{k}"
        if isinstance(v, dict):
            out.update(_flat(v, key + "."))
        else:
            out[key] = v
    return out


def _is_state(pattern: str) -> bool:
    return bool(re.search(r"(?i)inventory|states|vuln|inv-", pattern))


def _internal(v: str) -> bool:
    from .alerts import _private
    return _private(v) or v.endswith((".lan", ".local", ".internal", ".home"))


def summary(signals: list[dict]) -> str:
    if not signals:
        return "The fixed checks found nothing notable."
    return "\n".join(f"- [{s['level']}] {s['text']} ({', '.join(s['evidence']) or 'from the alert'})" for s in signals)


def rules_verdict(signals: list[dict], steps: list[dict], case: dict) -> dict:
    """A verdict from the signals alone (``soc.analysis: rules``, or when the model fails). Rules never close
    a case: a true positive needs a strong signal with evidence; everything else is handed to a person."""
    real = [s for s in signals if any(e.startswith("E") for e in s["evidence"])]
    high = [s for s in real if s["level"] == "high"]
    medium = [s for s in real if s["level"] == "medium"]
    own_medium = [s for s in medium if not s["name"].startswith("host_")]   # host-wide hints do not raise confidence
    good = [s for s in signals if s["name"] == "known_good"]
    findings = [{"text": s["text"], "evidence": [e for e in s["evidence"] if e.startswith("E")]} for s in high + medium]
    if high:
        kinds = {s["name"] for s in high}
        return {"verdict": "true_positive", "confidence": min(85, 60 + 10 * (len(kinds) - 1) + 5 * len(own_medium)),
                "summary": "Rule checks found: " + "; ".join(s["text"] for s in high + medium)[:1500],
                "findings": findings, "attack": [], "fix": {"type": "remediation", "steps": [
                    "Confirm the activity on the host, then contain it through your own process"]},
                "gaps": ["No model reviewed this case; the verdict comes from fixed rules."]}
    if steps and all(not s["ok"] for s in steps):
        return {"verdict": "logs_missing", "confidence": 0, "summary": "The fixed checks could not read any source.",
                "findings": []}
    if good:   # no strong signal and the case matches a known-good note: expected activity (a person still
        # reviews high-severity cases, see service.py)
        return {"verdict": "benign", "confidence": 60, "summary": good[0]["text"] + (
            "; other hints: " + "; ".join(s["text"] for s in medium) if medium else ""), "findings": findings}
    return {"verdict": "needs_analyst", "confidence": 30,
            "summary": ("Rule checks found: " + "; ".join(s["text"] for s in medium)) if medium else
            "The fixed checks found nothing decisive; a person should look.", "findings": findings}
