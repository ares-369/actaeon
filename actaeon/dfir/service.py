"""Investigation operations shared by the web API, the CLI and the MCP server."""

from __future__ import annotations

import csv
import hashlib
import io
import secrets
import threading
from pathlib import Path
from typing import Any

from .config import of
from .parsers import ParseError, parse_file
from .store import DfirStore

_locks: dict[str, threading.Lock] = {}
_locks_guard = threading.Lock()


def store_for(cfg) -> DfirStore:
    return DfirStore(cfg.data_dir / "dfir.sqlite")


def _lock(cid: str) -> threading.Lock:
    with _locks_guard:
        return _locks.setdefault(cid, threading.Lock())


def sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with Path(path).open("rb") as fh:
        while chunk := fh.read(1 << 20):
            h.update(chunk)
    return h.hexdigest()


def uploads_dir(cfg, cid: str) -> Path:
    """Uploaded files wait here until their import finishes, so an interrupted import can run again."""
    p = cfg.data_dir / "dfir-uploads" / cid
    p.mkdir(parents=True, exist_ok=True)
    return p


def import_uploads(cfg, cid: str, files: list, *, actor: str, host: str = "") -> list[dict]:
    out = []
    for item in files:
        path, name = item[0], item[1]
        p = Path(path)
        if not p.exists():
            out.append({"name": name, "status": "failed", "note": "the uploaded file is gone"})
            continue
        r = import_file(cfg, cid, p, name, actor=actor, keep=p, host=host,
                        origin=item[2] if len(item) > 2 else "upload")
        out.append(r)
        if r.get("status") == "done" or r.get("duplicate"):
            p.unlink(missing_ok=True)
            if r.get("source_id") and not r.get("duplicate"):
                store_for(cfg).set_source(r["source_id"], upload_path="")
    return out


def interrupted(cfg, cid: str, jobs=None) -> list[dict]:
    """Sources left 'importing' by a job that is no longer running."""
    st = store_for(cfg)
    c = st.case(cid) or {}
    job = jobs.get(c["job_id"]) if jobs and c.get("job_id") else None
    if job and job.get("status") in ("queued", "running"):
        return []
    return [s for s in st.sources(cid) if s["status"] == "importing"]


def retry_source(cfg, cid: str, sid: str, *, actor: str) -> list:
    """Drop what an interrupted import stored and return the kept upload to import again."""
    st = store_for(cfg)
    src = st.source(sid)
    if not src or src["case_id"] != cid:
        raise KeyError(sid)
    path = src.get("upload_path") or ""
    if not path or not Path(path).exists():
        raise ValueError("the uploaded file is no longer kept; upload it again")
    st.delete_source(cid, sid)
    st.update_case(cid, events=st.count(cid))
    st.log(cid, actor, "retry import", src["name"])
    return [[path, src["name"]]]


def import_file(cfg, cid: str, path: Path, name: str, *, actor: str, year: int | None = None,
                keep: Path | None = None, store: DfirStore | None = None, host: str = "",
                origin: str = "") -> dict:
    """Parse one evidence file into the case. The file's SHA-256 is recorded first; the same file twice is skipped."""
    st = store or store_for(cfg)
    if not st.case(cid):
        raise KeyError(cid)
    dc = of(cfg)
    path = Path(path)
    digest = sha256_of(path)
    old = st.find_source(cid, digest)
    if old:
        return {"source_id": old["id"], "duplicate": True, "name": name, "sha256": digest, "events": old["events"]}
    with _lock(cid):
        sid = st.add_source(cid, name=name, sha256=digest, size=path.stat().st_size, actor=actor)
        if keep:
            st.set_source(sid, upload_path=str(keep), origin=origin or "upload")
        elif origin:
            st.set_source(sid, origin=origin)
        seq = st.next_seq(cid)
        room = dc.max_events_per_case - st.count(cid)
        kind, members, errors, samples, hosts = "", [], 0, [], set()
        first = last = ""
        batch: list = []
        n = 0
        note = ""
        try:
            for ev in parse_file(path, name, year=year, max_unpacked=dc.max_upload_mb * 20 << 20,
                                 evtx_dump=dc.evtx_dump):
                if "_kind" in ev:
                    if "_member" in ev:
                        members.append(ev["_member"])
                    kind = kind or ev["_kind"]
                    continue
                if "_error" in ev:
                    errors += 1
                    if len(samples) < 20:
                        samples.append(ev["_error"])
                    continue
                if n >= room:
                    note = f"stopped at dfir.max_events_per_case ({dc.max_events_per_case} events per case)"
                    break
                if host and not ev["host"]:                      # e.g. a memory image's output names no host
                    ev["host"] = host[:200]
                batch.append((seq, ev))
                seq += 1
                n += 1
                if ev["host"]:
                    hosts.add(ev["host"])
                if ev["ts"]:
                    first = min(first, ev["ts"]) if first else ev["ts"]
                    last = max(last, ev["ts"])
                if len(batch) >= 2000:
                    st.add_events(cid, sid, batch)
                    batch = []
            st.add_events(cid, sid, batch)
            status = "done"
        except ParseError as exc:
            st.add_events(cid, sid, batch)
            status, note = "failed", str(exc)
        if members:
            note = (note + "; " if note else "") + f"{len(members)} file(s) read from the zip"
        yara_hits = 0
        if dc.yara_dirs:
            from .yarascan import scan
            try:
                hits, problems = scan(dc.yara_dirs, path, name, max_mb=dc.yara_max_mb)
            except Exception as exc:                      # a scan failure must not lose the parsed events
                hits, problems = [], [f"YARA scan failed: {exc}"[:300]]
            rows, dets = [], []
            for h in hits:
                where = name + (f" ({h['member']})" if h["member"] else "")
                ev = {"ts": "", "host": "", "channel": "yara", "event_id": "", "user": "", "process": "",
                      "summary": f"YARA rule {h['rule']} matched {where}", "data": {**h, "sha256": digest}}
                rows.append((seq, ev))
                dets.append((seq, f"yara:{h['namespace']}:{h['rule']}", f"YARA: {h['rule']}", h["level"], "yara", []))
                seq += 1
            st.add_events(cid, sid, rows)
            st.add_detections(cid, dets)
            if dets:
                st.refresh_levels(cid)
            yara_hits = len(hits)
            n += len(rows)
            if hits or problems:
                note = (note + "; " if note else "") + f"YARA: {yara_hits} match(es)" + (
                    "; " + "; ".join(problems[:3]) if problems else "")
        st.finish_source(sid, kind=kind, events=n, errors=errors, error_samples=samples, hosts=hosts, first_ts=first,
                         last_ts=last, status=status, note=note)
        st.update_case(cid, events=st.count(cid))
        st.log(cid, actor, "import", f"{name}: {n} events, sha256 {digest}")
    return {"source_id": sid, "name": name, "sha256": digest, "kind": kind, "events": n, "errors": errors,
            "status": status, "note": note, "hosts": sorted(hosts)[:50]}


def analyze(cfg, cid: str, *, actor: str = "") -> dict:
    from ..soc.util import iso
    from .analyze import run_all
    st = store_for(cfg)
    if not st.case(cid):
        raise KeyError(cid)
    with _lock(cid):
        res = run_all(cfg, of(cfg), st, cid)
        st.update_case(cid, analyzed=iso())
        st.log(cid, actor, "analyze", f"{res['sigma']['rules']} rules, {res['sigma']['hits']} hits")
    return res


def overview(cfg, cid: str) -> dict | None:
    st = store_for(cfg)
    c = st.case(cid)
    if not c:
        return None
    from .analyze import attack_of
    c.update(sources=st.sources(cid), hosts=st.hosts(cid), span=st.span(cid), detections=st.detection_summary(cid),
             analysis=st.analysis(cid), notes=st.notes(cid), attack=attack_of(st, cid))
    return c


EXPORT_COLS = ["Timestamp", "Host", "Log", "EventID", "Level", "Rules", "User", "Process", "Summary", "Seq", "Star",
               "Tags", "Comment", "Source"]
LEVEL_NAMES = {0: "", 1: "informational", 2: "low", 3: "medium", 4: "high", 5: "critical"}


def export_csv(cfg, cid: str, **filters: Any) -> str:
    """The timeline as CSV (one row per event), for spreadsheets or other timeline tools."""
    st = store_for(cfg)
    srcs = {s["id"]: s["name"] for s in st.sources(cid)}
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(EXPORT_COLS)
    off = 0
    while True:
        rows, _total = st.search(cid, limit=5000, offset=off, **filters)
        for e in rows:
            w.writerow([e["ts"], e["host"], e["channel"], e["event_id"], LEVEL_NAMES.get(e["level"] or 0, ""),
                        "; ".join(d["title"] for d in e["detections"]), e["user"], e["process"], e["summary"], e["seq"],
                        "yes" if e["star"] else "", ",".join(e["tags"]), e.get("comment") or "",
                        srcs.get(e["source_id"], "")])
        off += len(rows)
        if len(rows) < 5000:
            return buf.getvalue()


def report_markdown(cfg, cid: str) -> str:
    st = store_for(cfg)
    o = overview(cfg, cid)
    if not o:
        raise KeyError(cid)
    from ..soc.util import iso
    L = [f"# {o['title']}", "", f"Investigation {o['id']}, report written {iso()}.", ""]
    if o.get("description"):
        L += [o["description"], ""]
    sp = o.get("span") or {}
    L += [f"Events: {o['events']}. Time span: {sp.get('first') or '-'} to {sp.get('last') or '-'}. "
          f"Hosts: {', '.join(h['host'] for h in o['hosts'][:20] if h['host']) or '-'}.", ""]
    L += ["## Evidence", "", "| File | Kind | SHA-256 | Size | Events | Unreadable | Imported |", "|---|---|---|---|---|---|---|"]
    for s in o["sources"]:
        L.append(f"| {s['name']} | {s['kind']} | `{s['sha256']}` | {s['size']} | {s['events']} | {s['errors']} | "
                 f"{s['imported']} by {s.get('imported_by') or '-'} |")
    stories = st.stories(cid)
    if stories:
        b = stories[0]["body"]
        L += ["", "## What happened (written by a model; check the cited events)", "",
              f"Model {stories[0]['model']}, {stories[0]['ts']}.", "", b.get("summary", ""), ""]
        for p in b.get("phases") or []:
            cites = ", ".join(f"E{x}" for x in p.get("events") or [])
            L.append(f"- **{p.get('phase', '')}** {p.get('when', '')}: {p.get('what', '')} ({cites or 'no cited events'})"
                     + ("  *not supported by cited events*" if p.get("uncited") else ""))
        for k, title in (("open_questions", "Open questions"), ("next_steps", "Next steps")):
            if b.get(k):
                L += ["", f"### {title}", ""] + [f"- {x}" for x in b[k]]
    if o["detections"]:
        L += ["", "## Detections", "", "| Level | Rule | Events | Hosts | First | Last |", "|---|---|---|---|---|---|"]
        for d in o["detections"][:100]:
            L.append(f"| {d['level']} | {d['title']} | {d['n']} | {d['hosts']} | {d['first']} | {d['last']} |")
    starred, _ = st.search(cid, starred=True, limit=500)
    if starred:
        L += ["", "## Marked events", "", "| Event | Time | Host | What | Analyst comment |", "|---|---|---|---|---|"]
        for e in starred:
            L.append(f"| E{e['seq']} | {e['ts']} | {e['host']} | {e['summary'][:200].replace('|', '/')} | "
                     f"{(e.get('comment') or '').replace('|', '/')} |")
    if o["notes"]:
        L += ["", "## Notes", ""] + [f"- {n['kind']} ({n['status']}, {n['author'] or '-'}): {n['text']}" for n in o["notes"]]
    return "\n".join(L) + "\n"


def check_intel(cfg, cid: str, *, actor: str = "") -> dict:
    from ..connectors import get_hub
    from .intel import check
    st = store_for(cfg)
    if not st.case(cid):
        raise KeyError(cid)
    try:
        hub = get_hub(cfg)
    except Exception:
        hub = None
    with _lock(cid):
        res = check(cfg, st, cid, hub=hub)
    st.log(cid, actor, "check indicators", f"{res['checked']} checked, {res['matched']} known")
    return res


def pull_from_connector(cfg, cid: str, connector: str, tool: str, arguments: dict, *, actor: str,
                        host: str = "") -> dict:
    """Call one read-only connector tool (a Velociraptor MCP server's collection results, for example) and
    import what it returns as an evidence file. The connector's own policy decides which tools may be called."""
    import json as _json

    from ..connectors import get_hub
    from ..hunt.signals import payload
    st = store_for(cfg)
    if not st.case(cid):
        raise KeyError(cid)
    if not isinstance(arguments, dict):
        raise ValueError("arguments must be a JSON object")
    hub = get_hub(cfg)
    tools = {t["name"]: t for t in hub.tools(connector)}
    if tool not in tools or not tools[tool].get("allowed"):
        raise ValueError(f"{connector}.{tool} is not an allowed (read-only) tool")
    r = hub.call(connector, tool, arguments, actor=f"dfir {actor}".strip(), hunt_id=f"dfir-{cid}",
                 max_bytes=of(cfg).max_upload_mb << 20)
    if r.get("is_error"):
        raise ValueError(f"the tool returned an error: {payload(r.get('content') or '')[:300]}")
    text = payload(r.get("content") or "")
    try:
        data = _json.loads(text)
    except ValueError:
        data = None
    if isinstance(data, dict):                     # the rows are usually under a key
        rows = next((data[k] for k in ("rows", "results", "hits", "events", "items", "data") if isinstance(data.get(k), list)), None)
        if rows is not None:
            text = "\n".join(_json.dumps(x) for x in rows if isinstance(x, dict))
    name = f"{connector}.{tool}.jsonl"
    p = uploads_dir(cfg, cid) / f"pull-{secrets.token_hex(4)}-{name}"
    p.write_text(text, encoding="utf-8")
    try:
        res = import_file(cfg, cid, p, name, actor=actor, host=host, origin=f"connector {connector}.{tool}")
    finally:
        p.unlink(missing_ok=True)
    st.log(cid, actor, "pull", f"{connector}.{tool} {_json.dumps(arguments)[:200]}")
    return res


def from_soc_case(cfg, soc_case_id: str, *, actor: str) -> dict:
    """Open an investigation from an alert case: its alerts and the log events its investigation found become
    evidence (two sources, hashed like any file)."""
    import json as _json

    from ..access import can_see
    from ..rules.testing import events_from_result
    from ..soc.service import store_for as soc_store
    sc = soc_store(cfg).get_case(soc_case_id)
    if not sc or not can_see(sc.get("restricted") or []):
        raise KeyError(soc_case_id)
    st = store_for(cfg)
    existing = st.by_soc_case(soc_case_id)
    if existing:
        return {"id": existing[0]["id"], "existing": True}
    c = st.create_case(f"Alert case: {sc.get('title') or soc_case_id}"[:300],
                       (f"Opened from alert case {soc_case_id}. AI verdict: {sc.get('verdict') or '-'}. "
                        f"{sc.get('summary') or ''}")[:4000], actor=actor)
    st.update_case(c["id"], soc_case=soc_case_id)
    folder = uploads_dir(cfg, c["id"])
    files = []
    alerts = [{**(a.get("raw") or {}), "alert_title": a.get("title"), "alert_rule": a.get("rule_name"),
               "alert_severity": a.get("severity_label"), "timestamp": a.get("ts")} for a in sc.get("alerts") or []]
    if alerts:
        p = folder / f"soc-{soc_case_id}-alerts.jsonl"
        p.write_text("\n".join(_json.dumps(x, default=str) for x in alerts), encoding="utf-8")
        files.append((p, f"alert case {soc_case_id} alerts.jsonl"))
    found = []
    for s in sc.get("steps") or []:
        if s.get("kind") == "call" and s.get("ok"):
            found += events_from_result(s.get("result") or "", limit=200)
    if found:
        p = folder / f"soc-{soc_case_id}-evidence.jsonl"
        p.write_text("\n".join(_json.dumps(x, default=str) for x in found[:20000]), encoding="utf-8")
        files.append((p, f"alert case {soc_case_id} investigation results.jsonl"))
    for p, name in files:
        try:
            import_file(cfg, c["id"], p, name, actor=actor, origin=f"alert case {soc_case_id}")
        finally:
            p.unlink(missing_ok=True)
    st.log(c["id"], actor, "opened from alert case", soc_case_id)
    return {"id": c["id"], "existing": False, "events": st.count(c["id"])}
