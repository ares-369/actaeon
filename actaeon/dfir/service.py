"""Investigation operations shared by the web API, the CLI and the MCP server."""

from __future__ import annotations

import csv
import hashlib
import io
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


def import_file(cfg, cid: str, path: Path, name: str, *, actor: str, year: int | None = None) -> dict:
    """Parse one evidence file into the case. The file's SHA-256 is recorded first; the same file twice is skipped."""
    st = store_for(cfg)
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
        st.finish_source(sid, kind=kind, events=n, errors=errors, error_samples=samples, hosts=hosts, first_ts=first,
                         last_ts=last, status=status, note=note)
        st.update_case(cid, events=st.count(cid))
    return {"source_id": sid, "name": name, "sha256": digest, "kind": kind, "events": n, "errors": errors,
            "status": status, "note": note, "hosts": sorted(hosts)[:50]}


def analyze(cfg, cid: str) -> dict:
    from ..soc.util import iso
    from .analyze import run_all
    st = store_for(cfg)
    if not st.case(cid):
        raise KeyError(cid)
    with _lock(cid):
        res = run_all(cfg, of(cfg), st, cid)
        st.update_case(cid, analyzed=iso())
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
