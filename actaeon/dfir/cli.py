"""Command line for investigations: ``actaeon dfir ...``."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ACTIONS = ["list", "new", "import", "analyze", "show", "timeline", "story", "ask", "report", "export"]


def add_parsers(sub) -> None:
    p = sub.add_parser("dfir", help="offline investigations: list | new TITLE | import CASE FILE... | analyze CASE | "
                                    "show CASE | timeline CASE | story CASE | ask CASE QUESTION | report CASE | "
                                    "export CASE --out FILE.csv")
    p.add_argument("action", choices=ACTIONS)
    p.add_argument("args", nargs="*")
    p.add_argument("--description", default="")
    p.add_argument("--q", default="", help="timeline/export: search words or field:value")
    p.add_argument("--detected", action="store_true", help="timeline/export: only events with a detection")
    p.add_argument("--limit", type=int, default=100)
    p.add_argument("--year", type=int, default=None, help="import: year for syslog lines that have none")
    p.add_argument("--out", help="report/export: file to write")
    p.add_argument("--json", action="store_true")
    p.add_argument("--user", default="cli")


def run(a) -> int | None:
    if a.cmd != "dfir":
        return None
    from ..config import get_config
    from . import service as S
    from .config import of
    cfg = get_config()
    if not of(cfg).enabled:
        print("investigations are off: set dfir.enabled: true in config.yaml (docs/dfir.md)", file=sys.stderr)
        return 2
    st = S.store_for(cfg)
    out = lambda x: print(json.dumps(x, indent=1, default=str))  # noqa: E731
    if a.action == "list":
        for c in st.cases():
            print(f"{c['id']}  {c['status']:6} {c['events']:>9} events  {c['title']}")
        return 0
    if a.action == "new":
        if not a.args:
            print("new needs a title", file=sys.stderr)
            return 2
        c = st.create_case(" ".join(a.args), a.description, actor=a.user)
        print(c["id"])
        return 0
    if not a.args or not st.case(a.args[0]):
        print("give an investigation id (see: actaeon dfir list)", file=sys.stderr)
        return 2
    cid, rest = a.args[0], a.args[1:]
    if a.action == "import":
        files = [f for x in rest for f in (sorted(p for p in Path(x).rglob("*") if p.is_file()) if Path(x).is_dir()
                                           else [Path(x)])]
        if not files:
            print("import needs one or more files or folders", file=sys.stderr)
            return 2
        bad = 0
        for f in files:
            try:
                r = S.import_file(cfg, cid, f, f.name, actor=a.user, year=a.year)
            except Exception as exc:
                print(f"FAIL {f}: {exc}")
                bad += 1
                continue
            state = "already imported" if r.get("duplicate") else f"{r['status']}, {r['events']} events, {r['errors']} unreadable"
            print(f"{f.name}: {state}  sha256 {r['sha256']}" + (f"  ({r['note']})" if r.get("note") else ""))
            bad += r.get("status") == "failed"
        return 1 if bad else 0
    if a.action == "analyze":
        res = S.analyze(cfg, cid)
        sig = res["sigma"]
        print(f"{sig['rules']} rules run, {sig['matched_rules']} matched, {sig['hits']} hits, {sig['imported']} imported "
              f"detections, {res['bruteforce_hits']} logon(s) after a burst of failures; {sig['skipped_count']} rule(s) "
              "skipped (not testable locally)")
        for d in st.detection_summary(cid)[:40]:
            print(f"  {d['level']:13} {d['n']:>6}  {d['title']}")
        return 0
    if a.action == "show":
        o = S.overview(cfg, cid)
        if a.json:
            out(o)
            return 0
        print(f"{o['title']}  ({o['events']} events, {o['span'].get('first')} to {o['span'].get('last')})")
        for s in o["sources"]:
            print(f"  {s['status']:9} {s['events']:>8} {s['name']}  {s['sha256']}")
        for d in o["detections"][:30]:
            print(f"  {d['level']:13} {d['n']:>6}  {d['title']}")
        return 0
    if a.action in ("timeline", "export"):
        if a.action == "export":
            if not a.out:
                print("export needs --out FILE.csv", file=sys.stderr)
                return 2
            Path(a.out).write_text(S.export_csv(cfg, cid, q=a.q, detected=a.detected), encoding="utf-8")
            print(f"wrote {a.out}")
            return 0
        rows, total = st.search(cid, q=a.q, detected=a.detected, limit=a.limit)
        for e in rows:
            rules = "; ".join(d["title"] for d in e["detections"])
            print(f"E{e['seq']:<7} {e['ts']} {e['host'][:20]:20} {e['summary'][:140]}" + (f"  [{rules}]" if rules else ""))
        print(f"{len(rows)} of {total}")
        return 0
    if a.action == "report":
        text = S.report_markdown(cfg, cid)
        if a.out:
            Path(a.out).write_text(text, encoding="utf-8")
            print(f"wrote {a.out}")
        else:
            print(text)
        return 0
    from ..hunt.service import privacy_llm
    from ..providers import get_llm
    from . import ai
    try:
        if a.action == "story":
            r = ai.story(cfg, privacy_llm(cfg, get_llm()), cid, actor=a.user)
            if a.json:
                out(r)
                return 0
            print(r["summary"])
            for p in r["phases"]:
                print(f"- {p['phase']} {p['when']}: {p['what']}  ({', '.join(f'E{x}' for x in p['events']) or 'NOT CITED'})")
            return 0
        r = ai.ask(cfg, privacy_llm(cfg, get_llm()), cid, " ".join(rest), actor=a.user)
        print(r["answer"])
        print("cited: " + (", ".join(f"E{x}" for x in r["events"]) or "none"))
        return 0
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 1
