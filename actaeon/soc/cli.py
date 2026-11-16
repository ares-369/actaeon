"""Command line for alert triage: ``actaeon alerts``, ``cases``, ``triage``, ``triage-bench``."""

from __future__ import annotations

import getpass
import json
import sys
from pathlib import Path


def add_parsers(sub) -> None:
    p = sub.add_parser("alerts", help="alerts import FILE (JSON list, object or JSON lines; - = stdin) | list | poll")
    p.add_argument("action", choices=["import", "list", "poll"])
    p.add_argument("file", nargs="?")
    p.add_argument("--source", default="import")
    p.add_argument("--limit", type=int, default=50)
    p = sub.add_parser("cases", help="alert cases: cases list | show ID [--markdown] | close ID --verdict V")
    p.add_argument("action", nargs="?", choices=["list", "show", "close"], default="list")
    p.add_argument("id", nargs="?")
    p.add_argument("--open", action="store_true")
    p.add_argument("--limit", type=int, default=50)
    p.add_argument("--markdown", action="store_true")
    p.add_argument("--verdict")
    p.add_argument("--note")
    p.add_argument("--user")
    p = sub.add_parser("triage", help="investigate one alert case now (or every new case) and print the verdict")
    p.add_argument("id", nargs="?")
    p.add_argument("--limit", type=int, default=20, help="with no id: at most this many new cases")
    p = sub.add_parser("triage-bench", help="scored alert-triage benchmark (demo cases, or --cases FILE on your data)")
    p.add_argument("--dir", help="bench home for the demo cases (default: a temporary folder)")
    p.add_argument("--offline", action="store_true", help="use the scripted provider (checks the pipeline only)")
    p.add_argument("--cases", help="YAML with labelled alerts to triage with the current configuration")
    p.add_argument("--json", help="write the full result to this file")
    p = sub.add_parser("shift-report", help="markdown summary of the last N hours of alert cases")
    p.add_argument("--hours", type=int, default=12)


def print_case(c: dict, *, full: bool = False) -> None:
    r = c.get("report") or {}
    print(f"case {c['id']}  {c.get('status')}  verdict {c.get('verdict') or '-'} ({c.get('confidence') or 0})  "
          f"severity {c.get('severity_label')}")
    print(f"  {c.get('title')}")
    if c.get("summary"):
        print(f"  {c['summary']}")
    if c.get("error"):
        print(f"  error: {c['error']}")
    if full:
        for f in r.get("findings") or []:
            print(f"   - {f.get('text')} [{', '.join(f.get('evidence') or [])}]")
        fix = r.get("fix") or {}
        for i, s in enumerate(fix.get("steps") or [], 1):
            print(f"   fix {i}. {s}")
        for a in c.get("actions") or []:
            print(f"   action #{a['id']} {a['name']} {a['target']}: {a['status']}")
        for ch in r.get("checks") or []:
            print(f"   check: {ch}")


def run(a) -> int | None:
    """Handle the command if it is one of ours; None otherwise."""
    if a.cmd not in ("alerts", "cases", "triage", "triage-bench", "shift-report"):
        return None
    if a.cmd == "triage-bench":
        return _bench(a)
    from ..config import get_config
    from .service import store_for
    cfg = get_config()
    store = store_for(cfg)
    if a.cmd == "alerts":
        if a.action == "import":
            from .intake import ingest, load_file
            text = Path(a.file).read_text() if a.file and a.file != "-" else sys.stdin.read()
            print(json.dumps(ingest(cfg, store, load_file(text), source=a.source), indent=2))
        elif a.action == "poll":
            from ..connectors import get_hub
            from .intake import poll_source
            for src in cfg.soc.intake.sources:
                print(src["name"], json.dumps(poll_source(cfg, store, get_hub(cfg), src)))
            get_hub().close()
        else:
            for x in store.alerts(limit=a.limit):
                print(f"{x['ts'][:19]}  {x['severity']:3}  {x['status']:15}  {(x.get('case_id') or '-'):12}  "
                      f"{x['title'][:70]}")
        return 0
    if a.cmd == "cases":
        if a.action == "show":
            c = store.get_case(a.id or "")
            if not c:
                print("no such case")
                return 1
            if a.markdown:
                from .report import case_markdown
                print(case_markdown(c))
            else:
                print_case(c, full=True)
        elif a.action == "close":
            from .service import close_case
            close_case(store, a.id or "", user=a.user or getpass.getuser(), verdict=a.verdict or "", note=a.note or "")
            print("closed")
        else:
            for c in store.cases(limit=a.limit, open_only=a.open):
                print(f"{c['id']}  {c['status']:13} {(c.get('verdict') or '-'):15} {c.get('confidence') or 0:3}  "
                      f"{c['severity_label']:8} {c['alert_count']:3} alerts  {c['title'][:60]}")
        return 0
    if a.cmd == "shift-report":
        from .report import shift_markdown
        print(shift_markdown(store, a.hours))
        return 0
    from ..connectors import get_hub
    from .service import triage_case
    ids = [a.id] if a.id else [c["id"] for c in store.cases(status="new", limit=a.limit)]
    if not ids:
        print("no new cases")
    for cid in ids:
        print_case(triage_case(cfg, cid, actor="cli", manual=True), full=True)
        print()
    get_hub().close()
    return 0


def _bench(a) -> int:
    from .bench import run_bench, run_cases
    if a.cases:
        res = run_cases(Path(a.cases).expanduser())
    else:
        res = run_bench(Path(a.dir).expanduser() if a.dir else None, offline=a.offline)
    for r in res["cases"]:
        print(f"{'PASS' if r['pass'] else 'FAIL'} {r['name'][:28]:28} expected {r['expected']:15} got "
              f"{r['verdict'] or '-':15} status {r['status']:13} conf {r['confidence']:3} calls {r['calls']:2} "
              f"{r['seconds']:6.0f}s")
    s = res["score"]
    print(f"\n{s['passed']}/{s['total']} correct; true positives found {s['tp_found']}/{s['tp_total']} "
          f"(recall {s['recall']}); false alarms {s['false_alarms']} (precision {s['precision']}); handed to an "
          f"analyst {s['handed_over']}; wrongly closed {s['wrong_closures']}; claims with evidence "
          f"{s['evidence_coverage']}; tokens {s['tokens']}; median {s['median_seconds']} s per case")
    if a.offline:
        print("(offline: the scripted demo provider was used, so this checks the pipeline, not a model)")
    if a.json:
        Path(a.json).write_text(json.dumps(res, indent=1))
    return 0 if s["passed"] == s["total"] else 1
