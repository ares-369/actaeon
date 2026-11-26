"""Command line for the rule library: ``actaeon rules ...``."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ACTIONS = ["list", "show", "import", "test", "lint", "export", "coverage", "draft", "regress"]


def add_parsers(sub) -> None:
    p = sub.add_parser("rules", help="detection rule library: list | show ID | import PATH | test ID|--all | lint ID | "
                                     "export --out FILE.zip | coverage | draft TECHNIQUE | regress SAMPLES --baseline F")
    p.add_argument("action", choices=ACTIONS)
    p.add_argument("target", nargs="?", help="rule id, a file/folder to import, or a technique id to draft")
    p.add_argument("--status", default="", help="list: only this status; export: comma list (default ready)")
    p.add_argument("--all", action="store_true", help="test: every rule that is not retired")
    p.add_argument("--out", help="export: zip file to write")
    p.add_argument("--context", default="", help="draft: notes or an advisory for the model (text or @file)")
    p.add_argument("--json", action="store_true", help="print JSON")
    p.add_argument("--baseline", help="regress: baseline file (JSON) to compare with")
    p.add_argument("--update", action="store_true", help="regress: write the current result as the baseline")
    p.add_argument("--user", default="cli")


def run(a) -> int | None:
    if a.cmd != "rules":
        return None
    from ..config import get_config
    from . import service as S
    from .config import of
    cfg = get_config()
    if not of(cfg).enabled:
        print("the rule library is off: set rules.enabled: true in config.yaml (docs/rules.md)", file=sys.stderr)
        return 2
    out = lambda x: print(json.dumps(x, indent=1, default=str))  # noqa: E731
    st = S.store_for(cfg)
    if a.action == "list":
        rows = st.list(status=a.status or None)
        if a.json:
            out(rows)
        for r in rows if not a.json else []:
            last = r.get("last_run") or {}
            res = "-" if not last else ("pass" if last.get("ok") else f"{last.get('failed')} fail")
            print(f"{r['status']:8} v{r['version']:<3} {res:7} {r['id']}  {r['title']}  [{', '.join(r['attack'])}]")
        return 0
    if a.action == "coverage":
        cov = S.coverage(cfg)
        if a.json:
            out(cov)
            return 0
        for x in cov["techniques"]:
            mark = "GAP " if x["gap"] else "    "
            print(f"{mark}{x['technique']:10} ready {x['ready']} testing {x['testing']} draft {x['draft']}  "
                  f"{x['name']}  ({'; '.join(x['reasons']) or 'no demand recorded'})")
        print(f"\n{cov['ready']} technique(s) with a ready rule, {cov['gaps']} gap(s). {cov['note']}")
        return 0
    if a.action == "regress":
        from . import regress
        if not a.target or not a.baseline:
            print("regress needs a samples file or folder and --baseline FILE", file=sys.stderr)
            return 2
        now = regress.run(cfg, Path(a.target))
        if a.update:
            Path(a.baseline).write_text(json.dumps(now, indent=1, sort_keys=True), encoding="utf-8")
            print(f"baseline written: {len(now)} file(s), {sum(len(v) for v in now.values())} rule match(es)")
            return 0
        res = regress.compare(regress.load(Path(a.baseline)), now)
        if a.json:
            out(res)
        else:
            for x in res["lost"]:
                print(f"LOST   {x['file']}: {x['rule']} (matched {x['was']} event(s) before)")
            for x in res["fewer"]:
                print(f"fewer  {x['file']}: {x['rule']} {x['was']} -> {x['now']}")
            for x in res["new"]:
                print(f"new    {x['file']}: {x['rule']} ({x['now']})")
            for f, e in res["errors"].items():
                print(f"error  {f}: {e}")
            print(f"{len(res['lost'])} lost, {len(res['fewer'])} fewer, {len(res['new'])} new"
                  + (f", {len(res['missing_files'])} baseline file(s) missing" if res["missing_files"] else ""))
        return 0 if res["ok"] else 1
    if a.action == "import":
        if not a.target:
            print("import needs a file or folder of Sigma YAML", file=sys.stderr)
            return 2
        p = Path(a.target)
        files = sorted(x for x in p.rglob("*") if x.suffix in (".yml", ".yaml")) if p.is_dir() else [p]
        total = {"created": [], "updated": [], "unchanged": [], "errors": []}
        for f in files:
            res = S.import_text(cfg, f.read_text(encoding="utf-8", errors="replace"), actor=a.user, source=f.name)
            for k in total:
                total[k] += res[k]
        if a.json:
            out(total)
        else:
            print(f"created {len(total['created'])}, updated {len(total['updated'])}, unchanged "
                  f"{len(total['unchanged'])}, errors {len(total['errors'])}")
            for e in total["errors"][:50]:
                print("  " + e)
        return 0 if not total["errors"] else 1
    if a.action == "export":
        if not a.out:
            print("export needs --out FILE.zip", file=sys.stderr)
            return 2
        sts = tuple(x for x in (a.status or "ready").split(",") if x) or ("ready",)
        Path(a.out).write_bytes(S.export_zip(cfg, sts))
        print(f"wrote {a.out}")
        return 0
    if a.action == "draft":
        if not a.target:
            print("draft needs a technique id, e.g. T1059.001", file=sys.stderr)
            return 2
        from ..hunt.service import privacy_llm
        from ..providers import get_llm
        ctx = a.context
        if ctx.startswith("@"):
            ctx = Path(ctx[1:]).read_text(encoding="utf-8", errors="replace")
        try:
            r = S.draft_for_technique(cfg, privacy_llm(cfg, get_llm()), a.target, actor=a.user, context=ctx)
        except ValueError as exc:
            print(str(exc), file=sys.stderr)
            return 1
        print(f"draft {r['id']}  {r['title']}")
        print(r["sigma"])
        return 0
    if a.action == "test" and a.all:
        bad = 0
        for r in st.list(limit=5000):
            if r["status"] == "retired":
                continue
            res = S.run_tests(cfg, r["id"], actor=a.user)
            state = (res["unsupported"] and "unsupported") or ("pass" if res["ok"] else
                                                             "no tests" if not res["total"] else "FAIL")
            bad += state == "FAIL"
            print(f"{state:11} {res['passed']}/{res['total']}  {r['id']}  {r['title']}")
        return 1 if bad else 0
    if not a.target:
        print(f"{a.action} needs a rule id", file=sys.stderr)
        return 2
    if a.action == "test":
        try:
            res = S.run_tests(cfg, a.target, actor=a.user)
        except KeyError:
            print("no such rule", file=sys.stderr)
            return 1
        if a.json:
            out(res)
        else:
            if res["unsupported"]:
                print("cannot test locally: " + res["unsupported"])
            for x in res["results"]:
                print(f"{'ok  ' if x['ok'] else 'FAIL'} expect {x['expect']:8} {x['origin']:9} {x['name']}"
                      f"{'  ' + x['error'] if x['error'] else ''}")
            print(f"{res['passed']}/{res['total']} passed")
        return 0 if res.get("ok") else 1
    d = S.detail(cfg, a.target, actor=a.user)
    if not d:
        print("no such rule", file=sys.stderr)
        return 1
    if a.action == "lint":
        for x in d["lint"]:
            print(f"{x['level']:8} {x['text']}")
        print("no problems" if not d["lint"] else "")
        return 1 if any(x["level"] == "error" for x in d["lint"]) else 0
    if a.json:
        out(d)
        return 0
    print(f"{d['title']}  ({d['status']}, version {d['version']}, id {d['id']})")
    print(d["sigma"])
    print(f"tests: {len(d['tests'])}  last run: {d.get('last_run') or '-'}")
    for x in d["lint"]:
        print(f"lint {x['level']}: {x['text']}")
    for x in d["ready_problems"]:
        print(f"not ready: {x}")
    return 0
