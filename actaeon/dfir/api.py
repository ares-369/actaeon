"""Web API for investigations. Every route except /api/dfir/status answers 404 while dfir.enabled is false.

Evidence import and the analyzers run in a background thread (large files take minutes); the case shows what
is running in ``work``.
"""

from __future__ import annotations

import shutil
import tempfile
import threading
import time
from pathlib import Path

from flask import Response, g, jsonify, request

_work: dict[str, dict] = {}
_wlock = threading.Lock()


def _start(cid: str, what: str, fn) -> bool:
    with _wlock:
        cur = _work.get(cid)
        if cur and cur.get("running"):
            return False
        _work[cid] = {"what": what, "running": True, "started": time.time(), "error": "", "result": None}

    def run():
        try:
            res = fn()
            with _wlock:
                _work[cid].update(running=False, result=res)
        except Exception as exc:                 # shown to the analyst on the case page
            with _wlock:
                _work[cid].update(running=False, error=f"{type(exc).__name__}: {exc}"[:500])
    threading.Thread(target=run, daemon=True, name=f"dfir-{cid}").start()
    return True


def work_of(cid: str) -> dict | None:
    with _wlock:
        w = _work.get(cid)
        return dict(w) if w else None


def register(app) -> None:
    from ..config import get_config
    from . import service as S
    from .config import of

    def actor() -> str:
        return str(getattr(g, "actaeon_user", "") or "")

    def body() -> dict:
        b = request.get_json(silent=True)
        return b if isinstance(b, dict) else {}

    def bad(msg, code: int = 400):
        return jsonify({"error": str(msg)[:800]}), code

    def case_or_404(cid: str):
        return S.store_for(get_config()).case(cid)

    def llm():
        from ..hunt.service import privacy_llm
        from ..providers import get_llm
        c = get_config()
        return privacy_llm(c, get_llm())

    @app.before_request
    def _dfir_gate():
        p = request.path
        if p.startswith("/api/dfir") and p != "/api/dfir/status" and not of(get_config()).enabled:
            return jsonify({"error": "investigations are off (set dfir.enabled: true in config.yaml)"}), 404
        return None

    @app.route("/api/dfir/status")
    def dfir_status():
        c = get_config()
        d = of(c)
        try:
            import Evtx  # type: ignore[import-not-found]  # noqa: F401
            evtx = True
        except ImportError:
            evtx = False
        return jsonify({"enabled": d.enabled, "evtx": evtx, "max_upload_mb": d.max_upload_mb} if d.enabled
                       else {"enabled": False})

    @app.route("/api/dfir/cases", methods=["GET", "POST"])
    def dfir_cases():
        st = S.store_for(get_config())
        if request.method == "GET":
            return jsonify(st.cases())
        b = body()
        if not str(b.get("title", "")).strip():
            return bad("an investigation needs a title")
        return jsonify(st.create_case(str(b["title"]), str(b.get("description", "")), actor=actor())), 201

    @app.route("/api/dfir/cases/<cid>", methods=["GET", "POST"])
    def dfir_case(cid):
        c = get_config()
        if request.method == "POST":
            if not case_or_404(cid):
                return bad("not found", 404)
            S.store_for(c).update_case(cid, **{k: str(v) for k, v in body().items()
                                               if k in ("title", "description", "status")})
        work = work_of(cid)            # read before the overview: a job that ends in between must not leave old numbers
        o = S.overview(c, cid)
        if not o:
            return bad("not found", 404)
        o["work"] = work
        return jsonify(o)

    @app.route("/api/dfir/cases/<cid>/delete", methods=["POST"])
    def dfir_delete(cid):
        if not case_or_404(cid):
            return bad("not found", 404)
        if (work_of(cid) or {}).get("running"):
            return bad("wait for the running import or analysis to finish", 409)
        S.store_for(get_config()).delete_case(cid)
        return jsonify({"deleted": cid})

    @app.route("/api/dfir/cases/<cid>/upload", methods=["POST"])
    def dfir_upload(cid):
        c = get_config()
        if not case_or_404(cid):
            return bad("not found", 404)
        limit = of(c).max_upload_mb << 20
        if (request.content_length or 0) > limit:
            return bad(f"the upload is larger than dfir.max_upload_mb ({of(c).max_upload_mb} MB)", 413)
        files = request.files.getlist("files")
        if not files:
            return bad("send one or more files in the form field 'files'")
        tmp = Path(tempfile.mkdtemp(prefix="dfir-", dir=c.data_dir))
        saved = []
        for i, f in enumerate(files[:50]):
            name = Path(str(f.filename or f"upload-{i}")).name[:200] or f"upload-{i}"
            p = tmp / f"{i}-{name}"
            f.save(p)
            saved.append((p, name))
        who = actor()

        def run():
            try:
                return [S.import_file(c, cid, p, name, actor=who) for p, name in saved]
            finally:
                shutil.rmtree(tmp, ignore_errors=True)
        if not _start(cid, f"importing {len(saved)} file(s)", run):
            shutil.rmtree(tmp, ignore_errors=True)
            return bad("an import or analysis is already running for this investigation", 409)
        return jsonify({"started": True, "files": [n for _, n in saved]}), 202

    @app.route("/api/dfir/cases/<cid>/analyze", methods=["POST"])
    def dfir_analyze(cid):
        c = get_config()
        if not case_or_404(cid):
            return bad("not found", 404)
        if not _start(cid, "running the analyzers", lambda: S.analyze(c, cid)):
            return bad("an import or analysis is already running for this investigation", 409)
        return jsonify({"started": True}), 202

    @app.route("/api/dfir/cases/<cid>/events")
    def dfir_events(cid):
        if not case_or_404(cid):
            return bad("not found", 404)
        a = request.args
        rows, total = S.store_for(get_config()).search(
            cid, q=a.get("q", "")[:300], host=a.get("host", "")[:200], since=a.get("since", "")[:40],
            until=a.get("until", "")[:40], rule=a.get("rule", "")[:300], starred=a.get("starred") == "1",
            detected=a.get("detected") == "1", tag=a.get("tag", "")[:40], event_id=a.get("event_id", "")[:20],
            order=a.get("order", "ts"), limit=max(1, min(500, int(a.get("limit", 100) or 100))),
            offset=max(0, int(a.get("offset", 0) or 0)))
        return jsonify({"events": rows, "total": total})

    @app.route("/api/dfir/cases/<cid>/events/<int:seq>", methods=["GET", "POST"])
    def dfir_event(cid, seq):
        st = S.store_for(get_config())
        if request.method == "POST":
            b = body()
            e = st.mark(cid, seq, star=b.get("star") if isinstance(b.get("star"), bool) else None,
                        tags=[str(t) for t in b["tags"]] if isinstance(b.get("tags"), list) else None,
                        comment=str(b["comment"]) if "comment" in b else None)
        else:
            e = st.event(cid, seq)
        return jsonify(e) if e else bad("not found", 404)

    @app.route("/api/dfir/cases/<cid>/notes", methods=["POST"])
    def dfir_note(cid):
        if not case_or_404(cid):
            return bad("not found", 404)
        b = body()
        try:
            return jsonify(S.store_for(get_config()).add_note(
                cid, str(b.get("kind", "note")), str(b.get("text", "")), author=actor(),
                events=[int(x) for x in b.get("events") or [] if str(x).isdigit()][:50])), 201
        except ValueError as exc:
            return bad(exc)

    @app.route("/api/dfir/cases/<cid>/notes/<int:nid>/status", methods=["POST"])
    def dfir_note_status(cid, nid):
        try:
            S.store_for(get_config()).set_note_status(cid, nid, str(body().get("status", "")))
        except ValueError as exc:
            return bad(exc)
        return jsonify({"ok": True})

    @app.route("/api/dfir/cases/<cid>/story", methods=["GET", "POST"])
    def dfir_story(cid):
        from . import ai
        c = get_config()
        if not case_or_404(cid):
            return bad("not found", 404)
        if request.method == "GET":
            st = S.store_for(c)
            return jsonify({"stories": st.stories(cid, "story", 5), "answers": st.stories(cid, "answer", 20)})
        try:
            return jsonify(ai.story(c, llm(), cid, actor=actor())), 201
        except ValueError as exc:
            return bad(exc)

    @app.route("/api/dfir/cases/<cid>/ask", methods=["POST"])
    def dfir_ask(cid):
        from . import ai
        if not case_or_404(cid):
            return bad("not found", 404)
        try:
            return jsonify(ai.ask(get_config(), llm(), cid, str(body().get("question", "")), actor=actor()))
        except ValueError as exc:
            return bad(exc)

    @app.route("/api/dfir/cases/<cid>/export.csv")
    def dfir_export(cid):
        if not case_or_404(cid):
            return bad("not found", 404)
        a = request.args
        text = S.export_csv(get_config(), cid, q=a.get("q", "")[:300], host=a.get("host", "")[:200],
                            starred=a.get("starred") == "1", detected=a.get("detected") == "1",
                            rule=a.get("rule", "")[:300])
        return Response(text, mimetype="text/csv",
                        headers={"Content-Disposition": f"attachment; filename=investigation-{cid}.csv"})

    @app.route("/api/dfir/cases/<cid>/report.md")
    def dfir_report(cid):
        if not case_or_404(cid):
            return bad("not found", 404)
        return Response(S.report_markdown(get_config(), cid), mimetype="text/markdown",
                        headers={"Content-Disposition": f"attachment; filename=investigation-{cid}.md"})
