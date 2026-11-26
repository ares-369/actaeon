"""Web API for investigations. Every route except /api/dfir/status answers 404 while dfir.enabled is false.

Evidence import and the analyzers run as jobs (actaeon/tasks.py: dfir-import, dfir-analyze), so in
``jobs.mode: queue`` a worker runs them and they survive a server restart. Uploaded files are kept until their
import finishes; an import cut off by a restart shows as interrupted and can run again.
"""

from __future__ import annotations

import secrets
import time
from pathlib import Path

from flask import Response, g, jsonify, request


def register(app, jobs) -> None:
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

    def job_state(cid: str) -> dict | None:
        c = S.store_for(get_config()).case(cid) or {}
        if not c.get("job_id"):
            return None
        j = jobs.get(c["job_id"]) or {}
        st = j.get("status") or "gone"
        return {"what": c.get("job_what") or "", "status": st, "running": st in ("queued", "running"),
                "error": j.get("error") or "", "result": j.get("result")}

    def start(cid: str, what: str, task: str, params: dict) -> bool:
        w = job_state(cid)
        if w and w["running"]:
            return False
        jid = jobs.submit("dfir", {"case": cid, "what": what, "t": time.time()}, None, deduplicate=False, task=task,
                          params=params)
        S.store_for(get_config()).update_case(cid, job_id=jid, job_what=what)
        return True

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
            ch = {k: str(v)[:4000] for k, v in body().items() if k in ("title", "description", "status", "assignee")}
            S.store_for(c).update_case(cid, **ch)
            if ch:
                S.store_for(c).log(cid, actor(), "update", ", ".join(f"{k}: {v[:80]}" for k, v in ch.items()))
        work = job_state(cid)          # read before the overview: a job that ends in between must not leave old numbers
        o = S.overview(c, cid)
        if not o:
            return bad("not found", 404)
        o["work"] = work
        o["interrupted"] = [x["id"] for x in S.interrupted(c, cid, jobs)]
        o["activity"] = S.store_for(c).activity(cid, 50)
        return jsonify(o)

    @app.route("/api/dfir/cases/<cid>/delete", methods=["POST"])
    def dfir_delete(cid):
        if not case_or_404(cid):
            return bad("not found", 404)
        if (job_state(cid) or {}).get("running"):
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
        if (job_state(cid) or {}).get("running"):
            return bad("an import or analysis is already running for this investigation", 409)
        folder = S.uploads_dir(c, cid)
        saved = []
        for i, f in enumerate(files[:50]):
            name = Path(str(f.filename or f"upload-{i}")).name[:200] or f"upload-{i}"
            p = folder / f"{secrets.token_hex(4)}-{name}"
            f.save(p)
            saved.append([str(p), name])
        if not start(cid, f"importing {len(saved)} file(s)", "dfir-import",
                     {"case_id": cid, "files": saved, "actor": actor(),
                      "host": str(request.form.get("host", ""))[:200]}):
            for p, _ in saved:
                Path(p).unlink(missing_ok=True)
            return bad("an import or analysis is already running for this investigation", 409)
        return jsonify({"started": True, "files": [n for _, n in saved]}), 202

    @app.route("/api/dfir/cases/<cid>/analyze", methods=["POST"])
    def dfir_analyze(cid):
        if not case_or_404(cid):
            return bad("not found", 404)
        if not start(cid, "running the analyzers", "dfir-analyze", {"case_id": cid, "actor": actor()}):
            return bad("an import or analysis is already running for this investigation", 409)
        return jsonify({"started": True}), 202

    @app.route("/api/dfir/cases/<cid>/intel", methods=["POST"])
    def dfir_intel(cid):
        if not case_or_404(cid):
            return bad("not found", 404)
        if not start(cid, "checking indicators against intel", "dfir-intel", {"case_id": cid, "actor": actor()}):
            return bad("an import or analysis is already running for this investigation", 409)
        return jsonify({"started": True}), 202

    @app.route("/api/dfir/cases/<cid>/pull", methods=["POST"])
    def dfir_pull(cid):
        if not case_or_404(cid):
            return bad("not found", 404)
        b = body()
        conn, tool = str(b.get("connector", ""))[:100], str(b.get("tool", ""))[:100]
        args = b.get("arguments") or {}
        if not conn or not tool or not isinstance(args, dict):
            return bad("send connector, tool and arguments (a JSON object)")
        from ..connectors import get_hub
        try:
            allowed = {t["name"] for t in get_hub(get_config()).tools(conn) if t.get("allowed")}
        except Exception as exc:
            return bad(f"connector {conn}: {exc}")
        if tool not in allowed:
            return bad(f"{conn}.{tool} is not an allowed (read-only) tool")
        if not start(cid, f"pulling {conn}.{tool}", "dfir-pull", {"case_id": cid, "connector": conn, "tool": tool,
                                                                 "arguments": args, "actor": actor(),
                                                                 "host": str(b.get("host", ""))[:200]}):
            return bad("an import or analysis is already running for this investigation", 409)
        return jsonify({"started": True}), 202

    @app.route("/api/dfir/from-soc/<sid>", methods=["GET", "POST"])
    def dfir_from_soc(sid):
        c = get_config()
        if request.method == "GET":
            return jsonify(S.store_for(c).by_soc_case(sid))
        try:
            r = S.from_soc_case(c, sid, actor=actor())
        except KeyError:
            return bad("alert case not found", 404)
        return jsonify(r), (200 if r["existing"] else 201)

    @app.route("/api/dfir/cases/<cid>/sources/<sid>/retry", methods=["POST"])
    def dfir_retry(cid, sid):
        c = get_config()
        if sid not in [x["id"] for x in S.interrupted(c, cid, jobs)]:
            return bad("only an interrupted import can run again", 409)
        try:
            files = S.retry_source(c, cid, sid, actor=actor())
        except KeyError:
            return bad("not found", 404)
        except ValueError as exc:
            return bad(exc, 409)
        if not start(cid, "importing 1 file(s) again", "dfir-import", {"case_id": cid, "files": files, "actor": actor()}):
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
            if e:
                st.log(cid, actor(), "mark", f"E{seq} " + ", ".join(k for k in ("star", "tags", "comment") if k in b))
        else:
            e = st.event(cid, seq)
        return jsonify(e) if e else bad("not found", 404)

    @app.route("/api/dfir/cases/<cid>/events/<int:seq>/tree")
    def dfir_tree(cid, seq):
        from .views import process_tree
        try:
            return jsonify(process_tree(S.store_for(get_config()), cid, seq))
        except KeyError:
            return bad("not found", 404)

    @app.route("/api/dfir/cases/<cid>/notes", methods=["POST"])
    def dfir_note(cid):
        if not case_or_404(cid):
            return bad("not found", 404)
        b = body()
        try:
            n = S.store_for(get_config()).add_note(
                cid, str(b.get("kind", "note")), str(b.get("text", "")), author=actor(),
                events=[int(x) for x in b.get("events") or [] if str(x).isdigit()][:50])
            S.store_for(get_config()).log(cid, actor(), n["kind"], n["text"][:200])
            return jsonify(n), 201
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
            r = ai.story(c, llm(), cid, actor=actor())
        except ValueError as exc:
            return bad(exc)
        S.store_for(c).log(cid, actor(), "story", f"{r['events_given']} events, {r['weak_parts']} weak part(s)")
        return jsonify(r), 201

    @app.route("/api/dfir/cases/<cid>/ask", methods=["POST"])
    def dfir_ask(cid):
        from . import ai
        if not case_or_404(cid):
            return bad("not found", 404)
        try:
            r = ai.ask(get_config(), llm(), cid, str(body().get("question", "")), actor=actor())
        except ValueError as exc:
            return bad(exc)
        S.store_for(get_config()).log(cid, actor(), "ask", r["question"][:200])
        return jsonify(r)

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

    @app.route("/api/dfir/cases/<cid>/navigator.json")
    def dfir_navigator(cid):
        import json

        from ..navigator import case_layer
        c = case_or_404(cid)
        if not c:
            return bad("not found", 404)
        body = case_layer(c["title"], S.store_for(get_config()).detection_summary(cid))
        return Response(json.dumps(body, indent=1), mimetype="application/json",
                        headers={"Content-Disposition": f"attachment; filename=investigation-{cid}-layer.json"})

    @app.route("/api/dfir/cases/<cid>/report.md")
    def dfir_report(cid):
        if not case_or_404(cid):
            return bad("not found", 404)
        return Response(S.report_markdown(get_config(), cid), mimetype="text/markdown",
                        headers={"Content-Disposition": f"attachment; filename=investigation-{cid}.md"})
