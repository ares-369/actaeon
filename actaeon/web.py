"""Flask app factory for the Actaeon web UI and JSON API."""

from __future__ import annotations

import time

from flask import Flask, jsonify, render_template, request
from werkzeug.middleware.proxy_fix import ProxyFix

from . import __version__
from .auth import init_auth
from .config import LLM_ROLES, PROVIDERS, apply_llm_update, get_config, preview_llm_update
from .jobs import JobManager


def requests_exc():
    import requests
    return requests.RequestException


def create_app(cfg=None, *, start_scheduler: bool = False) -> Flask:
    cfg = cfg or get_config()
    app = Flask(__name__, static_folder="static", template_folder="templates")
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)  # type: ignore[method-assign]
    init_auth(app, cfg)
    cfg.data_dir.mkdir(parents=True, exist_ok=True)
    jobs = JobManager(cfg.data_dir / "actaeon.sqlite")
    app.extensions["actaeon_jobs"] = jobs

    @app.after_request
    def _security_headers(resp):
        resp.headers.setdefault("Content-Security-Policy",
                                "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
                                "font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; "
                                "form-action 'self'")
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("Referrer-Policy", "no-referrer")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        return resp

    @app.route("/")
    def index():
        return render_template("index.html", name=cfg.instance_name, version=__version__,
                               demo=bool((cfg.raw.get("actaeon") or {}).get("demo")))

    @app.route("/api/status")
    def status():
        c = get_config()
        return jsonify({
            "version": __version__,
            "instance": c.instance_name,
            "auth_mode": c.auth.mode,
            "connectors": len(c.connectors),
            "roles": {r: c.role_cfg(r) for r in LLM_ROLES},
        })

    @app.route("/api/settings/llm", methods=["GET", "POST"])
    def settings_llm():
        if request.method == "GET":
            c = get_config()
            return jsonify({
                "roles": {r: c.role_cfg(r) for r in LLM_ROLES},
                "providers": list(PROVIDERS),
                "configured": list((c.llm.get("providers") or {}).keys()),
            })
        body = request.get_json(silent=True) or {}
        roles = body.get("roles") or {}
        try:
            if body.get("preview"):
                return jsonify(preview_llm_update(roles))
            c = apply_llm_update(roles)
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400
        from .providers import get_llm
        get_llm(reload=True)
        return jsonify({"ok": True, "roles": {r: c.role_cfg(r) for r in LLM_ROLES}})

    def hub():
        from .connectors import get_hub
        return get_hub(get_config())

    @app.route("/api/connectors")
    def connectors():
        return jsonify([s.public() for s in hub().specs.values()])

    @app.route("/api/connectors/<name>/tools")
    def connector_tools(name):
        h = hub()
        if name not in h.specs:
            return jsonify({"error": "not found"}), 404
        try:
            return jsonify(h.tools(name, refresh=request.args.get("refresh") == "1"))
        except Exception as exc:
            return jsonify({"error": str(exc)[:300]}), 502

    @app.route("/api/connectors/<name>/test", methods=["POST"])
    def connector_test(name):
        h = hub()
        if name not in h.specs:
            return jsonify({"error": "not found"}), 404
        return jsonify(h.test(name))

    @app.route("/api/audit")
    def audit():
        return jsonify(hub().audit.recent(limit=min(500, int(request.args.get("limit", 100))),
                                          hunt_id=request.args.get("hunt_id") or None))

    def intel_store():
        from .intel import IntelStore
        return IntelStore(get_config().data_dir / "intel.sqlite")

    def _intel_kw(b):
        try:
            conf = int(b.get("confidence", 50))
        except (TypeError, ValueError):
            conf = 50
        tags = b.get("tags") or []
        if isinstance(tags, str):
            tags = [t.strip() for t in tags.split(",")]
        return {"confidence": conf, "tags": [str(t) for t in tags][:20]}

    @app.route("/api/intel/stats")
    def intel_stats():
        return jsonify(intel_store().stats())

    @app.route("/api/intel/indicators", methods=["GET", "POST"])
    def intel_indicators():
        st = intel_store()
        if request.method == "GET":
            return jsonify(st.list(kind=request.args.get("type") or None, tag=request.args.get("tag") or None,
                                   search=request.args.get("q", ""), limit=min(1000, int(request.args.get("limit", 100)))))
        b = request.get_json(silent=True) or {}
        kw = _intel_kw(b)
        if b.get("text"):
            if b.get("preview"):
                from .intel import extract
                return jsonify({"found": extract(str(b["text"])[:200_000])})
            r = st.add_text(str(b["text"])[:200_000], source=str(b.get("source") or "paste")[:60], **kw)
            return jsonify({k: r[k] for k in ("found", "new", "updated")})
        out, errors = [], []
        for v in (b.get("values") or [])[:5000]:
            try:
                out.append(st.add(str(v), b.get("type") or None, source=str(b.get("source") or "manual")[:60], **kw))
            except ValueError as exc:
                errors.append(str(exc))
        return jsonify({"added": out, "errors": errors})

    @app.route("/api/intel/indicators/<int:iid>/deactivate", methods=["POST"])
    def intel_deactivate(iid):
        return jsonify({"ok": intel_store().deactivate(iid)})

    @app.route("/api/intel/lookup")
    def intel_lookup():
        return jsonify(intel_store().lookup(request.args.get("value", "")))

    @app.route("/api/intel/advisories", methods=["GET", "POST"])
    def intel_advisories():
        st = intel_store()
        if request.method == "GET":
            return jsonify(st.advisories())
        b = request.get_json(silent=True) or {}
        if not str(b.get("text", "")).strip():
            return jsonify({"error": "text is required"}), 400
        return jsonify(st.add_advisory(str(b.get("title", ""))[:300], str(b["text"])[:200_000],
                                       source=str(b.get("source") or "advisory")[:60], url=str(b.get("url", ""))[:500],
                                       **_intel_kw(b)))

    @app.route("/api/intel/advisories/<int:aid>")
    def intel_advisory(aid):
        d = intel_store().advisory(aid)
        return (jsonify(d), 200) if d else (jsonify({"error": "not found"}), 404)

    @app.route("/api/intel/feeds/<name>/pull", methods=["POST"])
    def intel_pull(name):
        from .intel.feeds import pull_feed
        f = next((f for f in get_config().intel.get("feeds") or [] if f.get("name") == name), None)
        if not f:
            return jsonify({"error": "not found"}), 404
        try:
            return jsonify(pull_feed(intel_store(), f))
        except Exception as exc:
            return jsonify({"error": str(exc)[:300]}), 502

    from .hunt import service as hs
    from .hunt.library import starters
    from .hunt.service import start_hunt, store_for
    store_for(cfg).mark_orphans()
    if start_scheduler:
        from .hunt.scheduler import Scheduler
        app.extensions["actaeon_scheduler"] = Scheduler(cfg, jobs)
        app.extensions["actaeon_scheduler"].start()

    def _actor():
        from flask import session
        return str(session.get("user") or (request.authorization.username if request.authorization else "") or "")

    @app.route("/api/hunts", methods=["GET", "POST"])
    def hunts():
        if request.method == "GET":
            return jsonify(store_for(get_config()).list(limit=min(200, int(request.args.get("limit", 50)))))
        b = request.get_json(silent=True) or {}
        try:
            hid = start_hunt(jobs, get_config(), str(b.get("hypothesis", ""))[:4000], actor=_actor(),
                             context=str(b.get("context", ""))[:8000], max_steps=b.get("max_steps"))
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400
        return jsonify({"hunt_id": hid}), 202

    @app.route("/api/hunts/advisory/<int:aid>", methods=["POST"])
    def hunt_advisory(aid):
        c = get_config()
        try:
            hyp, ctx = hs.advisory_hunt(c, aid)
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 404
        return jsonify({"hunt_id": start_hunt(jobs, c, hyp, actor=_actor(), origin=f"advisory:{aid}",
                                              context=ctx)}), 202

    @app.route("/api/library", methods=["GET", "POST"])
    def library():
        c = get_config()
        lib = hs.library_for(c)
        if request.method == "GET":
            return jsonify({"saved": lib.list(), "starters": starters()})
        b = request.get_json(silent=True) or {}
        h = store_for(c).get(str(b.get("hunt_id", "")))
        if not h:
            return jsonify({"error": "hunt not found"}), 404
        try:
            return jsonify(lib.save_from_hunt(h, name=str(b.get("name", ""))[:200],
                                              interval_minutes=int(b.get("interval_minutes", 0) or 0),
                                              escalate=bool(b.get("escalate"))))
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400

    @app.route("/api/library/<int:sid>", methods=["GET", "POST"])
    def library_item(sid):
        lib = hs.library_for(get_config())
        if request.method == "POST":
            b = request.get_json(silent=True) or {}
            item = lib.set(sid, **b)
        else:
            item = lib.get(sid)
        return (jsonify(item), 200) if item else (jsonify({"error": "not found"}), 404)

    @app.route("/api/library/<int:sid>/<action>", methods=["POST"])
    def library_action(sid, action):
        c = get_config()
        lib = hs.library_for(c)
        if not lib.get(sid):
            return jsonify({"error": "not found"}), 404
        if action == "delete":
            return jsonify({"ok": lib.delete(sid)})
        if action == "run":
            jid = hs.start_job(jobs, "replay", {"saved_id": sid},
                               lambda: hs.run_replay(c, sid, jobs=jobs, actor=_actor() or "manual"))
            return jsonify({"job_id": jid}), 202
        return jsonify({"error": "unknown action"}), 400

    @app.route("/api/intel/web/pull", methods=["POST"])
    def intel_web_pull():
        c = get_config()
        jid = hs.start_job(jobs, "web-intel", {"web": True},
                           lambda: hs.run_web_intel(c, jobs=jobs))
        return jsonify({"job_id": jid}), 202

    @app.route("/api/autopilot", methods=["POST"])
    def autopilot():
        c = get_config()
        b = request.get_json(silent=True) or {}
        if b.get("dry_run", True):
            try:
                r = hs.run_autopilot(c, jobs, dry_run=True)
            except RuntimeError as exc:
                return jsonify({"error": str(exc)[:300]}), 502
            return jsonify(r)
        jid = hs.start_job(jobs, "autopilot", {"autopilot": True}, lambda: hs.run_autopilot(c, jobs))
        return jsonify({"job_id": jid}), 202

    @app.route("/api/intel/sweep", methods=["POST"])
    def intel_sweep():
        c = get_config()
        full = bool((request.get_json(silent=True) or {}).get("full"))
        jid = hs.start_job(jobs, "sweep", {"sweep": True, "full": full},
                           lambda: hs.run_sweep(c, full=full, actor=_actor() or "manual"))
        return jsonify({"job_id": jid}), 202

    @app.route("/api/memory/notes", methods=["GET", "POST"])
    def memory_notes():
        mem = hs.memory_for(get_config())
        if request.method == "GET":
            return jsonify(mem.notes())
        b = request.get_json(silent=True) or {}
        try:
            return jsonify(mem.add_note(str(b.get("text", "")), author=_actor(), tags=b.get("tags") or []))
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400

    @app.route("/api/memory/notes/<int:nid>/retire", methods=["POST"])
    def memory_retire(nid):
        return jsonify({"ok": hs.memory_for(get_config()).retire_note(nid)})

    @app.route("/api/memory/related")
    def memory_related():
        return jsonify(hs.memory_for(get_config()).related(request.args.get("q", "")))

    @app.route("/api/coverage")
    def coverage():
        from .hunt.coverage import build
        c = get_config()
        return jsonify(build(store_for(c), hs.library_for(c), hub().specs))

    def _hunt_or_404(hid):
        h = store_for(get_config()).get(hid)
        if not h:
            from flask import abort
            abort(404)
        return h

    @app.route("/api/hunts/<hid>/report.md")
    def hunt_report(hid):
        from .hunt.report import markdown
        h = _hunt_or_404(hid)
        return app.response_class(markdown(h, narrative=h.get("narrative") or ""), mimetype="text/markdown",
                                  headers={"Content-Disposition": f'attachment; filename="hunt-{hid}.md"'})

    @app.route("/api/hunts/<hid>/export.json")
    def hunt_export_json(hid):
        import json as _json
        return app.response_class(_json.dumps(_hunt_or_404(hid), indent=1), mimetype="application/json",
                                  headers={"Content-Disposition": f'attachment; filename="hunt-{hid}.json"'})

    @app.route("/api/hunts/<hid>/export.csv")
    def hunt_export_csv(hid):
        from .hunt.report import steps_csv
        return app.response_class(steps_csv(_hunt_or_404(hid)), mimetype="text/csv",
                                  headers={"Content-Disposition": f'attachment; filename="hunt-{hid}.csv"'})

    @app.route("/api/hunts/<hid>/feedback", methods=["POST"])
    def hunt_feedback(hid):
        b = request.get_json(silent=True) or {}
        try:
            return jsonify(hs.add_feedback(get_config(), hid, finding=int(b.get("finding", -1)),
                                           kind=str(b.get("kind", "")), comment=str(b.get("comment", "")),
                                           author=_actor()))
        except LookupError:
            return jsonify({"error": "not found"}), 404
        except (ValueError, TypeError) as exc:
            return jsonify({"error": str(exc)}), 400

    @app.route("/api/decode", methods=["POST"])
    def decode_api():
        from .decode import decode
        return jsonify(decode(str((request.get_json(silent=True) or {}).get("text", ""))[:200_000]))

    @app.route("/api/intel/advisories/import", methods=["POST"])
    def intel_import_advisory():
        from .intel.fetch import FetchError, fetch_url, pdf_to_text
        c = get_config()
        try:
            if request.files.get("file"):
                f = request.files["file"]
                data = f.read(15_000_001)
                if len(data) > 15_000_000:
                    return jsonify({"error": "file is larger than 15 MB"}), 400
                text = pdf_to_text(data) if data[:5] == b"%PDF-" else data.decode("utf-8", "replace")
                doc = {"title": (f.filename or "upload")[:200], "text": text, "url": ""}
                form = request.form
            else:
                form = request.get_json(silent=True) or {}
                doc = fetch_url(str(form.get("url", "")),
                                allow_private=bool((c.intel or {}).get("allow_private_urls", False)))
        except FetchError as exc:
            return jsonify({"error": str(exc)}), 400
        except requests_exc() as exc:
            return jsonify({"error": f"could not fetch: {exc}"}), 502
        title = str(form.get("title") or doc["title"] or doc.get("url") or "Imported advisory")[:300]
        try:
            conf = int(form.get("confidence", 50))
        except (TypeError, ValueError):
            conf = 50
        r = intel_store().add_advisory(title, doc["text"], source="import", url=doc.get("url", ""), confidence=conf,
                                       strict_links=True)
        return jsonify({**r, "title": title, "chars": len(doc["text"])})

    @app.route("/api/hunts/<hid>/chat", methods=["GET", "POST"])
    def hunt_chat(hid):
        from .hunt.chat import ChatLog, ask
        c = get_config()
        if request.method == "GET":
            if not store_for(c).get(hid, with_steps=False):
                return jsonify({"error": "not found"}), 404
            return jsonify(ChatLog(store_for(c).path).list(hid))
        msg = str((request.get_json(silent=True) or {}).get("message", ""))
        h = store_for(c).get(hid, with_steps=False)
        if not h:
            return jsonify({"error": "not found"}), 404
        if h["status"] in ("queued", "running") or not msg.strip():
            return jsonify({"error": "the hunt is still running" if msg.strip() else "message is required"}), 400
        who = _actor()
        jid = jobs.submit("chat", {"hunt_id": hid, "t": time.time()}, lambda ctl: ask(c, hid, msg, author=who),
                          deduplicate=False)
        return jsonify({"job_id": jid}), 202

    @app.route("/api/hunts/<hid>/narrative", methods=["POST"])
    def hunt_narrative(hid):
        from .hunt.report import narrative
        from .providers import get_llm
        h = _hunt_or_404(hid)
        text = narrative(hs.privacy_llm(get_config(), get_llm()), h)
        if not text:
            return jsonify({"error": "the reporter model did not answer"}), 502
        store_for(get_config()).update(hid, narrative=text)
        return jsonify({"narrative": text})

    @app.route("/api/hunts/<hid>")
    def hunt_get(hid):
        h = store_for(get_config()).get(hid)
        return (jsonify(h), 200) if h else (jsonify({"error": "not found"}), 404)

    @app.route("/api/hunts/<hid>/<action>", methods=["POST"])
    def hunt_action(hid, action):
        h = store_for(get_config()).get(hid, with_steps=False)
        if not h:
            return jsonify({"error": "not found"}), 404
        fn = {"stop": jobs.cancel, "pause": jobs.pause, "resume": jobs.resume}.get(action)
        if not fn:
            return jsonify({"error": "unknown action"}), 400
        return jsonify({"ok": bool(h.get("job_id")) and fn(h["job_id"])})

    from .mcp_server import build as build_mcp

    def _role():
        from flask import g
        return getattr(g, "actaeon_role", "viewer")

    mcp_srv = build_mcp(cfg, jobs, role_of=_role)

    @app.route("/mcp", methods=["POST", "GET", "DELETE"])
    def mcp_http():
        if request.method != "POST":
            return jsonify({"error": "use POST with a JSON-RPC message"}), 405
        msg = request.get_json(silent=True)
        if isinstance(msg, list):
            replies = [r for r in (mcp_srv.handle(m) for m in msg if isinstance(m, dict)) if r]
            return (jsonify(replies), 200) if replies else ("", 202)
        if not isinstance(msg, dict):
            return jsonify({"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "parse error"}}), 400
        reply = mcp_srv.handle(msg)
        return (jsonify(reply), 200) if reply else ("", 202)

    @app.route("/api/settings/llm/test", methods=["POST"])
    def settings_llm_test():
        from .cli import test_models
        return jsonify(test_models(get_config()))

    @app.route("/api/jobs")
    def list_jobs():
        return jsonify(jobs.list(limit=50))

    @app.route("/api/jobs/<job_id>", methods=["GET"])
    def get_job(job_id):
        j = jobs.get(job_id)
        return (jsonify(j), 200) if j else (jsonify({"error": "not found"}), 404)

    @app.route("/api/jobs/<job_id>/<action>", methods=["POST"])
    def job_action(job_id, action):
        fn = {"cancel": jobs.cancel, "pause": jobs.pause, "resume": jobs.resume}.get(action)
        if not fn:
            return jsonify({"error": "unknown action"}), 400
        return jsonify({"ok": fn(job_id)})

    return app
