"""Flask app factory for the Actaeon web UI and JSON API."""

from __future__ import annotations

from flask import Flask, jsonify, render_template, request
from werkzeug.middleware.proxy_fix import ProxyFix

from . import __version__
from .auth import init_auth
from .config import LLM_ROLES, PROVIDERS, apply_llm_update, get_config, preview_llm_update
from .jobs import JobManager


def create_app(cfg=None) -> Flask:
    cfg = cfg or get_config()
    app = Flask(__name__, static_folder="static", template_folder="templates")
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)  # type: ignore[method-assign]
    init_auth(app, cfg)
    cfg.data_dir.mkdir(parents=True, exist_ok=True)
    jobs = JobManager(cfg.data_dir / "actaeon.sqlite")
    app.extensions["actaeon_jobs"] = jobs

    @app.route("/")
    def index():
        return render_template("index.html", name=cfg.instance_name, version=__version__)

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
