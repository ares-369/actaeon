"""Flask app factory for the Actaeon web UI and JSON API."""

from __future__ import annotations

import json
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
    jobs = JobManager.from_config(cfg)
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

    @app.route("/api/retention", methods=["POST"])
    def retention_run():
        from .retention import purge
        return jsonify(purge(get_config(), dry_run=bool((request.get_json(silent=True) or {}).get("dry_run"))))

    @app.route("/api/audit/verify")
    def audit_verify():
        return jsonify(hub().audit.verify())

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
            try:
                limit = max(1, min(500, int(request.args.get("limit", 50))))
            except ValueError:
                limit = 50
            return jsonify(st.advisories(limit=limit))
        b = request.get_json(silent=True) or {}
        if not str(b.get("text", "")).strip():
            return jsonify({"error": "text is required"}), 400
        return jsonify(st.add_advisory(str(b.get("title", ""))[:300], str(b["text"])[:200_000],
                                       source=str(b.get("source") or "advisory")[:60], url=str(b.get("url", ""))[:500],
                                       **_intel_kw(b)))

    @app.route("/api/intel/actors", methods=["GET", "POST"])
    def intel_actors():
        st = intel_store()
        if request.method == "GET":
            return jsonify(st.actors())
        b = request.get_json(silent=True) or {}

        def lst(v):
            return [x.strip() for x in (v.split(",") if isinstance(v, str) else v or []) if str(x).strip()]
        try:
            return jsonify(st.save_actor(str(b.get("name", "")), aliases=lst(b.get("aliases")),
                                         description=str(b.get("description", ""))[:5000],
                                         techniques=lst(b.get("techniques")), tools=lst(b.get("tools")),
                                         indicators_text=str(b.get("indicators", ""))[:200_000]))
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400

    @app.route("/api/intel/actors/<key>")
    def intel_actor(key):
        a = intel_store().actor(key)
        return (jsonify(a), 200) if a else (jsonify({"error": "not found"}), 404)

    @app.route("/api/intel/actors/<key>/hunt", methods=["POST"])
    def intel_actor_hunt(key):
        try:
            return jsonify(hs.actor_campaign(get_config(), jobs, key, actor=_actor())), 202
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 404

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
    hs.resume_interrupted(cfg, jobs)      # hunts a previous process left running: continue or mark stopped
    if start_scheduler:
        from .hunt.scheduler import Scheduler
        app.extensions["actaeon_scheduler"] = Scheduler(cfg, jobs)
        app.extensions["actaeon_scheduler"].start()

    from .soc.api import register as register_soc
    register_soc(app, jobs, start_scheduler=start_scheduler)
    from .rules.api import register as register_rules
    register_rules(app)
    from .dfir.api import register as register_dfir
    register_dfir(app)

    def _actor():
        from flask import g
        return str(getattr(g, "actaeon_user", "") or "")

    @app.route("/api/me")
    def me():
        from flask import g
        c = get_config()
        u = _actor()
        a = getattr(g, "actaeon_access", None)
        return jsonify({"user": u, "role": getattr(g, "actaeon_role", "viewer"), "auth_mode": c.auth.mode,
                        "name": (c.auth.users.get(u) or {}).get("name", ""),
                        "groups": list(getattr(g, "actaeon_groups", []) or []),
                        "connectors": None if a is None or a.connectors is None else sorted(a.connectors)})

    @app.route("/api/users")
    def users():
        c = get_config()
        single = c.auth.mode in ("basic", "local") and bool(c.auth.password or c.auth.password_hash)
        names = sorted(set(c.auth.users) | ({c.auth.username} if single else set()))
        return jsonify([{"user": n, "name": (c.auth.users.get(n) or {}).get("name", ""),
                         "role": (c.auth.users.get(n) or {}).get("role", c.auth.default_role)} for n in names])

    @app.route("/api/hunts", methods=["GET", "POST"])
    def hunts():
        if request.method == "GET":
            return jsonify(store_for(get_config()).list(limit=min(200, int(request.args.get("limit", 50)))))
        b = request.get_json(silent=True) or {}
        context = str(b.get("context", ""))[:8000]
        if context and b.get("context_untrusted"):
            # handed over by another tool: built from collected reports, so data for the model, not instructions
            from .hunt.service import untrusted_context
            context = untrusted_context(context, str(b.get("context_from", "") or "another tool")[:60])
        try:
            hid = start_hunt(jobs, get_config(), str(b.get("hypothesis", ""))[:4000], actor=_actor(),
                             context=context, max_steps=b.get("max_steps"),
                             profile=str(b.get("profile") or "") or None)
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
            return jsonify({"saved": lib.list(), "starters": starters(c)})
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
                               lambda: hs.run_replay(c, sid, jobs=jobs, actor=_actor() or "manual"),
                               task="replay", params={"saved_id": sid, "actor": _actor() or "manual"})
            return jsonify({"job_id": jid}), 202
        return jsonify({"error": "unknown action"}), 400

    @app.route("/api/intel/web/pull", methods=["POST"])
    def intel_web_pull():
        c = get_config()
        jid = hs.start_job(jobs, "web-intel", {"web": True},
                           lambda: hs.run_web_intel(c, jobs=jobs), task="web-intel", params={})
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
        jid = hs.start_job(jobs, "autopilot", {"autopilot": True}, lambda: hs.run_autopilot(c, jobs),
                           task="autopilot", params={})
        return jsonify({"job_id": jid}), 202

    @app.route("/api/entities")
    def entities_list():
        a = request.args
        c = get_config()
        return jsonify(hs.entities_for(c).summary(c, type_=a.get("type") or None, q=a.get("q", ""),
                                                  recurring_only=a.get("recurring") in ("1", "true"),
                                                  limit=min(1000, int(a.get("limit", 200)))))

    @app.route("/api/entities/<etype>/<path:value>")
    def entity_history(etype, value):
        rows = hs.entities_for(get_config()).history(etype, value)
        return (jsonify(rows), 200) if rows else (jsonify({"error": "not found"}), 404)

    @app.route("/api/drift")
    def drift_status():
        from .hunt.drift import DriftStore, targets
        c = get_config()
        return jsonify({"targets": targets(c), "status": DriftStore(store_for(c).path).status(),
                        "runs": [h for h in store_for(c).list(limit=20, origin="drift:")]})

    @app.route("/api/drift/run", methods=["POST"])
    def drift_run():
        c = get_config()
        only = str((request.get_json(silent=True) or {}).get("name", "") or "") or None
        jid = hs.start_job(jobs, "drift", {"drift": True, "only": only},
                           lambda: hs.run_drift(c, only=only, jobs=jobs, actor=_actor() or "manual"),
                           task="drift", params={"only": only, "actor": _actor() or "manual"})
        return jsonify({"job_id": jid}), 202

    @app.route("/api/intel/sweep", methods=["POST"])
    def intel_sweep():
        c = get_config()
        full = bool((request.get_json(silent=True) or {}).get("full"))
        jid = hs.start_job(jobs, "sweep", {"sweep": True, "full": full},
                           lambda: hs.run_sweep(c, full=full, actor=_actor() or "manual"),
                           task="sweep", params={"full": full, "actor": _actor() or "manual"})
        return jsonify({"job_id": jid}), 202

    @app.route("/api/memory/notes", methods=["GET", "POST"])
    def memory_notes():
        mem = hs.memory_for(get_config())
        if request.method == "GET":
            return jsonify(mem.notes())
        b = request.get_json(silent=True) or {}
        try:
            return jsonify(mem.add_note(str(b.get("text", "")), author=_actor(), tags=b.get("tags") or [],
                                        expires_days=int(b.get("expires_days") or 0)))
        except (ValueError, TypeError) as exc:
            return jsonify({"error": str(exc)}), 400

    @app.route("/api/memory/notes/<int:nid>/retire", methods=["POST"])
    def memory_retire(nid):
        return jsonify({"ok": hs.memory_for(get_config()).retire_note(nid)})

    @app.route("/api/memory/related")
    def memory_related():
        return jsonify(hs.memory_for(get_config()).related(request.args.get("q", "")))

    def leads_store():
        return hs.leads_for(get_config())

    @app.route("/api/leads")
    def leads_list():
        a = request.args
        assignee = a.get("assignee")
        if assignee == "me":
            assignee = _actor()
        rows = leads_store().list(status=a.get("status") or None, severity=a.get("severity") or None,
                                  assignee=assignee if assignee is not None else None,
                                  open_only=a.get("open") == "1")
        return jsonify(rows)

    @app.route("/api/leads/stats")
    def leads_stats():
        return jsonify(leads_store().stats())

    @app.route("/api/leads/<int:cid>")
    def lead_get(cid):
        c = leads_store().get(cid)
        if not c:
            return jsonify({"error": "not found"}), 404
        h = store_for(get_config()).get(c["hunt_id"], with_steps=False) or {}
        c["hunt"] = {k: h.get(k) for k in ("id", "hypothesis", "status", "outcome", "origin", "created", "verdict")}
        return jsonify(c)

    @app.route("/api/leads/<int:cid>/<action>", methods=["POST"])
    def lead_action(cid, action):
        st = leads_store()
        b = request.get_json(silent=True) or {}
        who = _actor() or "unknown"
        try:
            if action == "acknowledge":
                out = st.acknowledge(cid, who)
            elif action == "assign":
                out = st.assign(cid, who, str(b.get("to", "")).strip()[:64])
            elif action == "status":
                out = st.set_status(cid, who, str(b.get("status", "")))
            elif action == "close":
                out = st.close(cid, who, str(b.get("resolution", "")), str(b.get("comment", ""))[:4000])
                if out.get("resolution") in ("false_positive", "benign_true_positive"):
                    h = store_for(get_config()).get(out["hunt_id"], with_steps=False) or {}
                    label = "False positive" if out["resolution"] == "false_positive" else "Known benign"
                    hs.memory_for(get_config()).add_note(
                        f"{label} (lead {cid}): {h.get('hypothesis', '')[:200]}. Analyst: {b.get('comment', '')}"[:2000],
                        author=who, tags=[out["resolution"], f"lead:{cid}"],
                        expires_days=hs.benign_note_days(get_config(), b.get("expires_days")),
                        restricted=h.get("restricted") or [])
            elif action == "reopen":
                out = st.reopen(cid, who, str(b.get("comment", ""))[:4000])
            elif action == "comment":
                out = st.comment(cid, who, str(b.get("text", ""))[:4000])
            else:
                return jsonify({"error": "unknown action"}), 400
        except LookupError:
            return jsonify({"error": "not found"}), 404
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400
        return jsonify(out)

    @app.route("/api/assistant", methods=["GET", "POST"])
    def assistant_api():
        from .assistant import Conversations, ask
        c = get_config()
        conv = Conversations(store_for(c).path)
        if request.method == "GET":
            return jsonify(conv.list())
        b = request.get_json(silent=True) or {}
        msg = str(b.get("message", "")).strip()
        if not msg:
            return jsonify({"error": "message is required"}), 400
        cid = b.get("conversation_id")
        if not (isinstance(cid, int) and conv.get(cid)):
            cid = conv.create(_actor() or "unknown", msg)
        who = _actor() or "unknown"
        jid = jobs.submit("ask", {"conv": cid, "t": time.time()},
                          lambda ctl: ask(c, msg, user=who, conv_id=cid), deduplicate=False,
                          task="ask", params={"message": msg, "user": who, "conv_id": cid})
        return jsonify({"conversation_id": cid, "job_id": jid}), 202

    @app.route("/api/assistant/<int:cid>")
    def assistant_conv(cid):
        from .assistant import Conversations
        d = Conversations(store_for(get_config()).path).get(cid)
        return (jsonify(d), 200) if d else (jsonify({"error": "not found"}), 404)

    def _send_report(doc, fmt, name):
        from .reporting import MIMES, render
        try:
            data = render(doc, fmt)
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400
        except RuntimeError as exc:
            return jsonify({"error": str(exc)}), 501
        return app.response_class(data, mimetype=MIMES[fmt],
                                  headers={"Content-Disposition": f'attachment; filename="{name}.{fmt}"'})

    @app.route("/api/hunts/<hid>/stix")
    def hunt_stix(hid):
        from .intel.stix import hunt_bundle
        b = hunt_bundle(_hunt_or_404(hid), producer_name=_producer())
        return app.response_class(json.dumps(b, indent=1), mimetype="application/stix+json;version=2.1",
                                  headers={"Content-Disposition": f'attachment; filename="hunt-{hid}.stix.json"'})

    @app.route("/api/intel/export.stix")
    def intel_export_stix():
        from .intel.stix import export_store
        a = request.args
        b = export_store(intel_store(), producer_name=_producer(), tag=a.get("tag") or None,
                         min_confidence=int(a.get("min_confidence", 0) or 0), changed_since=a.get("since") or None)
        return app.response_class(json.dumps(b, indent=1), mimetype="application/stix+json;version=2.1",
                                  headers={"Content-Disposition": 'attachment; filename="actaeon-intel.stix.json"'})

    def _producer() -> str:
        return str(((get_config().raw or {}).get("actaeon") or {}).get("instance_name") or "Actaeon")[:100]

    @app.route("/api/hunts/<hid>/report.<fmt>")
    def hunt_report_any(hid, fmt):
        from .hunt.report import markdown
        from .reporting import hunt_doc
        h = _hunt_or_404(hid)
        if fmt == "md" and request.args.get("style") != "summary":
            return app.response_class(markdown(h, narrative=h.get("narrative") or ""), mimetype="text/markdown",
                                      headers={"Content-Disposition": f'attachment; filename="hunt-{hid}.md"'})
        return _send_report(hunt_doc(h, lead=leads_store().by_hunt(hid)), fmt, f"hunt-{hid}")

    @app.route("/api/leads/<int:cid>/report.<fmt>")
    def lead_report(cid, fmt):
        from .reporting import lead_doc
        c = leads_store().get(cid)
        h = store_for(get_config()).get(c["hunt_id"]) if c else None
        if not c or not h:
            return jsonify({"error": "not found"}), 404
        return _send_report(lead_doc(c, h), fmt, f"lead-{cid}")

    @app.route("/api/reports/summary.<fmt>")
    def summary_report(fmt):
        from .reporting import summary_doc
        try:
            days = max(1, min(int(request.args.get("days", 7)), 366))
        except ValueError:
            days = 7
        return _send_report(summary_doc(get_config(), days), fmt, f"actaeon-summary-{days}d")

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
                                           author=_actor(), expires_days=b.get("expires_days")))
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

    @app.route("/api/hunts/plan", methods=["POST"])
    def hunt_plan():
        """The planning step only: no data queried, no hunt stored (operator role, like starting a hunt)."""
        b = request.get_json(silent=True) or {}
        try:
            return jsonify(hs.plan_hunt(get_config(), str(b.get("hypothesis", "")), context=str(b.get("context", ""))))
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400
        except RuntimeError as exc:
            return jsonify({"error": str(exc)[:300]}), 502

    @app.route("/api/tickets/reply", methods=["POST"])
    def ticket_reply():
        from .tickets import ReplyError, handle_reply
        b = request.get_json(silent=True) or {}
        try:
            return jsonify(handle_reply(get_config(), jobs, text=str(b.get("text", "")),
                                        author=str(b.get("author", "") or _actor()),
                                        hunt_id=b.get("hunt_id"), lead_id=b.get("lead_id"))), 202
        except ReplyError as exc:
            return jsonify({"error": str(exc)}), exc.status

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
                          deduplicate=False, task="chat", params={"hunt_id": hid, "message": msg, "author": who})
        return jsonify({"job_id": jid}), 202

    @app.route("/api/hunts/<hid>/detection", methods=["GET", "POST"])
    def hunt_detection(hid):
        from .hunt.detection import DetectionStore, draft
        c = get_config()
        h = store_for(c).get(hid)
        if not h:
            return jsonify({"error": "not found"}), 404
        ds = DetectionStore(store_for(c).path)
        if request.method == "GET":
            return jsonify(ds.list(hid))
        from .hunt.sigma_convert import targets
        from .providers import get_llm
        return jsonify(ds.save(draft(hs.privacy_llm(c, get_llm()), h, sigma_targets=targets(c), hub=hub())))

    @app.route("/api/sigma/convert", methods=["POST"])
    def sigma_convert_api():
        """Convert a Sigma rule (e.g. an edited draft) for every connector with a sigma: block."""
        from .hunt.detection import check_sigma
        from .hunt.sigma_convert import convert_for, targets
        b = request.get_json(silent=True) or {}
        rule, problems = check_sigma(str(b.get("sigma", ""))[:50_000], [])
        if problems:
            return jsonify({"error": "; ".join(problems)}), 400
        h = store_for(get_config()).get(str(b.get("hunt_id", ""))) if b.get("hunt_id") else None
        return jsonify({"sigma": rule, "converted": convert_for(rule, targets(get_config()),
                                                                hub=hub() if b.get("backtest") else None, h=h)})

    @app.route("/api/sigma/backends")
    def sigma_backends():
        from .hunt.sigma_convert import available
        return jsonify(available())

    @app.route("/api/hunts/<hid>/detection/backtest", methods=["POST"])
    def hunt_backtest(hid):
        from .hunt.detection import backtest
        h = _hunt_or_404(hid)
        days = int((request.get_json(silent=True) or {}).get("days", 14) or 14)
        return jsonify(backtest(hub(), h, days))

    @app.route("/api/hunts/<hid>/graph")
    def hunt_graph(hid):
        from .hunt.graph import build
        h = store_for(get_config()).get(hid)
        return (jsonify(build(h)), 200) if h else (jsonify({"error": "not found"}), 404)

    @app.route("/api/hunts/<hid>/timeline")
    def hunt_timeline(hid):
        from .hunt.timeline import build
        h = store_for(get_config()).get(hid)
        return (jsonify(build(h)), 200) if h else (jsonify({"error": "not found"}), 404)

    @app.route("/api/detections")
    def detections():
        from .hunt.detection import DetectionStore
        return jsonify(DetectionStore(store_for(get_config()).path).list())

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
        if not h:
            return jsonify({"error": "not found"}), 404
        lead = leads_store().by_hunt(hid)
        h["lead"] = {k: lead[k] for k in ("id", "status", "severity", "assignee", "resolution")} if lead else None
        return jsonify(h)

    @app.route("/api/hunts/<hid>/<action>", methods=["POST"])
    def hunt_action(hid, action):
        h = store_for(get_config()).get(hid, with_steps=False)
        if not h:
            return jsonify({"error": "not found"}), 404
        fn = {"stop": jobs.cancel, "pause": jobs.pause, "resume": jobs.resume}.get(action)
        if not fn:
            return jsonify({"error": "unknown action"}), 400
        ok = bool(h.get("job_id")) and fn(h["job_id"])
        if action == "resume" and not ok and h.get("status") in ("stopped", "error"):
            # not a paused job: continue a stopped or interrupted hunt from its stored steps
            full = store_for(get_config()).get(hid)
            return jsonify({"ok": True, "continued": True, "job_id": hs.resume_hunt(jobs, get_config(), full)})
        return jsonify({"ok": ok})

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

    @app.route("/api/settings/connectors", methods=["POST"])
    def settings_connectors():
        from .config import update_connectors
        b = request.get_json(silent=True) or {}
        try:
            r = update_connectors(b.get("connector"), remove=b.get("remove"), preview=bool(b.get("preview")))
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400
        if not b.get("preview") and r["changed"]:
            from .connectors import get_hub
            get_hub(get_config(), reload=True)
        return jsonify(r)

    @app.route("/api/doctor")
    def doctor_api():
        from .doctor import run as run_doctor
        return jsonify(run_doctor(offline=request.args.get("offline") == "1"))

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
