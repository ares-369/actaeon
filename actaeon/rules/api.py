"""Web API for the rule library. Every route except /api/rules/status answers 404 while rules.enabled is false."""

from __future__ import annotations

from flask import Response, g, jsonify, request


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

    def on():
        return of(get_config()).enabled

    @app.before_request
    def _rules_gate():
        p = request.path
        if p.startswith("/api/rules") and p != "/api/rules/status" and not on():
            return jsonify({"error": "the rule library is off (set rules.enabled: true in config.yaml)"}), 404
        return None

    @app.route("/api/rules/status")
    def rules_status():
        c = get_config()
        if not of(c).enabled:
            return jsonify({"enabled": False})
        rc = of(c)
        return jsonify({"enabled": True, "counts": S.store_for(c).counts(),
                        "settings": {"min_real_tests": rc.min_real_tests, "min_no_match_tests": rc.min_no_match_tests,
                                     "allow_self_approval": rc.allow_self_approval, "priorities": rc.priorities,
                                     "field_map": rc.field_map}})

    @app.route("/api/rules", methods=["GET", "POST"])
    def rules_list():
        c = get_config()
        if request.method == "GET":
            rows = S.store_for(c).list(status=request.args.get("status") or None, q=request.args.get("q", "")[:200],
                                       technique=request.args.get("technique", "")[:20].upper())
            return jsonify([r for r in rows if S.visible(r)])
        b = body()
        try:
            return jsonify(S.create(c, str(b.get("sigma", "")), actor=actor(), notes=str(b.get("notes", ""))[:2000])), 201
        except ValueError as exc:
            return bad(exc)

    @app.route("/api/rules/<rid>", methods=["GET", "POST"])
    def rule_one(rid):
        c = get_config()
        if request.method == "GET":
            d = S.detail(c, rid, actor=actor())
            return jsonify(d) if d else bad("not found", 404)
        b = body()
        try:
            if "notes" in b and "sigma" not in b:
                if not S.visible(S.store_for(c).get(rid)):
                    return bad("not found", 404)
                S.store_for(c).set_notes(rid, str(b["notes"]))
                return jsonify(S.store_for(c).get(rid))
            return jsonify(S.edit(c, rid, str(b.get("sigma", "")), actor=actor(), note=str(b.get("note", ""))[:500]))
        except KeyError:
            return bad("not found", 404)
        except ValueError as exc:
            return bad(exc)

    @app.route("/api/rules/<rid>/status", methods=["POST"])
    def rule_status(rid):
        try:
            return jsonify(S.change_status(get_config(), rid, str(body().get("action", "")), actor=actor()))
        except KeyError:
            return bad("not found", 404)
        except ValueError as exc:
            return bad(exc, 409)

    @app.route("/api/rules/<rid>/delete", methods=["POST"])
    def rule_delete(rid):
        c = get_config()
        r = S.store_for(c).get(rid)
        if not S.visible(r):
            return bad("not found", 404)
        if r["status"] not in ("draft", "retired"):
            return bad("only draft or retired rules can be deleted", 409)
        S.store_for(c).delete(rid)
        return jsonify({"deleted": rid})

    @app.route("/api/rules/<rid>/tests", methods=["POST"])
    def rule_add_test(rid):
        b = body()
        try:
            return jsonify(S.add_test(get_config(), rid, name=str(b.get("name", ""))[:200],
                                      expect=str(b.get("expect", "match")), event=b.get("event"),
                                      origin=str(b.get("origin", "real")), actor=actor(),
                                      source=str(b.get("source", ""))[:300])), 201
        except KeyError:
            return bad("not found", 404)
        except ValueError as exc:
            return bad(exc)

    @app.route("/api/rules/<rid>/tests/<int:tid>/delete", methods=["POST"])
    def rule_delete_test(rid, tid):
        c = get_config()
        if not S.visible(S.store_for(c).get(rid)):
            return bad("not found", 404)
        return jsonify({"deleted": S.store_for(c).delete_test(rid, tid)})

    @app.route("/api/rules/<rid>/run", methods=["POST"])
    def rule_run(rid):
        try:
            return jsonify(S.run_tests(get_config(), rid, actor=actor()))
        except KeyError:
            return bad("not found", 404)

    @app.route("/api/rules/<rid>/convert", methods=["POST"])
    def rule_convert(rid):
        from ..connectors import get_hub
        from ..hunt.sigma_convert import convert_for, targets
        c = get_config()
        r = S.store_for(c).get(rid)
        if not S.visible(r):
            return bad("not found", 404)
        b = body()
        days = max(1, min(30, int(b.get("days", 14) or 14)))
        tg = targets(c)
        if not tg:
            return bad("no connector has a sigma: block, so there is nothing to convert to (docs/detection.md)")
        return jsonify({"converted": convert_for(r["sigma"], tg, hub=get_hub(c) if b.get("backtest") else None,
                                                 h={"id": f"rule-{rid}"}, days=days)})

    @app.route("/api/rules/coverage")
    def rules_coverage():
        return jsonify(S.coverage(get_config()))

    @app.route("/api/rules/draft", methods=["POST"])
    def rules_draft():
        from ..hunt.service import privacy_llm
        from ..providers import get_llm
        c = get_config()
        b = body()
        try:
            return jsonify(S.draft_for_technique(c, privacy_llm(c, get_llm()), str(b.get("technique", "")).strip(),
                                                 actor=actor(), context=str(b.get("context", "")))), 201
        except ValueError as exc:
            return bad(exc)

    @app.route("/api/rules/from-hunt/<hid>", methods=["POST"])
    def rules_from_hunt(hid):
        from ..hunt.service import privacy_llm
        from ..hunt.service import store_for as hunt_store
        from ..providers import get_llm
        c = get_config()
        h = hunt_store(c).get(hid)
        if not h:
            return bad("hunt not found", 404)
        if h.get("status") in ("queued", "running"):
            return bad("the hunt is still running", 409)
        sigma = str(body().get("sigma", ""))
        try:
            return jsonify(S.from_hunt(c, h, actor=actor(), sigma=sigma,
                                       llm=None if sigma else privacy_llm(c, get_llm()))), 201
        except ValueError as exc:
            return bad(exc)

    @app.route("/api/rules/import", methods=["POST"])
    def rules_import():
        text = str(body().get("text", ""))
        if not text.strip() or len(text) > 2_000_000:
            return bad("send the Sigma YAML as text (one or more documents, up to 2 MB)")
        return jsonify(S.import_text(get_config(), text, actor=actor(), source="pasted in the web UI"))

    @app.route("/api/rules/export.zip")
    def rules_export():
        st = tuple(x for x in (request.args.get("status") or "ready").split(",") if x in
                   ("draft", "testing", "ready", "retired")) or ("ready",)
        data = S.export_zip(get_config(), st)
        return Response(data, mimetype="application/zip",
                        headers={"Content-Disposition": "attachment; filename=actaeon-rules.zip"})
