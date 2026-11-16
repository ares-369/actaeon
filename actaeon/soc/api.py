"""Web API for alert triage: alerts, cases, response actions, suppressions, metrics."""

from __future__ import annotations

from flask import Response, g, jsonify, request


def register(app, jobs, *, start_scheduler: bool = False) -> None:
    from ..config import get_config
    from . import graph as G
    from . import response as R
    from . import service as S
    from .intake import ingest
    from .metrics import metrics
    from .report import case_markdown, shift_markdown

    def store():
        return S.store_for(get_config())

    def hub():
        from ..connectors import get_hub
        return get_hub(get_config())

    def actor() -> str:
        return str(getattr(g, "actaeon_user", "") or "")

    def body() -> dict:
        b = request.get_json(silent=True)
        return b if isinstance(b, dict) else {}

    def bad(msg, code: int = 400):
        return jsonify({"error": str(msg)[:500]}), code

    def visible(case: dict) -> bool:
        from ..access import can_see
        return can_see(case.get("restricted") or [])

    def scheduler():
        return app.extensions.get("actaeon_soc_scheduler")

    @app.route("/api/soc/status")
    def soc_status():
        c = get_config()
        sch = scheduler()
        return jsonify({"response_mode": R.mode_text(c), "auto_triage": c.soc.auto,
                        "intake_sources": [s["name"] for s in c.soc.intake.sources],
                        "scheduler": getattr(sch, "last", None), "tokens_today": store().usage_today(),
                        "cases_today": store().triaged_today(), "budget_reached": S.budget_reached(c, store()),
                        "limits": {"max_tokens_per_day": c.soc.max_tokens_per_day,
                                   "max_cases_per_day": c.soc.max_cases_per_day}})

    # ---- alerts ----
    @app.route("/api/alerts", methods=["GET", "POST"])
    def soc_alerts():
        if request.method == "GET":
            return jsonify(store().alerts(status=request.args.get("status") or None, q=request.args.get("q", "")[:200],
                                          limit=min(1000, int(request.args.get("limit", 200)))))
        data = request.get_json(silent=True)
        if isinstance(data, dict) and isinstance(data.get("alerts"), list):
            items = data["alerts"]
        elif isinstance(data, dict):
            items = [data]
        elif isinstance(data, list):
            items = data
        else:
            return bad('send a JSON object, a list, or {"alerts": [...]}')
        try:
            out = ingest(get_config(), store(), items, source=str(request.args.get("source") or "webhook")[:40])
        except ValueError as exc:
            return bad(exc)
        if get_config().soc.auto:
            out["queued"] = S.queue_new(get_config(), jobs)
        return jsonify(out)

    @app.route("/api/intake/poll", methods=["POST"])
    def soc_poll():
        sch = scheduler() or S.Scheduler(get_config(), jobs)
        return jsonify(sch.once(force_poll=True))

    # ---- cases ----
    @app.route("/api/cases")
    def soc_cases():
        rows = store().cases(status=request.args.get("status") or None, verdict=request.args.get("verdict") or None,
                             open_only=request.args.get("open") == "1",
                             limit=min(500, int(request.args.get("limit", 200))))
        return jsonify([{k: v for k, v in c.items() if k not in ("report", "first_look")} for c in rows if visible(c)])

    def _case(cid):
        c = store().get_case(cid)
        return c if c and visible(c) else None

    @app.route("/api/cases/<cid>")
    def soc_case(cid):
        c = _case(cid)
        if not c:
            return bad("not found", 404)
        c["graph"] = G.graph(c)
        c["timeline"] = G.timeline(c)
        c["chain"] = G.attack_chain(c)
        c["related"] = [r for r in store().related_cases(cid) if visible(r)]
        c["catalogue"] = R.catalogue(get_config())
        c["response_mode"] = R.mode_text(get_config())
        c["basis"] = R.basis(c)
        for a in c["actions"]:
            a["stale"] = bool(a["status"] == "proposed" and a.get("basis") and a["basis"] != c["basis"])
        c["job"] = jobs.get(c["job_id"]) if c.get("job_id") else None
        return jsonify(c)

    @app.route("/api/cases/<cid>/report.md")
    def soc_case_report(cid):
        c = _case(cid)
        if not c:
            return bad("not found", 404)
        return Response(case_markdown(c), mimetype="text/markdown",
                        headers={"Content-Disposition": f'attachment; filename="case-{cid}.md"'})

    @app.route("/api/cases/<cid>/triage", methods=["POST"])
    def soc_case_triage(cid):
        c = _case(cid)
        if not c:
            return bad("not found", 404)
        if c["status"] == "triaging" and c.get("job_id") and (jobs.get(c["job_id"]) or {}).get("status") in (
                "running", "queued"):
            return bad("already being investigated", 409)
        return jsonify({"job_id": S.submit_triage(get_config(), jobs, cid, actor=actor(), manual=True)})

    @app.route("/api/cases/<cid>/stop", methods=["POST"])
    def soc_case_stop(cid):
        c = _case(cid)
        if not c:
            return bad("not found", 404)
        return jsonify({"stopped": bool(c.get("job_id") and jobs.cancel(c["job_id"]))})

    @app.route("/api/cases/<cid>/hunt", methods=["POST"])
    def soc_case_hunt(cid):
        """Escalate: start a full hunt from this case (its summary and entities become the hypothesis)."""
        c = _case(cid)
        if not c:
            return bad("not found", 404)
        from ..hunt.service import start_hunt
        ents = ", ".join(f"{e['type']} {e['value']}" for e in (c.get("entities") or [])[:12])
        hyp = str(body().get("hypothesis") or "").strip() or (
            f"Activity related to alert case {cid} ({c['title']}) is part of a wider intrusion: look for the same "
            f"behaviour and indicators on other hosts and accounts, before and after the alerts. Entities: {ents}.")
        try:
            hid = start_hunt(jobs, get_config(), hyp[:1500], actor=actor(), origin=f"case:{cid}",
                             context=f"Alert case {cid}: {(c.get('summary') or '')[:1500]}")
        except ValueError as exc:
            return bad(exc)
        store().add_note(cid, actor(), f"Started hunt {hid} from this case.")
        return jsonify({"hunt_id": hid})

    @app.route("/api/cases/<cid>/close", methods=["POST"])
    def soc_case_close(cid):
        if not _case(cid):
            return bad("not found", 404)
        b = body()
        try:
            return jsonify(S.close_case(store(), cid, user=actor(), verdict=str(b.get("verdict", "")),
                                        note=str(b.get("note", ""))))
        except ValueError as exc:
            return bad(exc)

    @app.route("/api/cases/<cid>/reopen", methods=["POST"])
    def soc_case_reopen(cid):
        if not _case(cid):
            return bad("not found", 404)
        return jsonify(S.reopen_case(store(), cid, user=actor()))

    @app.route("/api/cases/<cid>/notes", methods=["POST"])
    def soc_case_note(cid):
        if not _case(cid):
            return bad("not found", 404)
        text = str(body().get("text", "")).strip()
        if not text:
            return bad("empty note")
        store().add_note(cid, actor(), text)
        return jsonify({"ok": True})

    @app.route("/api/cases/<cid>/assign", methods=["POST"])
    def soc_case_assign(cid):
        if not _case(cid):
            return bad("not found", 404)
        who = str(body().get("assignee", "") or actor())[:100]
        store().set_case(cid, assignee=who)
        return jsonify({"ok": True, "assignee": who})

    @app.route("/api/cases/<cid>/tuning", methods=["POST"])
    def soc_case_tuning(cid):
        if not _case(cid):
            return bad("not found", 404)
        b = body()
        try:
            sid = S.apply_tuning(store(), cid, user=actor(), days=int(b.get("days", 30)),
                                 override=b.get("tuning") if isinstance(b.get("tuning"), dict) else None)
        except ValueError as exc:
            return bad(exc)
        return jsonify({"suppression_id": sid})

    @app.route("/api/cases/<cid>/actions", methods=["POST"])
    def soc_case_add_action(cid):
        """The analyst proposes an action from the catalogue themselves (it still needs approval)."""
        c = _case(cid)
        if not c:
            return bad("not found", 404)
        b = body()
        try:
            act = R.build(get_config(), str(b.get("name", "")), str(b.get("target", "")).strip(), cid)
        except R.ResponseError as exc:
            return bad(exc)
        aid = store().add_action(cid, **act, basis=R.basis(c),
                                 reason=f"proposed by {actor()}: {str(b.get('reason', ''))[:400]}")
        return jsonify(store().get_action(aid))

    # ---- actions ----
    def _action(aid):
        a = store().get_action(aid)
        return a if a and visible(store().get_case(a["case_id"], full=False) or {}) else None

    @app.route("/api/actions")
    def soc_actions():
        rows = store().actions(status=request.args.get("status") or None)
        return jsonify([a for a in rows if visible(store().get_case(a["case_id"], full=False) or {})])

    def _decide(aid: int, approve: bool):
        if not _action(aid):
            return bad("not found", 404)
        try:
            return jsonify(R.decide(get_config(), store(), hub(), aid, user=actor(), approve=approve,
                                    note=str(body().get("note", ""))[:1000]))
        except R.ResponseError as exc:
            return bad(exc, 409)

    @app.route("/api/actions/<int:aid>/approve", methods=["POST"])
    def soc_action_approve(aid):
        return _decide(aid, True)

    @app.route("/api/actions/<int:aid>/reject", methods=["POST"])
    def soc_action_reject(aid):
        return _decide(aid, False)

    @app.route("/api/actions/<int:aid>/undo", methods=["POST"])
    def soc_action_undo(aid):
        if not _action(aid):
            return bad("not found", 404)
        try:
            return jsonify(R.undo(get_config(), store(), hub(), aid, user=actor()))
        except R.ResponseError as exc:
            return bad(exc, 409)

    # ---- suppressions ----
    @app.route("/api/suppressions", methods=["GET", "POST"])
    def soc_suppressions():
        if request.method == "GET":
            return jsonify(store().suppressions(active_only=request.args.get("all") != "1"))
        b = body()
        try:
            sid = store().add_suppression(rule=str(b.get("rule", "")), entity_type=str(b.get("entity_type", "")),
                                          entity_value=str(b.get("entity_value", "")), reason=str(b.get("reason", "")),
                                          created_by=actor(), days=int(b.get("days", 30)))
        except ValueError as exc:
            return bad(exc)
        return jsonify({"id": sid})

    @app.route("/api/suppressions/<int:sid>/disable", methods=["POST"])
    def soc_suppression_disable(sid):
        store().disable_suppression(sid)
        return jsonify({"ok": True})

    # ---- metrics and reports ----
    @app.route("/api/soc/metrics")
    def soc_metrics():
        return jsonify(metrics(store(), max(1, min(90, int(request.args.get("days", 14))))))

    @app.route("/api/soc/shift.md")
    def soc_shift():
        hours = max(1, min(168, int(request.args.get("hours", 12))))
        return Response(shift_markdown(store(), hours), mimetype="text/markdown")

    if start_scheduler:
        main = app.extensions.get("actaeon_scheduler")
        sch = S.Scheduler(get_config(), jobs, leader=getattr(main, "leader", None))
        app.extensions["actaeon_soc_scheduler"] = sch
        sch.start()
