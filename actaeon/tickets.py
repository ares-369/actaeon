"""Replies from a ticket or case system continue the investigation.

An output (webhook or mcp_tool) opens a ticket that carries the hunt id. When
the analyst answers in that ticket, the ticket system posts the reply here:

    POST /api/tickets/reply   {"hunt_id": "...", "text": "...", "author": "jdoe"}
                              (or "lead_id": 12 instead of hunt_id)

What the reply does:

    /resume              resume the hunt if it is paused
    /hunt <hypothesis>   start a follow-up hunt; it gets the first hunt's record as context
    anything else        a question about the hunt: answered like the hunt chat (read-only
                         tool calls, cited evidence) in the background

Every reply is a comment on the lead. The answer to a question is a comment too,
and is sent to each output whose ``when`` lists ``reply`` (only those: ``all``
does not include replies), with ``{reply}``, ``{answer}`` and ``{reply_author}``
available in templates. Follow-up hunts send their results like any other hunt.

Ticket systems can authenticate with a bearer token (``tickets.token_env``),
which is valid on this one path only and acts as an operator.
"""

from __future__ import annotations

MAX_TEXT = 4000


class ReplyError(ValueError):
    def __init__(self, msg: str, status: int = 400):
        super().__init__(msg)
        self.status = status


def _find(cfg, hunt_id: str | None, lead_id) -> tuple[dict, dict | None]:
    from .hunt import service as hs
    leads = hs.leads_for(cfg)
    lead = None
    if lead_id not in (None, ""):
        try:
            lead = leads.get(int(lead_id))
        except (TypeError, ValueError):
            raise ReplyError("lead_id must be a number") from None
        if not lead:
            raise ReplyError("no such lead", 404)
        hunt_id = lead["hunt_id"]
    if not hunt_id:
        raise ReplyError("hunt_id or lead_id is required")
    h = hs.store_for(cfg).get(str(hunt_id), with_steps=False)
    if not h:
        raise ReplyError("no such hunt", 404)
    return h, lead or leads.by_hunt(h["id"])


def followup_context(h: dict) -> str:
    v = h.get("verdict") or {}
    lines = [f"This hunt follows up hunt {h['id']} ({h.get('outcome') or 'unfinished'}): {h.get('hypothesis', '')[:300]}",
             f"Its summary: {str(v.get('summary', ''))[:800]}"]
    lines += [f"- finding: {f['claim'][:300]}" for f in (v.get("findings") or [])[:8]]
    lines += [f"- gap: {g[:200]}" for g in (v.get("gaps") or [])[:5]]
    return "\n".join(lines)


def handle_reply(cfg, jobs, *, text: str, author: str = "", hunt_id: str | None = None, lead_id=None,
                 llm=None, hub=None) -> dict:
    from .hunt import service as hs
    text = (text or "").strip()[:MAX_TEXT]
    if not text:
        raise ReplyError("text is required")
    who = f"ticket:{(author or 'unknown').strip()[:80]}"
    h, lead = _find(cfg, hunt_id, lead_id)
    leads = hs.leads_for(cfg)

    def note(msg: str, by: str = "actaeon") -> None:
        if lead:
            leads.comment(lead["id"], by, msg[:MAX_TEXT])

    note(text, who)
    low = text.lower()
    if low == "/resume" or low.startswith("/resume "):
        ok = bool(h.get("job_id")) and jobs.resume(h["job_id"])
        note("resumed the hunt" if ok else "nothing to resume: the hunt is not paused")
        return {"action": "resume", "ok": ok, "hunt_id": h["id"]}
    if low.startswith("/hunt"):
        hypothesis = text[5:].strip()
        if not hypothesis:
            raise ReplyError("/hunt needs a hypothesis after it")
        new = hs.start_hunt(jobs, cfg, hypothesis, actor=who, origin=f"followup:{h['id']}",
                            context=followup_context(h), llm=llm, hub=hub)
        note(f"started follow-up hunt {new}")
        return {"action": "hunt", "ok": True, "hunt_id": new, "follows": h["id"]}
    if h["status"] in ("queued", "running"):
        raise ReplyError("the hunt is still running; reply /resume if it is paused, or ask when it has finished", 409)

    def work(ctl):
        from .hunt.chat import ask
        res = ask(cfg, h["id"], text, author=who, llm=llm, hub=hub)
        note(f"Actaeon: {res['answer']}" + (f" (evidence {', '.join(res['evidence'])})" if res["evidence"] else ""))
        from .outputs import dispatch
        fresh = hs.store_for(cfg).get(h["id"]) or h
        res["outputs"] = dispatch(cfg, fresh, hub=hub, event="reply",
                                  extra={"reply": text, "reply_author": author or "", "answer": res["answer"]})
        return res

    jid = jobs.submit("ticket-reply", {"hunt_id": h["id"]}, work)
    return {"action": "ask", "ok": True, "hunt_id": h["id"], "job_id": jid}
