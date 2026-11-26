"""The model's part of an investigation: the story of what happened, and answers to questions.

The model only sees events from the case (with ids like E123) and must cite them. Every citation is checked
against the events it was given: a part of the story with no valid citation is kept but marked unsupported, and
invalid ids are removed. The model never queries any system.
"""

from __future__ import annotations

import json
import re
from typing import Any

from ..connectors.untrusted import SYSTEM_RULE
from ..hunt.jsonparse import first_object
from .config import of
from .service import store_for

PHASES = ("initial access", "execution", "persistence", "privilege escalation", "defense evasion",
          "credential access", "discovery", "lateral movement", "collection", "command and control", "exfiltration",
          "impact", "other")

STORY_SYSTEM = f"""You are a digital forensics analyst. From the case events below (each starts with its id, e.g.
E123), write what happened, in time order. Use only these events; cite the ids that support each statement. Say
when something is likely but not proven, and what is missing. Reply with ONE JSON object:
{{"summary": "3-6 sentences", "phases": [{{"phase": one of {list(PHASES)}, "when": "time or range",
  "what": "what happened", "events": ["E123", ...]}}], "hosts_involved": [], "accounts_involved": [],
  "open_questions": ["what the evidence does not answer"], "next_steps": ["what to collect or check next"],
  "confidence": "low|medium|high"}}
{SYSTEM_RULE}"""

ASK_SYSTEM = f"""You are a digital forensics analyst answering a question about one case. You are given the case
summary and events (ids like E123). If you need other events, reply {{"search": "words", "host": "", "since": "",
"until": ""}} (at most 3 searches). When you can answer, reply {{"answer": "...", "events": ["E123", ...],
"confidence": "low|medium|high"}}. Cite only ids you were shown. Say so when the events do not answer it.
{SYSTEM_RULE}"""


def _line(e: dict) -> str:
    rules = "; ".join(sorted({d["title"] for d in e.get("detections") or []}))[:200]
    extra = (f" [rules: {rules}]" if rules else "") + (f" [analyst: {e['comment'][:200]}]" if e.get("comment") else "") \
        + (" [starred]" if e.get("star") else "")
    return f"E{e['seq']} {e['ts'] or '?'} {e['host'] or '-'} {e['channel'] or ''}/{e['event_id'] or ''} " \
           f"{e['summary'][:300]}{extra}"


def _context_events(cfg, cid: str) -> list[dict]:
    st = store_for(cfg)
    limit = of(cfg).story_events
    seqs: list[int] = []
    starred, _ = st.search(cid, starred=True, limit=limit)
    seqs += [e["seq"] for e in starred]
    per_rule = max(2, limit // max(1, len(st.detection_summary(cid)) or 1))
    for d in st.detection_summary(cid):
        rows, total = st.search(cid, rule=d["rule_key"], limit=min(per_rule, 6))
        seqs += [e["seq"] for e in rows]
        if total > len(rows):
            last, _ = st.search(cid, rule=d["rule_key"], order="-ts", limit=1)
            seqs += [e["seq"] for e in last]
    for n in st.notes(cid):
        seqs += [int(x) for x in n["events"] if str(x).isdigit()]
    seen = list(dict.fromkeys(seqs))[:limit]
    by = {e["seq"]: e for e in st.events_by_seq(cid, seen)}
    dets = st.detections_of(cid, list(by))
    for e in by.values():
        e["detections"] = dets.get(e["seq"], [])
    return [by[x] for x in seen if x in by]          # priority order: starred, then detections by level


def prompt_budget(cfg, role: str, reply_tokens: int) -> int:
    """Characters of prompt that fit the role's model. Local models (Ollama) have a set context window
    (``num_ctx``); others get a large fixed budget. About 3 characters per token for log text."""
    rc = cfg.role_cfg(role) if hasattr(cfg, "role_cfg") else {}
    prov = str(rc.get("provider") or "")
    ctx = 0
    think = 0
    if prov == "ollama":
        pc = cfg.provider_cfg("ollama") or {}
        try:
            ctx = int(pc.get("num_ctx") or 8192)
            think = 0 if pc.get("think") is False else int(pc.get("think_tokens") or 0)   # thinking uses context too
        except (TypeError, ValueError):
            ctx = 8192
    if not ctx:
        return 300_000
    return max(4_000, (ctx - reply_tokens - think - 1_500) * 3)


def fit(lines: list[str], head: str, budget: int) -> tuple[list[str], int]:
    """Keep lines in priority order until the budget is used; returns (kept, dropped)."""
    room = budget - len(head)
    kept = []
    for ln in lines:
        if room - len(ln) - 1 < 0:
            break
        kept.append(ln)
        room -= len(ln) + 1
    return kept, len(lines) - len(kept)


def facts_text(facts: dict, cap: int) -> str:
    """The case facts as JSON within ``cap`` characters: long lists are halved until it fits, so events keep room."""
    f = dict(facts)
    text = json.dumps(f, default=str)
    keys = ["rare_processes", "rare_parent_child", "logons_with_failures", "hosts", "detections", "analyst_notes"]
    while len(text) > cap and any(len(f.get(k) or []) > 1 for k in keys):
        for k in keys:
            if len(f.get(k) or []) > 1:
                f[k] = f[k][:len(f[k]) // 2]
        text = json.dumps(f, default=str)
    return text[:cap]


def _facts(cfg, cid: str) -> dict:
    st = store_for(cfg)
    c = st.case(cid) or {}
    an = st.analysis(cid)
    return {"case": c.get("title"), "description": c.get("description"), "events_in_case": c.get("events"),
            "time_span": st.span(cid), "hosts": [h["host"] for h in st.hosts(cid)[:30]],
            "detections": [{k: d[k] for k in ("title", "level", "n", "hosts", "first", "last")}
                           for d in st.detection_summary(cid)[:60]],
            "rare_processes": [x["value"] for x in ((an.get("stacking") or {}).get("processes") or [])[:15]],
            "rare_parent_child": [x["value"] for x in ((an.get("stacking") or {}).get("parent_child") or [])[:15]],
            "logons_with_failures": [{k: x[k] for k in ("account", "source", "ok", "failed")}
                                     for x in (an.get("logons") or [])[:15] if x["failed"]],
            "analyst_notes": [{"kind": n["kind"], "text": n["text"], "status": n["status"]} for n in st.notes(cid)]}


def _ids(v: Any) -> list[int]:
    out = []
    for x in v if isinstance(v, list) else []:
        m = re.fullmatch(r"E?(\d+)", str(x).strip())
        if m:
            out.append(int(m.group(1)))
    return out


def _model_name(llm, role: str) -> str:
    try:
        b = llm.for_role(role)
        return f"{getattr(b.provider, 'name', '?')}/{getattr(b, 'model', '?')}"
    except Exception:
        return "?"


def story(cfg, llm, cid: str, *, actor: str) -> dict:
    if llm is None:
        raise ValueError("writing the story needs a model; none is configured")
    st = store_for(cfg)
    if not st.case(cid):
        raise KeyError(cid)
    evs = _context_events(cfg, cid)
    if not evs:
        raise ValueError("nothing to write about yet: run the analyzers, or star the events that matter")
    budget = prompt_budget(cfg, "reporter", 3000) - len(STORY_SYSTEM)
    head = facts_text(_facts(cfg, cid), min(20_000, int(budget * 0.4))) + "\n\nEVENTS (time order):\n"
    lines, dropped_events = fit([_line(e) for e in evs], head, budget)
    evs = sorted(evs[:len(lines)], key=lambda e: (e["ts"] or "", e["seq"]))
    shown = {e["seq"] for e in evs}
    msg = head + "\n".join(_line(e) for e in evs)
    res = llm.for_role("reporter").chat([{"role": "system", "content": STORY_SYSTEM},
                                         {"role": "user", "content": msg}], max_tokens=3000)
    if res.error:
        raise ValueError(f"the model call failed: {res.error[:300]}")
    obj = first_object(res.text or "")
    if not obj:
        raise ValueError("the model did not return a story")
    phases, dropped = [], 0
    for p in obj.get("phases") or []:
        if not isinstance(p, dict):
            continue
        ids = _ids(p.get("events"))
        good = [i for i in ids if i in shown]
        dropped += len(ids) - len(good)
        ph = str(p.get("phase", "other")).lower()
        phases.append({"phase": ph if ph in PHASES else "other", "when": str(p.get("when", ""))[:120],
                       "what": str(p.get("what", ""))[:1500], "events": good, "uncited": not good})
    body = {"summary": str(obj.get("summary", ""))[:3000], "phases": phases,
            "hosts_involved": [str(x)[:200] for x in obj.get("hosts_involved") or []][:30],
            "accounts_involved": [str(x)[:200] for x in obj.get("accounts_involved") or []][:30],
            "open_questions": [str(x)[:500] for x in obj.get("open_questions") or []][:15],
            "next_steps": [str(x)[:500] for x in obj.get("next_steps") or []][:15],
            "confidence": str(obj.get("confidence", ""))[:10], "events_given": len(evs),
            "events_left_out": dropped_events,
            "citations_removed": dropped, "unsupported_parts": sum(1 for p in phases if p["uncited"])}
    sid = st.save_story(cid, "story", body, author=actor, model=_model_name(llm, "reporter"))
    return {"id": sid, **body}


def ask(cfg, llm, cid: str, question: str, *, actor: str, max_searches: int = 3) -> dict:
    if llm is None:
        raise ValueError("questions need a model; none is configured")
    st = store_for(cfg)
    if not st.case(cid):
        raise KeyError(cid)
    question = question.strip()[:2000]
    if not question:
        raise ValueError("ask a question")
    words = [w for w in re.findall(r"[\w.\\/:-]{3,}", question)
             if w.lower() not in {"what", "which", "when", "where", "who", "did", "does", "the", "and", "was", "were",
                                  "how", "from", "with", "any", "there", "this", "that", "for", "have", "has"}][:4]
    evs = _context_events(cfg, cid)[:120]
    for w in words:
        rows, _ = st.search(cid, q=w, limit=15)
        evs += rows
    uniq = {e["seq"]: e for e in evs}
    budget = prompt_budget(cfg, "analyst", 1500) - len(ASK_SYSTEM) - len(question) - 4 * 3000   # room for searches
    head = facts_text(_facts(cfg, cid), min(12_000, int(budget * 0.4))) + "\n\nEVENTS:\n"
    ordered = list(uniq.values())[::-1]                       # question matches first, then context events
    lines, _ = fit([_line(e) for e in ordered], head, budget)
    keep = ordered[:len(lines)]
    uniq = {e["seq"]: e for e in keep}
    msgs = [{"role": "system", "content": ASK_SYSTEM},
            {"role": "user", "content": head + "\n".join(_line(e) for e in sorted(keep, key=lambda e: e["ts"] or "")) +
             f"\n\nQUESTION: {question}"}]
    searches = []
    for _ in range(max_searches + 1):
        res = llm.for_role("analyst").chat(msgs, max_tokens=1500)
        if res.error:
            raise ValueError(f"the model call failed: {res.error[:300]}")
        obj = first_object(res.text or "") or {}
        if "search" in obj and len(searches) < max_searches:
            q = str(obj.get("search", ""))[:200]
            rows, total = st.search(cid, q=q, host=str(obj.get("host", ""))[:200], since=str(obj.get("since", ""))[:40],
                                    until=str(obj.get("until", ""))[:40], limit=12)
            searches.append({"q": q, "found": total})
            for e in rows:
                uniq[e["seq"]] = e
            msgs += [{"role": "assistant", "content": res.text or ""},
                     {"role": "user", "content": f"{total} event(s) match; first {len(rows)}:\n" +
                      "\n".join(_line(e) for e in rows) + "\nAnswer now, or search again."}]
            continue
        ids = _ids(obj.get("events"))
        good = [i for i in ids if i in uniq]
        body = {"question": question, "answer": str(obj.get("answer") or res.text or "")[:6000], "events": good,
                "citations_removed": len(ids) - len(good), "confidence": str(obj.get("confidence", ""))[:10],
                "searches": searches}
        st.save_story(cid, "answer", body, author=actor, model=_model_name(llm, "analyst"))
        return body
    raise ValueError("the model kept searching without answering")
