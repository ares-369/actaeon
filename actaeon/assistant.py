"""The Ask assistant: questions and hunt requests in plain language.

Actions the model can take (one JSON object per turn):
  search_records {query}            past hunts, leads and analyst notes that match
  get_hunt {id}                     one hunt's verdict and findings
  list_leads {status}               open or recent leads
  lookup_intel {value}              is a value in the intel store
  start_hunt {hypothesis, context}  run a full hunt now (stored like any hunt, origin ask:<user>)
  ask_hunt {hunt_id, question}      follow-up on a finished hunt (its chat; new searches become evidence)
  answer {text, hunts, leads}       final reply
Data is only searched inside hunts, so everything the assistant finds is stored
with its evidence. Conversations are stored with links to the hunts and leads used.
"""

from __future__ import annotations

import json
import re
import sqlite3
import threading
from datetime import datetime, timezone

from .connectors.untrusted import SYSTEM_RULE
from .hunt.jsonparse import first_object

MAX_ACTIONS = 6
MAX_HUNTS = 2
_lock = threading.Lock()

SYSTEM = f"""You are Actaeon's assistant for a security team. You answer questions and run threat hunts.
Reply with exactly ONE JSON object per turn, one of:
{{"action": "search_records", "query": "words"}}
{{"action": "get_hunt", "id": "hunt id"}}
{{"action": "list_leads", "status": "open|new|closed"}}
{{"action": "lookup_intel", "value": "IP, domain, hash ..."}}
{{"action": "start_hunt", "hypothesis": "a specific, testable hypothesis with a time window", "context": "why"}}
{{"action": "ask_hunt", "hunt_id": "id", "question": "follow-up question"}}
{{"action": "answer", "text": "plain answer", "hunts": ["ids you used"], "leads": [lead ids]}}
Rules: to find out whether something happened in the environment, start a hunt (you cannot search data
directly). Check records first so you do not repeat a recent hunt. Every factual claim must come from a tool
result; say plainly when you do not know. Name hunt ids and lead ids in the answer. At most {MAX_HUNTS} hunts.
{SYSTEM_RULE}"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class Conversations:
    def __init__(self, path):
        self.path = path
        with self._conn() as c:
            c.executescript("""
            CREATE TABLE IF NOT EXISTS conversations (id INTEGER PRIMARY KEY AUTOINCREMENT, user TEXT NOT NULL,
                created TEXT NOT NULL, updated TEXT NOT NULL, title TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS conv_msgs (id INTEGER PRIMARY KEY AUTOINCREMENT, conv_id INTEGER NOT NULL,
                ts TEXT NOT NULL, role TEXT NOT NULL, user TEXT, content TEXT NOT NULL, links TEXT);
            """)

    def _conn(self):
        c = sqlite3.connect(self.path, timeout=10)
        c.row_factory = sqlite3.Row
        return c

    def create(self, user: str, title: str) -> int:
        with _lock, self._conn() as c:
            return c.execute("INSERT INTO conversations (user, created, updated, title) VALUES (?,?,?,?)",
                             (user, _now(), _now(), title[:120])).lastrowid

    def add(self, cid: int, role: str, content: str, user: str = "", links: dict | None = None) -> None:
        with _lock, self._conn() as c:
            c.execute("INSERT INTO conv_msgs (conv_id, ts, role, user, content, links) VALUES (?,?,?,?,?,?)",
                      (cid, _now(), role, user, content[:20000], json.dumps(links or {})))
            c.execute("UPDATE conversations SET updated=? WHERE id=?", (_now(), cid))

    def get(self, cid: int) -> dict | None:
        with self._conn() as c:
            r = c.execute("SELECT * FROM conversations WHERE id=?", (int(cid),)).fetchone()
            if not r:
                return None
            msgs = [{**dict(m), "links": json.loads(m["links"] or "{}")}
                    for m in c.execute("SELECT * FROM conv_msgs WHERE conv_id=? ORDER BY id", (int(cid),))]
        return {**dict(r), "messages": msgs}

    def list(self, limit: int = 100) -> list[dict]:
        with self._conn() as c:
            return [dict(r) for r in c.execute("SELECT * FROM conversations ORDER BY updated DESC LIMIT ?",
                                               (int(limit),))]


def _records(cfg, query: str) -> dict:
    from .hunt import service as hs
    mem = hs.memory_for(cfg).related(query, k=5)
    words = [w for w in re.findall(r"[A-Za-z0-9._@:-]{3,}", query.lower())][:8]
    hunts = []
    for h in hs.store_for(cfg).list(limit=300):
        text = (h["hypothesis"] + " " + json.dumps(h.get("verdict") or {})).lower()
        if words and sum(w in text for w in words) >= max(1, len(words) // 2):
            hunts.append({"id": h["id"], "created": h["created"], "outcome": h["outcome"],
                          "hypothesis": h["hypothesis"][:200], "summary": ((h.get("verdict") or {}).get("summary")
                                                                           or "")[:300]})
        if len(hunts) >= 8:
            break
    leads = [{"id": c["id"], "status": c["status"], "severity": c["severity"], "title": c["title"][:160]}
             for c in hs.leads_for(cfg).list(limit=200)
             if words and any(w in c["title"].lower() for w in words)][:8]
    return {"hunts": hunts, "leads": leads, "notes": [n["text"][:300] for n in mem["notes"]],
            "related_past_hunts": [{"id": h["hunt_id"], "outcome": h["outcome"], "hypothesis": h["hypothesis"][:160]}
                                   for h in mem["hunts"]]}


def _hunt_brief(h: dict) -> dict:
    v = h.get("verdict") or {}
    return {"id": h["id"], "status": h["status"], "outcome": h.get("outcome"), "confidence": v.get("confidence"),
            "summary": v.get("summary"), "findings": [f"{f['claim']} ({', '.join(f['evidence'])})"
                                                      for f in v.get("findings") or []],
            "verification": (v.get("verification") or {}).get("result"), "needs_review": v.get("needs_review")}


def ask(cfg, message: str, *, user: str, conv_id: int | None = None, llm=None, hub=None) -> dict:
    from .hunt import service as hs
    message = (message or "").strip()[:4000]
    if not message:
        raise ValueError("message is required")
    conv = Conversations(hs.store_for(cfg).path)
    if conv_id is None or not conv.get(conv_id):
        conv_id = conv.create(user, message)
    conv.add(conv_id, "user", message, user)
    if llm is None:
        from .providers import get_llm
        llm = get_llm()
    plm = hs.privacy_llm(cfg, llm)
    hist = (conv.get(conv_id) or {}).get("messages", [])[-10:-1]
    history = "\n".join(f"{m['role'].upper()}: {m['content'][:1200]}" for m in hist)
    msgs = [{"role": "system", "content": SYSTEM},
            {"role": "user", "content": f"{hs.environment_context(cfg)}\n\nEarlier in this conversation:\n"
                                        f"{history or '(none)'}\n\nNew message from {user}: {message}"}]
    used_hunts: list[str] = []
    used_leads: list[int] = []
    started = 0
    final = None
    for step in range(MAX_ACTIONS + 1):
        if step == MAX_ACTIONS:
            msgs.append({"role": "user", "content": "No more actions. Give the answer now."})
        res = plm.for_role("analyst").chat(msgs, max_tokens=1500)
        if res.error:
            final = {"text": f"(the model could not answer: {res.error[:200]})"}
            break
        act = first_object(res.text) or {}
        kind = act.get("action")
        if kind == "answer" or step == MAX_ACTIONS or not kind:
            final = act if kind == "answer" else {"text": res.text[:4000]}
            break
        msgs.append({"role": "assistant", "content": json.dumps(act)[:3000]})
        try:
            if kind == "search_records":
                out = _records(cfg, str(act.get("query", "")))
            elif kind == "get_hunt":
                h = hs.store_for(cfg).get(str(act.get("id", "")))
                out = _hunt_brief(h) if h else {"error": "no such hunt"}
                if h:
                    used_hunts.append(h["id"])
            elif kind == "list_leads":
                stt = str(act.get("status", "open"))
                rows = hs.leads_for(cfg).list(open_only=stt == "open", status=stt if stt in ("new", "closed") else None,
                                              limit=20)
                out = [{"id": c["id"], "status": c["status"], "severity": c["severity"], "assignee": c["assignee"],
                        "title": c["title"][:160]} for c in rows]
            elif kind == "lookup_intel":
                out = hs.intel_for(cfg).lookup(str(act.get("value", "")))
            elif kind == "start_hunt":
                if started >= MAX_HUNTS:
                    out = {"error": f"at most {MAX_HUNTS} hunts per message"}
                else:
                    started += 1
                    hyp = str(act.get("hypothesis", "")).strip()[:1000]
                    h = hs.run_hunt(cfg, hyp, origin=f"ask:{user}", actor=user,
                                    context=f"Requested in the Ask assistant by {user}: {message[:500]}\n"
                                            f"{str(act.get('context', ''))[:500]}", llm=llm, hub=hub)
                    used_hunts.append(h["id"])
                    lead = hs.leads_for(cfg).by_hunt(h["id"])
                    if lead:
                        used_leads.append(lead["id"])
                    out = {**_hunt_brief(h), "lead": lead["id"] if lead else None}
            elif kind == "ask_hunt":
                from .hunt.chat import ask as hunt_ask
                hid = str(act.get("hunt_id", ""))
                out = hunt_ask(cfg, hid, str(act.get("question", "")), author=user, llm=llm, hub=hub)
                used_hunts.append(hid)
            else:
                out = {"error": f"unknown action {kind!r}"}
        except (ValueError, LookupError) as exc:
            out = {"error": str(exc)[:300]}
        msgs.append({"role": "user", "content": f"Result of {kind}:\n<<UNTRUSTED-DATA ask>>\n"
                                                f"{json.dumps(out, default=str)[:12000]}\n<<END-UNTRUSTED-DATA ask>>"})
    text = str((final or {}).get("text") or "(no answer)")[:8000]
    hunts = list(dict.fromkeys(used_hunts + [h for h in (final or {}).get("hunts") or [] if isinstance(h, str)
                                             and hs.store_for(cfg).get(h, with_steps=False)]))
    leads = list(dict.fromkeys(used_leads + [c for c in (final or {}).get("leads") or [] if isinstance(c, int)
                                             and hs.leads_for(cfg).get(c)]))
    conv.add(conv_id, "assistant", text, "actaeon", {"hunts": hunts, "leads": leads})
    return {"conversation_id": conv_id, "answer": text, "hunts": hunts, "leads": leads}
