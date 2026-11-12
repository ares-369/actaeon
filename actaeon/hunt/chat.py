"""Analyst chat on a hunt: ask about it, or steer it ("check the other hosts").

Each message gets one turn of the analyst model. It can answer from the hunt
record, or make up to ``MAX_CALLS`` read-only tool calls first. Calls go
through the same tool policy, validator, field guard and hub as a hunt; their
results are added to the same hunt as new evidence (E<n>), so the record stays
complete. Answers may cite evidence ids; citations that do not exist are
removed. The model cannot change the verdict; analysts give feedback on findings.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from datetime import datetime, timezone

from ..connectors import ROLES
from ..connectors.untrusted import SYSTEM_RULE
from .prompts import catalogue
from .signals import payload

MAX_CALLS = 5
CHAT_SYSTEM = f"""You help a security analyst with one threat hunt. You have its record and read-only tools.
Reply with exactly ONE JSON object. Either call a tool:
{{"action": "call", "connector": "name", "tool": "tool_name", "arguments": {{}}, "thought": "why"}}
or answer the analyst:
{{"action": "answer", "text": "your answer in plain language", "evidence": ["E3"]}}
Rules: cite evidence ids for every fact; say plainly when the record does not show something; keep answers short;
bound searches by time; at most {MAX_CALLS} calls before you answer. You cannot change the verdict.
{SYSTEM_RULE}"""
_lock = threading.Lock()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class ChatLog:
    def __init__(self, path):
        self.path = path
        with self._conn() as c:
            c.execute("CREATE TABLE IF NOT EXISTS chat (id INTEGER PRIMARY KEY AUTOINCREMENT, hunt_id TEXT NOT NULL, "
                      "ts TEXT NOT NULL, role TEXT NOT NULL, author TEXT, content TEXT NOT NULL, evidence TEXT)")

    def _conn(self):
        c = sqlite3.connect(self.path, timeout=10)
        c.row_factory = sqlite3.Row
        return c

    def add(self, hid: str, role: str, content: str, author: str = "", evidence: list | None = None) -> None:
        with _lock, self._conn() as c:
            c.execute("INSERT INTO chat (hunt_id, ts, role, author, content, evidence) VALUES (?,?,?,?,?,?)",
                      (hid, _now(), role, author[:100], content[:20000], json.dumps(evidence or [])))

    def list(self, hid: str) -> list[dict]:
        with self._conn() as c:
            return [{**dict(r), "evidence": json.loads(r["evidence"] or "[]")}
                    for r in c.execute("SELECT * FROM chat WHERE hunt_id=? ORDER BY id", (hid,))]


def _record(h: dict, budget: int = 24000) -> str:
    v = h.get("verdict") or {}
    lines = [f"Hypothesis: {h['hypothesis']}", f"Status: {h['status']}  Outcome: {h.get('outcome')}",
             f"Verdict summary: {v.get('summary', '')}"]
    for f in v.get("findings") or []:
        lines.append(f"Finding: {f['claim']} ({', '.join(f['evidence'])})")
    for f in h.get("feedback") or []:
        lines.append(f"Analyst feedback: {f['kind']} on '{f['claim']}' {f.get('comment', '')}")
    lines.append("Evidence:")
    used = sum(len(x) for x in lines)
    for s in reversed([s for s in h.get("steps") or [] if s["kind"] == "call"]):
        body = payload(s.get("result") or "")[:1500]
        item = (f"E{s['n']} {s['connector']}.{s['tool']} {json.dumps(s.get('arguments'), default=str)[:300]} "
                f"{'ok' if s['ok'] else 'failed'}\n<<UNTRUSTED-DATA rec>>\n{body}\n<<END-UNTRUSTED-DATA rec>>")
        if used + len(item) > budget:
            lines.append("[older evidence left out to save space]")
            break
        lines.insert(len(lines) - 0, item)
        used += len(item)
    return "\n".join(lines)


def ask(cfg, hid: str, message: str, *, author: str = "", llm=None, hub=None) -> dict:
    from . import service as hs
    store = hs.store_for(cfg)
    h = store.get(hid)
    if not h:
        raise LookupError("no such hunt")
    if h["status"] in ("queued", "running"):
        raise ValueError("the hunt is still running; ask when it has finished")
    message = (message or "").strip()[:4000]
    if not message:
        raise ValueError("message is required")
    log = ChatLog(store.path)
    log.add(hid, "analyst", message, author)
    if llm is None:
        from ..providers import get_llm
        llm = get_llm()
    llm = hs.privacy_llm(cfg, llm)
    hub = hs._hub(cfg, hub)
    tools = []
    for role in ROLES:
        tools += [{**t, "role": role} for t in hub.tools_for_role(role)]
    seen = set()
    tools = [t for t in tools if not ((t["connector"], t["name"]) in seen or seen.add((t["connector"], t["name"])))]
    history = [m for m in log.list(hid)][-12:]
    convo = "\n".join(f"{m['role'].upper()}: {m['content'][:1500]}" for m in history[:-1])
    base = [{"role": "system", "content": CHAT_SYSTEM},
            {"role": "user", "content": f"Hunt record:\n{_record(h)}\n\nTools:\n{catalogue(tools, compact=True)}\n\n"
                                        f"Earlier chat:\n{convo or '(none)'}\n\nAnalyst now asks: {message}"}]
    from .toolloop import run_loop
    final, _made, calls = run_loop(llm=llm, hub=hub, store=store, hid=hid, system=CHAT_SYSTEM,
                                  user=base[1]["content"], final_action="answer", max_calls=MAX_CALLS,
                                  max_results=cfg.hunt.max_results, actor=author or "chat", why_prefix="chat")
    t0 = time.monotonic()
    good = {f"E{s['n']}" for s in (store.get(hid) or {}).get("steps") or [] if s["kind"] == "call" and s["ok"]}
    answer = None
    if final:
        if final.get("error"):
            answer = {"text": f"(the model could not answer: {final['error'][:200]})", "evidence": []}
        else:
            answer = {"text": str(final.get("text") or "")[:6000] or "(empty answer)",
                      "evidence": [e for e in final.get("evidence") or [] if isinstance(e, str)]}
    answer = answer or {"text": "(no answer)", "evidence": []}
    dropped = [e for e in answer["evidence"] if e not in good]
    answer["evidence"] = [e for e in answer["evidence"] if e in good]
    if dropped:
        answer["text"] += f"\n\n[citations {', '.join(dropped)} removed: no such successful evidence]"
    log.add(hid, "actaeon", answer["text"], "model", answer["evidence"])
    return {"answer": answer["text"], "evidence": answer["evidence"], "calls": calls,
            "seconds": int(time.monotonic() - t0)}
