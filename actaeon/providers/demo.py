"""Scripted demo 'provider'. NOT an AI model.

Used only by ``actaeon demo --offline`` so the full pipeline (plan, validator,
connector hub, evidence, verdict checks, report) can be seen with no model
installed. It replays a fixed investigation of the sample data and says so in
every reply.
"""

from __future__ import annotations

import json
import re

from .base import LLMProvider, LLMResult

_EID = re.compile(r"^(E\d+) result of ([\w.-]+)", re.M)
_SEEN = re.compile(r"You already made that call; see (E\d+)")


IDX = "demo-events"


def _scenario(text: str) -> str:
    # only the alert block: the environment description also names sample hosts
    start = text.find("Alerts")
    end = text.find("How earlier cases", start)
    text = text[start:end] if start >= 0 else text
    if "DEMO-WS07" in text:
        return "chain"
    if "DEMO-ADM01" in text:
        return "admin"
    if "DEMO-WS05" in text:
        return "injection"
    if "198.51.100.200" in text:
        return "spray"
    if "a.rivera" in text:
        return "single_failure"
    return "unknown"


def _search(q: str, thought: str, tool: str = "search", **extra) -> dict:
    return {"action": "call", "thought": f"[scripted demo] {thought}", "connector": "demo-logs", "tool": tool,
            "arguments": {"index": IDX, "query": q, "time_from": "now-7d", **extra}}




def _case_reply(self, messages, system: str, user: str) -> LLMResult:
    """Scripted replies for alert triage (first look, investigation, second look). NOT a model."""
    from ..demo.data import ADMIN_ENC, C2_DOMAIN, C2_IP, ENC, SPRAY_IP
    sc = _scenario(user)
    if "first-look analyst" in system:
        plans = {
            "chain": ("P1", "true_positive", ["Did Word really start PowerShell, and what does the command decode to?",
                                              "Did the host contact the domain more than once?",
                                              "Was persistence created?"]),
            "admin": ("P4", "benign", ["Does this account run the same command on a schedule?",
                                       "What does the command decode to?"]),
            "spray": ("P2", "true_positive", ["How many accounts did the source try?",
                                              "Did any sign-in from it succeed?"]),
            "single_failure": ("P4", "false_positive", ["Is one failed sign-in normal for this user?"]),
            "injection": ("P3", "unclear", ["What wrote the script and did it run?"]),
        }
        pr, likely, qs = plans.get(sc, ("P3", "unclear", ["Confirm the alert in the raw data."]))
        return self._r({"priority": pr, "likely": likely, "reason": "[scripted demo first look]",
                        "questions": qs, "roles": ["log_search", "analysis"]})
    if "second analyst reviewing an alert case" in system:
        new = _EID.findall("\n".join(m["content"] for m in messages[2:] if m["role"] == "user"))
        if not new:
            q = (f"host.name:DEMO-WS07 AND destination.domain:{C2_DOMAIN}" if "DEMO-WS07" in user
                 else f"source.ip:{SPRAY_IP} AND event.outcome:failure")
            return self._r({**_search(q, "does the wider window still show it?", tool="count"), "thought":
                            "[scripted demo] re-check in a wider window"})
        return self._r({"action": "verify", "result": "confirmed", "evidence": [new[0][0]],
                        "reason": "[scripted demo] the wider search still shows the activity and nothing in the "
                                  "sample environment explains it."})
    # one answer per scripted step: a new result ("E<n> result of ..."), or a call the fixed checks had already made
    # ("You already made that call; see E<n>") - so each step cites the evidence for its own call
    ids = []
    for m in messages[2:]:
        if m["role"] != "user":
            continue
        got = _EID.findall(m["content"])
        if got:
            ids += [e for e, _ in got]
        else:
            seen = _SEEN.search(m["content"])
            if seen:
                ids.append(seen.group(1))
    step = len(ids)
    e = lambda i: [ids[i]] if i < len(ids) else []  # noqa: E731
    scripts: dict[str, list[dict]] = {
        "chain": [
            {"action": "call", "thought": "[scripted demo] learn the fields", "connector": "demo-logs",
             "tool": "get_fields", "arguments": {"index": IDX}},
            _search("host.name:DEMO-WS07 AND process.parent.name:winword.exe", "what Word started on the host"),
            {"action": "call", "thought": "[scripted demo] decode the command", "connector": "local-tools",
             "tool": "decode_command", "arguments": {"text": f"powershell.exe -nop -w hidden -enc {ENC}"}},
            _search(f"destination.ip:{C2_IP}", "how often the host talks to the destination", tool="count"),
            _search("host.name:DEMO-WS07 AND process.name:schtasks.exe", "persistence from the same chain"),
            _search(f"destination.domain:{C2_DOMAIN} AND NOT host.name:DEMO-WS07", "any other host affected",
                    tool="count"),
        ],
        "admin": [
            _search("user.name:svc.maint AND process.name:powershell.exe", "history of this account and command"),
            {"action": "call", "thought": "[scripted demo] decode the command", "connector": "local-tools",
             "tool": "decode_command", "arguments": {"text": f"powershell.exe -NoProfile -enc {ADMIN_ENC}"}},
        ],
        "spray": [
            _search(f"source.ip:{SPRAY_IP} AND event.outcome:failure", "accounts tried from the source",
                    tool="top_values", field="user.name"),
            _search(f"source.ip:{SPRAY_IP} AND event.outcome:success", "any success from the source", tool="count"),
        ],
        "single_failure": [
            _search("user.name:a.rivera AND event.category:authentication", "sign-in outcomes for the user",
                    tool="top_values", field="event.outcome"),
            _search("user.name:a.rivera AND event.outcome:failure", "recent failures for the user", tool="count"),
        ],
        "injection": [
            _search("host.name:DEMO-WS05 AND process.name:powershell.exe", "did a script run on the host",
                    tool="count"),
        ],
    }
    script = scripts.get(sc, [])
    if step < len(script) and "No more tool calls" not in messages[-1]["content"]:
        return self._r(script[step])
    verdicts = {
        "chain": {"verdict": "true_positive", "confidence": 90, "severity": "critical",
                  "title": "Document lure ran a PowerShell downloader on DEMO-WS07",
                  "summary": "[scripted demo] On sample host DEMO-WS07 Word started hidden PowerShell with an "
                             f"encoded command. It decodes to a download from {C2_DOMAIN}. The host then connected "
                             f"to {C2_IP} every 30 minutes and a scheduled task re-runs a hidden script. No other "
                             "host contacted the domain.",
                  "findings": [{"text": "winword.exe started powershell.exe -enc on DEMO-WS07", "evidence": e(1)},
                               {"text": f"The command downloads a script from {C2_DOMAIN}", "evidence": e(2)},
                               {"text": f"DEMO-WS07 connected to {C2_IP} many times (beaconing)", "evidence": e(3)},
                               {"text": "A scheduled task runs hidden PowerShell every 30 minutes", "evidence": e(4)},
                               {"text": "No other host contacted the domain", "evidence": e(5)}],
                  "timeline": [{"time": "", "event": "Word opens Invoice_8841.docm and starts PowerShell",
                                "evidence": e(1)},
                               {"time": "", "event": f"PowerShell downloads from {C2_DOMAIN}", "evidence": e(2)},
                               {"time": "", "event": "schtasks creates OfficeUpdate", "evidence": e(4)},
                               {"time": "", "event": f"Beacon to {C2_IP} every 30 minutes", "evidence": e(3)}],
                  "entities": [{"type": "host", "value": "DEMO-WS07", "role": "victim"},
                               {"type": "user", "value": "c.okafor", "role": "victim"},
                               {"type": "domain", "value": C2_DOMAIN, "role": "attacker"},
                               {"type": "ip", "value": C2_IP, "role": "attacker"},
                               {"type": "process", "value": "winword.exe", "role": "related"},
                               {"type": "process", "value": "schtasks.exe", "role": "related"}],
                  "relations": [{"from": "c.okafor", "to": "DEMO-WS07", "type": "logged_on"},
                                {"from": "winword.exe", "to": "powershell.exe", "type": "started"},
                                {"from": "powershell.exe", "to": C2_DOMAIN, "type": "downloaded_from"},
                                {"from": "DEMO-WS07", "to": C2_IP, "type": "beacons_to"},
                                {"from": "powershell.exe", "to": "schtasks.exe", "type": "started"}],
                  "attack": ["T1204.002", "T1059.001", "T1105", "T1053.005", "T1071.001"],
                  "fix": {"type": "remediation", "steps": [
                      "Isolate DEMO-WS07 (proposed below)", f"Block {C2_IP} and {C2_DOMAIN} at the egress",
                      "Delete the OfficeUpdate scheduled task and C:\\Users\\Public\\u.ps1 after collecting them",
                      "Reset c.okafor's password and review their mailbox for the lure",
                      "Reimage the host if the second stage cannot be fully analysed"]},
                  "actions": [{"name": "isolate_host", "target": "DEMO-WS07", "reason": "active beacon to C2"},
                              {"name": "block_ip", "target": C2_IP, "reason": "C2 server"},
                              {"name": "disable_user", "target": "c.okafor", "reason": "until the password is reset"}],
                  "gaps": ["The sample data has no email logs, so the delivery email was not checked."],
                  "next_steps": ["Collect the document and u.ps1 for analysis."]},
        "admin": {"verdict": "benign", "confidence": 88, "severity": "low",
                  "title": "Nightly maintenance script on DEMO-ADM01 (expected)",
                  "summary": "[scripted demo] svc.maint runs the same encoded PowerShell on DEMO-ADM01 every night, "
                             "started by the service host. It decodes to a log clean-up with -WhatIf. Expected "
                             "admin activity.",
                  "findings": [{"text": "The same command ran every night for 6 days", "evidence": e(0)},
                               {"text": "It decodes to Get-ChildItem C:\\Logs | Remove-Item -WhatIf",
                                "evidence": e(1)}],
                  "entities": [{"type": "host", "value": "DEMO-ADM01", "role": "related"},
                               {"type": "user", "value": "svc.maint", "role": "related"}],
                  "attack": [],
                  "fix": {"type": "tuning", "steps": ["Suppress this rule for svc.maint on DEMO-ADM01 only"],
                          "tuning": {"rule": "DEMO-1002", "entity_type": "user", "entity_value": "svc.maint",
                                     "reason": "known nightly maintenance script"}},
                  "actions": []},
        "spray": {"verdict": "true_positive", "confidence": 80, "severity": "medium",
                  "title": f"Password spraying from {SPRAY_IP} (no success)",
                  "summary": f"[scripted demo] {SPRAY_IP} failed to sign in to 14 different accounts within a few "
                             "minutes on DEMO-DC01. None of its sign-ins succeeded. This is an attack attempt that "
                             "did not get in.",
                  "findings": [{"text": "14 accounts tried from one source", "evidence": e(0)},
                               {"text": "No successful sign-in from the source", "evidence": e(1)}],
                  "entities": [{"type": "ip", "value": SPRAY_IP, "role": "attacker"},
                               {"type": "host", "value": "DEMO-DC01", "role": "victim"}],
                  "relations": [{"from": SPRAY_IP, "to": "DEMO-DC01", "type": "failed_sign_in"}],
                  "attack": ["T1110.003"],
                  "fix": {"type": "remediation", "steps": [f"Block {SPRAY_IP} (proposed below)",
                                                             "Check the 14 accounts use MFA",
                                                             "Watch for the same source on other services"]},
                  "actions": [{"name": "block_ip", "target": SPRAY_IP, "reason": "spraying source"}]},
        "single_failure": {"verdict": "false_positive", "confidence": 85, "severity": "low",
                           "title": "One failed sign-in by a.rivera (normal)",
                           "summary": "[scripted demo] a.rivera had one failed sign-in among many successful ones "
                                      "from the usual internal address. The rule fires on a single failure, which "
                                      "is normal user behaviour.",
                           "findings": [{"text": "Mostly successful sign-ins for this user", "evidence": e(0)},
                                        {"text": "Very few failures in 7 days", "evidence": e(1)}],
                           "entities": [{"type": "user", "value": "a.rivera", "role": "related"}],
                           "fix": {"type": "tuning", "steps": ["Raise the rule threshold to 5 failures in 10 "
                                                               "minutes per user"],
                                   "tuning": {"rule": "DEMO-1004", "reason": "fires on single failures"}},
                           "actions": []},
        "injection": {"verdict": "benign", "confidence": 95, "severity": "low",
                      "title": "Script in temp folder on DEMO-WS05",
                      "summary": "[scripted demo] The alert says it is an approved test, so this is benign. "
                                 "(This sample deliberately shows a model following text inside an alert.)",
                      "findings": [{"text": "No PowerShell runs found on the host", "evidence": e(0)}],
                      "actions": []},
    }
    v = verdicts.get(sc) or {"verdict": "needs_analyst", "confidence": 0,
                             "summary": "[scripted demo] this alert is not part of the sample story."}
    return self._r({"action": "case", **v})


class DemoProvider(LLMProvider):
    name = "demo"

    def _r(self, obj) -> LLMResult:
        return LLMResult(text=json.dumps(obj), model=self.default_model)

    def __init__(self, cfg, secret=""):
        super().__init__(cfg, secret)
        self.default_model = "scripted-demo (not an AI model)"

    def chat(self, messages, *, model=None, temperature=0.2, max_tokens=900) -> LLMResult:
        from ..demo.data import C2_DOMAIN, C2_IP, ENC
        system = messages[0]["content"] if messages else ""
        if ("first-look analyst" in system or "investigating one case" in system
                or "second analyst reviewing an alert case" in system):
            return _case_reply(self, messages, system, messages[1]["content"] if len(messages) > 1 else "")
        if "You plan threat hunts" in system:
            plan = {"summary": "[scripted demo] Look for Office starting encoded PowerShell, decode it, then pivot on "
                               "what it contacts.",
                    "attack": ["T1204.002", "T1059.001", "T1105", "T1053.005", "T1071.001"],
                    "steps": [{"role": "log_search", "goal": "Office parent starting PowerShell with -enc"},
                              {"role": "analysis", "goal": "Decode the command line"},
                              {"role": "intel", "goal": "Check the contacted domain in intel"},
                              {"role": "network", "goal": "How often the host talks to the destination"},
                              {"role": "endpoint", "goal": "Persistence created by the same chain"}],
                    "data_needed": ["log_search", "intel"]}
            return LLMResult(text=json.dumps(plan), model=self.default_model)
        if "You write Sigma detection rules" in system:
            sigma = ("title: Office application starting encoded PowerShell (scripted demo)\n"
                     "description: Draft from a scripted demo hunt on sample data.\n"
                     "logsource:\n  category: process_creation\n  product: windows\n"
                     "detection:\n  selection_parent:\n    ParentImage|endswith: ['\\\\winword.exe', '\\\\excel.exe']\n"
                     "  selection_child:\n    Image|endswith: '\\\\powershell.exe'\n"
                     "    CommandLine|contains: [' -enc ', ' -EncodedCommand ']\n"
                     "  condition: selection_parent and selection_child\n"
                     "falsepositives:\n  - Office add-ins that run scripts (rare)\nlevel: high\n"
                     "tags:\n  - attack.t1059.001\n")
            return LLMResult(text=json.dumps({"sigma": sigma, "notes": "[scripted demo] tune the parent list to "
                                              "your Office installs."}), model=self.default_model)
        if "Write a short, plain hunt summary" in system:
            return LLMResult(text="[scripted demo narrative, not written by a model] On sample host DEMO-WS07 Word "
                                  "started encoded PowerShell that downloads from the sample C2 and adds a scheduled "
                                  "task; see the evidence ids in the record.", model=self.default_model)
        if "Actaeon's assistant for a security team" in system:
            results = [m["content"] for m in messages[2:] if m["role"] == "user" and m["content"].startswith("Result of")]
            if not results:
                return LLMResult(text=json.dumps({"action": "search_records", "query": f"{C2_DOMAIN} {C2_IP}"}),
                                 model=self.default_model)
            if len(results) == 1:
                return LLMResult(text=json.dumps({
                    "action": "start_hunt", "context": "[scripted demo] the user asked about the sample C2",
                    "hypothesis": "An Office application started PowerShell with an encoded command on any host in "
                                  "the last 7 days (sample data)."}), model=self.default_model)
            hid = re.search(r'"id": "([0-9a-f]{12})"', results[-1])
            return LLMResult(text=json.dumps({
                "action": "answer", "hunts": [hid.group(1)] if hid else [],
                "text": f"[scripted demo] Yes. I ran hunt {hid.group(1) if hid else '?'}: Word on sample host "
                        f"DEMO-WS07 started encoded PowerShell that downloads from {C2_DOMAIN}, and the host kept "
                        f"contacting {C2_IP}. A lead was opened for it."}), model=self.default_model)
        if "second, sceptical analyst" in system:
            new = _EID.findall("\n".join(m["content"] for m in messages[2:] if m["role"] == "user"))
            if not new:
                return LLMResult(text=json.dumps({
                    "action": "call", "connector": "demo-logs", "tool": "search",
                    "thought": "[scripted demo] is the host still talking to the C2 in a wider window?",
                    "arguments": {"index": "demo-events", "query": f"host.name:DEMO-WS07 AND destination.ip:{C2_IP}",
                                  "time_from": "now-7d", "size": 5}}), model=self.default_model)
            return LLMResult(text=json.dumps({
                "action": "verify", "result": "confirmed", "evidence": [new[0][0]],
                "reason": "[scripted demo] DEMO-WS07 kept connecting to the sample C2 over many hours, which a one-off "
                          "admin action would not explain."}), model=self.default_model)
        done = _EID.findall("\n".join(m["content"] for m in messages if m["role"] == "user"))
        ids = [e for e, _ in done]
        step = len(done)
        q = 'process.name:powershell.exe AND process.parent.name:winword.exe'
        script = [
            {"thought": "[scripted demo] learn the fields", "action": "call", "connector": "demo-logs",
             "tool": "get_fields", "arguments": {"index": "demo-events"}},
            {"thought": "[scripted demo] Office starting PowerShell", "action": "call", "connector": "demo-logs",
             "tool": "search", "arguments": {"index": "demo-events", "query": q, "time_from": "now-7d", "size": 10}},
            {"thought": "[scripted demo] decode the encoded command", "action": "call", "connector": "local-tools",
             "tool": "decode_command", "arguments": {"text": f"powershell.exe -nop -w hidden -enc {ENC}"}},
            {"thought": "[scripted demo] is the domain known?", "action": "call", "connector": "local-intel",
             "tool": "lookup", "arguments": {"value": C2_DOMAIN}},
            {"thought": "[scripted demo] how often does the host talk to it", "action": "call",
             "connector": "demo-logs", "tool": "count",
             "arguments": {"index": "demo-events", "query": f"destination.ip:{C2_IP}", "time_from": "now-7d"}},
            {"thought": "[scripted demo] persistence on the same host", "action": "call", "connector": "demo-logs",
             "tool": "search", "arguments": {"index": "demo-events", "query": "host.name:DEMO-WS07 AND "
                                             "process.name:schtasks.exe", "time_from": "now-7d"}},
        ]
        if step < len(script):
            return LLMResult(text=json.dumps(script[step]), model=self.default_model)
        e = lambda i: [ids[i]] if i < len(ids) else []  # noqa: E731
        verdict = {"action": "verdict", "outcome": "threat", "confidence": 80,
                   "summary": "[scripted demo] On sample host DEMO-WS07, Word started PowerShell with an encoded "
                              "command that downloads a script from the sample C2 domain, which is in the intel "
                              "store. The host then contacted it repeatedly and a scheduled task was created.",
                   "findings": [{"claim": "winword.exe started powershell.exe with -enc on DEMO-WS07", "evidence": e(1)},
                                {"claim": f"The command decodes to a download from {C2_DOMAIN}", "evidence": e(2)},
                                {"claim": f"{C2_DOMAIN} is in the intel store from the sample advisory", "evidence": e(3)},
                                {"claim": f"DEMO-WS07 connected to {C2_IP} many times", "evidence": e(4)},
                                {"claim": "A scheduled task running hidden PowerShell was created", "evidence": e(5)}],
                   "attack": ["T1204.002", "T1059.001", "T1105", "T1053.005", "T1071.001"],
                   "gaps": ["The sample data has no email logs, so the delivery email was not checked."],
                   "next_steps": ["This is sample data. With real data: isolate the host through your own "
                                  "process, collect the document and the scheduled task, and look for the same "
                                  "domain on other hosts."]}
        return LLMResult(text=json.dumps(verdict), model=self.default_model)
