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


class DemoProvider(LLMProvider):
    name = "demo"

    def __init__(self, cfg, secret=""):
        super().__init__(cfg, secret)
        self.default_model = "scripted-demo (not an AI model)"

    def chat(self, messages, *, model=None, temperature=0.2, max_tokens=900) -> LLMResult:
        from ..demo.data import C2_DOMAIN, C2_IP, ENC
        system = messages[0]["content"] if messages else ""
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
