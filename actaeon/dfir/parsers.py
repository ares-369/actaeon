"""Evidence parsers: each turns a file into normalised events.

Formats, picked from the file name and its first bytes:

* Windows event logs (``.evtx``): needs ``pip install 'actaeon[dfir]'`` (python-evtx, Apache-2.0)
* JSON lines or a JSON list: Velociraptor results, Hayabusa JSONL, event logs exported as JSON (evtx_dump),
  osquery results, or any records with a time field
* CSV: Plaso (l2tcsv and psort's dynamic output), Hayabusa CSV, or any CSV with a time column
* Linux syslog and auth.log lines (RFC 3164 and ISO time stamps)
* ``.gz`` of any text format above, and ``.zip`` collections (each member parsed; size and count capped)

Every event keeps all its fields (``data``), plus a few normalised ones used for sorting, filters and the
summary line: ``ts`` (UTC, ``YYYY-MM-DDTHH:MM:SS.mmmZ``), ``host``, ``channel``, ``event_id``, ``user``,
``process`` and ``summary``. Windows events use the field names Sigma rules use (``EventID``, ``Channel``,
``Provider_Name``, ``Computer`` and the EventData names such as ``Image`` and ``CommandLine``).
"""

from __future__ import annotations

import csv
import gzip
import io
import json
import re
import tempfile
import xml.etree.ElementTree as ET  # nosec B405 - evidence XML from python-evtx; expat refuses entity expansion
import zipfile
from collections.abc import Iterator
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

MAX_ZIP_MEMBERS = 5000
MAX_FIELD = 20_000           # characters kept per field value
csv.field_size_limit(10_000_000)


class ParseError(ValueError):
    pass


# ---------------------------------------------------------------- time

_ISO = re.compile(r"^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})(?:[.,](\d+))?\s*(Z|UTC|[+-]\d{2}:?\d{2})?$", re.I)
_MON = {m: i + 1 for i, m in enumerate(("jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov",
                                        "dec"))}


def fmt(dt: datetime) -> str:
    dt = dt.astimezone(timezone.utc) if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def parse_time(v: Any, *, year: int | None = None) -> str:
    """Any common time stamp as UTC ``YYYY-MM-DDTHH:MM:SS.mmmZ``; empty when it cannot be read."""
    if v is None or v == "" or isinstance(v, bool):
        return ""
    s = str(v).strip()
    if isinstance(v, (int, float)) or re.fullmatch(r"\d{9,19}(\.\d+)?", s):
        n = float(s)
        if n > 1e17:
            n /= 1e9
        elif n > 1e14:
            n /= 1e6
        elif n > 1e11:
            n /= 1e3
        try:
            return fmt(datetime.fromtimestamp(n, timezone.utc))
        except (OverflowError, OSError, ValueError):
            return ""
    m = _ISO.match(s)
    if m:
        y, mo, d, hh, mm, ss, frac, tz = m.groups()
        us = int((frac or "0")[:6].ljust(6, "0"))
        try:
            dt = datetime(int(y), int(mo), int(d), int(hh), int(mm), int(ss), us, tzinfo=timezone.utc)
        except ValueError:
            return ""
        if tz and tz.upper() not in ("Z", "UTC"):
            sign = 1 if tz[0] == "+" else -1
            t = tz[1:].replace(":", "")
            from datetime import timedelta
            dt -= sign * timedelta(hours=int(t[:2]), minutes=int(t[2:4]))
        return fmt(dt)
    m = re.match(r"^(\d{1,2})/(\d{1,2})/(\d{4})[ T](\d{1,2}):(\d{2}):(\d{2})", s)        # Plaso l2tcsv MM/DD/YYYY
    if m:
        mo, d, y, hh, mm, ss = map(int, m.groups())
        try:
            return fmt(datetime(y, mo, d, hh, mm, ss, tzinfo=timezone.utc))
        except ValueError:
            return ""
    m = re.match(r"^([A-Za-z]{3})\s+(\d{1,2})\s(\d{2}):(\d{2}):(\d{2})", s)              # syslog, no year
    if m and m.group(1).lower() in _MON:
        try:
            return fmt(datetime(year or datetime.now(timezone.utc).year, _MON[m.group(1).lower()], int(m.group(2)),
                                int(m.group(3)), int(m.group(4)), int(m.group(5)), tzinfo=timezone.utc))
        except ValueError:
            return ""
    return ""


# ---------------------------------------------------------------- normalising

_TIME_KEYS = re.compile(r"(?i)(^|\.)(@timestamp|timestamp|systemtime|timecreated|eventtime|event_time|datetime|"
                        r"_ts|ts|time|_time|date|created|createtime|starttime|logtime)$")
_HOST_KEYS = re.compile(r"(?i)(^|\.)(computer|computername|hostname|host\.name|host|fqdn|device(name)?|agent\.name|"
                        r"clientid|endpoint)$")
_USER_KEYS = re.compile(r"(?i)(^|\.)(targetusername|subjectusername|user\.name|username|user|account(name)?|upn)$")
_PROC_KEYS = re.compile(r"(?i)(^|\.)(image|newprocessname|process\.executable|process\.name|exe|processname|"
                        r"program|path)$")


def flat(d: Any, prefix: str = "", out: dict | None = None) -> dict:
    out = {} if out is None else out
    if isinstance(d, dict):
        for k, v in d.items():
            key = f"{prefix}.{k}" if prefix else str(k)
            if isinstance(v, dict):
                flat(v, key, out)
            elif isinstance(v, list):
                out[key] = [str(x)[:MAX_FIELD] if not isinstance(x, (int, float, bool)) else x for x in v[:50]]
            elif isinstance(v, str):
                out[key] = v[:MAX_FIELD]
            else:
                out[key] = v
    return out


def _pick(data: dict, rx: re.Pattern, *, avoid: tuple[str, ...] = ()) -> str:
    for k, v in data.items():
        if rx.search(k) and v not in (None, "", "-", "None", "null") and not isinstance(v, (list, dict)) \
                and not any(a in k.lower() for a in avoid):
            return str(v)
    return ""


def _g(d: dict, *keys: str) -> str:
    for k in keys:
        v = d.get(k)
        if v not in (None, "", "-"):
            return str(v)
    return ""


def summary(d: dict) -> str:
    """One readable line, like the details column of event log triage tools."""
    eid = str(d.get("EventID", ""))
    ch = str(d.get("Channel", "")).lower()
    sysmon = "sysmon" in ch
    if eid in ("4624", "4625", "4648") and not sysmon:
        what = {"4624": "Logon", "4625": "Failed logon", "4648": "Explicit-credential logon"}[eid]
        who = "\\".join(x for x in (_g(d, "TargetDomainName"), _g(d, "TargetUserName")) if x)
        frm = _g(d, "IpAddress", "WorkstationName")
        lt = _g(d, "LogonType")
        return f"{what}{' type ' + lt if lt else ''} {who}{' from ' + frm if frm else ''}".strip()
    if (sysmon and eid == "1") or (eid == "4688" and not sysmon):
        par = _g(d, "ParentImage", "ParentProcessName")
        img = _g(d, "Image", "NewProcessName")
        cmd = _g(d, "CommandLine")
        user = _g(d, "User", "SubjectUserName")
        return f"{par + ' -> ' if par else ''}{img}{': ' + cmd if cmd and cmd != img else ''}" + \
            (f"  (user {user})" if user else "")
    if sysmon and eid == "3":
        return f"{_g(d, 'Image')} -> {_g(d, 'DestinationHostname', 'DestinationIp')}:{_g(d, 'DestinationPort')}"
    if sysmon and eid == "11":
        return f"{_g(d, 'Image')} wrote {_g(d, 'TargetFilename')}"
    if sysmon and eid in ("12", "13", "14"):
        return f"{_g(d, 'Image')} {_g(d, 'EventType')} {_g(d, 'TargetObject')} {_g(d, 'Details')}".strip()
    if sysmon and eid == "10":
        return f"{_g(d, 'SourceImage')} opened {_g(d, 'TargetImage')} (access {_g(d, 'GrantedAccess')})"
    if sysmon and eid == "8":
        return f"{_g(d, 'SourceImage')} started a thread in {_g(d, 'TargetImage')}"
    if sysmon and eid == "7":
        return f"{_g(d, 'Image')} loaded {_g(d, 'ImageLoaded')}"
    if sysmon and eid in ("17", "18"):
        return f"{_g(d, 'Image')} {'created' if eid == '17' else 'connected to'} pipe {_g(d, 'PipeName')}"
    if sysmon and eid in ("23", "26"):
        return f"{_g(d, 'Image')} deleted {_g(d, 'TargetFilename')}"
    if sysmon and eid == "22":
        return f"{_g(d, 'Image')} looked up {_g(d, 'QueryName')}"
    if eid == "7045":
        return f"Service installed {_g(d, 'ServiceName')}: {_g(d, 'ImagePath')} ({_g(d, 'AccountName')})"
    if eid in ("4697",):
        return f"Service installed {_g(d, 'ServiceName')}: {_g(d, 'ServiceFileName')}"
    if eid == "4698":
        return f"Scheduled task created {_g(d, 'TaskName')} by {_g(d, 'SubjectUserName')}"
    if eid == "4720":
        return f"User created {_g(d, 'TargetUserName')} by {_g(d, 'SubjectUserName')}"
    if eid in ("4728", "4732", "4756"):
        return f"{_g(d, 'MemberName', 'MemberSid')} added to group {_g(d, 'TargetUserName')} by {_g(d, 'SubjectUserName')}"
    if eid in ("1102", "104"):
        return f"Event log cleared by {_g(d, 'SubjectUserName', 'param1') or 'unknown'}"
    if eid in ("5140", "5145") and not sysmon:
        share = _g(d, "ShareName") + ("\\" + _g(d, "RelativeTargetName") if _g(d, "RelativeTargetName") else "")
        return f"Share access {share} by {_g(d, 'SubjectUserName')} from {_g(d, 'IpAddress')}"
    if eid in ("4768", "4769") and not sysmon:
        what = "Kerberos TGT" if eid == "4768" else f"Kerberos service ticket for {_g(d, 'ServiceName')}"
        return f"{what} to {_g(d, 'TargetUserName')} from {_g(d, 'IpAddress')} (encryption {_g(d, 'TicketEncryptionType')})"
    if eid == "4776" and not sysmon:
        return f"NTLM check of {_g(d, 'TargetUserName')} from {_g(d, 'Workstation')} (status {_g(d, 'Status')})"
    if eid == "4672" and not sysmon:
        return f"Special privileges given to {_g(d, 'SubjectDomainName')}\\{_g(d, 'SubjectUserName')}"
    if eid in ("4656", "4663") and not sysmon:
        return f"{_g(d, 'ProcessName')} accessed {_g(d, 'ObjectName')} ({_g(d, 'AccessMask', 'AccessList')})"
    if eid == "4662" and not sysmon:
        return f"Directory object access by {_g(d, 'SubjectUserName')}: {_g(d, 'Properties')[:200]}"
    if eid == "7036":
        return f"Service {_g(d, 'param1')} is {_g(d, 'param2')}"
    if eid == "4104":
        return "PowerShell script block: " + _g(d, "ScriptBlockText")[:300]
    if d.get("vol_plugin"):                                   # Volatility 3 rows
        if "ForeignAddr" in d:
            return (f"{_g(d, 'Owner')} (pid {_g(d, 'PID')}) {_g(d, 'Proto')} {_g(d, 'LocalAddr')}:{_g(d, 'LocalPort')} -> "
                    f"{_g(d, 'ForeignAddr')}:{_g(d, 'ForeignPort')} {_g(d, 'State')}")
        if "Protection" in d:
            return f"{_g(d, 'Process', 'ImageFileName')} (pid {_g(d, 'PID')}) memory {_g(d, 'Protection')} at {_g(d, 'Start VPN')}"
        if "ImageFileName" in d:
            return (f"{'  ' * int(d.get('tree_depth') or 0)}{_g(d, 'ImageFileName')} pid {_g(d, 'PID')} ppid {_g(d, 'PPID')}"
                    + (f": {_g(d, 'Args', 'Cmd')}" if _g(d, "Args", "Cmd") else ""))
    if d.get("RuleTitle"):
        det = d.get("Details")
        return f"{d['RuleTitle']}: {det if isinstance(det, str) else ''}".strip(": ")
    for k in ("message", "Message", "msg", "desc", "short", "Details", "details", "description"):
        if isinstance(d.get(k), str) and d[k].strip():
            return d[k].strip()[:400]
    skip = re.compile(r"(?i)(time|date|_ts|hash|guid|sid$|recordid|keywords|version|opcode|task$|level$|^eventid$|"
                      r"^provider_name$|^channel$|^computer$|^threadid$|^processid$|^userid$|^activityid$|^qualifiers$)")
    parts = [f"{k}={v}" for k, v in d.items() if not isinstance(v, (list, dict)) and v not in (None, "", "-")
             and not skip.search(k)][:6]
    return " ".join(parts)[:400]


def normalise(data: dict, *, year: int | None = None, ts: str = "") -> dict:
    eid = str(data.get("EventID", "") or "")
    if eid == "4688" and "Image" not in data:                 # Security 4688 under Sigma's process_creation names
        for a, b in (("Image", "NewProcessName"), ("ParentImage", "ParentProcessName"), ("User", "SubjectUserName")):
            if b in data and a not in data:
                data[a] = data[b]
    if not ts:
        for k, v in data.items():
            if _TIME_KEYS.search(k):
                ts = parse_time(v, year=year)
                if ts:
                    break
    return {"ts": ts, "host": _pick(data, _HOST_KEYS)[:200], "channel": str(data.get("Channel", "") or
                                                                          data.get("program", "") or
                                                                          data.get("vol_plugin", "") or "")[:120],
            "event_id": eid[:20], "user": _pick(data, _USER_KEYS)[:200],
            "process": _pick(data, _PROC_KEYS, avoid=("parent",))[:400], "summary": summary(data)[:500], "data": data}


# ---------------------------------------------------------------- Windows events

def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def from_event_xml(xml: str) -> dict:
    root = ET.fromstring(xml)  # nosec B314 - see the import note
    d: dict[str, Any] = {}
    for part in root:
        name = _local(part.tag)
        if name == "System":
            for el in part:
                t = _local(el.tag)
                if t == "Provider":
                    d["Provider_Name"] = el.get("Name", "")
                elif t == "TimeCreated":
                    d["TimeCreated"] = el.get("SystemTime", "")
                elif t == "Security":
                    if el.get("UserID"):
                        d["UserID"] = el.get("UserID")
                elif t == "Execution":
                    d["ProcessID"], d["ThreadID"] = el.get("ProcessID", ""), el.get("ThreadID", "")
                elif t == "Correlation":
                    if el.get("ActivityID"):
                        d["ActivityID"] = el.get("ActivityID")
                else:
                    d[t] = (el.text or "").strip()
        elif name == "EventData":
            n = 0
            for el in part:
                key = el.get("Name")
                if not key:
                    n += 1
                    key = f"Data{n}" if _local(el.tag) == "Data" else _local(el.tag)
                d[key] = (el.text or "").strip()[:MAX_FIELD]
        elif name in ("UserData", "RenderingInfo"):
            for el in part.iter():
                if len(el) == 0 and el is not part and (el.text or "").strip():
                    d.setdefault(_local(el.tag), el.text.strip()[:MAX_FIELD])
    return normalise(d, ts=parse_time(d.get("TimeCreated")))


def _text_of(v: Any) -> str:
    if isinstance(v, dict):
        for k in ("#text", "Value", "value", "#value"):
            if k in v:
                return str(v[k])
        return ""
    return "" if v is None else str(v)


def from_event_json(obj: dict) -> dict:
    """An event log record exported as JSON (evtx_dump, Velociraptor) with System + EventData."""
    ev = obj.get("Event", obj)
    sysd = ev.get("System") or {}
    d: dict[str, Any] = {}
    prov = sysd.get("Provider") or {}
    if isinstance(prov, dict):
        prov = prov.get("#attributes", prov)
        d["Provider_Name"] = prov.get("Name", "")
    tc = sysd.get("TimeCreated") or {}
    if isinstance(tc, dict):
        tc = tc.get("#attributes", tc).get("SystemTime", "")
    d["TimeCreated"] = tc
    for k in ("EventID", "Channel", "Computer", "EventRecordID", "Level"):
        if k in sysd:
            d[k] = _text_of(sysd[k])
    for k in ("EventData", "UserData"):
        data = ev.get(k)
        if isinstance(data, dict):
            for kk, vv in flat(data).items():
                leaf = kk.rsplit(".", 1)[-1]
                if leaf not in ("#attributes", "xmlns"):
                    d.setdefault(leaf, vv)
    for k, v in obj.items():                                  # Velociraptor adds its own columns next to the event
        if k not in ("Event", "System", "EventData", "UserData") and not isinstance(v, (dict, list)):
            d.setdefault(k, v)
    return normalise(d, ts=parse_time(d.get("TimeCreated")))


def _evtx_dump(tool: str, path: Path) -> Iterator[dict]:
    """Read an event log with the external evtx_dump tool (JSON lines out), which is far faster than python-evtx."""
    import subprocess  # nosec B404 - a fixed tool path from config.yaml, no shell, the file path as one argument
    exe = Path(tool).expanduser()
    if not exe.is_file():
        raise ParseError(f"dfir.evtx_dump: {tool} does not exist")
    with subprocess.Popen([str(exe), "-o", "jsonl", str(path)], stdout=subprocess.PIPE,  # nosec B603
                          stderr=subprocess.DEVNULL, text=True, encoding="utf-8", errors="replace") as proc:
        for n, line in enumerate(proc.stdout or [], 1):
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                yield from_event_json(json.loads(line))
            except (ValueError, AttributeError, TypeError) as exc:
                yield {"_error": f"record line {n}: {exc}"[:300]}
        if proc.wait() not in (0, None):
            yield {"_error": f"evtx_dump exited with code {proc.returncode}"}


def _evtx(path: Path) -> Iterator[dict]:
    try:
        import Evtx.Evtx as evtx  # type: ignore[import-not-found]
    except ImportError as exc:
        raise ParseError("reading .evtx files needs: pip install 'actaeon[dfir]' (python-evtx)") from exc
    with evtx.Evtx(str(path)) as log:
        for rec in log.records():
            try:
                yield from_event_xml(rec.xml())
            except Exception as exc:                    # one damaged record must not stop the file
                yield {"_error": f"record {getattr(rec, 'record_num', lambda: '?')()}: {exc}"[:300]}


# ---------------------------------------------------------------- JSON, CSV, syslog

def _from_obj(obj: dict, year: int | None) -> dict:
    if ("System" in obj and ("EventData" in obj or "UserData" in obj)) or \
            (isinstance(obj.get("Event"), dict) and "System" in obj["Event"]):
        return from_event_json(obj)
    d = flat(obj)
    for k in ("Details", "ExtraFieldInfo"):                  # Hayabusa JSONL keeps fields in these
        if isinstance(obj.get(k), dict):
            for kk, vv in obj[k].items():
                d.setdefault(str(kk), vv)
    return normalise(d, year=year)


def _vol_rows(rows: list, depth: int = 0, parent: dict | None = None) -> Iterator[dict]:
    """Volatility 3 JSON (``vol -r json``): rows with nested ``__children`` (process trees and the like)."""
    for r in rows:
        if not isinstance(r, dict):
            continue
        kids = r.get("__children") or []
        row = {k: v for k, v in r.items() if k != "__children"}
        if depth:
            row["tree_depth"] = depth
        if parent and "PID" in parent and "PPID" not in row:
            row["PPID"] = parent["PID"]
        yield row
        yield from _vol_rows(kids, depth + 1, row)


def _plugin(name: str) -> str:
    """windows.pslist.PsList.json or windows.netscan.json -> windows.pslist / windows.netscan."""
    stem = Path(name).name.split(".json")[0]
    parts = [p for p in stem.split(".") if p]
    return ".".join(parts[:2]) if len(parts) >= 2 and parts[0] in ("windows", "linux", "mac") else stem


def _json(fh: io.TextIOBase, year: int | None, name: str = "") -> Iterator[dict]:
    head = fh.read(1)
    while head and head.isspace():
        head = fh.read(1)
    if head == "[":
        try:
            data = json.loads(head + fh.read())
        except ValueError as exc:
            raise ParseError(f"not valid JSON: {exc}") from exc
        if any(isinstance(r, dict) and "__children" in r for r in data[:50]):
            plugin = _plugin(name)
            for row in _vol_rows(data):
                yield normalise({**flat(row), "vol_plugin": plugin}, year=year)
            return
        for i, obj in enumerate(data):
            yield _from_obj(obj, year) if isinstance(obj, dict) else {"_error": f"item {i} is not an object"}
        return
    first = True
    for n, line in enumerate(fh, 1):
        if first:
            line, first = head + line, False
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except ValueError:
            yield {"_error": f"line {n}: not JSON"}
            continue
        yield _from_obj(obj, year) if isinstance(obj, dict) else {"_error": f"line {n}: not an object"}


def _csv(fh: io.TextIOBase, year: int | None) -> Iterator[dict]:
    sample = fh.read(65536)
    fh.seek(0)
    try:
        dialect = csv.Sniffer().sniff(sample, delimiters=",;\t|")
    except csv.Error:
        dialect = csv.excel
    rd = csv.DictReader(fh, dialect=dialect)
    cols = {c.lower(): c for c in rd.fieldnames or []}
    for row in rd:
        d = {k: (v or "")[:MAX_FIELD] for k, v in row.items() if k}
        ts = ""
        if "date" in cols and "time" in cols:                 # Plaso l2tcsv
            tz = d.get(cols.get("timezone", ""), "UTC") or "UTC"
            ts = parse_time(f"{d[cols['date']]} {d[cols['time']]}") if tz.upper() in ("UTC", "GMT") else ""
        for k in ("Timestamp", "datetime"):
            if not ts and k.lower() in cols:
                ts = parse_time(d[cols[k.lower()]], year=year)
        yield normalise(d, year=year, ts=ts)


_SYSLOG = re.compile(r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s\d\d:\d\d:\d\d|\d{4}-\d\d-\d\dT\S+)\s+(?P<host>\S+)\s+"
                     r"(?P<prog>[^:\[\s]+)(?:\[(?P<pid>\d+)\])?:\s?(?P<msg>.*)$")
_AUTH = [
    (re.compile(r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\d.:a-fA-F]+)"), "ssh_failed"),
    (re.compile(r"Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>[\d.:a-fA-F]+)"), "ssh_accepted"),
    (re.compile(r"Invalid user (?P<user>\S+) from (?P<ip>[\d.:a-fA-F]+)"), "ssh_invalid_user"),
    (re.compile(r"^\s*(?P<user>\S+) : .*?COMMAND=(?P<command>.*)$"), "sudo"),
    (re.compile(r"new user: name=(?P<user>[^,\s]+)"), "user_added"),
    (re.compile(r"session opened for user (?P<user>\S+?)(?:\(uid=\d+\))?\b"), "session_opened"),
]


def _syslog(fh: io.TextIOBase, year: int | None) -> Iterator[dict]:
    for n, line in enumerate(fh, 1):
        line = line.rstrip("\n")
        if not line.strip():
            continue
        m = _SYSLOG.match(line)
        if not m:
            yield {"_error": f"line {n}: not a syslog line"}
            continue
        d: dict[str, Any] = {"hostname": m["host"], "program": m["prog"], "message": m["msg"][:MAX_FIELD]}
        if m["pid"]:
            d["pid"] = m["pid"]
        for rx, action in _AUTH:
            x = rx.search(m["msg"])
            if x:
                d["action"] = action
                d.update({("src_ip" if k == "ip" else k): v for k, v in x.groupdict().items() if v})
                break
        yield normalise(d, ts=parse_time(m["ts"], year=year))


# ---------------------------------------------------------------- detection of the format

def kind_of(name: str, head: bytes) -> str:
    n = name.lower()
    if n.endswith(".gz"):
        return "gzip"
    if head.startswith(b"ElfFile\x00") or n.endswith(".evtx"):
        return "evtx"
    if head.startswith(b"PK\x03\x04"):
        return "zip"
    if n.endswith((".jsonl", ".ndjson", ".json")):
        return "json"
    if n.endswith((".csv", ".tsv")):
        return "csv"
    text = head.lstrip(b"\xef\xbb\xbf").lstrip()
    if text[:1] in (b"{", b"["):
        return "json"
    first = text.split(b"\n", 1)[0].decode("utf-8", "replace")
    if _SYSLOG.match(first):
        return "syslog"
    if first.count(",") >= 2 or first.count("\t") >= 2:
        return "csv"
    if n.endswith((".log", ".txt")) or n.split("/")[-1].startswith(("auth", "syslog", "secure", "messages")):
        return "syslog"
    return ""


def _text(path: Path, kind: str, year: int | None, opener=None, name: str = "") -> Iterator[dict]:
    raw = opener() if opener else path.open("rb")
    with io.TextIOWrapper(raw, encoding="utf-8-sig", errors="replace", newline="") as fh:
        if kind == "json":
            yield from _json(fh, year, name)
        elif kind == "csv":
            yield from _csv(fh, year)
        else:
            yield from _syslog(fh, year)


def parse_file(path: Path, name: str = "", *, year: int | None = None, max_unpacked: int = 20 << 30,
               evtx_dump: str = "") -> Iterator[dict]:
    """Yield normalised events, ``{"_error": ...}`` for unreadable records and ``{"_member": name, "_kind": k}``
    markers when a zip member starts."""
    path = Path(path)
    name = name or path.name
    with path.open("rb") as fh:
        head = fh.read(4096)
    kind = kind_of(name, head)
    if not kind:
        raise ParseError(f"{name}: unknown format (supported: .evtx, JSON/JSON lines, CSV, syslog, .gz, .zip)")
    if kind == "evtx":
        yield {"_kind": "evtx"}
        yield from (_evtx_dump(evtx_dump, path) if evtx_dump else _evtx(path))
    elif kind == "gzip":
        inner = name[:-3]
        with gzip.open(path, "rb") as g:
            ihead = g.read(4096)
        ik = kind_of(inner, ihead)
        if ik not in ("json", "csv", "syslog"):
            raise ParseError(f"{name}: only text logs are read from .gz files")
        yield {"_kind": f"{ik}.gz"}
        yield from _text(path, ik, year, opener=lambda: gzip.open(path, "rb"), name=inner)  # noqa: SIM115 - closed by the TextIOWrapper in _text
    elif kind == "zip":
        yield {"_kind": "zip"}
        yield from _zip(path, year, max_unpacked, evtx_dump)
    else:
        yield {"_kind": kind}
        yield from _text(path, kind, year, name=name)


def _zip(path: Path, year: int | None, max_unpacked: int, evtx_dump: str = "") -> Iterator[dict]:
    with zipfile.ZipFile(path) as z:
        infos = [i for i in z.infolist() if not i.is_dir()]
        if len(infos) > MAX_ZIP_MEMBERS:
            raise ParseError(f"the zip has {len(infos)} files; at most {MAX_ZIP_MEMBERS} are read")
        if sum(i.file_size for i in infos) > max_unpacked:
            raise ParseError("the zip unpacks to more than the allowed size")
        for info in infos:
            with z.open(info) as m:
                head = m.read(4096)
            k = kind_of(info.filename, head)
            if not k or k == "zip":
                continue
            yield {"_member": info.filename, "_kind": k}
            with tempfile.TemporaryDirectory() as tmp:
                out = Path(tmp) / "member"
                with z.open(info) as src, out.open("wb") as dst:
                    while chunk := src.read(1 << 20):
                        dst.write(chunk)
                try:
                    for ev in parse_file(out, info.filename, year=year, evtx_dump=evtx_dump):
                        if "_kind" not in ev or "_member" in ev:
                            yield ev
                except ParseError as exc:
                    yield {"_error": f"{info.filename}: {exc}"}
