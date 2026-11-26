"""Match Sigma rules against single events locally: no log platform and no extra package needed.

Used to test rules against saved sample events (rules/testing.py). It covers what single-event Sigma
rules use:

* detection items: a field map (every field must match), a list of field maps (any one), keywords
* values: strings with ``*`` and ``?`` wildcards (case-insensitive, as Sigma specifies), numbers,
  booleans and ``null`` (field missing or empty)
* modifiers: contains, startswith, endswith, all, re (with i, m, s), cidr, exists, base64,
  base64offset, wide / utf16le / utf16be / utf16 (before base64), windash, lt, lte, gt, gte, cased
* conditions: and, or, not, brackets, ``1 of x*``, ``any of x*``, ``all of x*``, ``them``

Not covered: correlation rules, aggregations (``| count() > 5``), ``fieldref`` and ``expand``. Such a
rule raises :class:`Unsupported`; it is never reported as passing.

Field names: a rule field is looked up in the event as written, then through ``field_map``
(rule name -> event names), then case-insensitively, then by the last part of a dotted name
(``CommandLine`` finds ``data.win.eventdata.commandLine``). Each match reports which event field it
used, so a wrong mapping is visible.
"""

from __future__ import annotations

import base64
import fnmatch
import ipaddress
import re
from collections.abc import Callable
from typing import Any

import yaml

MAX_VALUE_CHARS = 100_000


class Unsupported(ValueError):
    """The rule uses a Sigma feature this matcher does not evaluate."""


# ---------------------------------------------------------------- events

def flatten(ev: Any, prefix: str = "", out: dict | None = None) -> dict[str, Any]:
    out = {} if out is None else out
    if isinstance(ev, dict):
        for k, v in ev.items():
            key = f"{prefix}.{k}" if prefix else str(k)
            if isinstance(v, dict):
                flatten(v, key, out)
            else:
                out[key] = v
    elif prefix:
        out[prefix] = ev
    return out


class Event:
    def __init__(self, ev: dict, field_map: dict[str, list[str]] | None = None):
        self.flat = flatten(ev if isinstance(ev, dict) else {})
        self.field_map = {k.lower(): v for k, v in (field_map or {}).items()}
        self.lower: dict[str, list[str]] = {}
        self.leaf: dict[str, list[str]] = {}
        for k in self.flat:
            self.lower.setdefault(k.lower(), []).append(k)
            self.leaf.setdefault(k.rsplit(".", 1)[-1].lower(), []).append(k)

    def lookup(self, name: str) -> list[str]:
        """Event keys for a rule field name, best tier first (empty when the field is not there)."""
        if name in self.flat:
            return [name]
        for mapped in self.field_map.get(name.lower(), []):
            if mapped in self.flat:
                return [mapped]
            if mapped.lower() in self.lower:
                return self.lower[mapped.lower()]
        if name.lower() in self.lower:
            return self.lower[name.lower()]
        return self.leaf.get(name.rsplit(".", 1)[-1].lower(), [])

    def strings(self) -> list[str]:
        out = []
        for v in self.flat.values():
            for x in v if isinstance(v, list) else [v]:
                s = _text(x)
                if s is not None:
                    out.append(s)
        return out


def _text(x: Any) -> str | None:
    if x is None or isinstance(x, (dict, list)):
        return None
    if isinstance(x, bool):
        return "true" if x else "false"
    return str(x)[:MAX_VALUE_CHARS]


# ---------------------------------------------------------------- values

def _wild(s: str, *, cased: bool, mode: str = "") -> re.Pattern:
    out, i = [], 0
    while i < len(s):
        ch = s[i]
        if ch == "\\" and i + 1 < len(s) and s[i + 1] in "*?\\":
            out.append(re.escape(s[i + 1]))
            i += 2
            continue
        out.append(".*" if ch == "*" else "." if ch == "?" else re.escape(ch))
        i += 1
    body = "".join(out)
    if mode in ("contains", "endswith"):
        body = ".*" + body
    if mode in ("contains", "startswith"):
        body = body + ".*"
    return re.compile("^" + body + "$", re.S | (0 if cased else re.I))


_DASHES = ("-", "/", "\u2013", "\u2014", "\u2015")


def _windash(s: str) -> list[str]:
    if "-" not in s and "/" not in s:
        return [s]
    out = []
    for d in _DASHES:
        v = re.sub(r"(^|\s)[-/]", lambda m, d=d: m.group(1) + d, s)
        if v not in out:
            out.append(v)
    return out


def _encode(s: str, enc: str | None) -> bytes:
    if enc in ("wide", "utf16le"):
        return s.encode("utf-16-le")
    if enc == "utf16be":
        return s.encode("utf-16-be")
    if enc == "utf16":
        return b"\xff\xfe" + s.encode("utf-16-le")
    return s.encode()


def _b64offset(b: bytes) -> list[str]:
    """The three base64 forms of ``b`` at each byte offset, trimmed to the stable middle (Sigma's rule)."""
    out = []
    for i in range(3):
        enc = base64.b64encode(b"\x00" * i + b).decode()
        start = (0, 2, 3)[i]
        end = len(enc) - ((0, 3, 2)[(len(b) + i) % 3])
        out.append(enc[start:end])
    return out


class FieldTest:
    """One ``Field|mod|mod: value(s)`` item, compiled."""

    def __init__(self, key: str, value: Any):
        parts = str(key).split("|")
        self.field = parts[0]
        mods = [m.lower() for m in parts[1:]]
        self.mods = mods
        known = {"contains", "startswith", "endswith", "all", "re", "i", "m", "s", "cidr", "exists", "base64",
                 "base64offset", "wide", "utf16le", "utf16be", "utf16", "windash", "lt", "lte", "gt", "gte", "cased",
                 "fieldref"}
        bad = [m for m in mods if m not in known]
        if bad:
            raise Unsupported(f"modifier(s) {bad} on {self.field!r} are not evaluated locally")
        self.all = "all" in mods
        self.cased = "cased" in mods
        vals = value if isinstance(value, list) else [value]
        self.kind = next((m for m in ("re", "cidr", "exists", "fieldref", "lt", "lte", "gt", "gte") if m in mods), "str")
        enc = next((m for m in ("wide", "utf16le", "utf16be", "utf16") if m in mods), None)
        if enc and "base64" not in mods and "base64offset" not in mods:
            raise Unsupported(f"{enc} without base64 on {self.field!r}")
        mode = next((m for m in ("contains", "startswith", "endswith") if m in mods), "")
        self.tests: list[Callable[[Any], bool]] = []
        if self.kind == "exists":
            want = bool(vals[0]) if vals else True
            self.exists = want
            return
        if self.kind == "fieldref":                  # the value names another field whose value must be equal
            self.refs = [str(v) for v in vals]
            return
        for v in vals:
            if self.kind == "re":
                flags = (re.I if "i" in mods else 0) | (re.M if "m" in mods else 0) | (re.S if "s" in mods else 0)
                try:
                    rx = re.compile(str(v), flags)
                except re.error as exc:
                    raise Unsupported(f"regex on {self.field!r} does not compile: {exc}") from exc
                self.tests.append(lambda x, rx=rx: (t := _text(x)) is not None and rx.search(t) is not None)
            elif self.kind == "cidr":
                try:
                    net = ipaddress.ip_network(str(v), strict=False)
                except ValueError as exc:
                    raise Unsupported(f"cidr value {v!r} on {self.field!r}: {exc}") from exc
                self.tests.append(lambda x, net=net: _in_net(x, net))
            elif self.kind in ("lt", "lte", "gt", "gte"):
                try:
                    n = float(v)
                except (TypeError, ValueError) as exc:
                    raise Unsupported(f"{self.kind} needs a number on {self.field!r}") from exc
                self.tests.append(lambda x, n=n, k=self.kind: _cmp(x, n, k))
            elif v is None:
                self.tests.append(lambda x: x is None or x == "")
            else:
                s = _text(v) or ""
                variants = [s]
                if "windash" in mods:
                    variants = _windash(s)
                if "base64offset" in mods:
                    variants = [p for x in variants for p in _b64offset(_encode(x, enc))]
                    mode = mode or "contains"
                elif "base64" in mods:
                    variants = [base64.b64encode(_encode(x, enc)).decode() for x in variants]
                pats = [_wild(x, cased=self.cased or "base64" in mods or "base64offset" in mods, mode=mode)
                        for x in variants]
                self.tests.append(lambda x, pats=pats: (t := _text(x)) is not None and any(p.match(t) for p in pats))

    def match(self, ev: Event) -> tuple[bool, list[str]]:
        keys = ev.lookup(self.field) if self.field else list(ev.flat)     # no field name: any field (keyword)
        if self.kind == "fieldref":
            mine = {_text(ev.flat[k]).lower() for k in keys if _text(ev.flat[k]) is not None}
            hits = []
            for ref in self.refs:
                other = {_text(ev.flat[k]).lower() for k in ev.lookup(ref) if _text(ev.flat[k]) is not None}
                hits.append(bool(mine & other))
            ok = all(hits) if self.all else any(hits)
            return ok, keys[:1] if ok else []
        if self.kind == "exists":
            present = any(not _empty(ev.flat[k]) for k in keys)
            return present == self.exists, keys[:1] if present else []
        values = [x for k in keys for x in (ev.flat[k] if isinstance(ev.flat[k], list) else [ev.flat[k]])]
        if not keys:
            values = [None]           # a missing field matches only ``null``

        def one(test) -> bool:
            return any(test(x) for x in values)
        ok = all(one(t) for t in self.tests) if self.all else any(one(t) for t in self.tests)
        return ok, (keys[:1] if ok and keys else [])


def _empty(v: Any) -> bool:
    return v is None or v == "" or v == []


def _in_net(x: Any, net) -> bool:
    try:
        return ipaddress.ip_address(str(x).strip()) in net
    except ValueError:
        return False


def _cmp(x: Any, n: float, kind: str) -> bool:
    try:
        v = float(x)
    except (TypeError, ValueError):
        return False
    return {"lt": v < n, "lte": v <= n, "gt": v > n, "gte": v >= n}[kind]


# ---------------------------------------------------------------- detection items

class Item:
    """One search identifier of the detection section."""

    def __init__(self, name: str, body: Any):
        self.name = name
        self.alts: list[Any] = []       # OR of: list[FieldTest] (AND) or keyword pattern
        if isinstance(body, dict):
            self.alts.append([FieldTest(k, v) for k, v in body.items()])
        elif isinstance(body, list):
            for x in body:
                if isinstance(x, dict):
                    self.alts.append([FieldTest(k, v) for k, v in x.items()])
                elif isinstance(x, (str, int, float)) and not isinstance(x, bool):
                    self.alts.append(_wild(str(x), cased=False, mode="contains"))
                else:
                    raise Unsupported(f"{name}: list items must be field maps or keywords")
        elif isinstance(body, (str, int, float)) and not isinstance(body, bool):
            self.alts.append(_wild(str(body), cased=False, mode="contains"))
        else:
            raise Unsupported(f"{name}: a search identifier must be a field map, a list or a keyword")
        if not self.alts:
            raise Unsupported(f"{name} is empty")

    def match(self, ev: Event, used: dict[str, str]) -> bool:
        for alt in self.alts:
            if isinstance(alt, list):
                found: dict[str, str] = {}
                ok = True
                for t in alt:
                    hit, keys = t.match(ev)
                    if not hit:
                        ok = False
                        break
                    if keys:
                        found[t.field] = keys[0]
                if ok:
                    used.update(found)
                    return True
            elif any(alt.match(s) for s in ev.strings()):
                used.setdefault("(keyword)", alt.pattern[:80])
                return True
        return False


# ---------------------------------------------------------------- condition

_TOK = re.compile(r"\(|\)|[^\s()]+")


def _parse_condition(text: str, names: list[str]):
    if "|" in text:
        raise Unsupported("aggregation conditions (| count() ...) are not evaluated locally")
    toks = _TOK.findall(text)
    pos = 0

    def peek():
        return toks[pos].lower() if pos < len(toks) else None

    def take():
        nonlocal pos
        pos += 1
        return toks[pos - 1]

    def targets(pattern: str) -> list[str]:
        if pattern.lower() == "them":
            got = [n for n in names if not n.startswith("_")]
        else:
            got = [n for n in names if fnmatch.fnmatchcase(n, pattern)]
        if not got:
            raise Unsupported(f"condition: '{pattern}' names no search identifier")
        return got

    def atom():
        t = peek()
        if t is None:
            raise Unsupported("condition ends too early")
        if t == "(":
            take()
            node = expr()
            if peek() != ")":
                raise Unsupported("condition: missing )")
            take()
            return node
        if t == "not":
            take()
            return ("not", atom())
        if t in ("1", "any", "all") and pos + 1 < len(toks) and toks[pos + 1].lower() == "of":
            q = take().lower()
            take()
            if pos >= len(toks):
                raise Unsupported("condition: 'of' needs a target")
            return ("all" if q == "all" else "any", targets(take()))
        name = take()
        if name not in names:
            raise Unsupported(f"condition names {name!r}, which is not in the detection section")
        return ("id", name)

    def conj():
        node = atom()
        while peek() == "and":
            take()
            node = ("and", node, atom())
        return node

    def expr():
        node = conj()
        while peek() == "or":
            take()
            node = ("or", node, conj())
        return node

    tree = expr()
    if pos != len(toks):
        raise Unsupported(f"condition: unexpected {toks[pos]!r}")
    return tree


def _eval(node, ev: Event, items: dict[str, Item], used: dict, cache: dict) -> bool:
    op = node[0]
    if op == "id":
        if node[1] not in cache:
            cache[node[1]] = items[node[1]].match(ev, used)
        return cache[node[1]]
    if op == "not":
        return not _eval(node[1], ev, items, {}, cache)
    if op == "and":
        return _eval(node[1], ev, items, used, cache) and _eval(node[2], ev, items, used, cache)
    if op == "or":
        return _eval(node[1], ev, items, used, cache) or _eval(node[2], ev, items, used, cache)
    if op == "any":
        return any(_eval(("id", n), ev, items, used, cache) for n in node[1])
    if op == "all":
        return all(_eval(("id", n), ev, items, used, cache) for n in node[1])
    raise Unsupported(f"condition node {op}")


# ---------------------------------------------------------------- rule

class CompiledRule:
    def __init__(self, doc: dict):
        if not isinstance(doc, dict):
            raise Unsupported("the rule is not a YAML mapping")
        if "correlation" in doc:
            raise Unsupported("correlation rules are not evaluated locally")
        det = doc.get("detection")
        if not isinstance(det, dict):
            raise Unsupported("the rule has no detection section")
        cond = det.get("condition")
        if cond is None:
            raise Unsupported("detection has no condition")
        if "timeframe" in det:
            raise Unsupported("timeframe rules are not evaluated locally")
        self.items = {str(k): Item(str(k), v) for k, v in det.items() if k != "condition"}
        names = list(self.items)
        conds = cond if isinstance(cond, list) else [cond]
        self.trees = [_parse_condition(str(c), names) for c in conds]
        self.title = str(doc.get("title", ""))

    def match(self, event: dict, field_map: dict[str, list[str]] | None = None) -> tuple[bool, dict[str, str]]:
        """(matched, {rule field: event field it matched on})."""
        ev = Event(event, field_map)
        for tree in self.trees:
            used: dict[str, str] = {}
            if _eval(tree, ev, self.items, used, {}):
                return True, used
        return False, {}

    def fields(self) -> list[str]:
        out = []
        for it in self.items.values():
            for alt in it.alts:
                if isinstance(alt, list):
                    out += [t.field for t in alt if t.field not in out]
        return out


def compile_rule(rule: str | dict) -> CompiledRule:
    if isinstance(rule, str):
        try:
            docs = [d for d in yaml.safe_load_all(rule) if d is not None]
        except yaml.YAMLError as exc:
            raise Unsupported(f"not valid YAML: {exc}"[:300]) from exc
        if len(docs) != 1:
            raise Unsupported("one rule per document is expected (rule collections are not evaluated locally)")
        rule = docs[0]
    return CompiledRule(rule)
