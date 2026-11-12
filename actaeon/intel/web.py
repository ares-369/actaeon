"""Web intel: pull advisories from feeds (RSS/Atom) or pages you list, and optionally hunt them.

    intel:
      web:
        interval_minutes: 60
        auto_hunt: true            # start an advisory hunt for each new advisory with indicators or techniques
        sources:
          - name: gov-advisories
            url: "https://example.org/advisories.xml"     # RSS or Atom
            keywords: []           # only items whose title or text mention one of these (optional)
            max_items: 10
          - name: vendor-blog
            url: "https://example.org/blog/"
            kind: page              # a single page, re-read when it changes

Every fetch goes through the same guard as advisory import (http(s) only,
private addresses refused, redirects checked, size cap). Items already pulled
are remembered by link, so each article is added once.
"""

from __future__ import annotations

import hashlib
import re
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

from .fetch import FetchError, fetch_url, html_to_text
from .store import IntelStore

_NS = {"atom": "http://www.w3.org/2005/Atom"}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def parse_feed(xml_text: str) -> list[dict]:
    """Items from an RSS 2.0 or Atom document: [{title, link, summary}]."""
    if "<!ENTITY" in xml_text[:5000].upper():
        raise FetchError("feed declares XML entities; refused")
    root = ET.fromstring(xml_text.encode() if isinstance(xml_text, str) else xml_text)
    items = []
    for it in root.iter("item"):
        items.append({"title": (it.findtext("title") or "").strip(), "link": (it.findtext("link") or "").strip(),
                      "summary": (it.findtext("description") or "").strip()})
    for it in root.iter("{http://www.w3.org/2005/Atom}entry"):
        link = ""
        for ln in it.findall("atom:link", _NS):
            if ln.get("rel", "alternate") == "alternate":
                link = ln.get("href", "")
                break
        items.append({"title": (it.findtext("atom:title", default="", namespaces=_NS) or "").strip(), "link": link,
                      "summary": (it.findtext("atom:summary", default="", namespaces=_NS)
                                  or it.findtext("atom:content", default="", namespaces=_NS) or "").strip()})
    return items


class WebIntel:
    def __init__(self, store: IntelStore, settings: dict, *, allow_private: bool = False, fetch=None):
        self.store, self.s = store, settings or {}
        self.allow_private = allow_private
        self._fetch = fetch or (lambda url, **kw: fetch_url(url, **kw))
        with store._conn() as c:
            c.execute("CREATE TABLE IF NOT EXISTS web_seen (key TEXT PRIMARY KEY, source TEXT, seen TEXT, "
                      "advisory_id INTEGER)")

    def _seen(self, key: str) -> bool:
        with self.store._conn() as c:
            return c.execute("SELECT 1 FROM web_seen WHERE key=?", (key,)).fetchone() is not None

    def _mark(self, key: str, source: str, aid: int | None) -> None:
        with self.store._conn() as c:
            c.execute("INSERT OR REPLACE INTO web_seen VALUES (?,?,?,?)", (key, source, _now(), aid))

    def _wanted(self, src: dict, text: str) -> bool:
        kws = [k.lower() for k in src.get("keywords") or []]
        return not kws or any(k in text.lower() for k in kws)

    def pull(self, only: str | None = None) -> dict:
        out = {"new_advisories": [], "errors": [], "skipped": 0}
        for src in self.s.get("sources") or []:
            name = str(src.get("name", ""))
            if only and name != only:
                continue
            if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,39}", name):
                out["errors"].append(f"bad source name {name!r}")
                continue
            try:
                if src.get("kind") == "page":
                    self._page(src, out)
                else:
                    self._feed(src, out)
            except (FetchError, ET.ParseError, OSError, ValueError) as exc:
                out["errors"].append(f"{name}: {exc}"[:300])
        return out

    def _add(self, src: dict, title: str, text: str, url: str, key: str, out: dict) -> None:
        r = self.store.add_advisory(title or url, text, source=f"web:{src['name']}", url=url,
                                    confidence=int(src.get("confidence", 50)),
                                    tags=["web", *list(src.get("tags") or [])], strict_links=True)
        self._mark(key, src["name"], r["advisory_id"])
        out["new_advisories"].append({"id": r["advisory_id"], "title": title, "url": url, "new": r["new"]})

    def _feed(self, src: dict, out: dict) -> None:
        doc = self._fetch(src["url"], allow_private=self.allow_private)
        items = parse_feed(doc["raw"] if "raw" in doc else doc["text"])
        for it in items[: int(src.get("max_items", 10))]:
            key = it["link"] or hashlib.sha256((it["title"] + it["summary"]).encode()).hexdigest()
            if self._seen(key):
                continue
            text = html_to_text(it["summary"])[1] if "<" in it["summary"] else it["summary"]
            if it["link"] and src.get("fetch_articles", True):
                try:
                    art = self._fetch(it["link"], allow_private=self.allow_private)
                    text = f"{text}\n\n{art['text']}"
                except FetchError as exc:
                    out["errors"].append(f"{src['name']}: {it['link']}: {exc}"[:300])
            if not self._wanted(src, f"{it['title']}\n{text}"):
                self._mark(key, src["name"], None)
                out["skipped"] += 1
                continue
            self._add(src, it["title"], text, it["link"], key, out)

    def _page(self, src: dict, out: dict) -> None:
        doc = self._fetch(src["url"], allow_private=self.allow_private)
        key = f"{src['url']}#{hashlib.sha256(doc['text'].encode()).hexdigest()[:16]}"
        if self._seen(key):
            return
        if not self._wanted(src, doc["text"]):
            self._mark(key, src["name"], None)
            out["skipped"] += 1
            return
        self._add(src, doc.get("title") or src["name"], doc["text"], src["url"], key, out)
