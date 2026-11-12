"""Get advisory text from a URL (HTML, plain text or PDF) or a local PDF file.

URL safety: only http(s); every redirect hop is checked; hosts that resolve to
private, loopback, link-local or reserved addresses are refused unless
``intel.allow_private_urls`` is true. The check happens before connecting, so a
host that changes its DNS answer between check and connect is not covered.
PDF text extraction needs the optional ``pdf`` extra (pypdf).
"""

from __future__ import annotations

import io
import ipaddress
import re
import socket
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urljoin, urlparse

import requests

MAX_BYTES = 15_000_000
MAX_TEXT = 200_000


class FetchError(ValueError):
    pass


class _Text(HTMLParser):
    SKIP = {"script", "style", "noscript", "svg", "nav", "footer", "header", "form"}
    BLOCK = {"p", "div", "br", "li", "tr", "h1", "h2", "h3", "h4", "h5", "h6", "pre", "section", "article", "td"}

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self.skip = 0
        self.title = ""
        self._in_title = False

    def handle_starttag(self, tag, attrs):
        if tag in self.SKIP:
            self.skip += 1
        if tag == "title":
            self._in_title = True
        if tag in self.BLOCK:
            self.parts.append("\n")

    def handle_endtag(self, tag):
        if tag in self.SKIP and self.skip:
            self.skip -= 1
        if tag == "title":
            self._in_title = False

    def handle_data(self, data):
        if self._in_title:
            self.title += data
        elif not self.skip:
            self.parts.append(data)


def html_to_text(html: str) -> tuple[str, str]:
    p = _Text()
    p.feed(html)
    text = re.sub(r"[ \t]+", " ", "".join(p.parts))
    text = re.sub(r"\n\s*\n+", "\n\n", text).strip()
    return p.title.strip(), text


def pdf_to_text(data: bytes) -> str:
    try:
        from pypdf import PdfReader
    except ImportError as exc:
        raise FetchError("PDF import needs the pdf extra: pip install 'actaeon[pdf]'") from exc
    try:
        reader = PdfReader(io.BytesIO(data))
        pages = [(pg.extract_text() or "") for pg in reader.pages[:200]]
    except Exception as exc:
        raise FetchError(f"could not read the PDF: {exc}") from exc
    text = "\n".join(pages).strip()
    if not text:
        raise FetchError("the PDF has no extractable text (it may be scanned images)")
    return text


def _check_host(url: str, allow_private: bool) -> None:
    u = urlparse(url)
    if u.scheme not in ("http", "https") or not u.hostname:
        raise FetchError("only http(s) URLs are allowed")
    if allow_private:
        return
    try:
        infos = socket.getaddrinfo(u.hostname, u.port or (443 if u.scheme == "https" else 80))
    except socket.gaierror as exc:
        raise FetchError(f"cannot resolve {u.hostname}") from exc
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if not ip.is_global:
            raise FetchError(f"{u.hostname} resolves to a non-public address; set intel.allow_private_urls to allow it")


def fetch_url(url: str, *, allow_private: bool = False, session=None, timeout: float = 30) -> dict:
    s = session or requests.Session()
    for _ in range(6):
        _check_host(url, allow_private)
        r = s.get(url, timeout=timeout, allow_redirects=False, stream=True, headers={"User-Agent": "actaeon"})
        if r.status_code in (301, 302, 303, 307, 308) and r.headers.get("Location"):
            url = urljoin(url, r.headers["Location"])
            r.close()
            continue
        break
    else:
        raise FetchError("too many redirects")
    if r.status_code >= 400:
        raise FetchError(f"HTTP {r.status_code}")
    data = b""
    for chunk in r.iter_content(65536):
        data += chunk
        if len(data) > MAX_BYTES:
            raise FetchError("document is larger than 15 MB")
    ctype = r.headers.get("Content-Type", "").lower()
    if "pdf" in ctype or data[:5] == b"%PDF-":
        title, text = Path(urlparse(url).path).name, pdf_to_text(data)
    elif "html" in ctype or b"<html" in data[:2000].lower():
        title, text = html_to_text(data.decode(r.encoding or "utf-8", "replace"))
    else:
        title, text = "", data.decode(r.encoding or "utf-8", "replace")
    return {"url": url, "title": title[:300], "text": text[:MAX_TEXT]}


def read_file(path: str) -> dict:
    p = Path(path).expanduser()
    data = p.read_bytes()[:MAX_BYTES]
    if data[:5] == b"%PDF-":
        return {"title": p.stem, "text": pdf_to_text(data)[:MAX_TEXT]}
    if p.suffix.lower() in (".html", ".htm"):
        title, text = html_to_text(data.decode("utf-8", "replace"))
        return {"title": title or p.stem, "text": text[:MAX_TEXT]}
    return {"title": p.stem, "text": data.decode("utf-8", "replace")[:MAX_TEXT]}
