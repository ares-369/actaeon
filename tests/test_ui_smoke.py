"""Browser smoke test: every page of the web UI, on the offline demo data, in headless Chromium.

Fails on a JavaScript error, a failed request, or "undefined" / "NaN" / "[object Object]" on screen, at desktop
and phone width. Skipped unless Playwright for Python and a Chromium are installed (the CI "UI smoke test" job
installs both). A local Chromium can be used with ACTAEON_UI_CHROMIUM=/path/to/chrome.
"""

import os
import socket
import subprocess
import sys
import time
import urllib.request

import pytest

sync_api = pytest.importorskip("playwright.sync_api")

PAGES = ["leads", "cases", "hunts", "ask", "library", "intel", "entities", "coverage", "reports", "connectors",
         "settings", "approvals", "socalerts", "socdash", "tuning"]
DETAIL = ("lead", "hunt", "case")
BAD_TEXT = ("undefined", "NaN", "[object Object]")


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="module")
def server(tmp_path_factory):
    home = tmp_path_factory.mktemp("ui-demo")
    port = _free_port()
    env = {k: v for k, v in os.environ.items() if k != "ACTAEON_CONFIG"}
    env["ACTAEON_HOME"] = str(home)
    subprocess.run([sys.executable, "-m", "actaeon", "demo", "--dir", str(home), "--offline", "--run",
                    "--port", str(port)], check=True, env=env, capture_output=True, timeout=600, cwd=home)
    proc = subprocess.Popen([sys.executable, "-m", "actaeon", "serve"], env=env, cwd=home,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    base = f"http://127.0.0.1:{port}"
    for _ in range(150):
        try:
            urllib.request.urlopen(base + "/healthz", timeout=1)
            break
        except OSError:
            time.sleep(0.2)
    else:
        proc.kill()
        pytest.fail("the demo server did not start: " + (proc.stdout.read() or b"").decode()[-2000:])
    yield base
    proc.terminate()
    proc.wait(timeout=10)


def _browser(p):
    exe = os.getenv("ACTAEON_UI_CHROMIUM")
    try:
        return p.chromium.launch(**({"executable_path": exe} if exe else {}), args=["--no-sandbox"])
    except sync_api.Error as exc:
        if "Executable doesn't exist" in str(exc):
            pytest.skip("no Chromium for Playwright: run `python -m playwright install chromium`")
        raise


def test_every_page_loads_cleanly(server):
    issues: list[str] = []
    with sync_api.sync_playwright() as p:
        b = _browser(p)
        page = b.new_page(viewport={"width": 1300, "height": 900})
        cur = {"page": ""}
        page.on("pageerror", lambda e: issues.append(f"[{cur['page']}] JS error: {e}"))
        page.on("console", lambda m: m.type == "error" and issues.append(f"[{cur['page']}] console: {m.text}"))
        page.on("response", lambda r: r.status >= 400 and issues.append(
            f"[{cur['page']}] HTTP {r.status} {r.url.replace(server, '')}"))
        details: list[str] = []
        for name in PAGES:
            cur["page"] = name
            page.goto(f"{server}/#{name}", wait_until="networkidle")
            page.wait_for_timeout(300)
            text = page.inner_text("main")
            issues += [f"[{name}] shows {bad!r}" for bad in BAD_TEXT if bad in text]
            for href in page.eval_on_selector_all("main a[href^='#']", "els => els.map(e => e.getAttribute('href'))"):
                kind = href[1:].split("/")[0]
                if "/" in href and kind in DETAIL and not any(d.startswith(f"#{kind}/") for d in details):
                    details.append(href)
        for href in details:
            cur["page"] = href
            page.goto(f"{server}/{href}", wait_until="networkidle")
            page.wait_for_timeout(300)
            text = page.inner_text("main")
            issues += [f"[{href}] shows {bad!r}" for bad in BAD_TEXT if bad in text]
        b.close()
    assert details, "no hunt, lead or case pages were reachable from the demo data"
    assert issues == []


def test_pages_fit_a_phone(server):
    wide: list[str] = []
    with sync_api.sync_playwright() as p:
        b = _browser(p)
        page = b.new_page(viewport={"width": 412, "height": 915})
        for name in PAGES:
            page.goto(f"{server}/#{name}", wait_until="networkidle")
            page.wait_for_timeout(300)
            w = page.evaluate("[document.documentElement.scrollWidth, window.innerWidth]")
            if w[0] > w[1] + 2:
                wide.append(f"{name}: {w[0]}px wide on a {w[1]}px screen")
        b.close()
    assert wide == []
