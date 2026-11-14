"""Rebuild the README screenshots (docs/screenshots/*.png) from the offline demo.

Usage (needs Playwright with Chromium):
    python scripts/make_screenshots.py [--actaeon PATH_TO_actaeon_CLI]

Runs `actaeon demo --offline --run` in a temporary folder (synthetic data, scripted, no model),
serves it on a free local port, and captures the Leads, Hunt, investigation graph, Entities and Coverage pages.
"""

from __future__ import annotations

import argparse
import os
import shutil
import socket
import subprocess
import tempfile
import time
import urllib.request
from pathlib import Path

OUT = Path(__file__).resolve().parents[1] / "docs" / "screenshots"


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--actaeon", default=shutil.which("actaeon") or "actaeon")
    a = ap.parse_args()
    from playwright.sync_api import sync_playwright

    d = tempfile.mkdtemp(prefix="actaeon-shots-")
    env = {**os.environ, "HOME": d}
    subprocess.run([a.actaeon, "demo", "--dir", f"{d}/demo", "--offline", "--run"], env=env, check=True,
                   capture_output=True)
    port = free_port()
    env.update(ACTAEON_HOME=f"{d}/demo", ACTAEON_BIND_PORT=str(port))
    srv = subprocess.Popen([a.actaeon, "serve"], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    base = f"http://127.0.0.1:{port}"
    try:
        for _ in range(60):
            try:
                urllib.request.urlopen(base + "/healthz", timeout=1)
                break
            except OSError:
                time.sleep(0.5)
        OUT.mkdir(parents=True, exist_ok=True)
        with sync_playwright() as p:
            b = p.chromium.launch()
            pg = b.new_page(viewport={"width": 1280, "height": 860}, device_scale_factor=2)
            shots = [("leads", "#leads"), ("entities", "#entities"), ("coverage", "#coverage")]
            for name, route in shots:
                pg.goto(base + "/" + route)
                pg.wait_for_timeout(1500)
                pg.screenshot(path=str(OUT / f"{name}.png"))
            pg.goto(base + "/#hunts")
            pg.wait_for_timeout(1200)
            pg.locator("main tbody tr", has_text="Office application").first.click()   # the main demo hunt
            pg.wait_for_timeout(1800)
            pg.screenshot(path=str(OUT / "hunt.png"))
            g = pg.locator("section", has=pg.locator("svg.graph")).first      # the investigation graph
            g.scroll_into_view_if_needed()
            pg.wait_for_timeout(500)
            g.screenshot(path=str(OUT / "graph.png"))
            b.close()
        print("wrote", ", ".join(sorted(p.name for p in OUT.glob("*.png"))))
    finally:
        srv.terminate()
        shutil.rmtree(d, ignore_errors=True)


if __name__ == "__main__":
    main()
