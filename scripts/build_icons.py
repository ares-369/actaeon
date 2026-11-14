"""Rebuild the icon subset in actaeon/static/mdi from the full Material Design Icons webfont.

The wheel ships only the icons the UI uses. After using a new icon name in app.js or index.html, run:

    npm pack @mdi/font@7.4.47 && tar xzf mdi-font-7.4.47.tgz      # gives package/css and package/fonts
    pip install fonttools brotli                                   # build-time only, not a dependency
    python scripts/build_icons.py package

tests/test_icons.py fails when the UI names an icon the subset lacks.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
STATIC = ROOT / "actaeon" / "static"
SOURCES = (STATIC / "app.js", ROOT / "actaeon" / "templates" / "index.html", ROOT / "actaeon" / "templates" / "login.html")


def used_names(known: set[str]) -> list[str]:
    text = "".join(p.read_text() for p in SOURCES)
    lits = set(re.findall(r"[\"'`]([a-z0-9-]+)[\"'`]", text)) | set(re.findall(r"mdi-([a-z0-9-]+)", text))
    return sorted(n for n in lits if n in known)


def main(pkg: str) -> None:
    from fontTools import subset
    pkg_dir = Path(pkg)
    css = (pkg_dir / "css" / "materialdesignicons.min.css").read_text()
    codes = dict(re.findall(r'\.mdi-([a-z0-9-]+)::?before\{content:"\\([0-9A-Fa-f]+)"', css))
    names = used_names(set(codes))
    out = STATIC / "mdi"
    (out / "fonts").mkdir(parents=True, exist_ok=True)
    (out / "css").mkdir(parents=True, exist_ok=True)
    opts = subset.Options()
    opts.flavor = "woff2"
    opts.layout_features = []
    opts.name_IDs = ["*"]
    font = subset.load_font(str(pkg_dir / "fonts" / "materialdesignicons-webfont.ttf"), opts)
    sub = subset.Subsetter(opts)
    sub.populate(unicodes=[int(codes[n], 16) for n in names])
    sub.subset(font)
    subset.save_font(font, str(out / "fonts" / "icons.woff2"), opts)
    rules = "".join(f'.mdi-{n}::before{{content:"\\{codes[n]}"}}\n' for n in names)
    (out / "css" / "icons.css").write_text(
        "/* Subset of Material Design Icons 7.4.47 (Apache-2.0, see ../LICENSE); built by scripts/build_icons.py */\n"
        '@font-face{font-family:"Material Design Icons";src:url("../fonts/icons.woff2") format("woff2");'
        "font-weight:normal;font-style:normal}\n"
        '.mdi::before,.mdi-set{display:inline-block;font:normal normal normal 24px/1 "Material Design Icons";'
        "font-size:inherit;text-rendering:auto;line-height:inherit;-webkit-font-smoothing:antialiased;"
        "-moz-osx-font-smoothing:grayscale}\n" + rules)
    print(f"{len(names)} icons, {(out / 'fonts' / 'icons.woff2').stat().st_size} bytes")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "package")
