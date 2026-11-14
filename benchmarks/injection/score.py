"""Score the prompt-injection scanner on benchmarks/injection/cases.yaml.

    python benchmarks/injection/score.py [--cases FILE] [--markdown] [--show-misses]

The scanner (actaeon/hunt/injection.py) is pattern-based. This measures how many planted attacks it
flags and how many benign look-alikes it flags by mistake. It does not measure whether a model would
have followed an attack it missed; the untrusted-data wrapping and the read-only tool policy are the
defences there.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import yaml

HERE = Path(__file__).resolve().parent


def score(cases: dict) -> dict:
    from actaeon.connectors.untrusted import wrap
    from actaeon.hunt.injection import scan

    def flagged(text: str) -> bool:
        return bool(scan(wrap("logs", "search", text, 20_000)["content"]))
    att = [(c, flagged(c["text"])) for c in cases.get("attack") or []]
    ben = [(c, flagged(c["text"])) for c in cases.get("benign") or []]
    tp = sum(1 for _, f in att if f)
    fp = sum(1 for _, f in ben if f)
    return {"attacks": len(att), "caught": tp, "benign": len(ben), "false_alarms": fp,
            "missed": [c for c, f in att if not f], "false_alarm_cases": [c for c, f in ben if f]}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--cases", default=str(HERE / "cases.yaml"))
    ap.add_argument("--markdown", action="store_true")
    ap.add_argument("--show-misses", action="store_true")
    a = ap.parse_args()
    r = score(yaml.safe_load(Path(a.cases).read_text(encoding="utf-8")))
    if a.markdown:
        print("| Set | Cases | Flagged |\n|---|---|---|")
        print(f"| Planted attacks | {r['attacks']} | {r['caught']} |")
        print(f"| Benign look-alikes | {r['benign']} | {r['false_alarms']} |")
    else:
        print(f"attacks caught {r['caught']}/{r['attacks']}, false alarms {r['false_alarms']}/{r['benign']}")
    if a.show_misses:
        for c in r["missed"]:
            print(f"  missed      [{c['field']}] {c['text'][:100]}")
        for c in r["false_alarm_cases"]:
            print(f"  false alarm [{c['field']}] {c['text'][:100]}")
    sys.exit(0)


if __name__ == "__main__":
    main()
