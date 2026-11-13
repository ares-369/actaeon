"""Load ExCyTIn-Bench incident logs (CSV + .meta) into one SQLite file per incident.

Usage: python load_sqlite.py <data_anonymized/incidents> <out_dir> [incident_38 ...]

Matches the benchmark's default "alert" layer: every table except AzureDiagnostics and
LAQueryLogs. Fields use the dataset's separator and quote character.
"""

import csv
import json
import os
import sqlite3
import sys
from pathlib import Path

SEP, QUOTE = "❖", '"'
SKIP = {"AzureDiagnostics", "LAQueryLogs"}
csv.field_size_limit(1 << 30)


def tables(folder: Path):
    for p in sorted(folder.iterdir()):
        if p.name.startswith(("._", ".")):
            continue
        if p.suffix == ".csv" and p.stem not in SKIP:
            yield p.stem, [p], p.with_suffix(".meta")
        elif p.is_dir() and p.name not in SKIP:
            parts = sorted(x for x in p.iterdir() if x.suffix == ".csv" and not x.name.startswith("._"))
            yield p.name, parts, p / f"{p.name}_0.meta"


def load(folder: Path, out: Path) -> None:
    tmp = out.with_suffix(".tmp")
    if tmp.exists():
        tmp.unlink()
    db = sqlite3.connect(tmp)
    db.execute("PRAGMA journal_mode=OFF")
    db.execute("PRAGMA synchronous=OFF")
    for name, parts, meta in tables(folder):
        cols = list(json.loads(meta.read_text(encoding="utf-8"))) if meta.exists() else None
        rows = 0
        for i, part in enumerate(parts):
            with open(part, encoding="utf-8-sig", newline="") as fh:
                r = csv.reader(fh, delimiter=SEP, quotechar=QUOTE)
                header = next(r, None)
                if header is None:
                    continue
                if i == 0:
                    cols = header if not cols or len(cols) != len(header) else cols
                    coldefs = ", ".join('"' + c.replace('"', "") + '" TEXT' for c in cols)
                    db.execute(f'CREATE TABLE "{name}" ({coldefs})')
                n = len(cols)
                batch = []
                for row in r:
                    row = (row + [""] * n)[:n]
                    batch.append([v if v != "" else None for v in row])
                    if len(batch) >= 5000:
                        db.executemany(f'INSERT INTO "{name}" VALUES ({",".join("?" * n)})', batch)
                        rows += len(batch)
                        batch = []
                if batch:
                    db.executemany(f'INSERT INTO "{name}" VALUES ({",".join("?" * n)})', batch)
                    rows += len(batch)
        print(f"  {name}: {rows} rows", flush=True)
    db.commit()
    db.close()
    os.replace(tmp, out)


def main() -> None:
    src, dst = Path(sys.argv[1]), Path(sys.argv[2])
    dst.mkdir(parents=True, exist_ok=True)
    want = sys.argv[3:] or sorted(p.name for p in src.iterdir() if p.is_dir())
    for inc in want:
        out = dst / f"{inc}.db"
        if out.exists():
            print(f"{inc}: exists, skipped")
            continue
        print(f"{inc}:", flush=True)
        load(src / inc, out)
        os.chmod(out, 0o444)


if __name__ == "__main__":
    main()
