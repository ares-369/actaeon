"""Convert a Sigma draft into a connector's own query language with pySigma.

Optional: ``pip install 'actaeon[sigma]'`` plus the pySigma backend for your
platform (each platform's backend is its own package). Then, per connector::

    connectors:
      - name: logs
        ...
        sigma:
          backend: <backend id>            # as the installed backend registers it; see `actaeon sigma backends`
          pipelines: [<pipeline id or a pipeline YAML file>]   # field mappings for your data
          format: default                  # backend output format
          backtest: true                   # count matches of the converted query over the last days

The converted queries are drafts like the Sigma rule itself: pySigma maps fields
and syntax, it does not know your data. The backtest shows how often a query
would have fired; zero matches can also mean the field mapping is wrong.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Any


class SigmaConvertError(ValueError):
    pass


@lru_cache(maxsize=1)
def _plugins():
    try:
        from sigma.plugins import InstalledSigmaPlugins
    except ImportError:
        return None
    return InstalledSigmaPlugins.autodiscover()


def available() -> dict[str, Any]:
    p = _plugins()
    if p is None:
        return {"installed": False, "backends": [], "pipelines": [],
                "hint": "pip install 'actaeon[sigma]' and the pySigma backend for your platform"}
    return {"installed": True, "backends": sorted(p.backends), "pipelines": sorted(p.pipelines)}


def validate_target(name: str, raw: Any) -> dict:
    """Check a connector's ``sigma:`` block (shape only; whether the backend is installed is checked at use)."""
    if not isinstance(raw, dict) or not str(raw.get("backend", "")).strip():
        raise ValueError(f"connector {name}: sigma needs a backend (see docs/detection.md)")
    pipes = raw.get("pipelines") or []
    if not isinstance(pipes, list) or not all(isinstance(x, str) for x in pipes):
        raise ValueError(f"connector {name}: sigma.pipelines must be a list of names or file paths")
    return {"backend": str(raw["backend"]).strip(), "pipelines": list(pipes),
            "format": str(raw.get("format", "default") or "default"), "backtest": bool(raw.get("backtest", True))}


def convert(rule_yaml: str, *, backend: str, pipelines: list[str] | None = None, fmt: str = "default") -> list[str]:
    p = _plugins()
    if p is None:
        raise SigmaConvertError("pySigma is not installed: pip install 'actaeon[sigma]'")
    cls = p.backends.get(backend)
    if cls is None:
        raise SigmaConvertError(f"no pySigma backend {backend!r} is installed (installed: "
                                f"{', '.join(sorted(p.backends)) or 'none'})")
    try:
        from sigma.collection import SigmaCollection
        from sigma.exceptions import SigmaError
    except ImportError as exc:     # pragma: no cover
        raise SigmaConvertError(str(exc)) from exc
    try:
        pipeline = p.get_pipeline_resolver().resolve(list(pipelines or []), target=backend) if pipelines else None
        b = cls(processing_pipeline=pipeline) if pipeline is not None else cls()
        out = b.convert(SigmaCollection.from_yaml(rule_yaml), fmt)
    except SigmaError as exc:
        raise SigmaConvertError(f"{type(exc).__name__}: {exc}"[:400]) from exc
    except Exception as exc:                                        # backends raise their own errors too
        raise SigmaConvertError(f"{type(exc).__name__}: {exc}"[:400]) from exc
    items = out if isinstance(out, list) else [out]
    return [i if isinstance(i, str) else str(i) for i in items]


def targets(cfg) -> list[dict]:
    """Connectors with a ``sigma:`` block, enabled, that the current caller may use."""
    from ..access import can_use
    out = []
    for raw in list(getattr(cfg, "connectors", None) or []):
        if not isinstance(raw, dict) or not raw.get("sigma") or raw.get("enabled", True) is False:
            continue
        name = str(raw.get("name", ""))
        if can_use(name):
            out.append({"connector": name, **validate_target(name, raw["sigma"])})
    return out


def convert_for(rule_yaml: str, tgts: list[dict], *, hub=None, h: dict | None = None, days: int = 14) -> list[dict]:
    """Convert for each target; with ``hub`` and ``backtest``, count the matches over the last ``days``."""
    from datetime import datetime, timedelta, timezone

    from ..connectors.hub import ToolCallError
    from .signals import hits
    out = []
    for t in tgts:
        row: dict[str, Any] = {"connector": t["connector"], "backend": t["backend"], "pipelines": t["pipelines"]}
        try:
            row["queries"] = convert(rule_yaml, backend=t["backend"], pipelines=t["pipelines"], fmt=t["format"])
        except SigmaConvertError as exc:
            row["error"] = str(exc)
            out.append(row)
            continue
        if hub is not None and t.get("backtest") and row["queries"] and isinstance(row["queries"][0], str):
            row["backtest"] = _count(hub, t["connector"], row["queries"][0], h or {}, days, hits, ToolCallError,
                                     datetime, timedelta, timezone)
        out.append(row)
    return out


def _count(hub, connector, query, h, days, hits, ToolCallError, datetime, timedelta, timezone) -> dict:
    try:
        tools = {x["name"]: x for x in hub.tools(connector) if x.get("allowed")}
    except Exception as exc:
        return {"error": f"cannot list tools: {exc}"[:200]}
    if "count" not in tools:
        return {"error": "this connector has no count tool"}
    props = ((tools["count"].get("inputSchema") or {}).get("properties") or {})
    args: dict[str, Any] = {"query": query}
    if "index" in props:
        idx = next((s["arguments"].get("index") for s in h.get("steps") or []
                    if s.get("connector") == connector and isinstance(s.get("arguments"), dict)
                    and s["arguments"].get("index")), None)
        if idx:
            args["index"] = idx
    days = max(1, min(int(days), 30))
    now = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0)
    if "time_from" in props:
        args.update(time_from=(now - timedelta(days=days)).isoformat(), time_to=now.isoformat())
    try:
        r = hub.call(connector, "count", args, actor="sigma-backtest", hunt_id=h.get("id", ""))
    except ToolCallError as exc:
        return {"error": str(exc)[:200]}
    if r.get("is_error"):
        return {"error": "the count failed (often a field-mapping or syntax problem): " + r["content"][-300:]}
    return {"days": days, "matches": hits(r["content"]), "index": args.get("index")}
