"""Tiny neutral value-coercion helpers shared by session.py and its extracted
mixins (auth / workspace_config). Kept dependency-free to avoid import cycles."""

from __future__ import annotations

import json
from typing import Any, Dict, Iterable, List


def _safe_str(x: Any) -> str:
    return x if isinstance(x, str) else ""


def _truthy(x: Any) -> bool:
    if isinstance(x, bool):
        return x
    if isinstance(x, (int, float)):
        return x != 0
    if isinstance(x, str):
        return x.strip().lower() in {"1", "true", "t", "yes", "y", "on"}
    return False


def uniq_strs(xs: Iterable[Any]) -> List[str]:
    """Order-preserving unique list of stripped, non-empty strings."""
    out: List[str] = []
    seen: set[str] = set()
    for x in xs:
        s = x.strip() if isinstance(x, str) else ""
        if s and s not in seen:
            seen.add(s)
            out.append(s)
    return out


def as_json_dict(v: Any) -> Dict[str, Any]:
    """Coerce a value that may be a dict or a JSON-encoded string into a dict.

    Returns {} for anything that is not a dict or does not parse to a dict.
    """
    if isinstance(v, dict):
        return v
    if isinstance(v, str):
        s = v.strip()
        if not s:
            return {}
        try:
            p = json.loads(s)
            return p if isinstance(p, dict) else {}
        except Exception:
            return {}
    return {}
