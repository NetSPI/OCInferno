"""Resolve a successful OCI API operation to the IAM permission(s) it proves.

Passive permission recording: when the global SDK hook in ``session.py`` sees a
2xx for operation ``X``, ``resolve_permissions``
returns the permission(s) a success implies, which the session merges into the
``user_permissions`` table. Data comes from
``mappings/oci_api_operation_permissions.json`` (extracted from the OCI policy
reference "Permissions Required for Each API Operation" tables).

Key facts baked into the map:
  * ``operations[op]`` -> the permission set a 2xx proves (ALL are required, so all
    are held on success).
  * ``ambiguous_operations[op]`` -> a per-service-slug map for operation names that
    recur across services with different permissions (``ListWorkRequests`` etc.).
    These must be disambiguated by service or we record nothing (never guess).
  * ``conditional_permissions`` (if present on an entry) are informational only --
    a plain success does not prove them, so we ignore them here.
"""

from __future__ import annotations

import json
import threading
from importlib import resources
from typing import Any, Dict, List, Optional

# Coarse service names from _infer_service_name_from_url (hostname label) mapped to
# the map's service slugs where they differ (Core's host is "iaas").
_SERVICE_ALIASES = {"iaas": "core"}

_LOCK = threading.Lock()
_MAP: Optional[Dict[str, Any]] = None


def _operation_candidates(op: str) -> List[str]:
    """The OCI SDK passes ``operation_name`` in snake_case (``list_domains``) but the
    map keys are the PascalCase API operation names from the docs (``ListDomains``).
    Return both forms so either matches (raw first, then the PascalCase conversion)."""
    candidates = [op]
    if "_" in op:
        candidates.append("".join(part[:1].upper() + part[1:] for part in op.split("_") if part))
    return candidates


def _load_map() -> Dict[str, Any]:
    global _MAP
    if _MAP is None:
        with _LOCK:
            if _MAP is None:
                try:
                    text = (
                        resources.files("ocinferno.mappings")
                        .joinpath("oci_api_operation_permissions.json")
                        .read_text(encoding="utf-8")
                    )
                    _MAP = json.loads(text)
                except Exception:
                    _MAP = {"operations": {}, "ambiguous_operations": {}}
    return _MAP


def resolve_permissions(operation: str, service: str = "") -> List[str]:
    """Return the permission(s) a SUCCESSFUL ``operation`` proves the caller holds.

    Returns ``[]`` for unknown or unresolvable-ambiguous operations (never guesses).
    """
    raw = str(operation or "").strip()
    if not raw or raw == "__doc":
        return []
    data = _load_map()
    ambiguous = data.get("ambiguous_operations") or {}
    operations = data.get("operations") or {}

    for op in _operation_candidates(raw):
        entry = ambiguous.get(op)
        if isinstance(entry, dict):
            svc = str(service or "").strip()
            for key in (svc, _SERVICE_ALIASES.get(svc, svc)):
                perms = entry.get(key)
                if isinstance(perms, list) and perms:
                    return [str(p) for p in perms]
            return []  # ambiguous op + unknown/mismatched service -> record nothing

        op_entry = operations.get(op)
        if isinstance(op_entry, dict):
            perms = op_entry.get("permissions") or []
            return [str(p) for p in perms if p]
    return []
