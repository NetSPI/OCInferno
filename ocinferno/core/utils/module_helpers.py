from __future__ import annotations

"""Common helper functions reused by many enumeration modules.

These are intentionally small and side-effect free so modules can share logic
without redefining the same helpers repeatedly.
"""

import os
import re
import requests
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from ocinferno.core.console import UtilityTools


def dedupe_strs(values: List[str]) -> List[str]:
    """Return input strings deduped in-order.

    Example:
        input  = ["a", "b", "a", "", "c"]
        output = ["a", "b", "c"]
    """
    seen = set()
    out: List[str] = []
    for x in values or []:
        if not isinstance(x, str) or not x:
            continue
        if x in seen:
            continue
        seen.add(x)
        out.append(x)
    return out


def print_results_table(
    rows: List[Dict[str, Any]],
    *,
    columns: List[str],
    sort_key: Optional[str] = None,
    empty_message: str = "[*] No results.",
    summary_message: str = "",
    summary_count: Optional[int] = None,
) -> None:
    """Print a standard results table + optional summary line.

    `summary_message` can use `{count}`.
    """
    items = [r for r in (rows or []) if isinstance(r, dict)]
    if items:
        if isinstance(sort_key, str) and sort_key:
            items = sorted(items, key=lambda x: str(x.get(sort_key) or ""))
        UtilityTools.print_limited_table(items, columns, sort_key=None)
    else:
        print(empty_message)

    if summary_message:
        count = len(items) if summary_count is None else int(summary_count)
        print(summary_message.format(count=count))


def parse_csv_args(values: List[str]) -> List[str]:
    """Parse repeated/CSV args into one deduped list.

    Example:
        input  = ["a,b", "c", "a"]
        output = ["a", "b", "c"]
    """
    parts: List[str] = []
    for v in values or []:
        if not v:
            continue
        parts.extend([x.strip() for x in str(v).split(",") if x and str(x).strip()])
    return dedupe_strs(parts)


def resolve_component_flags(args: Any, keys: List[str]) -> Dict[str, bool]:
    """Resolve component booleans with an "all if none selected" behavior.

    If any key in ``keys`` is explicitly set on ``args``, only those selected
    keys are enabled. If none are selected, all keys are enabled.
    """
    any_selected = any(bool(getattr(args, k, False)) for k in keys)
    if any_selected:
        return {k: bool(getattr(args, k, False)) for k in keys}
    return {k: True for k in keys}


def cached_table_count(
    session,
    *,
    table_name: str,
    compartment_id: Optional[str] = None,
    compartment_field: Optional[str] = "compartment_id",
) -> Optional[int]:
    """Return a cached row count for a table (best-effort).

    If ``compartment_id`` and ``compartment_field`` are provided, we try a scoped
    query first; otherwise, we fall back to counting all rows in the table.
    """
    if not table_name:
        return None
    rows: List[Dict[str, Any]] = []
    try:
        where = None
        if compartment_id and compartment_field:
            where = {compartment_field: compartment_id}
        rows = session.get_resource_fields(table_name, where_conditions=where) or []
    except Exception:
        try:
            rows = session.get_resource_fields(table_name) or []
        except Exception:
            return None
    return len(rows)


def save_rows(session, table_name: str, rows: List[Dict[str, Any]]) -> int:
    """Persist dict rows to a service table using the best available session API.

    Filters non-dict entries and returns the number of rows submitted/saved.
    """
    if not table_name:
        return 0

    valid = [r for r in (rows or []) if isinstance(r, dict)]
    if not valid:
        return 0

    save_many = getattr(session, "save_resources", None)
    if callable(save_many):
        try:
            return int(save_many(valid, table_name) or 0)
        except Exception:
            return 0

    save_one = getattr(session, "save_resource", None)
    if callable(save_one):
        written = 0
        for row in valid:
            try:
                save_one(row, table_name)
                written += 1
            except Exception:
                continue
        return written

    return 0


def fill_missing_fields(dst: Dict[str, Any], src: Dict[str, Any]) -> bool:
    """Fill only missing/empty fields in ``dst`` from ``src``.

    Empty means one of: ``None``, ``""``, ``[]``, ``{}``.

    Example:
        dst={"a":"", "b":1}, src={"a":"x", "b":2, "c":3}
        output dst={"a":"x", "b":1, "c":3}, returns True
    """
    changed = False
    for k, v in (src or {}).items():
        if dst.get(k) in (None, "", [], {}):
            if v not in (None, "", [], {}):
                dst[k] = v
                changed = True
    return changed


def unique_dict_rows_by_key(rows: List[Dict[str, Any]], key: str = "id") -> List[Dict[str, Any]]:
    """Deduplicate dict rows by ``key`` while preserving order.

    Rows without ``key`` are kept.
    """
    seen = set()
    out: List[Dict[str, Any]] = []
    for r in rows or []:
        if not isinstance(r, dict):
            continue
        rid = r.get(key)
        if isinstance(rid, str) and rid:
            if rid in seen:
                continue
            seen.add(rid)
        out.append(r)
    return out


def unique_rows_by_id(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Deduplicate rows by ``id`` key."""
    return unique_dict_rows_by_key(rows, key="id")


def ids_from_db(
    session,
    *,
    table_name: str,
    compartment_id: Optional[str] = None,
    id_key: str = "id",
) -> List[str]:
    """Load unique ID values from a DB table via ``session.get_resource_fields``.

    Example:
        ids_from_db(session, table_name="apigw_gateways", compartment_id="ocid1.compartment...")
    """
    where = {"compartment_id": compartment_id} if compartment_id else None
    rows = session.get_resource_fields(table_name, where_conditions=where) or []
    out: List[str] = []
    for r in rows:
        if isinstance(r, dict):
            rid = r.get(id_key)
            if isinstance(rid, str) and rid:
                out.append(rid)
    return dedupe_strs(out)


def domain_ids_from_db(
    session,
    *,
    table_name: str,
    compartment_id: str,
    domain_id_filter: str = "",
    id_key: str = "id",
) -> List[str]:
    """Return domain IDs for a compartment from DB, or a single CLI filter value.

    Example:
        domain_ids_from_db(session, table_name="iot_domains", compartment_id=cid, domain_id_filter="")
    """
    f = (domain_id_filter or "").strip()
    if f:
        return [f]

    try:
        return ids_from_db(session, table_name=table_name, compartment_id=compartment_id, id_key=id_key)
    except Exception:
        return []


def domain_matches(domain_row: Dict[str, Any], token: str) -> bool:
    """Substring matcher for Identity Domain rows using id/name/url fields."""
    t = (token or "").strip().lower()
    if not t:
        return True
    did = str(
        domain_row.get("id")
        or domain_row.get("domain_ocid")
        or domain_row.get("identity_domain_id")
        or ""
    ).lower()
    name = str(
        domain_row.get("display_name")
        or domain_row.get("displayName")
        or domain_row.get("name")
        or ""
    ).lower()
    url = str(domain_row.get("url") or "").lower()
    return (t in did) or (t in name) or (t in url)


def parse_iso_datetime(s: Optional[str]) -> Optional[datetime]:
    """Parse an ISO datetime string into timezone-aware ``datetime``.

    Accepts ``Z`` suffix and normalizes naive times to UTC.

    Example:
        input  = "2026-01-17T22:01:37Z"
        output = datetime(..., tzinfo=UTC)
    """
    if not s:
        return None
    s = s.strip()
    if not s:
        return None
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(s)
    except Exception as e:
        raise ValueError(f"Invalid datetime format: {s} (use ISO8601 like 2026-01-17T22:01:37Z)") from e
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def safe_int(v: Any) -> Optional[int]:
    """Convert ``v`` to ``int`` or return ``None`` on failure."""
    if v is None:
        return None
    try:
        return int(v)
    except Exception:
        return None


def write_bytes_file(path: str, blob: bytes) -> bool:
    """Write bytes to path. Returns True on success."""
    try:
        with open(path, "wb") as f:
            f.write(blob or b"")
        return True
    except Exception:
        return False


def write_response_stream_to_file(payload: Any, out_file: str, *, chunk_size: int = 1024 * 1024) -> bool:
    """Write an OCI SDK response body to a local file, whatever shape it arrives in.

    OCI SDK content/download responses show up as one of several shapes depending on
    the operation: raw bytes/bytearray/memoryview/str already; a plain file-like
    object (``.read()``); a ``requests``-style response (whole-payload ``.content``,
    a ``.text`` string body, or chunked ``.iter_content()``); the low-level urllib3
    stream via ``.raw`` (``.stream()`` preferred, ``.read()`` as a last resort); or a
    once-nested wrapper exposing the real payload under ``.data``. This tries each in
    turn so every call site can hand it ``resp.data`` (or ``resp``) directly instead of
    re-deriving the same shape-sniffing. Creates the parent directory. Returns True
    only once real bytes have landed on disk -- never leaves an empty file behind on
    an unrecognized/failed shape.
    """
    if payload is None:
        return False
    os.makedirs(os.path.dirname(out_file) or ".", exist_ok=True)

    if isinstance(payload, memoryview):
        payload = payload.tobytes()
    elif isinstance(payload, bytearray):
        payload = bytes(payload)

    if isinstance(payload, bytes):
        with open(out_file, "wb") as handle:
            handle.write(payload)
        return os.path.getsize(out_file) > 0

    if isinstance(payload, str):
        return write_response_stream_to_file(
            payload.encode("utf-8", errors="ignore"), out_file, chunk_size=chunk_size
        )

    content = getattr(payload, "content", None)
    if content is not None:
        return write_response_stream_to_file(content, out_file, chunk_size=chunk_size)

    text = getattr(payload, "text", None)
    if isinstance(text, str):
        return write_response_stream_to_file(text, out_file, chunk_size=chunk_size)

    if hasattr(payload, "iter_content") and callable(getattr(payload, "iter_content")):
        with open(out_file, "wb") as handle:
            for chunk in payload.iter_content(chunk_size=chunk_size):
                if chunk:
                    handle.write(chunk)
        return os.path.getsize(out_file) > 0

    raw = getattr(payload, "raw", None)
    if raw is not None:
        if hasattr(raw, "stream") and callable(getattr(raw, "stream")):
            with open(out_file, "wb") as handle:
                for chunk in raw.stream(chunk_size, decode_content=False):
                    if chunk:
                        handle.write(chunk)
            return os.path.getsize(out_file) > 0
        if hasattr(raw, "read") and callable(getattr(raw, "read")):
            with open(out_file, "wb") as handle:
                while True:
                    chunk = raw.read(chunk_size)
                    if not chunk:
                        break
                    handle.write(chunk)
            return os.path.getsize(out_file) > 0

    if hasattr(payload, "read") and callable(getattr(payload, "read")):
        with open(out_file, "wb") as handle:
            while True:
                chunk = payload.read(chunk_size)
                if not chunk:
                    break
                handle.write(chunk)
        return os.path.getsize(out_file) > 0

    nested = getattr(payload, "data", None)
    if nested is not None and nested is not payload:
        return write_response_stream_to_file(nested, out_file, chunk_size=chunk_size)

    return False


def safe_path_component(x: str) -> str:
    """Sanitize a value for path/file usage.

    Example:
        input  = "my path/with:chars"
        output = "my_path_with_chars"
    """
    x = str(x or "")
    x = x.replace("/", "_").replace("\\", "_").replace(":", "_")
    x = re.sub(r"\s+", "_", x)
    x = re.sub(r"[^A-Za-z0-9_.\-]", "", x).strip("._-")
    return x or "file"


def guess_blob_ext(blob: bytes, default_ext: str = "bin") -> str:
    """Guess a text payload extension from content bytes.

    Example:
        ``{"k":1}`` -> ``json``
        ``openapi: 3.0.0`` -> ``yaml``
    """
    if not blob:
        return default_ext
    head = blob[:256].lstrip()
    try:
        s = head.decode("utf-8", errors="ignore")
    except Exception:
        return default_ext
    if s.startswith("{"):
        return "json"
    if "openapi:" in s or s.startswith("openapi:") or "\npaths:" in s or "paths:" in s:
        return "yaml"
    return default_ext


def download_url_to_file(url: str, out_file: str, timeout: int = 60) -> bool:
    """Download URL content to file path.

    Returns True when bytes were written.
    """
    if not isinstance(url, str) or not url.strip():
        return False
    try:
        os.makedirs(os.path.dirname(out_file) or ".", exist_ok=True)
        resp = requests.get(url.strip(), timeout=timeout, stream=True)
        resp.raise_for_status()
        with open(out_file, "wb") as f:
            for chunk in resp.iter_content(chunk_size=1024 * 1024):
                if chunk:
                    f.write(chunk)
        return os.path.getsize(out_file) > 0
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Export stack moved to core/utils/exports.py; re-exported here for back-compat.
# ---------------------------------------------------------------------------
from ocinferno.core.utils.exports import (  # noqa: E402,F401
    export_compartment_tree_image,
    export_sqlite_db_to_excel,
    export_sqlite_dbs_to_csv_blob,
    export_sqlite_dbs_to_excel_blob,
    export_sqlite_dbs_to_json_blob,
)

__all__ = [
    "export_compartment_tree_image",
    "export_sqlite_db_to_excel",
    "export_sqlite_dbs_to_csv_blob",
    "export_sqlite_dbs_to_excel_blob",
    "export_sqlite_dbs_to_json_blob",
]
