from __future__ import annotations

"""Common helper functions reused by many enumeration modules.

These are intentionally small and side-effect free so modules can share logic
without redefining the same helpers repeatedly.
"""

import json
import os
import sys
import re
import sqlite3
import requests
import csv
import textwrap
from decimal import Decimal
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from xml.sax.saxutils import escape as xml_escape

from ocinferno.core.db import DataController
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


def append_passthrough_flags(
    argv: List[str],
    args: Any,
    flag_attr_pairs: Optional[List[tuple[str, str]]] = None,
) -> List[str]:
    """Append passthrough CLI flags based on argparse attributes.

    By default this appends ``--save``, ``--get``, and ``--download`` when
    their corresponding boolean attrs are true and not already present.
    """
    out = list(argv or [])
    pairs = flag_attr_pairs or [("--save", "save"), ("--get", "get"), ("--download", "download")]
    for flag, attr in pairs:
        if bool(getattr(args, attr, False)) and flag not in out:
            out.append(flag)
    return out


def filter_cli_args(argv: List[str], allowed_flags: set[str]) -> List[str]:
    """Filter argv to only include flags that exist in allowed_flags (and their values)."""
    out: List[str] = []
    i = 0
    while i < len(argv):
        tok = argv[i]
        if tok.startswith("--"):
            flag = tok.split("=", 1)[0]
            if flag in allowed_flags:
                out.append(tok)
                if "=" not in tok and i + 1 < len(argv):
                    nxt = argv[i + 1]
                    if not str(nxt).startswith("--"):
                        out.append(nxt)
                        i += 1
            else:
                if "=" not in tok and i + 1 < len(argv):
                    nxt = argv[i + 1]
                    if not str(nxt).startswith("--"):
                        i += 1
        i += 1
    return out


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
        rows = session.get_resource_fields(
            table_name=table_name,
            fields=[id_key, "compartment_id"],
            where_dict={"compartment_id": compartment_id},
        ) or []
    except Exception:
        return []

    out: List[str] = []
    seen = set()
    for r in rows:
        if not isinstance(r, dict):
            continue
        did = r.get(id_key)
        if isinstance(did, str) and did and did not in seen:
            seen.add(did)
            out.append(did)
    return out


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


def write_json_file(path: str, obj: Any) -> bool:
    """Write JSON object to file. Returns True on success."""
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(obj, f, sort_keys=False, indent=2)
        return True
    except Exception:
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


def _excel_safe_value(v: Any) -> Any:
    if v is None or isinstance(v, (str, int, float, bool)):
        return v
    if isinstance(v, bytes):
        try:
            return v.decode("utf-8", errors="replace")
        except Exception:
            return str(v)
    if isinstance(v, (dict, list, tuple)):
        try:
            return json.dumps(v, ensure_ascii=False, sort_keys=False)
        except Exception:
            return str(v)
    return str(v)


def _maybe_parse_json_text(v: Any) -> Any:
    """
    If a value is a JSON-looking string (object/array), parse it into real JSON.
    Keeps normal strings unchanged.
    """
    if not isinstance(v, str):
        return v
    s = v.strip()
    if not s:
        return v
    if not (s.startswith("{") or s.startswith("[")):
        return v
    try:
        parsed = json.loads(s)
    except Exception:
        return v
    return parsed


def _xml_safe_text(v: Any) -> str:
    s = str(v) if v is not None else ""
    # XML 1.0 valid control chars are tab/newline/carriage return; strip the rest.
    s = "".join(ch for ch in s if (ord(ch) >= 32 or ch in "\t\n\r"))
    return xml_escape(s)


def export_sqlite_db_to_excel(
    *,
    db_path: str,
    out_xlsx_path: str,
    single_sheet: bool = True,
) -> Dict[str, Any]:
    """Export a single SQLite DB to Excel.

    This is a thin wrapper around ``export_sqlite_dbs_to_excel_blob`` so both
    single-db and multi-db exports share the same implementation.
    """
    db_file = Path(db_path).expanduser().resolve()
    if not db_file.exists():
        raise FileNotFoundError(f"SQLite DB not found: {db_file}")

    result = export_sqlite_dbs_to_excel_blob(
        db_paths=[str(db_file)],
        out_xlsx_path=out_xlsx_path,
        single_sheet=single_sheet,
        condensed=False,
    )
    return {
        "ok": bool(result.get("ok")),
        "db_path": str(db_file),
        "xlsx_path": str(result.get("xlsx_path") or ""),
        "format": "xlsx",
        "tables": int(result.get("tables") or 0),
        "rows": int(result.get("rows") or 0),
        "single_sheet": bool(single_sheet),
        "python_executable": str(result.get("python_executable") or sys.executable),
        "writer_errors": list(result.get("writer_errors") or []),
    }


def _excel_sheet_title(base: str, used_titles: set[str]) -> str:
    clean = re.sub(r'[\\/*?:\[\]]+', "_", str(base or "sheet")).strip("_ ")
    if not clean:
        clean = "sheet"
    candidate = clean[:31]
    if candidate not in used_titles:
        used_titles.add(candidate)
        return candidate

    i = 2
    while True:
        suffix = f"_{i}"
        head = clean[: max(1, 31 - len(suffix))]
        candidate = f"{head}{suffix}"
        if candidate not in used_titles:
            used_titles.add(candidate)
            return candidate
        i += 1


def _apply_xlsx_condensed_layout(
    *,
    writer: Any,
    sheet_name: str,
) -> None:
    """
    Apply readability formatting for condensed sheets:
      - sensible column widths
      - wrapped JSON column
    """
    try:
        ws = (writer.sheets or {}).get(sheet_name)
    except Exception:
        ws = None
    if ws is None:
        return

    try:
        wrap_fmt = writer.book.add_format({"text_wrap": True, "valign": "top"})
        ws.set_column(0, 0, 30)   # Table Name
        ws.set_column(1, 1, 42)   # Compartment ID
        ws.set_column(2, 2, 28)   # Compartment Name
        ws.set_column(3, 3, 34)   # Resource Category
        ws.set_column(4, 4, 34)   # Resource Display Name
        ws.set_column(5, 5, 120, wrap_fmt)  # Remaining JSON
    except Exception:
        return


def _clean_compartment_label(name: str, cid: str, parent: str) -> str:
    n = str(name or "").strip()
    c = str(cid or "").strip()
    if not n or n == c:
        n = "NAME_UNKNOWN"
    if n != "NAME_UNKNOWN" and len(n) > 30:
        n = f"{n[:27]}..."
    return n


def _build_compartment_tree_layout(rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    raw_nodes: Dict[str, Dict[str, str]] = {}
    children: Dict[str, List[str]] = {}

    for row in rows or []:
        cid = _resource_display_value(row.get("compartment_id") or row.get("id"))
        if not cid:
            continue
        raw_name = (
            _resource_display_value(row.get("name"))
            or _resource_display_value(row.get("display_name"))
            or cid
        )
        parent = _resource_display_value(row.get("parent_compartment_id"))
        name = _clean_compartment_label(raw_name, cid, parent)
        raw_nodes[cid] = {"name": name, "parent": parent}

    node_ids = sorted(raw_nodes.keys(), key=lambda x: (raw_nodes[x]["name"].lower(), x.lower()))
    for cid in node_ids:
        children.setdefault(cid, [])

    roots: List[str] = []
    for cid in node_ids:
        parent = str(raw_nodes[cid].get("parent") or "")
        if parent and parent in raw_nodes and parent != cid:
            children.setdefault(parent, []).append(cid)
        else:
            roots.append(cid)

    for pid in list(children.keys()):
        children[pid] = sorted(
            list(dict.fromkeys(children[pid])),
            key=lambda x: (raw_nodes.get(x, {}).get("name", "").lower(), x.lower()),
        )

    if not roots and node_ids:
        roots = list(node_ids)
    else:
        roots = sorted(
            list(dict.fromkeys(roots)),
            key=lambda x: (raw_nodes.get(x, {}).get("name", "").lower(), x.lower()),
        )

    depth: Dict[str, int] = {}
    queue: List[str] = []
    for r in roots:
        depth[r] = 0
        queue.append(r)
    while queue:
        cur = queue.pop(0)
        cur_d = int(depth.get(cur, 0))
        for child in children.get(cur, []):
            nd = cur_d + 1
            if child not in depth or nd < int(depth[child]):
                depth[child] = nd
                queue.append(child)
    for cid in node_ids:
        depth.setdefault(cid, 0)

    assigned_x: Dict[str, float] = {}
    next_x = 0.0

    def _assign_x(cid: str, stack: set[str]) -> float:
        nonlocal next_x
        if cid in assigned_x:
            return assigned_x[cid]
        if cid in stack:
            x = next_x
            next_x += 1.0
            assigned_x[cid] = x
            return x
        stack.add(cid)
        kid_x: List[float] = []
        for child in children.get(cid, []):
            kid_x.append(_assign_x(child, stack))
        stack.discard(cid)
        if kid_x:
            x = sum(kid_x) / float(len(kid_x))
        else:
            x = next_x
            next_x += 1.0
        assigned_x[cid] = x
        return x

    seen: set[str] = set()
    for r in roots:
        _assign_x(r, set())
        seen.add(r)
    for cid in node_ids:
        if cid not in assigned_x:
            _assign_x(cid, set())
        seen.add(cid)

    nodes: Dict[str, Dict[str, Any]] = {}
    max_box_w = 220.0
    max_box_h = 88.0
    for cid in node_ids:
        name = str(raw_nodes.get(cid, {}).get("name") or cid)
        ocid_raw = str(cid or "")
        ocid_parts = textwrap.wrap(ocid_raw, width=30) or [ocid_raw]
        if ocid_parts:
            ocid_parts[0] = f"({ocid_parts[0]}"
            ocid_parts[-1] = f"{ocid_parts[-1]})"
        label_lines = [name] + ocid_parts
        max_chars = max((len(ln) for ln in label_lines), default=12)
        line_count = max(1, len(label_lines))
        box_w = min(440.0, max(220.0, max_chars * 8.1 + 30.0))
        box_h = min(220.0, max(84.0, line_count * 17.0 + 24.0))
        max_box_w = max(max_box_w, box_w)
        max_box_h = max(max_box_h, box_h)
        nodes[cid] = {
            "id": cid,
            "name": name,
            "parent": str(raw_nodes.get(cid, {}).get("parent") or ""),
            "x_idx": float(assigned_x.get(cid, 0.0)),
            "depth": int(depth.get(cid, 0)),
            "box_w": float(box_w),
            "box_h": float(box_h),
            "radius": float(max(box_w, box_h) / 2.0),
            "label_lines": label_lines,
        }

    x_spacing = max(320.0, max_box_w + 92.0)
    y_spacing = max(210.0, max_box_h + 86.0)
    min_x = min((nodes[cid]["x_idx"] for cid in node_ids), default=0.0)
    max_x = max((nodes[cid]["x_idx"] for cid in node_ids), default=0.0)
    max_depth = max((nodes[cid]["depth"] for cid in node_ids), default=0)
    pad = max(90.0, max(max_box_w, max_box_h) * 0.5 + 28.0)

    for cid in node_ids:
        n = nodes[cid]
        n["x"] = pad + (float(n["x_idx"]) - min_x) * x_spacing
        n["y"] = pad + float(int(n["depth"])) * y_spacing

    edges: List[tuple[str, str]] = []
    for pid in node_ids:
        for child in children.get(pid, []):
            if child in nodes and child != pid:
                edges.append((pid, child))

    width = int(max(980.0, (max_x - min_x) * x_spacing + pad * 2.0 + 1.0))
    height = int(max(700.0, float(max_depth) * y_spacing + pad * 2.0 + 1.0))

    return {
        "nodes": nodes,
        "node_order": node_ids,
        "edges": edges,
        "width": width,
        "height": height,
    }


def _render_compartment_tree_svg(layout: Dict[str, Any], out_file: Path) -> None:
    nodes: Dict[str, Dict[str, Any]] = dict(layout.get("nodes") or {})
    node_order: List[str] = list(layout.get("node_order") or [])
    edges: List[tuple[str, str]] = list(layout.get("edges") or [])
    width = int(layout.get("width") or 800)
    height = int(layout.get("height") or 600)

    lines: List[str] = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
        "<defs>",
        '<linearGradient id="bgGrad" x1="0%" y1="0%" x2="100%" y2="100%">',
        '<stop offset="0%" stop-color="#0b1020" />',
        '<stop offset="100%" stop-color="#151b2f" />',
        "</linearGradient>",
        '<marker id="arrow" markerWidth="10" markerHeight="8" refX="10" refY="4" orient="auto" markerUnits="strokeWidth">',
        '<path d="M0,0 L10,4 L0,8 z" fill="#8ea0bf" />',
        "</marker>",
        '<filter id="shadow" x="-30%" y="-30%" width="160%" height="160%">',
        '<feDropShadow dx="0" dy="3" stdDeviation="3" flood-color="#000000" flood-opacity="0.42"/>',
        "</filter>",
        "</defs>",
        f'<rect x="0" y="0" width="{width}" height="{height}" fill="url(#bgGrad)" />',
        '<text x="{x}" y="34" text-anchor="middle" font-family="Segoe UI, DejaVu Sans, Arial, sans-serif" font-size="18" font-weight="700" fill="#dbe7ff">OCI Compartment Hierarchy</text>'.format(
            x=width / 2
        ),
        '<g id="viewport">',
    ]

    edge_lines: List[str] = []
    for src, dst in edges:
        a = nodes.get(src)
        b = nodes.get(dst)
        if not a or not b:
            continue
        x1 = float(a["x"])
        y1 = float(a["y"]) + float(a.get("box_h") or 80.0) * 0.5 + 1.0
        x2 = float(b["x"])
        y2 = float(b["y"]) - float(b.get("box_h") or 80.0) * 0.5 - 1.8
        cy1 = y1 + max(16.0, (y2 - y1) * 0.32)
        cy2 = y2 - max(16.0, (y2 - y1) * 0.32)
        edge_lines.append(
            f'<path d="M {x1:.2f} {y1:.2f} C {x1:.2f} {cy1:.2f}, {x2:.2f} {cy2:.2f}, {x2:.2f} {y2:.2f}" '
            'fill="none" stroke="#8ea0bf" stroke-width="2" stroke-linecap="round" marker-end="url(#arrow)" opacity="0.9" />'
        )

    depth_palette = ["#081923", "#0b1c32", "#171133", "#251708", "#241024", "#101a28"]
    for cid in node_order:
        n = nodes.get(cid)
        if not n:
            continue
        x = float(n["x"])
        y = float(n["y"])
        w = float(n.get("box_w") or 220.0)
        h = float(n.get("box_h") or 84.0)
        depth = int(n.get("depth") or 0)
        fill = depth_palette[depth % len(depth_palette)]
        lines.append(
            f'<rect x="{(x - w/2 + 1.4):.2f}" y="{(y - h/2 + 2.2):.2f}" width="{w:.2f}" height="{h:.2f}" rx="16" '
            'fill="#000000" opacity="0.28" />'
        )
        lines.append(
            f'<rect x="{(x - w/2):.2f}" y="{(y - h/2):.2f}" width="{w:.2f}" height="{h:.2f}" rx="16" '
            f'fill="{fill}" stroke="#67f0e2" stroke-width="2.4" filter="url(#shadow)" />'
        )
        label_lines = list(n.get("label_lines") or [str(n.get("name") or cid)])
        line_h = 17.0
        base_y = y - ((len(label_lines) - 1) * line_h) / 2.0
        for i, txt in enumerate(label_lines):
            ty = base_y + i * line_h
            safe_txt = _xml_safe_text(txt)
            font_size = 15 if i == 0 else 13
            font_weight = "700" if i == 0 else "500"
            font_color = "#ffffff" if i == 0 else "#f3f7ff"
            lines.append(
                f'<text x="{x:.2f}" y="{ty:.2f}" text-anchor="middle" '
                'font-family="DejaVu Sans, Segoe UI, Arial, sans-serif" '
                f'font-size="{font_size}" font-weight="{font_weight}" fill="{font_color}" '
                'paint-order="stroke" stroke="#000000" stroke-width="1.25" stroke-linejoin="round">'
                f"{safe_txt}</text>"
            )

    lines.extend(edge_lines)
    lines.append("</g>")
    lines.append("<style><![CDATA[")
    lines.append("svg { cursor: grab; user-select: none; }")
    lines.append("]]></style>")
    lines.append("<script><![CDATA[")
    lines.append("(function(){")
    lines.append("  var svg = document.documentElement;")
    lines.append("  var vp = document.getElementById('viewport');")
    lines.append("  if (!svg || !vp) return;")
    lines.append("  var scale = 1.0, tx = 0.0, ty = 0.0;")
    lines.append("  var dragging = false, sx = 0.0, sy = 0.0;")
    lines.append("  function apply(){ vp.setAttribute('transform', 'translate(' + tx + ' ' + ty + ') scale(' + scale + ')'); }")
    lines.append("  svg.addEventListener('wheel', function(e){")
    lines.append("    e.preventDefault();")
    lines.append("    var rect = svg.getBoundingClientRect();")
    lines.append("    var mx = e.clientX - rect.left;")
    lines.append("    var my = e.clientY - rect.top;")
    lines.append("    var factor = e.deltaY < 0 ? 1.1 : 0.9;")
    lines.append("    var ns = Math.max(0.28, Math.min(4.5, scale * factor));")
    lines.append("    var wx = (mx - tx) / scale;")
    lines.append("    var wy = (my - ty) / scale;")
    lines.append("    scale = ns;")
    lines.append("    tx = mx - wx * scale;")
    lines.append("    ty = my - wy * scale;")
    lines.append("    apply();")
    lines.append("  }, { passive: false });")
    lines.append("  svg.addEventListener('mousedown', function(e){")
    lines.append("    dragging = true;")
    lines.append("    sx = e.clientX - tx;")
    lines.append("    sy = e.clientY - ty;")
    lines.append("    svg.style.cursor = 'grabbing';")
    lines.append("  });")
    lines.append("  window.addEventListener('mousemove', function(e){")
    lines.append("    if (!dragging) return;")
    lines.append("    tx = e.clientX - sx;")
    lines.append("    ty = e.clientY - sy;")
    lines.append("    apply();")
    lines.append("  });")
    lines.append("  window.addEventListener('mouseup', function(){")
    lines.append("    dragging = false;")
    lines.append("    svg.style.cursor = 'grab';")
    lines.append("  });")
    lines.append("  svg.addEventListener('dblclick', function(){ scale = 1.0; tx = 0.0; ty = 0.0; apply(); });")
    lines.append("  apply();")
    lines.append("})();")
    lines.append("]]></script>")
    lines.append("</svg>")
    out_file.write_text("\n".join(lines), encoding="utf-8")


def export_compartment_tree_image(
    *,
    db_path: str,
    out_path: str,
) -> Dict[str, Any]:
    """
    Export a compartment hierarchy image from service_info DB.
    """
    db_file = Path(db_path).expanduser()
    if not db_file.exists():
        raise FileNotFoundError(f"SQLite DB not found: {db_file}")

    conn = sqlite3.connect(str(db_file))
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    try:
        table_exists = cur.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='resource_compartments' LIMIT 1"
        ).fetchone()
        if not table_exists:
            raise RuntimeError("resource_compartments table not found in service DB.")
        pragma_rows = cur.execute('PRAGMA table_info("resource_compartments")').fetchall()
        column_names = {str(r["name"]) for r in pragma_rows if r and r["name"]}
        order_cols = [
            c for c in ("name", "display_name", "compartment_id", "id")
            if c in column_names
        ]
        if order_cols:
            order_expr = ", ".join(f'"{c}"' for c in order_cols)
            query = f'SELECT * FROM "resource_compartments" ORDER BY {order_expr}'
        else:
            query = 'SELECT * FROM "resource_compartments"'
        rows = [
            dict(r)
            for r in cur.execute(query).fetchall()
        ]
    finally:
        try:
            cur.close()
        except Exception:
            pass
        conn.close()

    layout = _build_compartment_tree_layout(rows)
    if not list(layout.get("nodes") or []):
        layout = {
            "nodes": {
                "empty": {
                    "id": "empty",
                    "name": "(no compartments found)",
                    "parent": "",
                    "x": 240.0,
                    "y": 180.0,
                    "x_idx": 0.0,
                    "depth": 0,
                    "radius": 120.0,
                    "label_lines": ["(no compartments found)"],
                }
            },
            "node_order": ["empty"],
            "edges": [],
            "width": 480,
            "height": 360,
        }

    out_file = Path(out_path).expanduser()
    out_file.parent.mkdir(parents=True, exist_ok=True)

    svg_file = out_file.with_suffix(".svg")
    _render_compartment_tree_svg(layout, svg_file)

    return {
        "ok": True,
        "format": "svg",
        "image_path": str(svg_file),
        "compartments": len(rows),
        "nodes": len(layout.get("node_order") or []),
        "edges": len(layout.get("edges") or []),
        "renderer": "svg-interactive",
    }


def export_sqlite_dbs_to_excel_blob(
    *,
    db_paths: List[str],
    out_xlsx_path: str,
    single_sheet: bool = True,
    condensed: bool = False,
) -> Dict[str, Any]:
    """
    Export multiple SQLite DBs into one Excel workbook.

    Behavior:
      - single_sheet=True: one sheet with `Database`, `resource`, and union of all columns
      - single_sheet=False: one sheet per table across all DBs
      - condensed=True: output `Table Name`, `Compartment ID`, `Compartment Name`,
        `Resource Category`, `Resource Display Name`, `Remaining JSON`
    """
    writer_errors: List[str] = []
    try:
        import pandas as _pd  # type: ignore

        pd = _pd
    except Exception as e:
        raise RuntimeError(
            "Excel export requires pandas with xlsxwriter engine installed."
        ) from e

    out_file = Path(out_xlsx_path).expanduser()
    if out_file.suffix.lower() not in {".xlsx", ".xlsm", ".xls"}:
        out_file = out_file.with_suffix(".xlsx")
    out_file.parent.mkdir(parents=True, exist_ok=True)

    refs = DataController.collect_sqlite_table_refs_by_paths(db_paths)
    db_count = len({str(r.get("db_name") or "") for r in refs})
    table_count = len(refs)

    all_columns: List[str] = []
    seen_columns = set()
    refs_by_db: Dict[str, List[Dict[str, Any]]] = {}
    for ref in refs:
        db_name = str(ref.get("db_name") or "")
        refs_by_db.setdefault(db_name, []).append(ref)
        for c in list(ref.get("columns") or []):
            if c not in seen_columns:
                seen_columns.add(c)
                all_columns.append(c)

    def _load_db_info(db_name: str, db_refs: List[Dict[str, Any]]) -> Dict[str, Any]:
        db_file = Path(str(db_refs[0].get("db_path") or ""))
        tables: List[Dict[str, Any]] = []
        rows_by_table: Dict[str, List[Dict[str, Any]]] = {}
        compartment_name_by_id: Dict[str, str] = {}
        domain_to_compartment: Dict[str, str] = {}
        iot_domain_to_compartment: Dict[str, str] = {}
        for ref in db_refs:
            table_name = str(ref.get("table_name") or "")
            cols = list(ref.get("columns") or [])
            tables.append({"name": table_name, "columns": cols})
            table_rows = DataController.fetch_sqlite_rows_by_path(str(db_file), table_name)
            rows_by_table[table_name] = table_rows

            if table_name == "resource_compartments":
                for rc_dict in table_rows:
                    cid = _resource_display_value(rc_dict.get("compartment_id") or rc_dict.get("id"))
                    cname = _resource_display_value(rc_dict.get("name") or rc_dict.get("display_name")) or cid
                    if cid:
                        compartment_name_by_id[cid] = cname

            if table_name == "identity_domains":
                for rd_dict in table_rows:
                    did = _resource_display_value(rd_dict.get("id"))
                    cid = _resource_display_value(rd_dict.get("compartment_id"))
                    if did and cid:
                        domain_to_compartment[did] = cid

            if table_name == "iot_domains":
                for ri_dict in table_rows:
                    did = _resource_display_value(ri_dict.get("id"))
                    cid = _resource_display_value(ri_dict.get("compartment_id"))
                    if did and cid:
                        iot_domain_to_compartment[did] = cid

        return {
            "name": db_name,
            "path": str(db_file),
            "tables": tables,
            "rows_by_table": rows_by_table,
            "compartment_name_by_id": compartment_name_by_id,
            "domain_to_compartment": domain_to_compartment,
            "iot_domain_to_compartment": iot_domain_to_compartment,
        }

    db_infos: List[Dict[str, Any]] = []
    for db_name, db_refs in refs_by_db.items():
        db_infos.append(_load_db_info(db_name, db_refs))

    def _iter_table_rows(db_info: Dict[str, Any]):
        rows_by_table = dict(db_info.get("rows_by_table") or {})
        for table in list(db_info.get("tables") or []):
            table_name = str(table.get("name") or "")
            for rd in list(rows_by_table.get(table_name) or []):
                yield table_name, rd

    def _build_condensed_record(db_info: Dict[str, Any], table_name: str, rd: Dict[str, Any]) -> Dict[str, Any]:
        compartment_id = _row_compartment_id(
            rd,
            domain_to_compartment=dict(db_info.get("domain_to_compartment") or {}),
            iot_domain_to_compartment=dict(db_info.get("iot_domain_to_compartment") or {}),
        )
        compartment_name = str((db_info.get("compartment_name_by_id") or {}).get(compartment_id, "") or "")
        display_name, display_key = _row_simple_resource_display_name(rd)
        return {
            "Table Name": table_name,
            "Compartment ID": compartment_id,
            "Compartment Name": compartment_name,
            "Resource Category": _simple_resource_label_from_table_name(table_name),
            "Resource Display Name": display_name,
            "Remaining JSON": _row_remaining_json(rd, display_key=display_key),
        }

    condensed_header = [
        "Table Name",
        "Compartment ID",
        "Compartment Name",
        "Resource Category",
        "Resource Display Name",
        "Remaining JSON",
    ]

    exported_rows = 0
    try:
        with pd.ExcelWriter(str(out_file), engine="xlsxwriter") as writer:
            if condensed and single_sheet:
                records: List[Dict[str, Any]] = []
                for db in db_infos:
                    for table_name, rd in _iter_table_rows(db):
                        records.append(_build_condensed_record(db, table_name, rd))
                exported_rows = len(records)
                sheet_name = "all_resources"
                pd.DataFrame(records, columns=condensed_header).to_excel(
                    writer, sheet_name=sheet_name, index=False
                )
                _apply_xlsx_condensed_layout(
                    writer=writer,
                    sheet_name=sheet_name,
                )
            elif condensed and not single_sheet:
                used_titles: set[str] = set()
                for db in db_infos:
                    for table in db["tables"]:
                        table_name = str(table["name"])
                        title = _excel_sheet_title(f'{db["name"]}_{table_name}', used_titles)
                        table_rows = list((db.get("rows_by_table") or {}).get(table_name) or [])
                        records = [_build_condensed_record(db, table_name, rd) for rd in table_rows]
                        exported_rows += len(records)
                        pd.DataFrame(records, columns=condensed_header).to_excel(
                            writer, sheet_name=title, index=False
                        )
                        _apply_xlsx_condensed_layout(
                            writer=writer,
                            sheet_name=title,
                        )
                if not used_titles:
                    sheet_name = "all_resources"
                    pd.DataFrame(columns=condensed_header).to_excel(
                        writer, sheet_name=sheet_name, index=False
                    )
                    _apply_xlsx_condensed_layout(
                        writer=writer,
                        sheet_name=sheet_name,
                    )
            elif single_sheet:
                wide_columns = ["Database", "resource"] + all_columns
                records: List[Dict[str, Any]] = []
                for db in db_infos:
                    for table_name, rd in _iter_table_rows(db):
                        row_obj: Dict[str, Any] = {"Database": db["name"], "resource": table_name}
                        for c in all_columns:
                            row_obj[c] = _excel_safe_value(rd.get(c))
                        records.append(row_obj)
                exported_rows = len(records)
                pd.DataFrame(records, columns=wide_columns).to_excel(
                    writer, sheet_name="all_tables", index=False
                )
            else:
                used_titles: set[str] = set()
                for db in db_infos:
                    for table in db["tables"]:
                        table_name = str(table["name"])
                        cols = list(table["columns"] or [])
                        title = _excel_sheet_title(f'{db["name"]}_{table_name}', used_titles)
                        table_rows = list((db.get("rows_by_table") or {}).get(table_name) or [])
                        records: List[Dict[str, Any]] = []
                        for rd in table_rows:
                            row_obj: Dict[str, Any] = {"Database": db["name"], "resource": table_name}
                            for c in cols:
                                row_obj[c] = _excel_safe_value(rd.get(c))
                            records.append(row_obj)
                        exported_rows += len(records)
                        pd.DataFrame(records, columns=["Database", "resource"] + cols).to_excel(
                            writer, sheet_name=title, index=False
                        )
                if not used_titles:
                    pd.DataFrame(columns=["Database", "resource"]).to_excel(
                        writer, sheet_name="all_tables", index=False
                    )
    except Exception as e:
        writer_errors.append(f"pandas xlsxwriter writer failed: {type(e).__name__}: {e}")
        raise RuntimeError(
            "Excel export failed. Ensure pandas and xlsxwriter are installed."
        ) from e

    return {
        "ok": True,
        "xlsx_path": str(out_file),
        "format": "xlsx",
        "databases": int(db_count),
        "tables": int(table_count),
        "rows": int(exported_rows),
        "single_sheet": bool(single_sheet),
        "condensed": bool(condensed),
        "python_executable": sys.executable,
        "writer_errors": writer_errors,
    }


def export_sqlite_dbs_to_csv_blob(
    *,
    db_paths: List[str],
    out_csv_path: str,
) -> Dict[str, Any]:
    """
    Export multiple SQLite DBs into one flat CSV file.

    CSV columns:
      - Database
      - resource (table name)
      - union of all discovered table columns
    """
    out_file = Path(out_csv_path).expanduser()
    out_file.parent.mkdir(parents=True, exist_ok=True)

    refs = DataController.collect_sqlite_table_refs_by_paths(db_paths)
    discovered: List[tuple[str, str, str]] = []
    all_columns: List[str] = []
    seen_columns = set()
    table_count = len(refs)
    db_count = len({str(r.get("db_name") or "") for r in refs})

    for ref in refs:
        db_name = str(ref.get("db_name") or "")
        db_path = str(ref.get("db_path") or "")
        table_name = str(ref.get("table_name") or "")
        columns = list(ref.get("columns") or [])
        for c in columns:
            if c not in seen_columns:
                seen_columns.add(c)
                all_columns.append(c)
        discovered.append((db_name, db_path, table_name))

    header = ["Database", "resource"] + all_columns
    exported_rows = 0
    with out_file.open("w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(header)

        for db_name, db_path, table_name in discovered:
            for rd in DataController.fetch_sqlite_rows_by_path(str(db_path), str(table_name)):
                row = [db_name, table_name] + [_excel_safe_value(rd.get(c)) for c in all_columns]
                writer.writerow(row)
                exported_rows += 1

    return {
        "ok": True,
        "csv_path": str(out_file),
        "databases": int(db_count),
        "tables": int(table_count),
        "rows": int(exported_rows),
    }


def export_sqlite_dbs_to_json_blob(
    *,
    db_paths: List[str],
    out_json_path: str,
) -> Dict[str, Any]:
    """
    Export multiple SQLite DBs into one JSON blob for easy search.

    Output shape:
      {
        "databases": {
          "<db_stem>": {
            "<table_name>": [ ...rows... ]
          }
        },
        "records": [
          {"database":"service_info","table_name":"identity_users","resource":"identity_users","row":{...}},
          ...
        ],
        "summary": {...}
      }

    jq examples (assuming file is sqlite_blob.json):
      # 1) List all table names in service_info DB
      jq -r '.databases.service_info | keys[]' sqlite_blob.json

      # 2) Dump every row from one table
      jq '.databases.service_info.identity_users[]' sqlite_blob.json

      # 3) Filter rows in a table
      jq '.databases.service_info.identity_users[] | select(.lifecycle_state=="ACTIVE")' sqlite_blob.json

      # 4) Count rows in a table
      jq '.databases.service_info.identity_users | length' sqlite_blob.json

      # 5) Flat-record search across ALL tables
      jq '.records[] | select(.table_name=="identity_users") | .row' sqlite_blob.json

      # 6) Search for any value containing a keyword (case-insensitive)
      jq --arg q "admin" '
        .records[]
        | select((.row | tostring | ascii_downcase) | contains($q))
      ' sqlite_blob.json
    """
    out_file = Path(out_json_path)
    out_file.parent.mkdir(parents=True, exist_ok=True)

    blob: Dict[str, Any] = {"databases": {}, "records": []}
    summary: Dict[str, Any] = {"databases": 0, "tables": 0, "rows": 0}

    refs = DataController.collect_sqlite_table_refs_by_paths(db_paths)
    grouped: Dict[str, List[Dict[str, Any]]] = {}
    for ref in refs:
        grouped.setdefault(str(ref.get("db_name") or ""), []).append(ref)

    summary["databases"] = len(grouped)
    for db_name, db_refs in grouped.items():
        db_tables: Dict[str, List[Dict[str, Any]]] = {}
        blob["databases"][db_name] = db_tables
        for ref in db_refs:
            table_name = str(ref.get("table_name") or "")
            db_path = str(ref.get("db_path") or "")
            out_rows: List[Dict[str, Any]] = []
            for raw in DataController.fetch_sqlite_rows_by_path(db_path, table_name):
                cleaned = {k: _maybe_parse_json_text(_excel_safe_value(v)) for k, v in raw.items()}
                cleaned["resource"] = table_name
                out_rows.append(cleaned)
                blob["records"].append(
                    {
                        "database": db_name,
                        "table_name": table_name,
                        "resource": table_name,
                        "row": cleaned,
                    }
                )
            db_tables[table_name] = out_rows
            summary["tables"] += 1
            summary["rows"] += len(out_rows)

    blob["summary"] = summary
    out_file.write_text(json.dumps(blob, ensure_ascii=False, indent=2), encoding="utf-8")

    return {
        "ok": True,
        "json_path": str(out_file),
        **summary,
    }


def _resource_display_value(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, (int, float, bool, Decimal)):
        return str(value)
    if isinstance(value, dict):
        for k in ("display_name", "displayName", "display", "name", "user_name", "value", "id", "ocid"):
            v = _resource_display_value(value.get(k))
            if v:
                return v
        try:
            return json.dumps(value, ensure_ascii=False, sort_keys=False)
        except Exception:
            return str(value)
    if isinstance(value, list):
        parts: List[str] = []
        for item in value[:3]:
            s = _resource_display_value(item)
            if s:
                parts.append(s)
        return "; ".join(parts)
    return str(value)


def _row_simple_resource_display_name(row: Dict[str, Any]) -> tuple[str, str]:
    name_keys = [
        "display_name",
        "displayName",
        "resource_name",
        "name",
        "user_name",
        "username",
        "email",
        "email_address",
        "bucket_name",
        "namespace",
        "domain",
        "path",
    ]
    for key in name_keys:
        s = _resource_display_value(row.get(key))
        if s:
            return s, key
    return "", ""


def _simple_resource_label_from_table_name(table_name: str) -> str:
    tokens = [t for t in str(table_name or "").strip().split("_") if t]
    if not tokens:
        return "Resource"

    last = tokens[-1]
    if len(last) > 3 and last.endswith("ies"):
        last = f"{last[:-3]}y"
    elif len(last) > 1 and last.endswith("s") and not last.endswith("ss"):
        last = last[:-1]
    tokens[-1] = last

    return " ".join(t.capitalize() for t in tokens)

def _row_remaining_json(
    row: Dict[str, Any],
    *,
    display_key: str = "",
) -> str:
    drop_keys = {
        "compartment_id",
        "compartment_ocid",
        "compartmentId",
        "compartmentOcid",
        "domain_ocid",
        "identity_domain_id",
        "iot_domain_id",
    }
    if display_key:
        drop_keys.add(display_key)

    remaining = {
        k: _maybe_parse_json_text(v)
        for k, v in (row or {}).items()
        if str(k) not in drop_keys
    }
    return json.dumps(remaining, ensure_ascii=False, sort_keys=True, indent=2, default=str)


def _row_compartment_id(
    row: Dict[str, Any],
    *,
    domain_to_compartment: Dict[str, str],
    iot_domain_to_compartment: Dict[str, str],
) -> str:
    direct_keys = [
        "compartment_id",
        "compartment_ocid",
        "compartmentId",
        "compartmentOcid",
    ]
    for key in direct_keys:
        cid = _resource_display_value(row.get(key))
        if cid:
            return cid

    dom_id = _resource_display_value(row.get("domain_ocid") or row.get("identity_domain_id"))
    if dom_id and dom_id in domain_to_compartment:
        return domain_to_compartment[dom_id]

    iot_dom_id = _resource_display_value(row.get("iot_domain_id"))
    if iot_dom_id and iot_dom_id in iot_domain_to_compartment:
        return iot_domain_to_compartment[iot_dom_id]

    return ""
