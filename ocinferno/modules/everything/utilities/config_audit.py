#!/usr/bin/env python3
from __future__ import annotations

# =============================================================================
# NOTICE - LLM GENERATED FOUNDATION
# =============================================================================
# This module was initially generated with assistance from a Large Language
# Model (LLM). It is actively being manually reviewed, verified, and expanded
# by maintainers. 
# =============================================================================
import textwrap
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional, Tuple

try:  # prettytable is an OPTIONAL extra
    from prettytable import PrettyTable
except ImportError:  # pragma: no cover
    PrettyTable = None
from ocinferno.core.console import _plain_table

try:
    from ocinferno.core.console import UtilityTools
except Exception:
    # Keep config_audit importable in minimal/unit-test environments where
    # optional OCI SDK dependencies are not installed.
    class UtilityTools:  # type: ignore[override]
        RESET = ""
        RED = ""
        YELLOW = ""
        BRIGHT_BLACK = ""
        BRIGHT_RED = ""
        BRIGHT_GREEN = ""
        BOLD = ""
import json

# as_json_dict is kept available as a helper for operator-authored checks (see the
# "HOW TO ADD YOUR OWN CHECK" guide below), even though the shipped example only uses _safe_str.
from ocinferno.core.coerce import _safe_str, as_json_dict  # noqa: F401

try:
    from oci_lexer_parser import parse_policy_statements
except Exception:  # pragma: no cover
    # Keep config_audit importable in minimal/unit-test environments where the
    # (ANTLR4-backed) policy lexer is not installed.
    parse_policy_statements = None


# =============================================================================
# Models
# =============================================================================

@dataclass
class ConfigFinding:
    table_name: str
    service: str

    issue_code: str
    title: str
    severity: str  # INFO | LOW | MEDIUM | HIGH | CRITICAL
    description: str

    # Explicit per-finding (no generic extractor)
    location: Dict[str, str]  # compartment_id + entity_id + optional domain_ocid

    # Offending row (trimmed)
    row: Dict[str, Any]

    # What to run next (if applicable)
    recommended_module: Optional[str] = None
    notes: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ServiceAuditResult:
    service: str
    findings: List[ConfigFinding] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class AuditReport:
    results_by_service: List[ServiceAuditResult] = field(default_factory=list)

    def total_findings(self) -> int:
        return sum(len(s.findings) for s in self.results_by_service)

    def to_dict(self) -> Dict[str, Any]:
        return {"results_by_service": [s.to_dict() for s in self.results_by_service]}


# =============================================================================
# Small helpers
# =============================================================================

def _trim_row(row: Dict[str, Any], *, max_len: int = 260) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for k, v in (row or {}).items():
        if v is None or isinstance(v, (int, float, bool)):
            out[k] = v
            continue
        s = str(v)
        if len(s) > max_len:
            s = s[: max_len - 1] + "…"
        out[k] = s
    return out


def _loc_base(
    *,
    compartment_id: str,
    entity_id: str,
    domain_ocid: Optional[str] = None,
    **extra: Any,
) -> Dict[str, Any]:
    loc = {
        "compartment_id": compartment_id,
        "entity_id": entity_id,
    }
    if domain_ocid:
        loc["domain_ocid"] = domain_ocid

    # allow arbitrary key/value additions
    loc.update({k: v for k, v in extra.items() if v is not None})
    return loc



def _short_id(s: str, *, head: int = 30, tail: int = 10) -> str:
    s = _safe_str(s)
    if not s:
        return ""
    if len(s) <= head + tail + 3:
        return s
    return s[:head] + "…" + s[-tail:]


def _wrap_paragraph(s: str, width: int = 92) -> str:
    s = (s or "").strip()
    if not s:
        return ""
    lines = [ln.strip() for ln in s.splitlines()]
    paras: List[str] = []
    buf: List[str] = []
    for ln in lines:
        if not ln:
            if buf:
                paras.append(" ".join(buf).strip())
                buf = []
            continue
        buf.append(ln)
    if buf:
        paras.append(" ".join(buf).strip())

    out_lines: List[str] = []
    for p in paras:
        out_lines.extend(textwrap.wrap(p, width=width))
        out_lines.append("")
    while out_lines and out_lines[-1] == "":
        out_lines.pop()
    return "\n".join(out_lines)


def _indent_block(s: str, indent: int = 6) -> str:
    if not s:
        return ""
    pad = " " * indent
    return "\n".join(pad + ln for ln in s.splitlines())


def _render_locations_table(locations: List[Dict[str, Any]], rows: Optional[List[Dict[str, Any]]] = None) -> str:
    """
    Render a single table containing multiple affected entities.

    Behavior:
      - Always include compartment_id and entity_id first (if present anywhere).
      - Include domain_ocid early if present anywhere.
      - Include ALL other location keys that appear across rows.
      - If rows provided, add a best-effort "name" column (display/name/etc).
      - Shorten *_id / *_ocid values via _short_id() for readability.
    """
    locations = [loc for loc in (locations or []) if isinstance(loc, dict)]
    rows = rows or []

    if not locations:
        return ""

    # Optional "name" column (best-effort)
    def _best_name(r: Dict[str, Any]) -> str:
        if not isinstance(r, dict):
            return ""
        for k in ("display_name", "name", "bucket_name", "repository_name"):
            v = r.get(k)
            if isinstance(v, str) and v.strip():
                return v.strip()
        return ""

    name_vals: List[str] = []
    have_name = False
    for r in rows:
        nm = _best_name(r)
        name_vals.append(nm)
        if nm:
            have_name = True

    # Collect all keys across all locations
    all_keys: List[str] = []
    seen = set()
    for loc in locations:
        for k in loc.keys():
            if k not in seen:
                seen.add(k)
                all_keys.append(k)

    # Column ordering:
    # - compartment_id, entity_id first (if present anywhere)
    # - domain_ocid next (if present)
    # - everything else (stable order as discovered)
    base_first = []
    for k in ("compartment_id", "entity_id"):
        if k in seen:
            base_first.append(k)

    have_dom = "domain_ocid" in seen

    # Remove base keys from the "rest"
    rest = [k for k in all_keys if k not in ("compartment_id", "entity_id", "domain_ocid")]

    fields = base_first[:]
    if have_dom:
        fields.append("domain_ocid")
    fields.extend(rest)
    if have_name:
        fields.append("name")

    table_rows: List[List[str]] = []

    def _fmt_value(k: str, v: Any) -> str:
        # Normalize None
        if v is None:
            return ""

        # Prefer short IDs for common id-ish fields
        if isinstance(v, str):
            s = v.strip()
            if not s:
                return ""
            if k.endswith("_ocid") or k.endswith("_id") or k in ("compartment_id", "entity_id", "domain_ocid"):
                return _short_id(s)
            return s

        # Keep small scalars readable
        if isinstance(v, (int, float, bool)):
            return str(v)

        # Avoid dumping giant dict/list blobs into table
        try:
            return str(v)
        except Exception:
            return "<unprintable>"

    for i, loc in enumerate(locations):
        row_out: List[str] = []
        for k in fields:
            if k == "name":
                row_out.append(name_vals[i] if i < len(name_vals) else "")
                continue
            row_out.append(_fmt_value(k, loc.get(k)))
        table_rows.append(row_out)

    if PrettyTable is None:
        return _plain_table(fields, table_rows)
    t = PrettyTable()
    t.field_names = fields
    t.align = "l"
    for r in table_rows:
        t.add_row(r)
    return str(t)



def _truthy_str(x: Any) -> bool:
    if isinstance(x, bool):
        return x
    if isinstance(x, (int, float)):
        return x != 0
    s = _safe_str(x).strip().lower()
    return s in ("1", "true", "t", "yes", "y", "on")


def _falsy_str(x: Any) -> bool:
    if isinstance(x, bool):
        return not x
    if isinstance(x, (int, float)):
        return x == 0
    s = _safe_str(x).strip().lower()
    return s in ("0", "false", "f", "no", "n", "off")


def _as_json_list(v: Any) -> List[Any]:
    if isinstance(v, list):
        return v
    if isinstance(v, str):
        s = v.strip()
        if not s:
            return []
        try:
            p = json.loads(s)
            return p if isinstance(p, list) else []
        except Exception:
            return []
    return []


def _as_int(v: Any, default: int = 0) -> int:
    try:
        if v is None or (isinstance(v, str) and not v.strip()):
            return default
        return int(v)
    except Exception:
        return default


def _is_public_cidr(v: Any) -> bool:
    s = _safe_str(v).strip().lower()
    return s in ("0.0.0.0/0", "::/0", "any", "all", "*")


def _is_protocol_any(v: Any) -> bool:
    s = _safe_str(v).strip().lower()
    return s in ("all", "any", "*", "-1")


def _is_private_ipv4(ip: str) -> bool:
    s = _safe_str(ip).strip()
    if not s:
        return False
    parts = s.split(".")
    if len(parts) != 4:
        return False
    try:
        o = [int(x) for x in parts]
    except Exception:
        return False
    if any(x < 0 or x > 255 for x in o):
        return False
    if o[0] == 10:
        return True
    if o[0] == 172 and 16 <= o[1] <= 31:
        return True
    if o[0] == 192 and o[1] == 168:
        return True
    return False


def _is_ipv4(ip: str) -> bool:
    s = _safe_str(ip).strip()
    if not s:
        return False
    parts = s.split(".")
    if len(parts) != 4:
        return False
    try:
        o = [int(x) for x in parts]
    except Exception:
        return False
    return all(0 <= x <= 255 for x in o)


def _contains_sensitive_key_name(k: str) -> bool:
    key = _safe_str(k).strip().lower()
    if not key:
        return False
    tokens = ("password", "passwd", "secret", "token", "private", "apikey", "api_key", "key")
    return any(t in key for t in tokens)


def _age_days(ts: Any) -> Optional[float]:
    """Best-effort age (in days) of an ISO-8601 timestamp string, None if unparseable."""
    s = _safe_str(ts).strip()
    if not s:
        return None

    from datetime import datetime, timezone

    candidate = s
    if candidate.endswith("Z"):
        candidate = candidate[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(candidate)
    except Exception:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    try:
        delta = datetime.now(timezone.utc) - dt
        return delta.total_seconds() / 86400.0
    except Exception:
        return None


def _condition_mentions_value(st: Dict[str, Any], needle: str) -> bool:
    """Walk a parsed policy statement's `conditions` tree (nested all/any groups of
    clauses) looking for any clause whose rhs literal/value mentions `needle`
    (case-insensitive). Used to tell "has a where clause" apart from "has a where
    clause that actually protects the thing we care about"."""
    needle = needle.strip().lower()
    if not needle:
        return False

    def _walk(node: Any) -> bool:
        if not isinstance(node, dict):
            return False
        if node.get("type") == "clause":
            inner = node.get("node") or {}
            rhs = inner.get("rhs")
            rhs_val = rhs.get("value") if isinstance(rhs, dict) else rhs
            if needle in _safe_str(rhs_val).strip().lower():
                return True
            return False
        for item in node.get("items") or []:
            if _walk(item):
                return True
        return False

    return _walk(st.get("conditions") or {})


# =============================================================================
# Service Auditors (one class per service)
# =============================================================================

class ServiceAuditor:
    service: str = "unknown"

    def __init__(self, *, session, debug: bool = False, row_trim: int = 260):
        self.session = session
        self.debug = debug
        self.row_trim = row_trim
        self._row_cache: Dict[tuple, List[Dict[str, Any]]] = {}

    def finding(
        self,
        *,
        table_name: str,
        issue_code: str,
        title: str,
        severity: str,
        description: str,
        location: Dict[str, str],
        row: Dict[str, Any],
        recommended_module: Optional[str] = None,
        notes: Optional[str] = None,
    ) -> ConfigFinding:
        return ConfigFinding(
            table_name=table_name,
            service=self.service,
            issue_code=issue_code,
            title=title,
            severity=severity,
            description=description,
            location=location,
            row=_trim_row(row, max_len=self.row_trim),
            recommended_module=recommended_module,
            notes=notes,
        )

    def get_rows(self, table_name: str, where_conditions: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        cache_key = (table_name, tuple(sorted((where_conditions or {}).items())))
        if cache_key in self._row_cache:
            return self._row_cache[cache_key]
        rows: List[Dict[str, Any]] = []
        if where_conditions:
            try:
                rows = self.session.get_resource_fields(table_name, where_conditions=where_conditions) or []
            except TypeError:
                rows = self.session.get_resource_fields(table_name) or []
        else:
            rows = self.session.get_resource_fields(table_name) or []
        self._row_cache[cache_key] = rows
        return rows

    def run_checks(self) -> ServiceAuditResult:
        raise NotImplementedError


# =============================================================================
# Configuration auditors
# =============================================================================
#
# process_config_check is intentionally MINIMAL. OCInferno's job is to *gather*
# data that could hold secrets or be misconfigured (enumerate resources and
# download their user-supplied content to disk); the OPERATOR reviews that
# content locally and decides what matters. This module is not a secret scanner.
# It ships one worked example so the audit framework stays exercised and is easy
# to extend with whatever checks a given engagement needs.
#
# HOW TO ADD YOUR OWN CHECK
# -------------------------
#   1. Subclass ServiceAuditor and set `service` to a short slug.
#   2. Implement run_checks(self) -> ServiceAuditResult:
#        * read saved rows with self.get_rows("<table_name>")  (optionally
#          where_conditions={...}); table names are in mappings/database_info.json.
#        * for each row that fails your rule, append self.finding(
#              table_name=..., issue_code=..., title=...,
#              severity="INFO|LOW|MEDIUM|HIGH|CRITICAL", description=...,
#              location=_loc_base(compartment_id=..., entity_id=...), row=row)
#   3. Register the class in DEFAULT_SERVICE_AUDITORS below.
#
# Handy framework helpers (defined above under "Small helpers"):
#   _safe_str, as_json_dict, _is_public_cidr, _is_private_ipv4,
#   _contains_sensitive_key_name, _age_days, _wrap_paragraph, _loc_base.


class ExamplePublicBucketAuditor(ServiceAuditor):
    """EXAMPLE auditor: flag Object Storage buckets that allow public access.

    Copy this shape to author your own checks: point get_rows() at the table you
    care about, test each row, and emit self.finding(...) for the ones that fail.
    """

    service = "object_storage"

    def run_checks(self) -> ServiceAuditResult:
        res = ServiceAuditResult(service=self.service)
        for row in self.get_rows("object_storage_buckets"):
            access = _safe_str(row.get("public_access_type")).strip()
            # "NoPublicAccess" is the locked-down default; anything else is public.
            if access and access != "NoPublicAccess":
                res.findings.append(self.finding(
                    table_name="object_storage_buckets",
                    issue_code="OBJECT_STORAGE_PUBLIC_BUCKET",
                    title="Bucket allows public (unauthenticated) access",
                    severity="HIGH",
                    description=_wrap_paragraph(
                        "public_access_type is '" + access + "'. Objects may be "
                        "readable without authentication. Confirm this is intended; "
                        "otherwise set the bucket to NoPublicAccess."
                    ),
                    location=_loc_base(
                        compartment_id=_safe_str(row.get("compartment_id")),
                        entity_id=_safe_str(row.get("id") or row.get("name")),
                    ),
                    row=row,
                    recommended_module="modules run enum_objectstorage --buckets --get",
                ))
        return res


DEFAULT_SERVICE_AUDITORS: List[type[ServiceAuditor]] = [
    ExamplePublicBucketAuditor,
]


def run_audit(*, session, debug: bool = False, include_services: Optional[List[str]] = None) -> AuditReport:
    include = {s.strip() for s in (include_services or []) if s and s.strip()}
    report = AuditReport(results_by_service=[])

    for cls in DEFAULT_SERVICE_AUDITORS:
        if include and cls.service not in include:
            continue
        auditor = cls(session=session, debug=debug)
        report.results_by_service.append(auditor.run_checks())

    return report


def _sev_color(sev: str) -> str:
    sev = (sev or "").upper().strip()
    return {
        "CRITICAL": UtilityTools.BRIGHT_RED,
        "HIGH": UtilityTools.RED,
        "MEDIUM": UtilityTools.YELLOW,
        "LOW": UtilityTools.BRIGHT_BLACK,
        "INFO": UtilityTools.BRIGHT_BLACK,
    }.get(sev, UtilityTools.BRIGHT_BLACK)


def _group_findings(findings: List[ConfigFinding]) -> Dict[Tuple[str, str, str, str, str, str, str], List[ConfigFinding]]:
    """
    Group findings so print output shows ONE finding per issue, with many affected entities.
    Key includes fields that define the "same issue" bucket.
    """
    groups: Dict[Tuple[str, str, str, str, str, str, str], List[ConfigFinding]] = {}
    for f in findings or []:
        key = (
            _safe_str(f.issue_code),
            _safe_str(f.title),
            _safe_str(f.severity),
            _safe_str(f.table_name),
            _safe_str(f.recommended_module),
            _safe_str(f.description),
            _safe_str(f.notes),
        )
        groups.setdefault(key, []).append(f)
    return groups


def print_audit_report(report: AuditReport, *, max_findings_per_service: int = 50) -> None:
    total = report.total_findings()
    print(f"{UtilityTools.BOLD}{UtilityTools.BRIGHT_GREEN}[*] Config audit findings: {total}{UtilityTools.RESET}")

    for svc in report.results_by_service:
        if not svc.findings and not svc.errors:
            continue

        print(f"{UtilityTools.BOLD}{svc.service}{UtilityTools.RESET}")

        if svc.errors:
            for e in svc.errors:
                print(f"  {UtilityTools.RED}[X]{UtilityTools.RESET} {e}")

        # GROUP HERE
        grouped = _group_findings(svc.findings)
        group_items = list(grouped.items())

        # Keep stable-ish order: severity then issue_code
        def _sev_rank(s: str) -> int:
            s = (s or "").upper().strip()
            return {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}.get(s, 9)

        group_items.sort(key=lambda kv: (_sev_rank(kv[0][2]), kv[0][0]))

        # Limit by number of grouped issues, not raw rows
        shown = group_items[:max_findings_per_service]
        for key, findings in shown:
            issue_code, title, severity, table_name, recommended_module, description, notes = key
            sev = (severity or "").upper().strip()
            sev_color = _sev_color(sev)

            # Header line (ONE per issue)
            count = len(findings)
            plural = "s" if count != 1 else ""
            print(f"  {sev_color}{sev}{UtilityTools.RESET} {issue_code}: {UtilityTools.BOLD}{title}{UtilityTools.RESET} ({count} affected item{plural})")

            desc = _wrap_paragraph(description, width=92)
            if desc:
                print(_indent_block(desc, indent=6))

            # Locations table (multi-row)
            locs = [f.location for f in findings if isinstance(f.location, dict)]
            rows = [f.row for f in findings if isinstance(f.row, dict)]
            if locs:
                loc_table = _render_locations_table(locs, rows=rows)
                print(_indent_block(loc_table, indent=6))

            if recommended_module:
                print(f"      {UtilityTools.BRIGHT_GREEN}next:{UtilityTools.RESET} {recommended_module}")

            notes_wrapped = _wrap_paragraph(notes or "", width=92)
            if notes_wrapped:
                print(_indent_block(notes_wrapped, indent=6))

            print()

        if len(group_items) > max_findings_per_service:
            print(f"  {UtilityTools.BRIGHT_BLACK}... ({len(group_items) - max_findings_per_service} more){UtilityTools.RESET}")
