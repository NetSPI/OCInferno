#!/usr/bin/env python3
from __future__ import annotations

# =============================================================================
# NOTICE - LLM GENERATED FOUNDATION
# =============================================================================
# This module was initially generated with assistance from a Large Language
# Model (LLM). It is actively being manually reviewed, verified, and expanded
# by maintainers. 
# =============================================================================

import argparse
import textwrap
from dataclasses import dataclass, asdict, field
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

from ocinferno.core.coerce import _safe_str, as_json_dict

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
        rows: List[Dict[str, Any]] = []
        if where_conditions:
            try:
                rows = self.session.get_resource_fields(table_name, where_conditions=where_conditions) or []
            except TypeError:
                rows = self.session.get_resource_fields(table_name) or []
        else:
            rows = self.session.get_resource_fields(table_name) or []
        return rows

    def run_checks(self) -> ServiceAuditResult:
        raise NotImplementedError


# -----------------------------------------------------------------------------
# Vault service auditor
# -----------------------------------------------------------------------------

class VaultServiceAuditor(ServiceAuditor):
    service = "vault"

    T_VAULTS = "vault_vaults"
    T_KEYS = "vault_keys"
    T_SECRETS = "vault_secret"
    T_BUNDLES = "vault_secret_bundle"

    def run_checks(self) -> ServiceAuditResult:
        res = ServiceAuditResult(service=self.service)
        try:
            self._check_vaults_not_virtual_private(res)
        except Exception as e:
            res.errors.append(f"vaults: {type(e).__name__}: {e}")

        try:
            self._check_keys_software_protection(res)
        except Exception as e:
            res.errors.append(f"keys: {type(e).__name__}: {e}")

        return res

    def _check_vaults_not_virtual_private(self, res: ServiceAuditResult) -> None:
        rows = self.get_rows(self.T_VAULTS, where_conditions={"lifecycle_state": "ACTIVE"})
        for r in rows:
            cid = _safe_str(r.get("compartment_id")) or _safe_str(r.get("compartment_ocid"))
            vid = _safe_str(r.get("id"))
            if not cid or not vid:
                continue

            vault_type = _safe_str(r.get("vault_type")).upper()
            if vault_type == "DEFAULT":
                loc = _loc_base(compartment_id=cid, entity_id=vid)
                res.findings.append(
                    self.finding(
                        table_name=self.T_VAULTS,
                        issue_code="VAULT_KMS_VIRTUAL_PRIVATE_VAULT",
                        title="Vault is not a Virtual Private Vault",
                        severity="MEDIUM",
                        description=_wrap_paragraph(
                            """
                            Vault is using the DEFAULT vault type rather than a Virtual Private Vault (VPV).
                            VPVs provide a dedicated HSM partition with stronger isolation and are generally
                            preferred for high‑sensitivity key material and compliance‑driven environments.
                            """
                        ),
                        location=loc,
                        row=r,
                        recommended_module="modules run enum_vault --vaults",
                        notes=_wrap_paragraph(
                            """
                            Remediation: create a Virtual Private Vault and migrate keys/secrets that require
                            stronger isolation. This is often a posture/compliance control rather than an
                            immediate exploit path.
                            """
                        ),
                    )
                )

    def _check_keys_software_protection(self, res: ServiceAuditResult) -> None:
        rows = self.get_rows(self.T_KEYS, where_conditions={"lifecycle_state": "ACTIVE"})
        for r in rows:
            cid = _safe_str(r.get("compartment_id")) or _safe_str(r.get("compartment_ocid"))
            kid = _safe_str(r.get("id"))
            if not cid or not kid:
                continue

            protection = _safe_str(r.get("protection_mode")).upper()
            if protection == "SOFTWARE":
                loc = _loc_base(compartment_id=cid, entity_id=kid)
                res.findings.append(
                    self.finding(
                        table_name=self.T_KEYS,
                        issue_code="VAULT_KMS_SOFTWARE_KEY",
                        title="Key protection mode is SOFTWARE",
                        severity="LOW",
                        description=_wrap_paragraph(
                            """
                            Key protection mode is SOFTWARE instead of HSM. SOFTWARE keys are cheaper but provide
                            weaker protections for key material compared to HSM‑backed keys.
                            """
                        ),
                        location=loc,
                        row=r,
                        recommended_module="modules run enum_vault --keys --key-id <key_ocid>",
                        notes=_wrap_paragraph(
                            """
                            Remediation: use HSM protection for sensitive keys. Evaluate alongside IAM controls
                            on key usage (encrypt/decrypt/generateDataKey). This is a posture signal.

                            """
                        ),
                    )
                )


# -----------------------------------------------------------------------------
# Object Storage service auditor
# -----------------------------------------------------------------------------

class ObjectStorageServiceAuditor(ServiceAuditor):
    service = "object_storage"

    T_OS_NAMESPACES = "object_storage_namespaces"
    T_OS_BUCKETS = "object_storage_buckets"
    T_OS_OBJECTS = "object_storage_bucket_objects"
    T_LOG_LOGS = "logging_logs"
    T_OS_PARS = "object_storage_preauthenticated_requests"

    def run_checks(self) -> ServiceAuditResult:
        res = ServiceAuditResult(service=self.service)
        try:
            self._check_buckets_public_access(res)
        except Exception as e:
            res.errors.append(f"public_access: {type(e).__name__}: {e}")
        try:
            self._check_buckets_versioning(res)
        except Exception as e:
            res.errors.append(f"versioning: {type(e).__name__}: {e}")
        try:
            self._check_buckets_logging(res)
        except Exception as e:
            res.errors.append(f"logging: {type(e).__name__}: {e}")
        try:
            self._check_buckets_cmk_encryption(res)
        except Exception as e:
            res.errors.append(f"cmk_encryption: {type(e).__name__}: {e}")
        try:
            self._check_preauthenticated_requests(res)
        except Exception as e:
            res.errors.append(f"preauthenticated_requests: {type(e).__name__}: {e}")
        return res

    def _check_buckets_public_access(self, res: ServiceAuditResult) -> None:
        rows = self.get_rows(self.T_OS_BUCKETS)
        for r in rows:
            cid = _safe_str(r.get("compartment_id")) or _safe_str(r.get("compartment_ocid"))
            bucket_id = _safe_str(r.get("id"))
            public_access_type = _safe_str(r.get("public_access_type"))
            loc = _loc_base(compartment_id=cid, entity_id=bucket_id)

            if public_access_type == "ObjectRead":
                res.findings.append(
                    self.finding(
                        table_name=self.T_OS_BUCKETS,  # FIXED (was T_VAULTS)
                        issue_code="OBJECT_STORAGE_BUCKET_PUBLIC_DOWNLOAD_AND_LIST",
                        title="The bucket allows anonymous downloads",
                        severity="CRITICAL",
                        description=_wrap_paragraph(
                            """
                            Bucket allows anonymous list + download access (ObjectRead). This can expose all object
                            names and contents to the internet if the namespace is known.
                            """
                        ),
                        location=loc,
                        row=r,
                        recommended_module="modules run enum_objectstorage --buckets --get --namespaces <namespace>",
                        notes=_wrap_paragraph(
                            """
                            Remediation: set Public Access Type to “NoPublicAccess” unless explicitly required.
                            Use GetBucket to verify settings and review access logs for potential exposure.

                            """
                        ),
                    )
                )
 
            elif public_access_type == "ObjectReadWithoutList":
                res.findings.append(
                    self.finding(
                        table_name=self.T_OS_BUCKETS,  # FIXED (was T_VAULTS)
                        issue_code="OBJECT_STORAGE_BUCKET_PUBLIC_DOWNLOAD",
                        title="The bucket allows anonymous downloads",
                        severity="HIGH",
                        description=_wrap_paragraph(
                            """
                            Bucket allows anonymous downloads (ObjectReadWithoutList). Object contents can be
                            retrieved if names are guessed or leaked.
                            """
                        ),
                        location=loc,
                        row=r,
                        recommended_module="modules run enum_objectstorage --buckets --get --namespaces <namespace>",
                        notes=_wrap_paragraph(
                            """
                            Remediation: set Public Access Type to “NoPublicAccess” unless explicitly required.
                            Review logs for potential downloads of sensitive objects.

                            """
                        ),
                    )
                )

    def _check_buckets_versioning(self, res: ServiceAuditResult) -> None:
        rows = self.get_rows(self.T_OS_BUCKETS)
        for r in rows:
            cid = _safe_str(r.get("compartment_id"))
            bucket_id = _safe_str(r.get("id"))
            versioning = _safe_str(r.get("versioning"))
            if versioning == "Disabled":
                loc = _loc_base(compartment_id=cid, entity_id=bucket_id)
                res.findings.append(
                    self.finding(
                        table_name=self.T_OS_BUCKETS,
                        issue_code="OBJECT_STORAGE_BUCKET_VERSIONING_DISABLED",
                        title="The bucket lacks versioning",
                        severity="MEDIUM",
                        description=_wrap_paragraph(
                            """
                            Bucket versioning is disabled. Without versioning, accidental deletes/overwrites or
                            ransomware‑style changes are harder to recover.
                            """
                        ),
                        location=loc,
                        row=r,
                        recommended_module="modules run enum_objectstorage --buckets --get --namespaces <namespace>",
                        notes=_wrap_paragraph(
                            """
                            Remediation: enable versioning for buckets that store important or regulated data.
                            The relevant bucket field is only viewable if one has permissions to GetBucket.
                            ListBucket does not contain the info needed.

                            """
                        ),
                    )
                )

    def _check_buckets_logging(self, res: ServiceAuditResult) -> None:

        row_logs = self.get_rows(self.T_LOG_LOGS)
        row_buckets = self.get_rows(self.T_OS_BUCKETS)

        for row_bucket in row_buckets:
            cid = _safe_str(row_bucket.get("compartment_id"))
            bucket_id = _safe_str(row_bucket.get("id"))

            write_log, read_log = False, False

            bucket_name = row_bucket.get("name")

            for log in row_logs:

                cfg = as_json_dict(log.get("configuration"))
                src = as_json_dict(cfg.get("source"))
                if not src:
                    continue

                # Only object-storage service logs carry a bucket name in
                # source.resource; skip logs for other services.
                log_service = _safe_str(src.get("service")).strip().lower()
                if log_service and log_service != "objectstorage":
                    continue

                log_bucket_name = src.get("resource")
                log_source_category = _safe_str(src.get("category")).strip().lower()

                if log_bucket_name == bucket_name:
                    if log_source_category == "write":
                        write_log = True
                    elif log_source_category == "read":
                        read_log = True
                
            if not write_log:
                loc = _loc_base(compartment_id=cid, entity_id=bucket_id)
                res.findings.append(
                    self.finding(
                        table_name=self.T_OS_BUCKETS,
                        issue_code="OBJECT_STORAGE_NO_WRITE_LOG",
                        title="The bucket lacks a write level audit log for the bucket",
                        severity="LOW",
                        description=_wrap_paragraph(
                            """
                            No write‑level audit logs are configured for the bucket. This reduces visibility into
                            object creation, overwrite, and delete actions.
                            """
                        ),
                        location=loc,
                        row=row_bucket,
                        recommended_module="modules run enum_objectstorage --buckets --get --namespaces <namespace>",
                        notes=_wrap_paragraph(
                            "Remediation: enable write logs to detect create/update/delete activity. "
                        ),
                    )
                )
            if not read_log:
                loc = _loc_base(compartment_id=cid, entity_id=bucket_id)
                res.findings.append(
                    self.finding(
                        table_name=self.T_OS_BUCKETS,
                        issue_code="OBJECT_STORAGE_NO_READ_LOG",
                        title="The bucket lacks a read level audit log for the bucket",
                        severity="LOW",
                        description=_wrap_paragraph(
                            """
                            No read‑level audit logs are configured for the bucket. This limits ability to detect
                            data exfiltration or suspicious access.
                            """
                        ),
                        location=loc,
                        row=row_bucket,
                        recommended_module="modules run enum_objectstorage --buckets --get --namespaces <namespace>",
                        notes=_wrap_paragraph(
                            "Remediation: enable read logs to detect access and potential exfiltration. "
                        ),
                    )
                )


    def _check_buckets_cmk_encryption(self, res: ServiceAuditResult) -> None:
        rows = self.get_rows(self.T_OS_BUCKETS)
        for r in rows:
            cid = _safe_str(r.get("compartment_id"))
            bucket_id = _safe_str(r.get("id"))
            kms_key = _safe_str(r.get("kms_key_id"))
            get_run = r.get("get_run")

            if (not kms_key) and bool(get_run):
                loc = _loc_base(compartment_id=cid, entity_id=bucket_id)
                res.findings.append(
                    self.finding(
                        table_name=self.T_OS_BUCKETS,
                        issue_code="OBJECT_STORAGE_BUCKET_CMK_NOT_SET_UP",
                        title="The bucket lacks CMK.",
                        severity="MEDIUM",
                        description=_wrap_paragraph(
                            """
                            Customer‑managed keys (CMK) are not configured. CMK adds an extra authorization layer:
                            principals must hold KMS decrypt permissions to read objects.
                            """
                        ),
                        location=loc,
                        row=r,
                        recommended_module="modules run enum_objectstorage --buckets --get --namespaces <namespace>",
                        notes=_wrap_paragraph(
                            """
                            Remediation: enable KMS encryption on sensitive buckets and restrict key usage.
                            GetBucket is required to see CMK settings.

                            """
                        ),
                    )
                )

    def _check_preauthenticated_requests(self, res: ServiceAuditResult) -> None:
        # object_storage_preauthenticated_requests has no compartment_id -- join to
        # object_storage_buckets by (namespace, bucket name) to resolve it.
        bucket_cid_by_key: Dict[Tuple[str, str], str] = {}
        for b in self.get_rows(self.T_OS_BUCKETS):
            ns = _safe_str(b.get("namespace"))
            name = _safe_str(b.get("name"))
            if ns and name:
                bucket_cid_by_key[(ns, name)] = _safe_str(b.get("compartment_id"))

        for r in self.get_rows(self.T_OS_PARS):
            ns = _safe_str(r.get("namespace"))
            bucket_name = _safe_str(r.get("bucket_name"))
            par_id = _safe_str(r.get("id"))
            if not ns or not bucket_name or not par_id:
                continue

            access_type = _safe_str(r.get("access_type"))
            if access_type not in ("AnyObjectWrite", "AnyObjectReadWrite", "AnyObjectRead"):
                continue

            cid = bucket_cid_by_key.get((ns, bucket_name), "")
            loc = _loc_base(
                compartment_id=cid,
                entity_id=par_id,
                namespace=ns or None,
                bucket_name=bucket_name or None,
            )

            if access_type in ("AnyObjectWrite", "AnyObjectReadWrite"):
                res.findings.append(
                    self.finding(
                        table_name=self.T_OS_PARS,
                        issue_code="OBJECT_STORAGE_PAR_ANY_OBJECT_WRITE",
                        title="Pre-Authenticated Request grants unauthenticated bucket-wide write access",
                        severity="CRITICAL",
                        description=_wrap_paragraph(
                            f"""
                            This Pre-Authenticated Request (PAR) has access_type={access_type}, a bucket-wide
                            (not single-object) grant. Anyone holding the PAR's secret URL can write/overwrite
                            ANY object in bucket "{bucket_name}" with zero OCI authentication -- no IAM
                            credentials, no policy evaluation, nothing but knowledge of the URL.
                            """
                        ),
                        location=loc,
                        row=r,
                        recommended_module="modules run enum_objectstorage --pars --namespaces <namespace>",
                        notes=_wrap_paragraph(
                            """
                            Remediation: delete this PAR if it isn't actively required; if it is, scope it to a
                            single object_name instead of a bucket-wide Any* access type, and set the shortest
                            viable time_expires.
                            """
                        ),
                    )
                )
                continue

            res.findings.append(
                self.finding(
                    table_name=self.T_OS_PARS,
                    issue_code="OBJECT_STORAGE_PAR_ANY_OBJECT_READ",
                    title="Pre-Authenticated Request grants unauthenticated bucket-wide read access",
                    severity="HIGH",
                    description=_wrap_paragraph(
                        f"""
                        This Pre-Authenticated Request (PAR) has access_type=AnyObjectRead, a bucket-wide (not
                        single-object) grant. Anyone holding the PAR's secret URL can list and read EVERY object
                        in bucket "{bucket_name}" with zero OCI authentication.
                        """
                    ),
                    location=loc,
                    row=r,
                    recommended_module="modules run enum_objectstorage --pars --namespaces <namespace>",
                    notes=_wrap_paragraph(
                        """
                        Remediation: delete this PAR if it isn't actively required; if it is, scope it to a
                        single object_name instead of a bucket-wide Any* access type, and set the shortest
                        viable time_expires.
                        """
                    ),
                )
            )


class ComputeServiceAuditor(ServiceAuditor):
    service = "compute"

    TABLE_INSTANCES = "compute_instances"
    _TERMINAL_INSTANCE_STATES = {"TERMINATED", "TERMINATING"}

    def run_checks(self) -> ServiceAuditResult:
        res = ServiceAuditResult(service=self.service)
        try:
            self._check_shielded_instances(res)
        except Exception as e:
            res.errors.append(f"shielded_instances: {type(e).__name__}: {e}")
        try:
            self._check_confidential_computing(res)
        except Exception as e:
            res.errors.append(f"confidential_computing: {type(e).__name__}: {e}")
        try:
            self._check_imds_service(res)
        except Exception as e:
            res.errors.append(f"imds_service: {type(e).__name__}: {e}")
        try:
            self._check_in_transit_encryption(res)
        except Exception as e:
            res.errors.append(f"in_transit_encryption: {type(e).__name__}: {e}")
        return res

    def _check_shielded_instances(self, res: ServiceAuditResult) -> None:
        rows = self.get_rows(self.TABLE_INSTANCES)
        for r in rows:
            if _safe_str(r.get("lifecycle_state")).upper() in self._TERMINAL_INSTANCE_STATES:
                continue
            
            cid = _safe_str(r.get("compartment_id"))
            instance_id = _safe_str(r.get("id"))

            platform_config = as_json_dict(r.get("platform_config"))
            if not platform_config:
                continue

            measured_boot = platform_config.get("is_measured_boot_enabled")
            secure_boot = platform_config.get("is_secure_boot_enabled")
            tpm_module = platform_config.get("is_trusted_platform_module_enabled")

            if (secure_boot) or (measured_boot and tpm_module) or (measured_boot and secure_boot and tpm_module):
                continue
            else:
                loc = _loc_base(compartment_id=cid, entity_id=instance_id)
                res.findings.append(
                    self.finding(
                        table_name=self.TABLE_INSTANCES,
                        issue_code="COMPUTE_SHIELDED_INSTANCES",
                        title="The compute instance does not have shielded instances enabled per one of the possible combinations",
                        severity="INFO",
                        description=_wrap_paragraph(
                            """
                            Shielded instance protections are not enabled (secure boot and/or measured boot + TPM).
                            This weakens protections against boot‑level tampering.
                            """
                        ),
                        location=loc,
                        row=r,
                        recommended_module="modules run enum_core_compute --instances --get",
                        notes=_wrap_paragraph(
                            "Remediation: enable shielded instance settings where supported. "
                        ),
                    )
                )


    def _check_confidential_computing(self, res: ServiceAuditResult) -> None:
        
        rows = self.get_rows(self.TABLE_INSTANCES)
        for r in rows:
            if _safe_str(r.get("lifecycle_state")).upper() in self._TERMINAL_INSTANCE_STATES:
                continue
            
            cid = _safe_str(r.get("compartment_id"))
            instance_id = _safe_str(r.get("id"))

            platform_config = as_json_dict(r.get("platform_config"))
            if not platform_config:
                continue

            confiential_computing = platform_config.get("is_memory_encryption_enabled")

            if not confiential_computing:
                loc = _loc_base(compartment_id=cid, entity_id=instance_id)
                res.findings.append(
                    self.finding(
                        table_name=self.TABLE_INSTANCES,
                        issue_code="COMPUTE_CONFIDENTIAL_COMPUTING",
                        title="The compute instance is not using confidential computing",
                        severity="INFO",
                        description=_wrap_paragraph(
                            """
                            Confidential computing (memory encryption) is disabled. This reduces isolation of
                            running workloads from host‑level inspection.
                            """
                        ),
                        location=loc,
                        row=r,
                        recommended_module="modules run enum_core_compute --instances --get",
                        notes=_wrap_paragraph(
                            "Remediation: enable memory encryption on supported shapes. "
                        ),
                    )
                )

    def _check_imds_service(self, res: ServiceAuditResult) -> None:
        rows = self.get_rows(self.TABLE_INSTANCES)
        for r in rows:
            if _safe_str(r.get("lifecycle_state")).upper() in self._TERMINAL_INSTANCE_STATES:
                continue
            
            cid = _safe_str(r.get("compartment_id"))
            instance_id = _safe_str(r.get("id"))
            instance_options = as_json_dict(r.get("instance_options"))
            if not instance_options:
                continue

            imds_legacy_enabled = not instance_options.get("are_legacy_imds_endpoints_disabled")

            if imds_legacy_enabled:
                loc = _loc_base(compartment_id=cid, entity_id=instance_id)
                res.findings.append(
                    self.finding(
                        table_name=self.TABLE_INSTANCES,
                        issue_code="COMPUTE_IMDS_V1",
                        title="The compute instance has legacy IMDS enabled (aka IMDSv1)",
                        severity="LOW",
                        description=_wrap_paragraph(
                            """
                            Legacy IMDS (v1) endpoints are enabled. IMDSv1 is more susceptible to SSRF‑style
                            credential theft compared to IMDSv2.
                            """
                        ),
                        location=loc,
                        row=r,
                        recommended_module="modules run enum_core_compute --instances --get",
                        notes=_wrap_paragraph(
                            "Remediation: disable legacy IMDS endpoints (use IMDSv2 only). "
                        ),
                    )
                )

    def _check_in_transit_encryption(self, res: ServiceAuditResult) -> None:
        
        rows = self.get_rows(self.TABLE_INSTANCES)
        for r in rows:
            if _safe_str(r.get("lifecycle_state")).upper() in self._TERMINAL_INSTANCE_STATES:
                continue
            
            cid = _safe_str(r.get("compartment_id"))
            instance_id = _safe_str(r.get("id"))
            launch_options = as_json_dict(r.get("launch_options"))
            if not launch_options:
                continue

            is_pv_encryption_in_transit_enabled = launch_options.get("is_pv_encryption_in_transit_enabled")

            if not is_pv_encryption_in_transit_enabled:
                loc = _loc_base(compartment_id=cid, entity_id=instance_id)
                res.findings.append(
                    self.finding(
                        table_name=self.TABLE_INSTANCES,
                        issue_code="COMPUTE_IN_TRANSIT_ENCRYPTION",
                        title="The compute instance does nto use in-transit encryption",
                        severity="LOW",
                        description=_wrap_paragraph(
                            """
                            In‑transit encryption between instance and boot volume is disabled. This can expose
                            data in transit within the host network path.
                            """
                        ),
                        location=loc,
                        row=r,
                        recommended_module="modules run enum_core_compute --instances --get",
                        notes=_wrap_paragraph(
                            "Remediation: enable in-transit encryption for supported shapes and images. "
                        ),
                    )
                )





# -----------------------------------------------------------------------------
# Kubernetes service auditor
# -----------------------------------------------------------------------------

class KubernetesServiceAuditor(ServiceAuditor):
    service = "kubernetes"

    TABLE_CLUSTERS = "containerengine_clusters"
    TABLE_NODE_POOLS = "containerengine_node_pools"
    TABLE_VIRTUAL_NODE_POOLS = "containerengine_virtual_node_pools"
    TABLE_VIRTUAL_NODES = "containerengine_virtual_nodes"

    def run_checks(self) -> ServiceAuditResult:
        res = ServiceAuditResult(service=self.service)
        try:
            self._check_manage_api_public_endpoint(res)
        except Exception as e:
            res.errors.append(f"{type(e).__name__}: {e}")
        return res

    def _check_manage_api_public_endpoint(self, res: ServiceAuditResult) -> None:
        rows = self.get_rows(self.TABLE_CLUSTERS, where_conditions={"lifecycle_state": "ACTIVE"})
        for r in rows:
            cid = _safe_str(r.get("compartment_id"))
            cluster_id = _safe_str(r.get("id"))
            if not cid or not cluster_id:
                continue

            ep_cfg = as_json_dict(r.get("endpoint_config"))
            eps = as_json_dict(r.get("endpoints"))

            is_pub = ep_cfg.get("is_public_ip_enabled")
            pub_ep = eps.get("public_endpoint")

            if bool(is_pub) and _safe_str(pub_ep):
                loc = _loc_base(compartment_id=cid, entity_id=cluster_id)
                res.findings.append(
                    self.finding(
                        table_name=self.TABLE_CLUSTERS,
                        issue_code="KUBERNETES_ENGINE_PUBLIC_ENDPOINT",
                        title="The cluster has a public endpoint for the management plane",
                        severity="MEDIUM",
                        description=_wrap_paragraph(
                            """
                            The Kubernetes control plane has a public endpoint. This increases exposure of the
                            management plane to the internet.
                            """
                        ),
                        location=loc,
                        row=r,
                        recommended_module="modules run enum_kubernetes --clusters",
                        notes=_wrap_paragraph(
                            "Remediation: restrict the endpoint to private IPs or use allow‑listed CIDRs. "
                        ),
                    )
                )


# -----------------------------------------------------------------------------
# Container Registry service auditor
# -----------------------------------------------------------------------------

class ContainerRegistryServiceAuditor(ServiceAuditor):
    service = "container_registry"

    T_REPOSITORIES = "cr_repositories"
    T_IMAGES = "cr_images"

    def run_checks(self) -> ServiceAuditResult:
        res = ServiceAuditResult(service=self.service)
        try:
            self._check_public_repository(res)
        except Exception as e:
            res.errors.append(f"{type(e).__name__}: {e}")
        try:
            self._check_repository_immutability(res)
        except Exception as e:
            res.errors.append(f"{type(e).__name__}: {e}")
        return res

    def _check_public_repository(self, res: ServiceAuditResult) -> None:
        rows = self.get_rows(self.T_REPOSITORIES, where_conditions={"lifecycle_state": "AVAILABLE"})
        for r in rows:
            cid = _safe_str(r.get("compartment_id"))
            rid = _safe_str(r.get("id"))
            if not cid or not rid:
                continue

            # FIX: don't treat "false" as truthy
            is_public = _truthy_str(r.get("is_public"))
            if is_public:
                loc = _loc_base(compartment_id=cid, entity_id=rid)
                res.findings.append(
                    self.finding(
                        table_name=self.T_REPOSITORIES,
                        issue_code="PUBLIC_REPOSITORY",
                        title="The Container Registry repository is marked as 'public'",
                        severity="HIGH",
                        description=_wrap_paragraph(
                            "The repository is public. Images and metadata may be accessible without authentication."
                        ),
                        location=loc,
                        row=r,
                        recommended_module="modules run enum_containerregistry --repositories --get",
                        notes=_wrap_paragraph(
                            "Remediation: set repository visibility to private unless public access is required. "
                        ),
                    )
                )

    def _check_repository_immutability(self, res: ServiceAuditResult) -> None:
        rows = self.get_rows(self.T_REPOSITORIES, where_conditions={"lifecycle_state": "AVAILABLE"})
        for r in rows:
            cid = _safe_str(r.get("compartment_id"))
            rid = _safe_str(r.get("id"))
            if not cid or not rid:
                continue

            is_immutable = _truthy_str(r.get("is_immutable"))
            if is_immutable:
                continue

            loc = _loc_base(compartment_id=cid, entity_id=rid)
            res.findings.append(
                self.finding(
                    table_name=self.T_REPOSITORIES,
                    issue_code="CONTAINER_REGISTRY_REPO_MUTABLE",
                    title="Container Registry repository is mutable",
                    severity="MEDIUM",
                    description=_wrap_paragraph(
                        """
                        Repository is mutable (tags can be overwritten). This can enable supply‑chain confusion,
                        rollback attacks, or untracked image changes.
                        """
                    ),
                    location=loc,
                    row=r,
                    recommended_module="modules run enum_containerregistry --repositories --get",
                    notes=_wrap_paragraph(
                        "Remediation: enable immutability for sensitive repositories. "
                    ),
                )
            )

# DNS
class DNSServiceAuditor(ServiceAuditor):
    service = "dns"

    T_ZONES = "dns_zones"
    T_ZONE_RECORDS = "dns_zone_records"

    _DEAD_ZONE_STATES = {"DELETED", "DELETING", "FAILED"}

    def run_checks(self) -> ServiceAuditResult:
        res = ServiceAuditResult(service=self.service)
        try:

            self._check_zone_dnssec(res)
        except Exception as e:
            res.errors.append(f"{type(e).__name__}: {e}")
        return res

    def _check_zone_dnssec(self, res: ServiceAuditResult) -> None:
        rows = self.get_rows(self.T_ZONES, where_conditions = {"scope": "GLOBAL"})
        for r in rows:
            if _safe_str(r.get("lifecycle_state")).upper() in self._DEAD_ZONE_STATES:
                continue
            # SECONDARY zones mirror an external primary via zone transfer -- DNSSEC
            # signing is owned by that primary, and OCI does not support independently
            # enabling DNSSEC on a SECONDARY zone. Flagging one here would be a false
            # positive: there is no action the tenant can take on this zone to "fix" it.
            if _safe_str(r.get("zone_type")).upper() == "SECONDARY":
                continue
            cid = _safe_str(r.get("compartment_id")) or _safe_str(r.get("compartment_ocid"))
            rid = _safe_str(r.get("id"))
            if not cid or not rid:
                continue
            dnssec_state = _safe_str(r.get("dnssec_state"))
            if dnssec_state != "ENABLED":
                loc = _loc_base(compartment_id=cid, entity_id=rid)
                res.findings.append(
                    self.finding(
                        table_name=self.T_ZONES,
                        issue_code="DNS_DNSSEC_DISABLED",
                        title="Public DNS zone does not have DNSSEC enabled",
                        severity="MEDIUM",
                        description=_wrap_paragraph(
                            "DNSSEC is not enabled for this public zone, which can allow DNS spoofing/poisoning."
                        ),
                        location=loc,
                        row=r,
                        recommended_module="modules run enum_dns --zones",
                        notes=_wrap_paragraph(
                            "Remediation: enable DNSSEC for public zones where supported. "
                        ),
                    )
                )

# -----------------------------------------------------------------------------
# Network Firewall service auditor
# -----------------------------------------------------------------------------

class NetworkFirewallServiceAuditor(ServiceAuditor):
    service = "network_firewall"

    T_RULES = "network_firewall_security_rules"
    T_FIREWALLS = "network_firewall_firewalls"

    # Lifecycle states where a NetworkFirewall instance is not (or no longer) enforcing
    # traffic -- a policy referenced only by firewalls in these states is not live.
    _DEAD_FIREWALL_STATES = {"DELETED", "DELETING", "FAILED"}

    @staticmethod
    def _as_str_list(v: Any) -> List[str]:
        if isinstance(v, list):
            return [str(x).strip().lower() for x in v if str(x).strip()]
        if isinstance(v, str) and v.strip():
            return [v.strip().lower()]
        return []

    def _attached_policy_ids(self) -> set:
        """Policy IDs referenced by at least one non-dead NetworkFirewall instance.

        A Network Firewall Policy is a standalone rules container in OCI -- it only
        enforces traffic once a separate `NetworkFirewall` resource is deployed into a
        subnet referencing it (`network_firewall_policy_id`). A policy with risky rules
        but no live firewall attached poses no current traffic-path risk (mirrors
        GovernanceRulesServiceAuditor's rule/attachment split).
        """
        ids = set()
        for fw in self.get_rows(self.T_FIREWALLS):
            state = _safe_str(fw.get("lifecycle_state")).upper()
            if state in self._DEAD_FIREWALL_STATES:
                continue
            pid = _safe_str(fw.get("network_firewall_policy_id"))
            if pid:
                ids.add(pid)
        return ids

    def run_checks(self) -> ServiceAuditResult:
        res = ServiceAuditResult(service=self.service)
        try:
            self._check_allow_without_conditions(res)
            self._check_inspect_missing_mode(res)
            self._check_allow_any_any(res)
        except Exception as e:
            res.errors.append(f"{type(e).__name__}: {e}")
        return res

    def _rule_loc(self, r: Dict[str, Any]) -> Dict[str, Any]:
        cid = _safe_str(r.get("compartment_id")) or "unknown"
        pid = _safe_str(r.get("network_firewall_policy_id")) or _safe_str(r.get("parent_resource_id"))
        name = _safe_str(r.get("name"))
        entity = f"{pid}:{name}" if pid and name else (name or pid or "unknown")
        return _loc_base(
            compartment_id=cid,
            entity_id=entity,
            policy_id=(pid or None),
            rule_name=(name or None),
        )

    def _check_allow_without_conditions(self, res: ServiceAuditResult) -> None:
        rows = self.get_rows(self.T_RULES)
        attached = self._attached_policy_ids()
        for r in rows:
            action = _safe_str(r.get("action")).upper()
            if action != "ALLOW":
                continue

            cond = as_json_dict(r.get("condition"))
            src = self._as_str_list(cond.get("source_address"))
            dst = self._as_str_list(cond.get("destination_address"))
            app = self._as_str_list(cond.get("application"))
            svc = self._as_str_list(cond.get("service"))
            url = self._as_str_list(cond.get("url"))

            if src or dst or app or svc or url:
                continue

            pid = _safe_str(r.get("network_firewall_policy_id"))
            is_live = bool(pid) and pid in attached

            res.findings.append(
                self.finding(
                    table_name=self.T_RULES,
                    issue_code="NETWORK_FIREWALL_ALLOW_WITHOUT_MATCH_CRITERIA",
                    title="Allow rule has no match criteria" if is_live
                    else "Allow rule has no match criteria (policy not currently attached to a firewall)",
                    severity="CRITICAL" if is_live else "LOW",
                    description=_wrap_paragraph(
                        """
                        ALLOW rule has no match criteria (no src/dst/app/service/url). This can behave as an
                        overly broad allow in policy evaluation.
                        """
                        if is_live else
                        """
                        ALLOW rule has no match criteria (no src/dst/app/service/url), but this policy is not
                        currently referenced by any active NetworkFirewall instance (`network_firewall_firewalls`),
                        so it is not enforcing traffic today. This is configuration debt, not a live exposure --
                        it becomes CRITICAL the moment the policy is attached to a firewall.
                        """
                    ),
                    location=self._rule_loc(r),
                    row=r,
                    recommended_module="modules run enum_networkfirewall --firewalls --get",
                    notes=_wrap_paragraph(
                        "Remediation: add explicit source/destination/service/application/url conditions. "
                        if is_live else
                        "Remediation: add explicit source/destination/service/application/url conditions before "
                        "this policy is ever attached to a firewall, or delete the policy if it is unused. "
                    ),
                )
            )

    def _check_inspect_missing_mode(self, res: ServiceAuditResult) -> None:
        rows = self.get_rows(self.T_RULES)
        for r in rows:
            action = _safe_str(r.get("action")).upper()
            if action != "INSPECT":
                continue

            inspection = _safe_str(r.get("inspection")).upper()
            if inspection in ("INTRUSION_DETECTION", "INTRUSION_PREVENTION"):
                continue

            res.findings.append(
                self.finding(
                    table_name=self.T_RULES,
                    issue_code="NETWORK_FIREWALL_INSPECT_WITHOUT_MODE",
                    title="Inspect rule has no valid inspection mode",
                    severity="MEDIUM",
                    description=_wrap_paragraph(
                        """
                        INSPECT rule has no valid inspection mode. This can weaken intended IDS/IPS behavior.
                        """
                    ),
                    location=self._rule_loc(r),
                    row=r,
                    recommended_module="modules run enum_networkfirewall --firewalls --get",
                    notes=_wrap_paragraph(
                        "Remediation: set inspection to INTRUSION_DETECTION or INTRUSION_PREVENTION. "
                    ),
                )
            )

    def _check_allow_any_any(self, res: ServiceAuditResult) -> None:
        rows = self.get_rows(self.T_RULES)
        attached = self._attached_policy_ids()
        any_tokens = {"any", "all", "*"}
        for r in rows:
            action = _safe_str(r.get("action")).upper()
            if action != "ALLOW":
                continue

            cond = as_json_dict(r.get("condition"))
            src = set(self._as_str_list(cond.get("source_address")))
            dst = set(self._as_str_list(cond.get("destination_address")))
            svc = set(self._as_str_list(cond.get("service")))

            if not src or not dst:
                continue
            if src.isdisjoint(any_tokens) or dst.isdisjoint(any_tokens):
                continue
            if svc and svc.isdisjoint(any_tokens):
                continue

            pid = _safe_str(r.get("network_firewall_policy_id"))
            is_live = bool(pid) and pid in attached

            res.findings.append(
                self.finding(
                    table_name=self.T_RULES,
                    issue_code="NETWORK_FIREWALL_ALLOW_ANY_ANY",
                    title="Allow rule appears to permit any-to-any traffic" if is_live
                    else "Allow rule appears to permit any-to-any traffic (policy not currently attached to a firewall)",
                    severity="CRITICAL" if is_live else "LOW",
                    description=_wrap_paragraph(
                        """
                        Rule appears to allow ANY‑to‑ANY traffic. Broad allow rules can bypass segmentation
                        controls and increase blast radius.
                        """
                        if is_live else
                        """
                        Rule appears to allow ANY‑to‑ANY traffic, but this policy is not currently referenced by
                        any active NetworkFirewall instance (`network_firewall_firewalls`), so it is not
                        enforcing traffic today. This is configuration debt, not a live exposure -- it becomes
                        CRITICAL the moment the policy is attached to a firewall.
                        """
                    ),
                    location=self._rule_loc(r),
                    row=r,
                    recommended_module="modules run enum_networkfirewall --firewalls --get",
                    notes=_wrap_paragraph(
                        "Remediation: narrow to explicit address/service objects and limit to required flows. "
                        if is_live else
                        "Remediation: narrow to explicit address/service objects before this policy is ever "
                        "attached to a firewall, or delete the policy if it is unused. "
                    ),
                )
            )

# -----------------------------------------------------------------------------
# Identity Domains service auditor
# -----------------------------------------------------------------------------

class IdentityDomainsServiceAuditor(ServiceAuditor):
    service = "identity_domains"

    T_USERS = "identity_domain_users"
    T_GROUPS = "identity_domain_groups"
    T_MEMBERSHIPS = "identity_user_group_memberships"

    T_MFA = "identity_domain_authentication_factor_settings"
    T_PW = "identity_domain_password_policies"
    T_API_KEYS = "identity_domain_user_api_keys"

    def run_checks(self) -> ServiceAuditResult:
        res = ServiceAuditResult(service=self.service)
        try:
            self._check_mfa_disabled_or_unknown(res)
        except Exception as e:
            res.errors.append(f"mfa_settings: {type(e).__name__}: {e}")
        try:
            self._check_users_not_in_group(res)
        except Exception as e:
            res.errors.append(f"users_not_in_group: {type(e).__name__}: {e}")
        try:
            self._check_api_key_assignment(res)
        except Exception as e:
            res.errors.append(f"api_key_assignment: {type(e).__name__}: {e}")
        try:
            self._check_pw_policy(res)
        except Exception as e:
            res.errors.append(f"password_policy: {type(e).__name__}: {e}")
        return res

    def _check_mfa_disabled_or_unknown(self, res: ServiceAuditResult) -> None:
        rows = self.get_rows(self.T_MFA)
        for r in rows:
            cid = _safe_str(r.get("compartment_ocid")) or _safe_str(r.get("compartment_id"))
            dom = _safe_str(r.get("domain_ocid"))
            rid = _safe_str(r.get("id"))
            if not cid or not dom or not rid:
                continue

            mfa_cat = _safe_str(r.get("mfa_enabled_category")).strip().lower()
            if not mfa_cat or mfa_cat in ("none", "disabled", "off"):
                loc = _loc_base(compartment_id=cid, entity_id=rid, domain_ocid=dom)
                res.findings.append(
                    self.finding(
                        table_name=self.T_MFA,
                        issue_code="IDD_MFA_DISABLED_OR_UNKNOWN",
                        title="MFA appears disabled or unspecified",
                        severity="MEDIUM",
                        description=_wrap_paragraph(f"MFA appears disabled or unspecified (mfa_enabled_category={mfa_cat!r})."),
                        location=loc,
                        row=r,
                        recommended_module="modules run enum_identity --domains --idd-mfa-settings",
                        notes=_wrap_paragraph(
                            "Remediation: enable MFA for the domain and enforce strong MFA policies. "
                        ),
                    )
                )

    def _check_users_not_in_group(self, res: ServiceAuditResult) -> None:
        rows = self.get_rows(self.T_USERS) 
        
        for r in rows:
            cid = _safe_str(r.get("compartment_ocid")) or _safe_str(r.get("compartment_id"))
            dom = _safe_str(r.get("domain_ocid"))
            rid = _safe_str(r.get("id"))
            if not cid or not dom or not rid:
                continue
            groups = _as_json_list(r.get("groups"))
            if groups:
                continue

            loc = _loc_base(compartment_id=cid, entity_id=rid, domain_ocid=dom)
            res.findings.append(
                self.finding(
                    table_name=self.T_USERS,
                    issue_code="IDD_USER_NOT_IN_GROUP",
                    title="User is not in any group (potentially weaker governance)",
                    severity="LOW",
                    description=_wrap_paragraph(
                        "User appears to have no group memberships. Centralized group governance may be bypassed."
                    ),
                    location=loc,
                    row=r,
                    recommended_module="modules run enum_identity --domains",
                    notes=_wrap_paragraph(
                        "Remediation: assign users to least‑privilege groups and enforce consistent policies. "
                    ),
                )
            )

    def _check_api_key_assignment(self, res: ServiceAuditResult) -> None:
        rows = self.get_rows(self.T_API_KEYS)
        user_keys: Dict[str, List[Dict[str, Any]]] = {}

        for r in rows:
            user_obj = as_json_dict(r.get("user"))
            user_ocid = _safe_str(user_obj.get("ocid"))
            if not user_ocid:
                continue
            user_keys.setdefault(user_ocid, []).append(r)

        for _, key_rows in user_keys.items():
            if len(key_rows) <= 1:
                continue

            for key_specifics in key_rows:
                cid = _safe_str(key_specifics.get("compartment_ocid")) or _safe_str(key_specifics.get("compartment_id"))
                dom = _safe_str(key_specifics.get("domain_ocid"))
                rid = _safe_str(key_specifics.get("id"))
                if not cid or not dom or not rid:
                    continue

                user_key = as_json_dict(key_specifics.get("user"))
                user_name = _safe_str(user_key.get("name"))
                user_id = _safe_str(user_key.get("id"))

                loc = _loc_base(
                    compartment_id=cid,
                    entity_id=rid,
                    domain_ocid=dom,
                    user_display_name=user_name or None,
                    user_id=user_id or None,
                )
                res.findings.append(
                    self.finding(
                        table_name=self.T_API_KEYS,
                        issue_code="IDD_USER_WITH_MULTIPLE_API_KEYS",
                        title="Identity Domain user has multiple API keys",
                        severity="LOW",
                        description=_wrap_paragraph(
                            "User has more than one recorded API key, increasing key-sprawl risk."
                        ),
                        location=loc,
                        row=key_specifics,
                        recommended_module="modules run enum_identity --domains",
                        notes=_wrap_paragraph(
                            "Remediation: review key sprawl; rotate/revoke unused keys and enforce key hygiene. "
                        ),
                    )
                )

    def _check_pw_policy(self, res: ServiceAuditResult) -> None:
        # Baseline standards for a practical warning threshold
        policy_min_len = 14
        policy_expire_days = 60
        policy_previous_passwords_tracked = 10
        policy_account_lockout_threshold = 4

        rows = self.get_rows(self.T_PW)
        # Policies with a priority are typically the active/evaluated policies
        rows = [row for row in rows if row.get("priority") is not None]

        for r in rows:
            cid = _safe_str(r.get("compartment_ocid"))
            dom = _safe_str(r.get("domain_ocid"))
            rid = _safe_str(r.get("id"))
            if not cid or not dom or not rid:
                continue

            name = _safe_str(r.get("name")) or rid
            min_len = _as_int(r.get("min_length"), 0)
            expire_days = _as_int(r.get("password_expires_after"), 10**9)
            pw_hist = _as_int(r.get("num_passwords_in_history"), 0)
            lockout = _as_int(r.get("max_incorrect_attempts"), 10**9)

            weak_points: List[str] = []
            if min_len < policy_min_len:
                weak_points.append(f"min_length={min_len} (<{policy_min_len})")
            if expire_days > policy_expire_days:
                weak_points.append(f"password_expires_after={expire_days} (>{policy_expire_days})")
            if pw_hist < policy_previous_passwords_tracked:
                weak_points.append(
                    f"num_passwords_in_history={pw_hist} (<{policy_previous_passwords_tracked})"
                )
            if lockout > policy_account_lockout_threshold:
                weak_points.append(
                    f"max_incorrect_attempts={lockout} (>{policy_account_lockout_threshold})"
                )

            if _as_int(r.get("min_lower_case"), 0) <= 0:
                weak_points.append("min_lower_case not enforced")
            if _as_int(r.get("min_numerals"), 0) <= 0:
                weak_points.append("min_numerals not enforced")
            if _as_int(r.get("min_special_chars"), 0) <= 0:
                weak_points.append("min_special_chars not enforced")
            if _as_int(r.get("min_upper_case"), 0) <= 0:
                weak_points.append("min_upper_case not enforced")

            if not weak_points:
                continue

            loc = _loc_base(compartment_id=cid, entity_id=rid, domain_ocid=dom)
            res.findings.append(
                self.finding(
                    table_name=self.T_PW,
                    issue_code="IDD_PW_WEAK_POLICY",
                    title="Identity Domain password policy is weak",
                    severity="MEDIUM",
                    description=_wrap_paragraph(
                        f"Password policy '{name}' has weak settings: " + "; ".join(weak_points)
                    ),
                    location=loc,
                    row=r,
                    recommended_module="modules run enum_identity --domains",
                    notes=_wrap_paragraph(
                        "Remediation: increase min length, enforce complexity, reduce expiry window, "
                        "increase password history, and tighten lockout thresholds. "
                    ),
                )
            )



class ApiGatewayServiceAuditor(ServiceAuditor):
    service = "api_gateway"

    T_GATEWAYS = "apigw_gateways"
    T_DEPLOYMENTS = "apigw_deployments"

    # Lifecycle states where a gateway/deployment is not (or no longer) live -- shared
    # SDK enum across both resource types.
    _DEAD_STATES = {"DELETED", "DELETING", "FAILED"}

    def _public_gateway_ids(self) -> set:
        ids = set()
        for gw in self.get_rows(self.T_GATEWAYS):
            if _safe_str(gw.get("lifecycle_state")).upper() in self._DEAD_STATES:
                continue
            if "PUBLIC" not in _safe_str(gw.get("endpoint_type")).upper():
                continue
            gid = _safe_str(gw.get("id"))
            if gid:
                ids.add(gid)
        return ids

    def run_checks(self) -> ServiceAuditResult:
        res = ServiceAuditResult(service=self.service)
        try:
            self._check_public_gateways(res)
        except Exception as e:
            res.errors.append(f"gateways: {type(e).__name__}: {e}")
        try:
            self._check_deployment_authentication(res)
        except Exception as e:
            res.errors.append(f"deployment_authentication: {type(e).__name__}: {e}")
        return res

    def _check_public_gateways(self, res: ServiceAuditResult) -> None:
        rows = self.get_rows(self.T_GATEWAYS)
        for r in rows:
            cid = _safe_str(r.get("compartment_id"))
            gid = _safe_str(r.get("id"))
            if not cid or not gid:
                continue
            endpoint_type = _safe_str(r.get("endpoint_type")).upper()
            if "PUBLIC" not in endpoint_type:
                continue

            loc = _loc_base(compartment_id=cid, entity_id=gid)
            res.findings.append(
                self.finding(
                    table_name=self.T_GATEWAYS,
                    issue_code="APIGW_PUBLIC_ENDPOINT",
                    title="API Gateway endpoint is public",
                    severity="MEDIUM",
                    description=_wrap_paragraph(
                        """
                        API Gateway is configured with a public endpoint. Public endpoints can increase
                        external attack surface for exposed APIs if authentication and policy controls are weak.
                        """
                    ),
                    location=loc,
                    row=r,
                    recommended_module="modules run enum_apigateway --gateways --get",
                    notes=_wrap_paragraph(
                        "Remediation: prefer private endpoints where feasible, and enforce strong auth/policies "
                        "for publicly exposed APIs."
                    ),
                )
            )

            nsg_ids = _as_json_list(r.get("network_security_group_ids"))
            if not nsg_ids:
                res.findings.append(
                    self.finding(
                        table_name=self.T_GATEWAYS,
                        issue_code="APIGW_PUBLIC_NO_NSG",
                        title="Public API Gateway has no NSG restrictions",
                        severity="HIGH",
                        description=_wrap_paragraph(
                            """
                            Public API Gateway does not appear to have NSGs configured. This reduces
                            network-layer filtering options.
                            """
                        ),
                        location=loc,
                        row=r,
                        recommended_module="modules run enum_apigateway --gateways --get",
                        notes=_wrap_paragraph(
                            "Remediation: attach restrictive NSGs and limit ingress paths."
                        ),
                    )
                )

    def _check_deployment_authentication(self, res: ServiceAuditResult) -> None:
        public_gateways = self._public_gateway_ids()
        rows = self.get_rows(self.T_DEPLOYMENTS)
        for r in rows:
            if _safe_str(r.get("lifecycle_state")).upper() in self._DEAD_STATES:
                continue
            cid = _safe_str(r.get("compartment_id"))
            did = _safe_str(r.get("id"))
            gid = _safe_str(r.get("gateway_id"))
            if not cid or not did:
                continue
            if gid not in public_gateways:
                continue

            # specification is only populated on a full get_deployment response --
            # list_deployments summaries omit it. Gate here to avoid false positives
            # from summary-only enumeration (matches the WAF actions[]/WAAS
            # policy_config --get gates).
            spec = as_json_dict(r.get("specification"))
            if not spec:
                continue

            request_policies = as_json_dict(spec.get("request_policies"))
            authentication = as_json_dict(request_policies.get("authentication"))
            path_prefix = _safe_str(r.get("path_prefix"))

            if not authentication:
                loc = _loc_base(compartment_id=cid, entity_id=did, gateway_id=gid, path_prefix=path_prefix or None)
                res.findings.append(
                    self.finding(
                        table_name=self.T_DEPLOYMENTS,
                        issue_code="APIGW_DEPLOYMENT_NO_AUTHENTICATION",
                        title="API Gateway deployment on a public gateway has no authentication configured",
                        severity="CRITICAL",
                        description=_wrap_paragraph(
                            """
                            This deployment's specification has no request_policies.authentication policy at
                            all (no JWT/Token/Custom/Dynamic authenticator), and it is routed through a gateway
                            with a PUBLIC endpoint. Every route under this deployment's path prefix accepts
                            unauthenticated requests directly from the internet -- there is no credential check
                            anywhere in the request path.
                            """
                        ),
                        location=loc,
                        row=r,
                        recommended_module="modules run enum_apigateway --deployments --get",
                        notes=_wrap_paragraph(
                            """
                            Remediation: add a request_policies.authentication policy (JWT, token, or custom
                            authorizer function) to the deployment, or move it behind a private gateway if public
                            access was never intended.
                            """
                        ),
                    )
                )
                # The whole deployment is already unauthenticated -- per-route
                # ANONYMOUS-override findings below would be pure noise here.
                continue

            for route in _as_json_list(spec.get("routes")):
                if not isinstance(route, dict):
                    continue
                route_policies = as_json_dict(route.get("request_policies"))
                authorization = as_json_dict(route_policies.get("authorization"))
                if _safe_str(authorization.get("type")).upper() != "ANONYMOUS":
                    continue

                route_path = _safe_str(route.get("path"))
                methods = _as_json_list(route.get("methods"))
                full_path = f"{path_prefix}{route_path}" if path_prefix else route_path
                loc = _loc_base(compartment_id=cid, entity_id=did, gateway_id=gid, route_path=full_path or None)
                res.findings.append(
                    self.finding(
                        table_name=self.T_DEPLOYMENTS,
                        issue_code="APIGW_ROUTE_ANONYMOUS_AUTHORIZATION",
                        title="API Gateway route explicitly allows anonymous access on a public gateway",
                        severity="HIGH",
                        description=_wrap_paragraph(
                            f"""
                            Route "{full_path or route_path}" ({', '.join(_safe_str(m) for m in methods) or 'any method'})
                            sets request_policies.authorization.type=ANONYMOUS, which overrides the deployment's
                            authenticator and lets this specific route bypass authentication entirely, on a
                            gateway with a PUBLIC endpoint.
                            """
                        ),
                        location=loc,
                        row=r,
                        recommended_module="modules run enum_apigateway --deployments --get",
                        notes=_wrap_paragraph(
                            """
                            Remediation: confirm this route is genuinely intended to be public (e.g. a health
                            check); otherwise remove the ANONYMOUS authorization override so the deployment's
                            authenticator applies.
                            """
                        ),
                    )
                )


class BastionServiceAuditor(ServiceAuditor):
    service = "bastion"

    T_BASTIONS = "bastion_bastions"

    def run_checks(self) -> ServiceAuditResult:
        res = ServiceAuditResult(service=self.service)
        try:
            self._check_cidr_allow_list(res)
        except Exception as e:
            res.errors.append(f"cidr_allow_list: {type(e).__name__}: {e}")
        return res

    def _check_cidr_allow_list(self, res: ServiceAuditResult) -> None:
        rows = self.get_rows(self.T_BASTIONS, where_conditions={"lifecycle_state": "ACTIVE"})
        for r in rows:
            cid = _safe_str(r.get("compartment_id"))
            bid = _safe_str(r.get("id"))
            if not cid or not bid:
                continue
            allow_list = _as_json_list(r.get("cidr_block_allow_list"))
            if not allow_list:
                continue
            if any(_is_public_cidr(x) for x in allow_list):
                loc = _loc_base(compartment_id=cid, entity_id=bid)
                res.findings.append(
                    self.finding(
                        table_name=self.T_BASTIONS,
                        issue_code="BASTION_ALLOWLIST_ANY",
                        title="Bastion CIDR allow list includes any-address CIDR",
                        severity="HIGH",
                        description=_wrap_paragraph(
                            """
                            Bastion allow list includes 0.0.0.0/0 (or equivalent). This exposes bastion
                            sessions to the internet.
                            """
                        ),
                        location=loc,
                        row=r,
                        recommended_module="modules run enum_core_network --bastion --get",
                        notes=_wrap_paragraph(
                            "Remediation: restrict bastion CIDRs to approved administrative source ranges."
                        ),
                    )
                )

class BlockStorageServiceAuditor(ServiceAuditor):
    service = "block_storage"

    T_VOLUMES = "blockstorage_volumes"
    T_BOOT_VOLUMES = "blockstorage_boot_volumes"

    def run_checks(self) -> ServiceAuditResult:
        res = ServiceAuditResult(service=self.service)
        try:
            self._check_volume_cmk(res)
        except Exception as e:
            res.errors.append(f"volumes: {type(e).__name__}: {e}")
        try:
            self._check_boot_volume_cmk(res)
        except Exception as e:
            res.errors.append(f"boot_volumes: {type(e).__name__}: {e}")
        return res

    def _check_volume_cmk(self, res: ServiceAuditResult) -> None:
        rows = self.get_rows(self.T_VOLUMES)
        for r in rows:
            cid = _safe_str(r.get("compartment_id"))
            vid = _safe_str(r.get("id"))
            if not cid or not vid:
                continue
            if _safe_str(r.get("lifecycle_state")).upper() not in ("AVAILABLE", "IN_USE", "PROVISIONING", "ACTIVE"):
                continue
            if _safe_str(r.get("kms_key_id")):
                continue
            loc = _loc_base(compartment_id=cid, entity_id=vid)
            res.findings.append(
                self.finding(
                    table_name=self.T_VOLUMES,
                    issue_code="BLOCK_VOLUME_NO_CMK",
                    title="Block volume has no customer-managed key",
                    severity="LOW",
                    description=_wrap_paragraph(
                        """
                        Volume is not tied to a customer-managed KMS key. Default provider-managed encryption
                        may be sufficient for many workloads, but CMK is often required for stricter controls.
                        """
                    ),
                    location=loc,
                    row=r,
                    recommended_module="modules run enum_core_block_storage --volumes --get",
                    notes=_wrap_paragraph(
                        "Remediation: use CMK-backed encryption for high-sensitivity workloads."
                    ),
                )
            )

    def _check_boot_volume_cmk(self, res: ServiceAuditResult) -> None:
        rows = self.get_rows(self.T_BOOT_VOLUMES)
        for r in rows:
            cid = _safe_str(r.get("compartment_id"))
            vid = _safe_str(r.get("id"))
            if not cid or not vid:
                continue
            if _safe_str(r.get("lifecycle_state")).upper() not in ("AVAILABLE", "IN_USE", "PROVISIONING", "ACTIVE"):
                continue
            if _safe_str(r.get("kms_key_id")):
                continue
            loc = _loc_base(compartment_id=cid, entity_id=vid)
            res.findings.append(
                self.finding(
                    table_name=self.T_BOOT_VOLUMES,
                    issue_code="BOOT_VOLUME_NO_CMK",
                    title="Boot volume has no customer-managed key",
                    severity="LOW",
                    description=_wrap_paragraph(
                        "Boot volume is not configured with a customer-managed KMS key."
                    ),
                    location=loc,
                    row=r,
                    recommended_module="modules run enum_core_block_storage --boot-volumes --get",
                    notes=_wrap_paragraph(
                        "Remediation: evaluate CMK usage for boot volumes that host sensitive workloads."
                    ),
                )
            )


class NetworkingServiceAuditor(ServiceAuditor):
    service = "networking"

    T_SECURITY_LISTS = "virtual_network_security_lists"
    T_ROUTE_TABLES = "virtual_network_route_tables"
    T_SUBNETS = "virtual_network_subnets"

    # Lifecycle states where a subnet/security-list/route-table is not (or no longer)
    # part of a live VCN -- shared across all three tables (identical SDK enum).
    _TERMINAL_VCN_STATES = {"TERMINATED", "TERMINATING"}

    def _security_list_subnet_map(self) -> dict:
        """Map security list ID -> list of attached subnet IDs, read from the
        denormalized attached_subnet_ids column written by enum_core_network.

        Falls back to building the map from the subnets table directly so the
        audit still works if the backfill hasn't run yet (e.g. subnets were
        enumerated before the column was added).
        """
        sl_rows = self.get_rows(self.T_SECURITY_LISTS)
        mapping: dict = {}
        any_populated = False
        for sl in sl_rows:
            sl_id = _safe_str(sl.get("id"))
            attached = _as_json_list(sl.get("attached_subnet_ids"))
            if attached:
                any_populated = True
            mapping[sl_id] = [_safe_str(s) for s in attached if s]

        if any_populated:
            return mapping

        # Fallback: derive from subnets table cross-compartment
        for sn in self.get_rows(self.T_SUBNETS):
            if _safe_str(sn.get("lifecycle_state")).upper() in self._TERMINAL_VCN_STATES:
                continue
            sn_id = _safe_str(sn.get("id"))
            for sid in _as_json_list(sn.get("security_list_ids")):
                sid = _safe_str(sid)
                if sid:
                    mapping.setdefault(sid, [])
                    if sn_id not in mapping[sid]:
                        mapping[sid].append(sn_id)
        return mapping

    def _attached_route_table_ids(self) -> set:
        """Route table IDs referenced by at least one non-terminal subnet."""
        ids = set()
        for sn in self.get_rows(self.T_SUBNETS):
            if _safe_str(sn.get("lifecycle_state")).upper() in self._TERMINAL_VCN_STATES:
                continue
            rid = _safe_str(sn.get("route_table_id"))
            if rid:
                ids.add(rid)
        return ids

    def run_checks(self) -> ServiceAuditResult:
        res = ServiceAuditResult(service=self.service)
        try:
            self._check_security_lists(res)
        except Exception as e:
            res.errors.append(f"security_lists: {type(e).__name__}: {e}")
        try:
            self._check_route_tables(res)
        except Exception as e:
            res.errors.append(f"route_tables: {type(e).__name__}: {e}")
        try:
            self._check_subnets(res)
        except Exception as e:
            res.errors.append(f"subnets: {type(e).__name__}: {e}")
        return res

    def _check_security_lists(self, res: ServiceAuditResult) -> None:
        rows = self.get_rows(self.T_SECURITY_LISTS)
        sl_subnet_map = self._security_list_subnet_map()
        not_attached_suffix = _wrap_paragraph(
            """
            This security list is not currently referenced by any live subnet's
            `security_list_ids`, so it is not filtering traffic today. This is
            configuration debt, not a live exposure -- it becomes an active risk the
            moment the list is attached to a subnet.
            """
        )
        for r in rows:
            cid = _safe_str(r.get("compartment_id"))
            sid = _safe_str(r.get("id"))
            if not cid or not sid:
                continue
            if _safe_str(r.get("lifecycle_state")).upper() in self._TERMINAL_VCN_STATES:
                continue

            attached_subnets = sl_subnet_map.get(sid, [])
            is_live = bool(attached_subnets)

            ingress = _as_json_list(r.get("ingress_security_rules"))
            egress = _as_json_list(r.get("egress_security_rules"))
            loc = _loc_base(compartment_id=cid, entity_id=sid, vcn_id=_safe_str(r.get("vcn_id")) or None)
            subnet_note = (
                _wrap_paragraph(f"Attached subnets: {', '.join(attached_subnets)}") if attached_subnets else ""
            )

            for rule in ingress:
                if not isinstance(rule, dict):
                    continue
                source = rule.get("source")
                if not _is_public_cidr(source):
                    continue
                proto = rule.get("protocol")
                tcp_opts = as_json_dict(rule.get("tcp_options"))
                dst_port = as_json_dict(tcp_opts.get("destination_port_range"))
                port_min = _as_int(dst_port.get("min"), default=-1)
                port_max = _as_int(dst_port.get("max"), default=-1)

                if _is_protocol_any(proto):
                    res.findings.append(
                        self.finding(
                            table_name=self.T_SECURITY_LISTS,
                            issue_code="VCN_SECURITY_LIST_INGRESS_ANY_ANY",
                            title="Security list ingress allows any protocol from internet" if is_live
                            else "Security list ingress allows any protocol from internet (not attached to a subnet)",
                            severity="HIGH" if is_live else "LOW",
                            description=_wrap_paragraph(
                                "Ingress rule allows 0.0.0.0/0 (or equivalent) with any protocol."
                            ) + ("" if is_live else not_attached_suffix),
                            location=loc,
                            row=r,
                            recommended_module="modules run enum_core_network --security-lists --get",
                            notes=_wrap_paragraph("Remediation: restrict source CIDRs and allowed protocols/ports.")
                            + subnet_note,
                        )
                    )
                    continue

                if _safe_str(proto) in ("6", "TCP", "tcp"):
                    if port_min == 22 and port_max == 22:
                        res.findings.append(
                            self.finding(
                                table_name=self.T_SECURITY_LISTS,
                                issue_code="VCN_SECURITY_LIST_SSH_OPEN_TO_INTERNET",
                                title="Security list exposes SSH (22) to internet" if is_live
                                else "Security list exposes SSH (22) to internet (not attached to a subnet)",
                                severity="HIGH" if is_live else "LOW",
                                description=_wrap_paragraph(
                                    "Ingress rule exposes SSH from any-address CIDR."
                                ) + ("" if is_live else not_attached_suffix),
                                location=loc,
                                row=r,
                                recommended_module="modules run enum_core_network --security-lists --get",
                                notes=_wrap_paragraph("Remediation: restrict SSH ingress to approved admin CIDRs.")
                                + subnet_note,
                            )
                        )
                    if port_min == 3389 and port_max == 3389:
                        res.findings.append(
                            self.finding(
                                table_name=self.T_SECURITY_LISTS,
                                issue_code="VCN_SECURITY_LIST_RDP_OPEN_TO_INTERNET",
                                title="Security list exposes RDP (3389) to internet" if is_live
                                else "Security list exposes RDP (3389) to internet (not attached to a subnet)",
                                severity="HIGH" if is_live else "LOW",
                                description=_wrap_paragraph(
                                    "Ingress rule exposes RDP from any-address CIDR."
                                ) + ("" if is_live else not_attached_suffix),
                                location=loc,
                                row=r,
                                recommended_module="modules run enum_core_network --security-lists --get",
                                notes=_wrap_paragraph("Remediation: restrict RDP ingress to approved admin CIDRs.")
                                + subnet_note,
                            )
                        )

            for rule in egress:
                if not isinstance(rule, dict):
                    continue
                dest = rule.get("destination")
                if not _is_public_cidr(dest):
                    continue
                if _is_protocol_any(rule.get("protocol")):
                    res.findings.append(
                        self.finding(
                            table_name=self.T_SECURITY_LISTS,
                            issue_code="VCN_SECURITY_LIST_EGRESS_ANY_ANY",
                            title="Security list egress allows any protocol to internet" if is_live
                            else "Security list egress allows any protocol to internet (not attached to a subnet)",
                            severity="LOW",
                            description=_wrap_paragraph(
                                "Egress rule allows any protocol to 0.0.0.0/0 (or equivalent)."
                            ) + ("" if is_live else not_attached_suffix),
                            location=loc,
                            row=r,
                            recommended_module="modules run enum_core_network --security-lists --get",
                            notes=_wrap_paragraph("Remediation: tighten egress to least privilege.")
                            + subnet_note,
                        )
                    )

    def _check_route_tables(self, res: ServiceAuditResult) -> None:
        rows = self.get_rows(self.T_ROUTE_TABLES)
        attached = self._attached_route_table_ids()
        for r in rows:
            cid = _safe_str(r.get("compartment_id"))
            rid = _safe_str(r.get("id"))
            if not cid or not rid:
                continue
            if _safe_str(r.get("lifecycle_state")).upper() in self._TERMINAL_VCN_STATES:
                continue
            is_live = rid in attached
            rules = _as_json_list(r.get("route_rules"))
            for rule in rules:
                if not isinstance(rule, dict):
                    continue
                dst = rule.get("destination")
                entity = _safe_str(rule.get("network_entity_id")).lower()
                if not _is_public_cidr(dst):
                    continue
                if "internetgateway" not in entity and "internet-gateway" not in entity:
                    continue
                loc = _loc_base(compartment_id=cid, entity_id=rid, vcn_id=_safe_str(r.get("vcn_id")) or None)
                res.findings.append(
                    self.finding(
                        table_name=self.T_ROUTE_TABLES,
                        issue_code="VCN_ROUTE_TABLE_DEFAULT_TO_IGW",
                        title="Route table has default route to internet gateway" if is_live
                        else "Route table has default route to internet gateway (not attached to a subnet)",
                        severity="MEDIUM" if is_live else "LOW",
                        description=_wrap_paragraph(
                            "Route table contains a default route (0.0.0.0/0 or equivalent) to an internet gateway."
                        ) + ("" if is_live else _wrap_paragraph(
                            """
                            This route table is not currently referenced by any live subnet's `route_table_id`,
                            so it is not routing traffic today. This is configuration debt, not a live exposure --
                            it becomes an active risk the moment the table is attached to a subnet.
                            """
                        )),
                        location=loc,
                        row=r,
                        recommended_module="modules run enum_core_network --route-tables --get",
                        notes=_wrap_paragraph(
                            "Remediation: ensure default internet routes are only attached to intended public subnets."
                        ),
                    )
                )

    def _check_subnets(self, res: ServiceAuditResult) -> None:
        rows = self.get_rows(self.T_SUBNETS)
        for r in rows:
            cid = _safe_str(r.get("compartment_id"))
            sid = _safe_str(r.get("id"))
            if not cid or not sid:
                continue
            if _safe_str(r.get("lifecycle_state")).upper() in self._TERMINAL_VCN_STATES:
                continue
            allows_public_ip = _falsy_str(r.get("prohibit_public_ip_on_vnic"))
            if not allows_public_ip:
                continue
            loc = _loc_base(compartment_id=cid, entity_id=sid, vcn_id=_safe_str(r.get("vcn_id")) or None)
            res.findings.append(
                self.finding(
                    table_name=self.T_SUBNETS,
                    issue_code="VCN_SUBNET_ALLOWS_PUBLIC_IP",
                    title="Subnet allows public IP assignment on VNICs",
                    severity="MEDIUM",
                    description=_wrap_paragraph(
                        "Subnet does not prohibit public IP assignment on attached VNICs."
                    ),
                    location=loc,
                    row=r,
                    recommended_module="modules run enum_core_network --subnets --get",
                    notes=_wrap_paragraph(
                        "Remediation: disable public IP assignment by default for private subnets."
                    ),
                )
            )


class NetworkLoadBalancerServiceAuditor(ServiceAuditor):
    service = "network_load_balancer"

    T_NLBS = "network_load_balancers"

    def run_checks(self) -> ServiceAuditResult:
        res = ServiceAuditResult(service=self.service)
        try:
            self._check_public_nlbs(res)
        except Exception as e:
            res.errors.append(f"nlbs: {type(e).__name__}: {e}")
        return res

    def _check_public_nlbs(self, res: ServiceAuditResult) -> None:
        rows = self.get_rows(self.T_NLBS, where_conditions={"lifecycle_state": "ACTIVE"})
        for r in rows:
            cid = _safe_str(r.get("compartment_id"))
            nid = _safe_str(r.get("id"))
            if not cid or not nid:
                continue
            public = _falsy_str(r.get("is_private"))
            if not public:
                continue
            loc = _loc_base(compartment_id=cid, entity_id=nid, subnet_id=_safe_str(r.get("subnet_id")) or None)
            res.findings.append(
                self.finding(
                    table_name=self.T_NLBS,
                    issue_code="NLB_PUBLIC",
                    title="Network Load Balancer is public",
                    severity="MEDIUM",
                    description=_wrap_paragraph(
                        "NLB is configured as public and reachable from internet-routed paths."
                    ),
                    location=loc,
                    row=r,
                    recommended_module="modules run enum_network_load_balancers --get",
                    notes=_wrap_paragraph("Remediation: use private NLBs unless internet exposure is required."),
                )
            )

            nsg_ids = _as_json_list(r.get("network_security_group_ids"))
            if not nsg_ids:
                res.findings.append(
                    self.finding(
                        table_name=self.T_NLBS,
                        issue_code="NLB_PUBLIC_NO_NSG",
                        title="Public NLB has no NSG restrictions",
                        severity="HIGH",
                        description=_wrap_paragraph(
                            "Public NLB has no attached NSGs, reducing network-level filtering controls."
                        ),
                        location=loc,
                        row=r,
                        recommended_module="modules run enum_network_load_balancers --get",
                        notes=_wrap_paragraph("Remediation: attach restrictive NSGs and explicit ingress policy."),
                    )
                )


class LoggingServiceAuditor(ServiceAuditor):
    service = "logging"

    T_LOGS = "logging_logs"

    # Lifecycle states where a log object row is no longer meaningful to audit --
    # DELETING/FAILED, but NOT INACTIVE (INACTIVE is a real, currently-existing
    # log configuration state, distinct from the separate is_enabled flag).
    _DEAD_LOG_STATES = {"DELETING", "FAILED"}

    def run_checks(self) -> ServiceAuditResult:
        res = ServiceAuditResult(service=self.service)
        try:
            self._check_disabled_logs(res)
        except Exception as e:
            res.errors.append(f"disabled_logs: {type(e).__name__}: {e}")
        try:
            self._check_retention_duration(res)
        except Exception as e:
            res.errors.append(f"retention_duration: {type(e).__name__}: {e}")
        return res

    def _check_disabled_logs(self, res: ServiceAuditResult) -> None:
        rows = self.get_rows(self.T_LOGS)
        for r in rows:
            if _safe_str(r.get("lifecycle_state")).upper() in self._DEAD_LOG_STATES:
                continue
            cid = _safe_str(r.get("compartment_id"))
            lid = _safe_str(r.get("id"))
            if not cid or not lid:
                continue
            if _truthy_str(r.get("is_enabled")):
                continue
            loc = _loc_base(compartment_id=cid, entity_id=lid, log_group_id=_safe_str(r.get("log_group_id")) or None)
            res.findings.append(
                self.finding(
                    table_name=self.T_LOGS,
                    issue_code="LOGGING_LOG_DISABLED",
                    title="Log object is disabled",
                    severity="MEDIUM",
                    description=_wrap_paragraph(
                        "Log collection is disabled for this log object."
                    ),
                    location=loc,
                    row=r,
                    recommended_module="modules run enum_logging --logs --get",
                    notes=_wrap_paragraph("Remediation: enable log collection for security-relevant sources."),
                )
            )

    def _check_retention_duration(self, res: ServiceAuditResult) -> None:
        rows = self.get_rows(self.T_LOGS)
        for r in rows:
            if _safe_str(r.get("lifecycle_state")).upper() in self._DEAD_LOG_STATES:
                continue
            cid = _safe_str(r.get("compartment_id"))
            lid = _safe_str(r.get("id"))
            if not cid or not lid:
                continue
            retention = _as_int(r.get("retention_duration"), default=0)
            if retention <= 0 or retention >= 30:
                continue
            loc = _loc_base(compartment_id=cid, entity_id=lid, log_group_id=_safe_str(r.get("log_group_id")) or None)
            res.findings.append(
                self.finding(
                    table_name=self.T_LOGS,
                    issue_code="LOGGING_RETENTION_SHORT",
                    title="Log retention appears short",
                    severity="LOW",
                    description=_wrap_paragraph(
                        f"Retention duration is {retention} day(s), which may be insufficient for investigations."
                    ),
                    location=loc,
                    row=r,
                    recommended_module="modules run enum_logging --logs --get",
                    notes=_wrap_paragraph("Remediation: align log retention with incident response and compliance needs."),
                )
            )


class ResourceManagerServiceAuditor(ServiceAuditor):
    service = "resource_manager"

    T_STACKS = "resource_manager_stacks"
    T_CONFIG_SOURCE_PROVIDER = "resource_manager_config_source_providers"
    T_PRIVATE_ENDPOINTS = "resource_manager_private_endpoints"

    def run_checks(self) -> ServiceAuditResult:
        res = ServiceAuditResult(service=self.service)
        try:
            self._check_stack_variables_for_sensitive_values(res)
        except Exception as e:
            res.errors.append(f"stacks: {type(e).__name__}: {e}")
        try:
            self._check_config_source_provider_secret_ref(res)
        except Exception as e:
            res.errors.append(f"config_source_provider: {type(e).__name__}: {e}")
        try:
            self._check_private_endpoint_no_nsg(res)
        except Exception as e:
            res.errors.append(f"private_endpoints: {type(e).__name__}: {e}")
        return res

    def _check_stack_variables_for_sensitive_values(self, res: ServiceAuditResult) -> None:
        rows = self.get_rows(self.T_STACKS)
        for r in rows:
            cid = _safe_str(r.get("compartment_id"))
            sid = _safe_str(r.get("id"))
            if not cid or not sid:
                continue

            vars_obj = as_json_dict(r.get("variables"))
            if not vars_obj:
                continue

            sensitive_hits: List[str] = []
            for k, v in vars_obj.items():
                if not _contains_sensitive_key_name(k):
                    continue
                if v is None:
                    continue
                sv = _safe_str(v)
                if sv:
                    sensitive_hits.append(k)

            if not sensitive_hits:
                continue

            loc = _loc_base(compartment_id=cid, entity_id=sid)
            notes = (
                "Variables include keys that look secret-bearing: "
                + ", ".join(sorted(set(sensitive_hits))[:12])
            )
            res.findings.append(
                self.finding(
                    table_name=self.T_STACKS,
                    issue_code="ORM_STACK_VARIABLE_POTENTIAL_SECRET",
                    title="Resource Manager stack variables may contain secrets",
                    severity="MEDIUM",
                    description=_wrap_paragraph(
                        """
                        Stack variable keys indicate potential secret material (for example password/token/private key).
                        Plaintext stack variables can leak in stack exports and job artifacts.
                        """
                    ),
                    location=loc,
                    row=r,
                    recommended_module="modules run enum_resourcemanager --stacks --jobs --get --download",
                    notes=_wrap_paragraph(
                        notes
                        + ". Remediation: move secrets to OCI Vault references and avoid plaintext variable values."
                    ),
                )
            )

    def _check_config_source_provider_secret_ref(self, res: ServiceAuditResult) -> None:
        rows = self.get_rows(self.T_CONFIG_SOURCE_PROVIDER)
        for r in rows:
            cid = _safe_str(r.get("compartment_id"))
            pid = _safe_str(r.get("id"))
            if not cid or not pid:
                continue

            username = _safe_str(r.get("username"))
            secret_id = _safe_str(r.get("secret_id"))
            if username and not secret_id:
                loc = _loc_base(compartment_id=cid, entity_id=pid)
                res.findings.append(
                    self.finding(
                        table_name=self.T_CONFIG_SOURCE_PROVIDER,
                        issue_code="ORM_CONFIG_SOURCE_PROVIDER_MISSING_SECRET_REF",
                        title="Config source provider has username but no secret reference",
                        severity="MEDIUM",
                        description=_wrap_paragraph(
                            "Configuration source provider has a username set but no `secret_id` reference."
                        ),
                        location=loc,
                        row=r,
                        recommended_module="modules run enum_resourcemanager --config-source-providers --get",
                        notes=_wrap_paragraph(
                            "Remediation: store credentials in OCI Vault and reference them via secret OCIDs."
                        ),
                    )
                )

    def _check_private_endpoint_no_nsg(self, res: ServiceAuditResult) -> None:
        """`source_ips` on a Resource Manager PrivateEndpoint is Oracle's own
        auto-assigned OUTBOUND address (the IPs RM uses to reach into the customer's
        VCN) -- not a customer-configurable inbound allowlist, so it can never
        represent "open to the public" (the previous `ORM_PRIVATE_ENDPOINT_SOURCE_IP_ANY`
        check compared it against public-CIDR tokens and was structurally inert/
        meaningless). The real inbound access-control lever on this resource is
        `nsg_id_list`; an empty list means the endpoint relies solely on the
        subnet-wide security list rather than a dedicated NSG.
        """
        rows = self.get_rows(self.T_PRIVATE_ENDPOINTS)
        for r in rows:
            cid = _safe_str(r.get("compartment_id"))
            peid = _safe_str(r.get("id"))
            if not cid or not peid:
                continue
            if _safe_str(r.get("lifecycle_state")).upper() in ("DELETING", "DELETED", "FAILED"):
                continue
            nsg_ids = _as_json_list(r.get("nsg_id_list"))
            if nsg_ids:
                continue
            loc = _loc_base(compartment_id=cid, entity_id=peid, subnet_id=_safe_str(r.get("subnet_id")) or None)
            res.findings.append(
                self.finding(
                    table_name=self.T_PRIVATE_ENDPOINTS,
                    issue_code="ORM_PRIVATE_ENDPOINT_NO_NSG",
                    title="Resource Manager private endpoint has no NSG restrictions",
                    severity="MEDIUM",
                    description=_wrap_paragraph(
                        """
                        The private endpoint's `nsg_id_list` is empty, so network access relies solely on the
                        subnet-wide Security List rather than a dedicated Network Security Group scoping inbound
                        access to specific client resources.
                        """
                    ),
                    location=loc,
                    row=r,
                    recommended_module="modules run enum_resourcemanager --private-endpoints --get",
                    notes=_wrap_paragraph(
                        "Remediation: attach a restrictive NSG to the private endpoint (nsg_id_list) scoping "
                        "access to the specific client resources/NSGs that need it."
                    ),
                )
            )


class DatabaseServiceAuditor(ServiceAuditor):
    service = "database"

    T_ORACLE = "db_db_systems"
    T_AUTONOMOUS = "db_autonomous_databases"

    def run_checks(self) -> ServiceAuditResult:
        res = ServiceAuditResult(service=self.service)
        # NOTE: The former MySQL `encrypt_data`/`secure_connections` checks were
        # removed: those columns hold EncryptDataDetails/SecureConnectionDetails
        # objects (key_generation_type), not enable/disable booleans, and MySQL
        # DB Systems are encrypted at rest by default. The former PostgreSQL
        # `is_public` network check was removed too: oci.psql NetworkDetails has
        # no such field (DB systems are always subnet-private).
        try:
            self._check_oracle_kms_key(res)
        except Exception as e:
            res.errors.append(f"oracle: {type(e).__name__}: {e}")
        try:
            self._check_autonomous_databases(res)
        except Exception as e:
            res.errors.append(f"autonomous: {type(e).__name__}: {e}")
        return res

    def _check_oracle_kms_key(self, res: ServiceAuditResult) -> None:
        rows = self.get_rows(self.T_ORACLE)
        for r in rows:
            cid = _safe_str(r.get("compartment_id"))
            dbid = _safe_str(r.get("id"))
            if not cid or not dbid:
                continue
            if _safe_str(r.get("kms_key_id")):
                continue
            loc = _loc_base(compartment_id=cid, entity_id=dbid)
            res.findings.append(
                self.finding(
                    table_name=self.T_ORACLE,
                    issue_code="ORACLE_DB_NO_CMK",
                    title="Oracle DB system has no customer-managed key",
                    severity="MEDIUM",
                    description=_wrap_paragraph(
                        "Oracle DB system does not reference a customer-managed KMS key."
                    ),
                    location=loc,
                    row=r,
                    recommended_module="modules run enum_databases --oracle --get",
                    notes=_wrap_paragraph("Remediation: use CMK-backed encryption where policy/compliance requires it."),
                )
            )

    def _check_autonomous_databases(self, res: ServiceAuditResult) -> None:
        rows = self.get_rows(self.T_AUTONOMOUS)
        for r in rows:
            cid = _safe_str(r.get("compartment_id"))
            dbid = _safe_str(r.get("id"))
            if not cid or not dbid:
                continue
            loc = _loc_base(compartment_id=cid, entity_id=dbid)

            public_endpoint = _safe_str(r.get("public_endpoint"))
            whitelisted_ips = _as_json_list(r.get("whitelisted_ips"))
            subnet_id = _safe_str(r.get("subnet_id"))
            private_endpoint = _safe_str(r.get("private_endpoint"))

            # Public when there IS a public endpoint, or when nothing scopes
            # access at all (no ACL, no private subnet, no private endpoint).
            publicly_exposed = bool(public_endpoint) or (
                not whitelisted_ips and not subnet_id and not private_endpoint
            )
            if publicly_exposed:
                res.findings.append(
                    self.finding(
                        table_name=self.T_AUTONOMOUS,
                        issue_code="AUTONOMOUS_DB_PUBLIC_EXPOSURE",
                        title="Autonomous Database is publicly reachable",
                        severity="CRITICAL",
                        description=_wrap_paragraph(
                            """
                            The Autonomous Database exposes a public endpoint or has no network
                            access controls (no allow-listed IPs, no private subnet, no private
                            endpoint), leaving it reachable from the internet.
                            """
                        ),
                        location=loc,
                        row=r,
                        recommended_module="modules run enum_databases --autonomous --get",
                        notes=_wrap_paragraph(
                            "Remediation: use a private endpoint/subnet or restrict access with an IP allow-list."
                        ),
                    )
                )

            if _falsy_str(r.get("is_mtls_connection_required")):
                res.findings.append(
                    self.finding(
                        table_name=self.T_AUTONOMOUS,
                        issue_code="AUTONOMOUS_DB_MTLS_NOT_REQUIRED",
                        title="Autonomous Database does not require mTLS",
                        severity="MEDIUM",
                        description=_wrap_paragraph(
                            "The Autonomous Database allows TLS (non-mutual) connections; mTLS is not enforced."
                        ),
                        location=loc,
                        row=r,
                        recommended_module="modules run enum_databases --autonomous --get",
                        notes=_wrap_paragraph("Remediation: require mutual TLS (mTLS) for client connections."),
                    )
                )

            if not _safe_str(r.get("kms_key_id")):
                res.findings.append(
                    self.finding(
                        table_name=self.T_AUTONOMOUS,
                        issue_code="AUTONOMOUS_DB_NO_CMK",
                        title="Autonomous Database has no customer-managed key",
                        severity="MEDIUM",
                        description=_wrap_paragraph(
                            "The Autonomous Database does not reference a customer-managed KMS key (Oracle-managed default)."
                        ),
                        location=loc,
                        row=r,
                        recommended_module="modules run enum_databases --autonomous --get",
                        notes=_wrap_paragraph("Remediation: use CMK-backed encryption where policy/compliance requires it."),
                    )
                )


class NotificationsServiceAuditor(ServiceAuditor):
    service = "notifications"

    T_SUBSCRIPTIONS = "notification_subscriptions"

    def run_checks(self) -> ServiceAuditResult:
        res = ServiceAuditResult(service=self.service)
        try:
            self._check_http_subscriptions(res)
        except Exception as e:
            res.errors.append(f"subscriptions: {type(e).__name__}: {e}")
        return res

    def _check_http_subscriptions(self, res: ServiceAuditResult) -> None:
        # OCI's ons subscription protocol enum (CUSTOM_HTTPS/EMAIL/HTTPS/ORACLE_FUNCTIONS/
        # PAGERDUTY/SLACK/SMS) never issues a bare "HTTP" value, so string-matching
        # protocol=="HTTP" can never fire. What OCI DOES allow is a CUSTOM_HTTPS/HTTPS
        # subscription whose endpoint URL is plain "http://" free text -- check that.
        rows = self.get_rows(self.T_SUBSCRIPTIONS)
        for r in rows:
            if _safe_str(r.get("lifecycle_state")).upper() == "DELETED":
                continue
            cid = _safe_str(r.get("compartment_id"))
            sid = _safe_str(r.get("id"))
            if not cid or not sid:
                continue
            endpoint = _safe_str(r.get("endpoint")).strip().lower()
            if not endpoint.startswith("http://"):
                continue
            loc = _loc_base(compartment_id=cid, entity_id=sid, topic_id=_safe_str(r.get("topic_id")) or None)
            res.findings.append(
                self.finding(
                    table_name=self.T_SUBSCRIPTIONS,
                    issue_code="NOTIFICATION_HTTP_SUBSCRIPTION",
                    title="Notification subscription uses HTTP (plaintext)",
                    severity="MEDIUM",
                    description=_wrap_paragraph(
                        "Subscription endpoint uses plaintext http://, which does not provide TLS protection "
                        "in transit."
                    ),
                    location=loc,
                    row=r,
                    recommended_module="modules run enum_notifications --subscriptions --get",
                    notes=_wrap_paragraph("Remediation: use HTTPS endpoints for notification subscriptions."),
                )
            )


class FunctionsServiceAuditor(ServiceAuditor):
    service = "functions"

    T_APPS = "functions_apps"
    T_FUNCTIONS = "functions_functions"

    def run_checks(self) -> ServiceAuditResult:
        res = ServiceAuditResult(service=self.service)
        try:
            self._check_function_invoke_endpoint_scheme(res)
        except Exception as e:
            res.errors.append(f"invoke_endpoint: {type(e).__name__}: {e}")
        try:
            self._check_app_syslog_url(res)
        except Exception as e:
            res.errors.append(f"syslog_url: {type(e).__name__}: {e}")
        return res

    def _check_function_invoke_endpoint_scheme(self, res: ServiceAuditResult) -> None:
        rows = self.get_rows(self.T_FUNCTIONS)
        for r in rows:
            cid = _safe_str(r.get("compartment_id"))
            fid = _safe_str(r.get("id"))
            if not cid or not fid:
                continue
            ep = _safe_str(r.get("invoke_endpoint")).strip().lower()
            if not ep.startswith("http://"):
                continue
            loc = _loc_base(compartment_id=cid, entity_id=fid, application_id=_safe_str(r.get("application_id")) or None)
            res.findings.append(
                self.finding(
                    table_name=self.T_FUNCTIONS,
                    issue_code="FUNCTION_INVOKE_ENDPOINT_HTTP",
                    title="Function invoke endpoint uses HTTP",
                    severity="MEDIUM",
                    description=_wrap_paragraph(
                        "Invoke endpoint starts with HTTP (plaintext) instead of HTTPS."
                    ),
                    location=loc,
                    row=r,
                    recommended_module="modules run enum_functions --functions --get",
                    notes=_wrap_paragraph("Remediation: require HTTPS endpoints for function invocation."),
                )
            )

    def _check_app_syslog_url(self, res: ServiceAuditResult) -> None:
        rows = self.get_rows(self.T_APPS)
        for r in rows:
            cid = _safe_str(r.get("compartment_id"))
            aid = _safe_str(r.get("id"))
            if not cid or not aid:
                continue
            syslog_url = _safe_str(r.get("syslog_url")).strip().lower()
            if not syslog_url.startswith("http://"):
                continue
            loc = _loc_base(compartment_id=cid, entity_id=aid)
            res.findings.append(
                self.finding(
                    table_name=self.T_APPS,
                    issue_code="FUNCTION_APP_SYSLOG_HTTP",
                    title="Function application syslog URL uses HTTP",
                    severity="MEDIUM",
                    description=_wrap_paragraph(
                        "Syslog URL starts with HTTP (plaintext)."
                    ),
                    location=loc,
                    row=r,
                    recommended_module="modules run enum_functions --apps --get",
                    notes=_wrap_paragraph("Remediation: use TLS-protected log destinations."),
                )
            )


class FileStorageServiceAuditor(ServiceAuditor):
    service = "file_storage"

    T_EXPORTS = "file_storage_exports"
    T_MOUNT_TARGETS = "file_storage_mount_targets"
    T_FILE_SYSTEMS = "file_storage_file_systems"

    def run_checks(self) -> ServiceAuditResult:
        res = ServiceAuditResult(service=self.service)
        try:
            self._check_exports_open_to_any(res)
        except Exception as e:
            res.errors.append(f"exports: {type(e).__name__}: {e}")
        try:
            self._check_mount_target_nsg(res)
        except Exception as e:
            res.errors.append(f"mount_targets: {type(e).__name__}: {e}")
        try:
            self._check_file_system_cmk(res)
        except Exception as e:
            res.errors.append(f"file_systems: {type(e).__name__}: {e}")
        return res

    def _check_file_system_cmk(self, res: ServiceAuditResult) -> None:
        rows = self.get_rows(self.T_FILE_SYSTEMS)
        for r in rows:
            cid = _safe_str(r.get("compartment_id"))
            fid = _safe_str(r.get("id"))
            if not cid or not fid:
                continue
            if _safe_str(r.get("lifecycle_state")).upper() not in ("ACTIVE",):
                continue
            if _safe_str(r.get("kms_key_id")):
                continue
            loc = _loc_base(compartment_id=cid, entity_id=fid)
            res.findings.append(
                self.finding(
                    table_name=self.T_FILE_SYSTEMS,
                    issue_code="FILE_STORAGE_FILE_SYSTEM_NO_CMK",
                    title="File Storage file system has no customer-managed key",
                    severity="LOW",
                    description=_wrap_paragraph(
                        """
                        File system is not tied to a customer-managed KMS key (falls back to Oracle-managed
                        encryption). Data is still encrypted at rest by default; this flags absence of
                        customer control over the key, not plaintext data.
                        """
                    ),
                    location=loc,
                    row=r,
                    recommended_module="modules run enum_filestorage --file-systems --get",
                    notes=_wrap_paragraph(
                        "Remediation: use CMK-backed encryption for file systems hosting sensitive workloads."
                    ),
                )
            )

    def _check_exports_open_to_any(self, res: ServiceAuditResult) -> None:
        rows = self.get_rows(self.T_EXPORTS)
        for r in rows:
            eid = _safe_str(r.get("id"))
            if not eid:
                continue
            opts = _as_json_list(r.get("export_options"))
            for opt in opts:
                if not isinstance(opt, dict):
                    continue
                src = opt.get("source")
                access = _safe_str(opt.get("access")).upper()
                if not _is_public_cidr(src):
                    continue
                if access not in ("READ_WRITE", "READONLY", "READ_ONLY", "READWRITE"):
                    continue
                loc = _loc_base(
                    compartment_id=_safe_str(r.get("compartment_id")) or "unknown",
                    entity_id=eid,
                    export_set_id=_safe_str(r.get("export_set_id")) or None,
                )
                res.findings.append(
                    self.finding(
                        table_name=self.T_EXPORTS,
                        issue_code="FILE_STORAGE_EXPORT_OPEN_TO_ANY",
                        title="File Storage export allows any-address source",
                        severity="HIGH",
                        description=_wrap_paragraph(
                            "Export option allows 0.0.0.0/0 (or equivalent), which can expose NFS shares broadly."
                        ),
                        location=loc,
                        row=r,
                        recommended_module="modules run enum_filestorage --exports --get",
                        notes=_wrap_paragraph("Remediation: restrict export source CIDRs to trusted networks."),
                    )
                )

    def _check_mount_target_nsg(self, res: ServiceAuditResult) -> None:
        rows = self.get_rows(self.T_MOUNT_TARGETS)
        for r in rows:
            cid = _safe_str(r.get("compartment_id"))
            mid = _safe_str(r.get("id"))
            if not cid or not mid:
                continue
            nsg_ids = _as_json_list(r.get("nsg_ids"))
            if nsg_ids:
                continue
            loc = _loc_base(compartment_id=cid, entity_id=mid, subnet_id=_safe_str(r.get("subnet_id")) or None)
            res.findings.append(
                self.finding(
                    table_name=self.T_MOUNT_TARGETS,
                    issue_code="FILE_STORAGE_MOUNT_TARGET_NO_NSG",
                    title="File Storage mount target has no NSG",
                    severity="MEDIUM",
                    description=_wrap_paragraph(
                        "Mount target has no NSGs attached, reducing network-level access controls."
                    ),
                    location=loc,
                    row=r,
                    recommended_module="modules run enum_filestorage --mount-targets --get",
                    notes=_wrap_paragraph("Remediation: attach NSGs and limit ingress to required clients only."),
                )
            )


class IdentityServiceAuditor(ServiceAuditor):
    service = "identity"

    T_API_KEYS = "identity_user_api_keys"
    T_POLICIES = "identity_policies"
    T_MEMBERSHIPS = "identity_user_group_memberships"

    # Verbs (or an all-resources grant) broad enough that an unconditional any-user/
    # any-group grant is a full-blast-radius exposure rather than a bounded one.
    _BROAD_VERBS = {"manage"}

    _ADMIN_GROUP_NAME = "administrators"
    _API_KEY_MAX_AGE_DAYS = 90
    _ADMIN_PROTECTING_RESOURCE_TYPES = ("users", "groups")

    def run_checks(self) -> ServiceAuditResult:
        res = ServiceAuditResult(service=self.service)
        try:
            self._check_multiple_api_keys_per_user(res)
        except Exception as e:
            res.errors.append(f"api_keys: {type(e).__name__}: {e}")
        try:
            self._check_api_key_rotation_age(res)
        except Exception as e:
            res.errors.append(f"api_key_rotation_age: {type(e).__name__}: {e}")
        try:
            self._check_admin_group_member_has_api_key(res)
        except Exception as e:
            res.errors.append(f"admin_group_api_keys: {type(e).__name__}: {e}")
        try:
            self._check_any_user_any_group_unconditional(res)
        except Exception as e:
            res.errors.append(f"policies: {type(e).__name__}: {e}")
        try:
            self._check_tenancy_wide_manage_all_non_admin_group(res)
        except Exception as e:
            res.errors.append(f"policies_manage_all: {type(e).__name__}: {e}")
        try:
            self._check_iam_admin_group_not_protected(res)
        except Exception as e:
            res.errors.append(f"policies_admin_group_protection: {type(e).__name__}: {e}")
        return res

    @staticmethod
    def _st_has_conditions(st: Dict[str, Any]) -> bool:
        cond = st.get("conditions") or {}
        if not isinstance(cond, dict):
            return False
        if cond.get("clauses"):
            return True
        if cond.get("items"):
            return True
        if _safe_str(cond.get("type")).lower() == "clause":
            return True
        return False

    @staticmethod
    def _parse_allow_statements(statements: List[str]) -> List[Tuple[int, str, Dict[str, Any]]]:
        """Parse a policy's raw statement strings and yield (original_index, raw_text,
        parsed_statement) for every statement that parsed successfully and is an ALLOW.
        Centralizes the index-remapping (parser drops failed statements from `parsed`
        rather than null-padding, so positions shift) that every policy-statement check
        in this class needs.
        """
        try:
            payload, diagnostics = parse_policy_statements(statements, nested_simplify=True, error_mode="report")
        except Exception:
            return []

        parsed = (payload or {}).get("statements") or []
        failed_indices = {
            e.get("statement_index")
            for e in ((diagnostics or {}).get("errors") or [])
            if isinstance(e, dict)
        }
        success_indices = [i for i in range(len(statements)) if i not in failed_indices]

        out: List[Tuple[int, str, Dict[str, Any]]] = []
        for parsed_pos, st in enumerate(parsed):
            if not isinstance(st, dict) or _safe_str(st.get("kind")).lower() != "allow":
                continue
            orig_idx = success_indices[parsed_pos] if parsed_pos < len(success_indices) else None
            if orig_idx is None:
                continue
            out.append((orig_idx, statements[orig_idx], st))
        return out

    def _check_any_user_any_group_unconditional(self, res: ServiceAuditResult) -> None:
        """Flag ALLOW statements whose subject is OCI's true "everyone" wildcards --
        `any-user` (every principal, including service/instance/resource principals) or
        `any-group` (Oracle's recommended everyone-equivalent for user-like principals) --
        with no `where` clause narrowing who/what the grant applies to. A named
        group/dynamic-group with a broad grant is normal and NOT flagged here; this is
        specifically the "the grant applies to literally anyone" case.
        """
        if parse_policy_statements is None:
            return

        rows = self.get_rows(self.T_POLICIES)
        for r in rows:
            cid = _safe_str(r.get("compartment_id"))
            pid = _safe_str(r.get("id"))
            if not cid or not pid:
                continue

            statements = [s for s in _as_json_list(r.get("statements")) if isinstance(s, str) and s.strip()]
            if not statements:
                continue

            try:
                payload, diagnostics = parse_policy_statements(
                    statements, nested_simplify=True, error_mode="report"
                )
            except Exception:
                continue

            parsed = (payload or {}).get("statements") or []
            # Statements that fail to parse are silently dropped from `parsed` (not
            # null-padded), so indices shift -- rebuild the original-index mapping from
            # diagnostics rather than assuming parsed[i] corresponds to statements[i].
            failed_indices = {
                e.get("statement_index")
                for e in ((diagnostics or {}).get("errors") or [])
                if isinstance(e, dict)
            }
            success_indices = [i for i in range(len(statements)) if i not in failed_indices]

            for parsed_pos, st in enumerate(parsed):
                if not isinstance(st, dict):
                    continue
                if _safe_str(st.get("kind")).lower() != "allow":
                    continue

                subject = st.get("subject") or {}
                subject_type = _safe_str(subject.get("type")).lower()
                if subject_type not in ("any-user", "any-group"):
                    continue
                if self._st_has_conditions(st):
                    continue

                orig_idx = success_indices[parsed_pos] if parsed_pos < len(success_indices) else None
                raw_text = statements[orig_idx] if orig_idx is not None else ""

                actions = st.get("actions") or {}
                verbs = {_safe_str(v).lower() for v in (actions.get("values") or [])}
                resources = st.get("resources") or {}
                resource_type = _safe_str(resources.get("type")).lower()
                broad = bool(verbs & self._BROAD_VERBS) or resource_type == "all-resources"

                loc = _loc_base(compartment_id=cid, entity_id=pid, statement_index=orig_idx)
                res.findings.append(
                    self.finding(
                        table_name=self.T_POLICIES,
                        issue_code="IAM_POLICY_ANY_USER_OR_GROUP_NO_CONDITIONS",
                        title=f"Policy statement grants to {subject_type} with no conditions",
                        severity="CRITICAL" if broad else "HIGH",
                        description=_wrap_paragraph(
                            f"""
                            Statement "{raw_text}" has subject "{subject_type}" -- OCI's true "everyone in the
                            tenancy" wildcard subjects (any-user additionally matches service/instance/resource
                            principals; any-group is Oracle's recommended everyone-equivalent for user-like
                            principals) -- and carries no `where` clause narrowing which principals or contexts
                            the grant applies to. Every principal matching {subject_type} receives this
                            permission unconditionally.
                            """
                        ),
                        location=loc,
                        row=r,
                        recommended_module="modules run enum_identity --policies --get",
                        notes=_wrap_paragraph(
                            f"Remediation: replace {subject_type} with an explicit group/dynamic-group, or add "
                            "a `where` clause (e.g. request.principal.type, request.user.id) narrowing the "
                            "grant to only the principals that actually need it."
                        ),
                    )
                )

    def _check_tenancy_wide_manage_all_non_admin_group(self, res: ServiceAuditResult) -> None:
        """Flag `Allow group <X> to manage all-resources in tenancy` grants where <X> is
        NOT the built-in Administrators group. This is functionally tenancy-admin-equivalent
        access handed to a group that isn't the audited/intentional admin group -- the same
        signal Prowler (identity_tenancy_admin_permissions_limited) and Steampipe
        (identity_only_administrators_group_with_manage_all_resources) flag, mapping to CIS
        OCI Foundations 1.3.
        """
        if parse_policy_statements is None:
            return

        rows = self.get_rows(self.T_POLICIES)
        for r in rows:
            cid = _safe_str(r.get("compartment_id"))
            pid = _safe_str(r.get("id"))
            if not cid or not pid:
                continue

            statements = [s for s in _as_json_list(r.get("statements")) if isinstance(s, str) and s.strip()]
            if not statements:
                continue

            for orig_idx, raw_text, st in self._parse_allow_statements(statements):
                subject = st.get("subject") or {}
                if _safe_str(subject.get("type")).lower() != "group":
                    continue
                subj_values = subject.get("values") or []
                group_name = _safe_str(subj_values[0].get("label")) if subj_values and isinstance(subj_values[0], dict) else ""
                if not group_name or group_name.strip().lower() == self._ADMIN_GROUP_NAME:
                    continue

                actions = st.get("actions") or {}
                verbs = {_safe_str(v).lower() for v in (actions.get("values") or [])}
                resources = st.get("resources") or {}
                location_scope = st.get("location") or {}
                if "manage" not in verbs:
                    continue
                if _safe_str(resources.get("type")).lower() != "all-resources":
                    continue
                if _safe_str(location_scope.get("type")).lower() != "tenancy":
                    continue

                loc = _loc_base(compartment_id=cid, entity_id=pid, statement_index=orig_idx)
                res.findings.append(
                    self.finding(
                        table_name=self.T_POLICIES,
                        issue_code="IAM_POLICY_MANAGE_ALL_RESOURCES_NON_ADMIN_GROUP",
                        title=f"Group '{group_name}' has tenancy-admin-equivalent access outside Administrators",
                        severity="HIGH",
                        description=_wrap_paragraph(
                            f"""
                            Statement "{raw_text}" grants group '{group_name}' the ability to manage all
                            resources in the tenancy -- equivalent to full tenancy-admin access -- but this
                            group is not the built-in Administrators group. Admin-equivalent access outside
                            the one audited admin group makes it easy to lose track of who actually has
                            full control of the tenancy.
                            """
                        ),
                        location=loc,
                        row=r,
                        recommended_module="modules run enum_identity --policies --get",
                        notes=_wrap_paragraph(
                            "Remediation: scope this grant to specific compartments/services instead of the "
                            "whole tenancy, or consolidate tenancy-wide admin access into the Administrators group."
                        ),
                    )
                )

    def _check_iam_admin_group_not_protected(self, res: ServiceAuditResult) -> None:
        """Flag `Allow group <X> to use/manage users|groups in tenancy` grants that carry
        no condition protecting the Administrators group. Without a `where target.group.name
        != 'Administrators'`-style clause, a member of the granted group can add themselves
        (or anyone) to Administrators -- a privilege-escalation path. Matches Prowler
        (identity_iam_admins_cannot_update_tenancy_admins) and Steampipe
        (identity_iam_administrators_no_update_tenancy_administrators_group), CIS OCI 1.13.
        """
        if parse_policy_statements is None:
            return

        rows = self.get_rows(self.T_POLICIES)
        for r in rows:
            cid = _safe_str(r.get("compartment_id"))
            pid = _safe_str(r.get("id"))
            if not cid or not pid:
                continue

            statements = [s for s in _as_json_list(r.get("statements")) if isinstance(s, str) and s.strip()]
            if not statements:
                continue

            for orig_idx, raw_text, st in self._parse_allow_statements(statements):
                subject = st.get("subject") or {}
                if _safe_str(subject.get("type")).lower() != "group":
                    continue
                subj_values = subject.get("values") or []
                group_name = _safe_str(subj_values[0].get("label")) if subj_values and isinstance(subj_values[0], dict) else ""
                if not group_name or group_name.strip().lower() == self._ADMIN_GROUP_NAME:
                    continue

                actions = st.get("actions") or {}
                verbs = {_safe_str(v).lower() for v in (actions.get("values") or [])}
                resources = st.get("resources") or {}
                resource_values = {_safe_str(v).lower() for v in (resources.get("values") or [])}
                location_scope = st.get("location") or {}
                if not (verbs & {"use", "manage"}):
                    continue
                if _safe_str(resources.get("type")).lower() != "specific":
                    continue
                if not (resource_values & set(self._ADMIN_PROTECTING_RESOURCE_TYPES)):
                    continue
                if _safe_str(location_scope.get("type")).lower() != "tenancy":
                    continue
                if _condition_mentions_value(st, self._ADMIN_GROUP_NAME):
                    continue

                loc = _loc_base(compartment_id=cid, entity_id=pid, statement_index=orig_idx)
                res.findings.append(
                    self.finding(
                        table_name=self.T_POLICIES,
                        issue_code="IAM_POLICY_ADMIN_GROUP_NOT_PROTECTED",
                        title=f"Group '{group_name}' can manage tenancy users/groups without an Administrators exclusion",
                        severity="HIGH",
                        description=_wrap_paragraph(
                            f"""
                            Statement "{raw_text}" lets group '{group_name}' use/manage users or groups
                            tenancy-wide with no condition excluding the Administrators group. A member of
                            '{group_name}' can therefore add themselves (or another principal they control)
                            to Administrators -- a privilege-escalation path to full tenancy control.
                            """
                        ),
                        location=loc,
                        row=r,
                        recommended_module="modules run enum_identity --policies --get",
                        notes=_wrap_paragraph(
                            "Remediation: add a `where target.group.name != 'Administrators'` (or equivalent) "
                            "condition so this grant cannot be used to modify tenancy-admin membership."
                        ),
                    )
                )

    def _check_multiple_api_keys_per_user(self, res: ServiceAuditResult) -> None:
        rows = self.get_rows(self.T_API_KEYS)
        by_user: Dict[str, List[Dict[str, Any]]] = {}
        for r in rows:
            uid = _safe_str(r.get("user_id"))
            if not uid:
                continue
            by_user.setdefault(uid, []).append(r)

        for uid, items in by_user.items():
            if len(items) <= 1:
                continue
            for r in items:
                cid = _safe_str(r.get("compartment_id"))
                key_id = _safe_str(r.get("key_id")) or _safe_str(r.get("id"))
                if not cid or not key_id:
                    continue
                loc = _loc_base(compartment_id=cid, entity_id=key_id, user_id=uid)
                res.findings.append(
                    self.finding(
                        table_name=self.T_API_KEYS,
                        issue_code="IAM_USER_MULTIPLE_API_KEYS",
                        title="IAM user has multiple API keys",
                        severity="LOW",
                        description=_wrap_paragraph(
                            "User has more than one active/recorded API key, which can increase key-sprawl risk."
                        ),
                        location=loc,
                        row=r,
                        recommended_module="modules run enum_identity --api-keys",
                        notes=_wrap_paragraph("Remediation: rotate/revoke stale keys and enforce key hygiene."),
                    )
                )

    def _check_api_key_rotation_age(self, res: ServiceAuditResult) -> None:
        rows = self.get_rows(self.T_API_KEYS, where_conditions={"lifecycle_state": "ACTIVE"})
        for r in rows:
            cid = _safe_str(r.get("compartment_id"))
            key_id = _safe_str(r.get("key_id")) or _safe_str(r.get("id"))
            uid = _safe_str(r.get("user_id"))
            if not cid or not key_id:
                continue
            age = _age_days(r.get("time_created"))
            if age is None or age <= self._API_KEY_MAX_AGE_DAYS:
                continue
            loc = _loc_base(compartment_id=cid, entity_id=key_id, user_id=uid or None)
            res.findings.append(
                self.finding(
                    table_name=self.T_API_KEYS,
                    issue_code="IAM_USER_API_KEY_STALE",
                    title="IAM user API key has not been rotated in over 90 days",
                    severity="MEDIUM",
                    description=_wrap_paragraph(
                        f"""
                        API key was created {age:.0f} days ago and is still ACTIVE. A long-lived,
                        never-rotated credential increases the blast radius of a leaked key -- the
                        longer it's valid, the longer a compromise stays exploitable.
                        """
                    ),
                    location=loc,
                    row=r,
                    recommended_module="modules run enum_identity --principals",
                    notes=_wrap_paragraph(
                        "Remediation: rotate the API key (upload a new one, then delete the old one)."
                    ),
                )
            )

    def _check_admin_group_member_has_api_key(self, res: ServiceAuditResult) -> None:
        membership_rows = self.get_rows(self.T_MEMBERSHIPS)
        admin_user_ids = {
            _safe_str(m.get("user_id"))
            for m in membership_rows
            if _safe_str(m.get("group_name")).strip().lower() == self._ADMIN_GROUP_NAME
            and _safe_str(m.get("user_id"))
        }
        if not admin_user_ids:
            return

        key_rows = self.get_rows(self.T_API_KEYS, where_conditions={"lifecycle_state": "ACTIVE"})
        for r in key_rows:
            uid = _safe_str(r.get("user_id"))
            if uid not in admin_user_ids:
                continue
            cid = _safe_str(r.get("compartment_id"))
            key_id = _safe_str(r.get("key_id")) or _safe_str(r.get("id"))
            if not cid or not key_id:
                continue
            loc = _loc_base(compartment_id=cid, entity_id=key_id, user_id=uid)
            res.findings.append(
                self.finding(
                    table_name=self.T_API_KEYS,
                    issue_code="IAM_ADMIN_USER_HAS_API_KEY",
                    title="Administrators-group member holds an active API key",
                    severity="HIGH",
                    description=_wrap_paragraph(
                        """
                        This user is a member of the built-in Administrators group AND holds an active
                        API signing key. A leaked/stolen key for a tenancy-admin user grants an attacker
                        full tenancy control -- the largest possible blast radius for a single credential.
                        """
                    ),
                    location=loc,
                    row=r,
                    recommended_module="modules run enum_identity --principals",
                    notes=_wrap_paragraph(
                        "Remediation: avoid API keys on admin accounts (use a break-glass process instead), "
                        "or move day-to-day admin actions to a lower-privileged, scoped identity."
                    ),
                )
            )


class ArtifactRegistryServiceAuditor(ServiceAuditor):
    service = "artifact_registry"

    T_REPOSITORIES = "ar_repositories"

    def run_checks(self) -> ServiceAuditResult:
        res = ServiceAuditResult(service=self.service)
        try:
            self._check_repository_immutability(res)
        except Exception as e:
            res.errors.append(f"repository_immutability: {type(e).__name__}: {e}")
        return res

    def _check_repository_immutability(self, res: ServiceAuditResult) -> None:
        rows = self.get_rows(self.T_REPOSITORIES, where_conditions={"lifecycle_state": "AVAILABLE"})
        for r in rows:
            cid = _safe_str(r.get("compartment_id"))
            rid = _safe_str(r.get("id"))
            if not cid or not rid:
                continue
            if _truthy_str(r.get("is_immutable")):
                continue

            loc = _loc_base(compartment_id=cid, entity_id=rid)
            res.findings.append(
                self.finding(
                    table_name=self.T_REPOSITORIES,
                    issue_code="ARTIFACT_REPOSITORY_MUTABLE",
                    title="Artifact Registry repository is mutable",
                    severity="MEDIUM",
                    description=_wrap_paragraph(
                        "Repository appears mutable. Mutable artifacts can weaken supply-chain integrity."
                    ),
                    location=loc,
                    row=r,
                    recommended_module="modules run enum_artifactregistry --repositories --get",
                    notes=_wrap_paragraph(
                        "Remediation: enable repository immutability for sensitive artifact repositories."
                    ),
                )
            )


class DataScienceServiceAuditor(ServiceAuditor):
    service = "data_science"

    T_PRIVATE_ENDPOINTS = "data_science_private_endpoints"

    def run_checks(self) -> ServiceAuditResult:
        res = ServiceAuditResult(service=self.service)
        try:
            self._check_private_endpoint_subnet(res)
        except Exception as e:
            res.errors.append(f"private_endpoint_subnet: {type(e).__name__}: {e}")
        return res

    def _check_private_endpoint_subnet(self, res: ServiceAuditResult) -> None:
        rows = self.get_rows(self.T_PRIVATE_ENDPOINTS)
        for r in rows:
            cid = _safe_str(r.get("compartment_id"))
            pe_id = _safe_str(r.get("id"))
            if not cid or not pe_id:
                continue
            subnet_id = _safe_str(r.get("subnet_id"))
            if subnet_id:
                continue

            loc = _loc_base(compartment_id=cid, entity_id=pe_id)
            res.findings.append(
                self.finding(
                    table_name=self.T_PRIVATE_ENDPOINTS,
                    issue_code="DATA_SCIENCE_PRIVATE_ENDPOINT_NO_SUBNET",
                    title="Data Science private endpoint has no subnet reference",
                    severity="MEDIUM",
                    description=_wrap_paragraph(
                        "Private endpoint row has no subnet_id, which can indicate incomplete or misconfigured network placement."
                    ),
                    location=loc,
                    row=r,
                    recommended_module="modules run enum_datascience --private-endpoints --get",
                    notes=_wrap_paragraph(
                        "Remediation: ensure private endpoints are bound to intended private subnets."
                    ),
                )
            )


class BlockchainServiceAuditor(ServiceAuditor):
    service = "blockchain"

    T_PLATFORMS = "blockchain_platforms"

    _DEAD_PLATFORM_STATES = {"DELETED", "DELETING", "FAILED", "INACTIVE"}

    def run_checks(self) -> ServiceAuditResult:
        res = ServiceAuditResult(service=self.service)
        try:
            self._check_plaintext_service_endpoint(res)
        except Exception as e:
            res.errors.append(f"service_endpoint: {type(e).__name__}: {e}")
        return res

    def _check_plaintext_service_endpoint(self, res: ServiceAuditResult) -> None:
        rows = self.get_rows(self.T_PLATFORMS)
        for r in rows:
            if _safe_str(r.get("lifecycle_state")).upper() in self._DEAD_PLATFORM_STATES:
                continue
            cid = _safe_str(r.get("compartment_id"))
            pid = _safe_str(r.get("id"))
            if not cid or not pid:
                continue
            endpoint = _safe_str(r.get("service_endpoint")).strip().lower()
            if not endpoint.startswith("http://"):
                continue
            loc = _loc_base(compartment_id=cid, entity_id=pid)
            res.findings.append(
                self.finding(
                    table_name=self.T_PLATFORMS,
                    issue_code="BLOCKCHAIN_SERVICE_ENDPOINT_HTTP",
                    title="Blockchain service endpoint uses plaintext HTTP",
                    severity="MEDIUM",
                    description=_wrap_paragraph(
                        "Blockchain platform service endpoint appears to use plaintext HTTP."
                    ),
                    location=loc,
                    row=r,
                    recommended_module="modules run enum_blockchain --platforms --get",
                    notes=_wrap_paragraph("Remediation: require HTTPS endpoints."),
                )
            )


class IoTServiceAuditor(ServiceAuditor):
    service = "iot"

    T_DOMAIN_GROUPS = "iot_domain_groups"
    T_DOMAINS = "iot_domains"

    _DEAD_STATES = {"DELETED", "DELETING", "FAILED"}

    def run_checks(self) -> ServiceAuditResult:
        res = ServiceAuditResult(service=self.service)
        try:
            self._check_domain_group_vcn_allow_list(res)
        except Exception as e:
            res.errors.append(f"domain_group_vcn_allow_list: {type(e).__name__}: {e}")
        try:
            self._check_domain_identity_allow_list(res)
        except Exception as e:
            res.errors.append(f"domain_identity_allow_list: {type(e).__name__}: {e}")
        return res

    def _check_domain_group_vcn_allow_list(self, res: ServiceAuditResult) -> None:
        rows = self.get_rows(self.T_DOMAIN_GROUPS)
        for r in rows:
            if _safe_str(r.get("lifecycle_state")).upper() in self._DEAD_STATES:
                continue
            cid = _safe_str(r.get("compartment_id"))
            gid = _safe_str(r.get("id"))
            if not cid or not gid:
                continue
            # db_allow_listed_vcn_ids only appears on the full IotDomainGroup GET
            # response -- list summaries omit it entirely (None), which must not be
            # confused with a genuinely empty (collected) allow-list.
            raw_allow_list = r.get("db_allow_listed_vcn_ids")
            if raw_allow_list is None:
                continue
            allow_list = _as_json_list(raw_allow_list)
            if allow_list:
                continue
            loc = _loc_base(compartment_id=cid, entity_id=gid)
            res.findings.append(
                self.finding(
                    table_name=self.T_DOMAIN_GROUPS,
                    issue_code="IOT_DOMAIN_GROUP_VCN_ALLOWLIST_EMPTY",
                    title="IoT domain group has empty DB VCN allow list",
                    severity="MEDIUM",
                    description=_wrap_paragraph(
                        "IoT domain group DB VCN allow list is empty, increasing risk of broad backend DB exposure."
                    ),
                    location=loc,
                    row=r,
                    recommended_module="modules run enum_iot --domain-groups --get",
                    notes=_wrap_paragraph("Remediation: restrict DB access to explicit approved VCN IDs."),
                )
            )

    def _check_domain_identity_allow_list(self, res: ServiceAuditResult) -> None:
        rows = self.get_rows(self.T_DOMAINS)
        for r in rows:
            if _safe_str(r.get("lifecycle_state")).upper() in self._DEAD_STATES:
                continue
            cid = _safe_str(r.get("compartment_id"))
            did = _safe_str(r.get("id"))
            if not cid or not did:
                continue
            # db_allow_listed_identity_group_names is GET-only (absent from
            # IotDomainSummary) -- None means "not collected", not "empty".
            raw_group_allow_list = r.get("db_allow_listed_identity_group_names")
            if raw_group_allow_list is None:
                continue
            group_allow_list = _as_json_list(raw_group_allow_list)
            if group_allow_list:
                continue
            loc = _loc_base(compartment_id=cid, entity_id=did, domain_group_id=_safe_str(r.get("iot_domain_group_id")) or None)
            res.findings.append(
                self.finding(
                    table_name=self.T_DOMAINS,
                    issue_code="IOT_DOMAIN_IDENTITY_GROUP_ALLOWLIST_EMPTY",
                    title="IoT domain has empty identity-group allow list for DB access",
                    severity="MEDIUM",
                    description=_wrap_paragraph(
                        "IoT domain DB identity-group allow list is empty. Access controls may be overly broad or undefined."
                    ),
                    location=loc,
                    row=r,
                    recommended_module="modules run enum_iot --domains --get",
                    notes=_wrap_paragraph("Remediation: define explicit identity groups allowed for DB interactions."),
                )
            )


class EmailServiceAuditor(ServiceAuditor):
    service = "email"

    T_DOMAINS = "email_domains"
    T_DKIMS = "email_domain_dkims"
    T_SPFS = "email_domain_spfs"
    T_SENDERS = "email_senders"
    T_CONFIG = "email_configuration"

    def run_checks(self) -> ServiceAuditResult:
        res = ServiceAuditResult(service=self.service)
        try:
            self._check_domain_auth_records(res)
        except Exception as e:
            res.errors.append(f"domain_auth_records: {type(e).__name__}: {e}")
        try:
            self._check_unverified_senders(res)
        except Exception as e:
            res.errors.append(f"unverified_senders: {type(e).__name__}: {e}")
        try:
            self._check_plaintext_submit_endpoints(res)
        except Exception as e:
            res.errors.append(f"submit_endpoints: {type(e).__name__}: {e}")
        return res

    def _check_domain_auth_records(self, res: ServiceAuditResult) -> None:
        domain_rows = self.get_rows(self.T_DOMAINS)
        dkim_rows = self.get_rows(self.T_DKIMS)
        spf_rows = self.get_rows(self.T_SPFS)

        dkim_domain_ids = {
            _safe_str(r.get("email_domain_id"))
            for r in dkim_rows
            if _safe_str(r.get("email_domain_id")) and _safe_str(r.get("lifecycle_state")).upper() == "ACTIVE"
        }
        spf_domain_ids = {
            _safe_str(r.get("email_domain_id"))
            for r in spf_rows
            if _safe_str(r.get("email_domain_id")) and _safe_str(r.get("lifecycle_state")).upper() == "ACTIVE"
        }

        for r in domain_rows:
            cid = _safe_str(r.get("compartment_id"))
            did = _safe_str(r.get("id"))
            if not cid or not did:
                continue
            if _safe_str(r.get("lifecycle_state")).upper() not in ("", "ACTIVE"):
                continue

            loc = _loc_base(compartment_id=cid, entity_id=did)
            if did not in dkim_domain_ids:
                res.findings.append(
                    self.finding(
                        table_name=self.T_DOMAINS,
                        issue_code="EMAIL_DOMAIN_DKIM_MISSING",
                        title="Email domain has no active DKIM",
                        severity="MEDIUM",
                        description=_wrap_paragraph(
                            "Domain has no active DKIM configuration, which can weaken sender authenticity guarantees."
                        ),
                        location=loc,
                        row=r,
                        recommended_module="modules run enum_email --domains --dkims",
                        notes=_wrap_paragraph(
                            "Remediation: configure and enable DKIM for each sending domain."
                        ),
                    )
                )

            if did not in spf_domain_ids:
                res.findings.append(
                    self.finding(
                        table_name=self.T_DOMAINS,
                        issue_code="EMAIL_DOMAIN_SPF_MISSING",
                        title="Email domain has no active SPF",
                        severity="MEDIUM",
                        description=_wrap_paragraph(
                            "Domain has no active SPF configuration, which can increase spoofing risk."
                        ),
                        location=loc,
                        row=r,
                        recommended_module="modules run enum_email --domains --spfs",
                        notes=_wrap_paragraph(
                            "Remediation: configure SPF records for authorized sending infrastructure."
                        ),
                    )
                )

    def _check_unverified_senders(self, res: ServiceAuditResult) -> None:
        rows = self.get_rows(self.T_SENDERS)
        for r in rows:
            cid = _safe_str(r.get("compartment_id"))
            sid = _safe_str(r.get("id"))
            if not cid or not sid:
                continue
            if _truthy_str(r.get("is_email_verified")):
                continue
            loc = _loc_base(compartment_id=cid, entity_id=sid)
            res.findings.append(
                self.finding(
                    table_name=self.T_SENDERS,
                    issue_code="EMAIL_SENDER_NOT_VERIFIED",
                    title="Email sender identity is not verified",
                    severity="MEDIUM",
                    description=_wrap_paragraph(
                        "Sender identity is unverified and may fail anti-spoofing controls or operational checks."
                    ),
                    location=loc,
                    row=r,
                    recommended_module="modules run enum_email --senders",
                    notes=_wrap_paragraph("Remediation: verify sender identities before operational use."),
                )
            )

    def _check_plaintext_submit_endpoints(self, res: ServiceAuditResult) -> None:
        rows = self.get_rows(self.T_CONFIG)
        for r in rows:
            cid = _safe_str(r.get("compartment_id"))
            if not cid:
                continue

            http_ep = _safe_str(r.get("http_submit_endpoint")).strip().lower()
            smtp_ep = _safe_str(r.get("smtp_submit_endpoint")).strip().lower()
            if not http_ep.startswith("http://") and not smtp_ep.startswith("http://"):
                continue

            loc = _loc_base(compartment_id=cid, entity_id=cid)
            res.findings.append(
                self.finding(
                    table_name=self.T_CONFIG,
                    issue_code="EMAIL_SUBMIT_ENDPOINT_PLAINTEXT",
                    title="Email submit endpoint appears to use plaintext HTTP",
                    severity="MEDIUM",
                    description=_wrap_paragraph(
                        "One or more submit endpoints appear to use plaintext HTTP transport."
                    ),
                    location=loc,
                    row=r,
                    recommended_module="modules run enum_email --email-configuration",
                    notes=_wrap_paragraph("Remediation: enforce TLS-enabled submit endpoints."),
                )
            )


class CacheServiceAuditor(ServiceAuditor):
    service = "cache"

    T_CLUSTERS = "cache_clusters"
    T_USERS = "cache_users"

    def run_checks(self) -> ServiceAuditResult:
        res = ServiceAuditResult(service=self.service)
        try:
            self._check_clusters_without_nsg(res)
        except Exception as e:
            res.errors.append(f"clusters_without_nsg: {type(e).__name__}: {e}")
        try:
            self._check_public_cluster_endpoints(res)
        except Exception as e:
            res.errors.append(f"public_cluster_endpoints: {type(e).__name__}: {e}")
        try:
            self._check_weak_user_auth_mode(res)
        except Exception as e:
            res.errors.append(f"weak_user_auth_mode: {type(e).__name__}: {e}")
        return res

    def _check_clusters_without_nsg(self, res: ServiceAuditResult) -> None:
        rows = self.get_rows(self.T_CLUSTERS, where_conditions={"lifecycle_state": "ACTIVE"})
        for r in rows:
            cid = _safe_str(r.get("compartment_id"))
            cluster_id = _safe_str(r.get("id"))
            if not cid or not cluster_id:
                continue
            nsg_ids = _as_json_list(r.get("nsg_ids"))
            if nsg_ids:
                continue
            loc = _loc_base(compartment_id=cid, entity_id=cluster_id, subnet_id=_safe_str(r.get("subnet_id")) or None)
            res.findings.append(
                self.finding(
                    table_name=self.T_CLUSTERS,
                    issue_code="CACHE_CLUSTER_NO_NSG",
                    title="Cache cluster has no NSG attachments",
                    severity="MEDIUM",
                    description=_wrap_paragraph(
                        "Cache cluster has no NSGs configured, reducing network-level traffic filtering."
                    ),
                    location=loc,
                    row=r,
                    recommended_module="modules run enum_all",
                    notes=_wrap_paragraph("Remediation: attach restrictive NSGs to cache clusters."),
                )
            )

    def _check_public_cluster_endpoints(self, res: ServiceAuditResult) -> None:
        rows = self.get_rows(self.T_CLUSTERS, where_conditions={"lifecycle_state": "ACTIVE"})
        endpoint_fields = (
            "primary_endpoint_ip_address",
            "discovery_endpoint_ip_address",
            "replicas_endpoint_ip_address",
        )
        for r in rows:
            cid = _safe_str(r.get("compartment_id"))
            cluster_id = _safe_str(r.get("id"))
            if not cid or not cluster_id:
                continue

            exposed = False
            for field_name in endpoint_fields:
                ip = _safe_str(r.get(field_name)).strip()
                if not ip:
                    continue
                if _is_ipv4(ip) and not _is_private_ipv4(ip):
                    exposed = True
                    break
            if not exposed:
                continue

            loc = _loc_base(compartment_id=cid, entity_id=cluster_id, subnet_id=_safe_str(r.get("subnet_id")) or None)
            res.findings.append(
                self.finding(
                    table_name=self.T_CLUSTERS,
                    issue_code="CACHE_CLUSTER_PUBLIC_ENDPOINT_IP",
                    title="Cache cluster endpoint appears publicly routable",
                    severity="HIGH",
                    description=_wrap_paragraph(
                        "Cache endpoint IP appears outside RFC1918 private ranges."
                    ),
                    location=loc,
                    row=r,
                    recommended_module="modules run enum_all",
                    notes=_wrap_paragraph("Remediation: place cache endpoints on private subnets only."),
                )
            )

    def _check_weak_user_auth_mode(self, res: ServiceAuditResult) -> None:
        # authentication_mode is a nested object on OciCacheUser (e.g.
        # {"authentication_type": "PASSWORD", "hashed_passwords": [...]} or
        # {"authentication_type": "IAM"}), persisted as a JSON string -- it is never
        # a bare "NONE"/"DISABLED" token. Detect an effectively passwordless
        # (Redis ACL "nopass") user via the actual PASSWORD-with-no-hashes shape
        # and/or a literal "nopass" token in acl_string, rather than string-matching
        # a shape this field never takes.
        rows = self.get_rows(self.T_USERS, where_conditions={"lifecycle_state": "ACTIVE"})
        for r in rows:
            cid = _safe_str(r.get("compartment_id"))
            uid = _safe_str(r.get("id"))
            if not cid or not uid:
                continue

            status = _safe_str(r.get("status")).strip().upper()
            if status and status != "ON":
                continue

            auth_mode = as_json_dict(r.get("authentication_mode"))
            auth_type = _safe_str(auth_mode.get("authentication_type")).strip().upper()
            hashed_passwords = _as_json_list(auth_mode.get("hashed_passwords"))
            acl_string = _safe_str(r.get("acl_string")).lower()

            is_nopass = (auth_type == "PASSWORD" and not hashed_passwords) or ("nopass" in acl_string)
            if not is_nopass:
                continue

            name = _safe_str(r.get("name")) or uid
            loc = _loc_base(compartment_id=cid, entity_id=uid)
            res.findings.append(
                self.finding(
                    table_name=self.T_USERS,
                    issue_code="CACHE_USER_WEAK_AUTH_MODE",
                    title="Cache user is enabled with no password (nopass)",
                    severity="CRITICAL",
                    description=_wrap_paragraph(
                        f"""
                        Cache user "{name}" has status=ON with no password configured (PASSWORD
                        authentication_mode with zero hashed_passwords, and/or "nopass" in its ACL string). Any
                        client that can reach the cluster's endpoint on the network can authenticate as this
                        user with no credential at all.
                        """
                    ),
                    location=loc,
                    row=r,
                    recommended_module="modules run enum_databases --cache-users --get",
                    notes=_wrap_paragraph(
                        "Remediation: set a password (hashed_passwords) for this user, switch it to IAM "
                        "authentication_mode, or disable it (status=OFF) if unused."
                    ),
                )
            )


class ManagedKafkaServiceAuditor(ServiceAuditor):
    service = "managed_kafka"

    T_CLUSTERS = "kafka_clusters"

    def run_checks(self) -> ServiceAuditResult:
        res = ServiceAuditResult(service=self.service)
        try:
            self._check_plaintext_bootstrap(res)
        except Exception as e:
            res.errors.append(f"plaintext_bootstrap: {type(e).__name__}: {e}")
        try:
            self._check_missing_auth_secret(res)
        except Exception as e:
            res.errors.append(f"missing_auth_secret: {type(e).__name__}: {e}")
        return res

    def _check_plaintext_bootstrap(self, res: ServiceAuditResult) -> None:
        # kafka_bootstrap_urls is list[BootstrapUrl] ({"name": ..., "url": "host:port"}),
        # GET-only (absent from KafkaClusterSummary/list). It is NOT a comma-delimited
        # string of "protocol://host:port" entries -- parse it as the JSON list it
        # actually is and inspect each entry's listener name/url.
        rows = self.get_rows(self.T_CLUSTERS, where_conditions={"lifecycle_state": "ACTIVE"})
        for r in rows:
            cid = _safe_str(r.get("compartment_id"))
            cluster_id = _safe_str(r.get("id"))
            if not cid or not cluster_id:
                continue

            raw_urls = r.get("kafka_bootstrap_urls")
            if raw_urls is None:
                continue
            entries = _as_json_list(raw_urls)
            if not entries:
                continue
            plaintext = False
            for entry in entries:
                if not isinstance(entry, dict):
                    continue
                name = _safe_str(entry.get("name")).strip().lower()
                url = _safe_str(entry.get("url")).strip().lower()
                if "plaintext" in name or ":9092" in url:
                    plaintext = True
                    break
            if not plaintext:
                continue

            loc = _loc_base(compartment_id=cid, entity_id=cluster_id)
            res.findings.append(
                self.finding(
                    table_name=self.T_CLUSTERS,
                    issue_code="KAFKA_PLAINTEXT_BOOTSTRAP_URL",
                    title="Managed Kafka bootstrap URL indicates plaintext listener",
                    severity="MEDIUM",
                    description=_wrap_paragraph(
                        "Bootstrap URL appears to include plaintext listener semantics (for example port 9092)."
                    ),
                    location=loc,
                    row=r,
                    recommended_module="modules run enum_managedkafka --clusters --get",
                    notes=_wrap_paragraph(
                        "Remediation: prefer TLS-enabled listeners and enforce authenticated client access."
                    ),
                )
            )

    def _check_missing_auth_secret(self, res: ServiceAuditResult) -> None:
        rows = self.get_rows(self.T_CLUSTERS, where_conditions={"lifecycle_state": "ACTIVE"})
        for r in rows:
            cid = _safe_str(r.get("compartment_id"))
            cluster_id = _safe_str(r.get("id"))
            if not cid or not cluster_id:
                continue

            # secret_id/client_certificate_bundle are GET-only (absent from
            # KafkaClusterSummary/list, always None together with kafka_bootstrap_urls
            # on a list-only row) -- without --get, "not configured" is indistinguishable
            # from "not looked at", so skip rather than false-positive.
            if r.get("kafka_bootstrap_urls") is None:
                continue

            secret_id = _safe_str(r.get("secret_id"))
            cert_bundle = _safe_str(r.get("client_certificate_bundle"))
            if secret_id or cert_bundle:
                continue

            loc = _loc_base(compartment_id=cid, entity_id=cluster_id)
            res.findings.append(
                self.finding(
                    table_name=self.T_CLUSTERS,
                    issue_code="KAFKA_AUTH_MATERIAL_NOT_CONFIGURED",
                    title="Managed Kafka cluster has no recorded auth secret/certificate bundle",
                    severity="MEDIUM",
                    description=_wrap_paragraph(
                        "No client auth secret or certificate bundle is recorded for this cluster."
                    ),
                    location=loc,
                    row=r,
                    recommended_module="modules run enum_managedkafka --clusters --get",
                    notes=_wrap_paragraph("Remediation: configure authenticated client access paths."),
                )
            )


class DevOpsServiceAuditor(ServiceAuditor):
    service = "devops"

    T_REPOSITORIES = "devops_repositories"

    def run_checks(self) -> ServiceAuditResult:
        res = ServiceAuditResult(service=self.service)
        try:
            self._check_plaintext_repository_urls(res)
        except Exception as e:
            res.errors.append(f"plaintext_repository_urls: {type(e).__name__}: {e}")
        return res

    def _check_plaintext_repository_urls(self, res: ServiceAuditResult) -> None:
        rows = self.get_rows(self.T_REPOSITORIES)
        for r in rows:
            cid = _safe_str(r.get("compartment_id"))
            rid = _safe_str(r.get("id"))
            if not cid or not rid:
                continue
            http_url = _safe_str(r.get("http_url")).strip().lower()
            repo_url = _safe_str(r.get("repository_url")).strip().lower()
            if not http_url.startswith("http://") and not repo_url.startswith("http://"):
                continue

            loc = _loc_base(compartment_id=cid, entity_id=rid, project_id=_safe_str(r.get("project_id")) or None)
            res.findings.append(
                self.finding(
                    table_name=self.T_REPOSITORIES,
                    issue_code="DEVOPS_REPOSITORY_HTTP_URL",
                    title="DevOps repository URL uses plaintext HTTP",
                    severity="MEDIUM",
                    description=_wrap_paragraph(
                        "Repository URL appears to use plaintext HTTP transport."
                    ),
                    location=loc,
                    row=r,
                    recommended_module="modules run enum_devops --repositories --get",
                    notes=_wrap_paragraph("Remediation: enforce HTTPS/SSH repository URLs."),
                )
            )


class CloudGuardServiceAuditor(ServiceAuditor):
    service = "cloud_guard"

    T_TARGETS = "cloud_guard_targets"
    T_DATA_SOURCES = "cloud_guard_data_sources"

    def run_checks(self) -> ServiceAuditResult:
        res = ServiceAuditResult(service=self.service)
        try:
            self._check_target_state(res)
        except Exception as e:
            res.errors.append(f"target_state: {type(e).__name__}: {e}")
        try:
            self._check_data_source_state(res)
        except Exception as e:
            res.errors.append(f"data_source_state: {type(e).__name__}: {e}")
        return res

    def _check_target_state(self, res: ServiceAuditResult) -> None:
        rows = self.get_rows(self.T_TARGETS)
        for r in rows:
            cid = _safe_str(r.get("compartment_id"))
            tid = _safe_str(r.get("id"))
            if not cid or not tid:
                continue
            state = _safe_str(r.get("state")).upper()
            lifecycle = _safe_str(r.get("lifecycle_state")).upper()
            if state in ("ACTIVE", "") and lifecycle in ("ACTIVE", ""):
                continue
            loc = _loc_base(
                compartment_id=cid,
                entity_id=tid,
                target_resource_id=_safe_str(r.get("target_resource_id")) or None,
            )
            res.findings.append(
                self.finding(
                    table_name=self.T_TARGETS,
                    issue_code="CLOUD_GUARD_TARGET_NOT_ACTIVE",
                    title="Cloud Guard target is not active",
                    severity="MEDIUM",
                    description=_wrap_paragraph(
                        f"Cloud Guard target state={state or 'UNKNOWN'}, lifecycle_state={lifecycle or 'UNKNOWN'}."
                    ),
                    location=loc,
                    row=r,
                    recommended_module="modules run enum_cloudguard --targets",
                    notes=_wrap_paragraph(
                        "Remediation: ensure required Cloud Guard targets are in ACTIVE state."
                    ),
                )
            )

    def _check_data_source_state(self, res: ServiceAuditResult) -> None:
        rows = self.get_rows(self.T_DATA_SOURCES)
        for r in rows:
            cid = _safe_str(r.get("compartment_id"))
            dsid = _safe_str(r.get("id"))
            if not cid or not dsid:
                continue
            lifecycle = _safe_str(r.get("lifecycle_state")).upper()
            if lifecycle in ("ACTIVE", ""):
                continue
            loc = _loc_base(compartment_id=cid, entity_id=dsid)
            res.findings.append(
                self.finding(
                    table_name=self.T_DATA_SOURCES,
                    issue_code="CLOUD_GUARD_DATA_SOURCE_NOT_ACTIVE",
                    title="Cloud Guard data source is not active",
                        severity="LOW",
                    description=_wrap_paragraph(
                        f"Cloud Guard data source lifecycle_state={lifecycle or 'UNKNOWN'}."
                    ),
                    location=loc,
                    row=r,
                    recommended_module="modules run enum_cloudguard --data-sources",
                    notes=_wrap_paragraph(
                        "Remediation: validate detector data sources are healthy and active."
                    ),
                )
            )


class ComputeInstanceAgentServiceAuditor(ServiceAuditor):
    service = "compute_instance_agent"

    T_PLUGINS = "compute_instance_agent_plugins"
    T_COMMANDS = "compute_instance_agent_commands"

    def run_checks(self) -> ServiceAuditResult:
        res = ServiceAuditResult(service=self.service)
        try:
            self._check_run_command_plugin_enabled(res)
        except Exception as e:
            res.errors.append(f"run_command_plugin: {type(e).__name__}: {e}")
        try:
            self._check_command_history_present(res)
        except Exception as e:
            res.errors.append(f"command_history: {type(e).__name__}: {e}")
        return res

    def _check_run_command_plugin_enabled(self, res: ServiceAuditResult) -> None:
        rows = self.get_rows(self.T_PLUGINS)
        for r in rows:
            instance_id = _safe_str(r.get("instance_id"))
            name = _safe_str(r.get("name")).strip()
            status = _safe_str(r.get("status")).upper()
            if not instance_id or "RUN COMMAND" not in name.upper():
                continue
            if status not in ("RUNNING", "ENABLED"):
                continue

            loc = _loc_base(
                compartment_id=_safe_str(r.get("compartment_id")) or "unknown",
                entity_id=instance_id,
                plugin_name=name or None,
            )
            res.findings.append(
                self.finding(
                    table_name=self.T_PLUGINS,
                    issue_code="INSTANCE_AGENT_RUN_COMMAND_ENABLED",
                    title="Compute Instance Run Command plugin is enabled",
                    severity="INFO",
                    description=_wrap_paragraph(
                        "Run Command plugin is enabled, which expands remote command-execution surface."
                    ),
                    location=loc,
                    row=r,
                    recommended_module="modules run enum_core_compute --instance-agent-plugins --get",
                    notes=_wrap_paragraph(
                        "Remediation: disable Run Command where not required and tightly scope IAM permissions "
                        "(`instance-agent-command-family`, `instance-agent-command-execution-family`)."
                    ),
                )
            )

    def _check_command_history_present(self, res: ServiceAuditResult) -> None:
        rows = self.get_rows(self.T_COMMANDS)
        for r in rows:
            cmd_id = _safe_str(r.get("id"))
            instance_id = _safe_str(r.get("target_instance_id"))
            if not cmd_id or not instance_id:
                continue
            loc = _loc_base(
                compartment_id=_safe_str(r.get("compartment_id")) or "unknown",
                entity_id=cmd_id,
                target_instance_id=instance_id,
            )
            res.findings.append(
                self.finding(
                    table_name=self.T_COMMANDS,
                    issue_code="INSTANCE_AGENT_COMMAND_HISTORY_PRESENT",
                    title="Instance agent command history exists",
                    severity="INFO",
                    description=_wrap_paragraph(
                        "Instance has recorded Run Command activity. Review command content/output for sensitive operations."
                    ),
                    location=loc,
                    row=r,
                    recommended_module="modules run enum_core_compute --instance-agent-commands --instance-agent-command-executions --get --download",
                    notes=_wrap_paragraph("Remediation: monitor and restrict who can submit instance agent commands."),
                )
            )


class GoldenGateServiceAuditor(ServiceAuditor):
    service = "goldengate"

    T_CONNECTIONS = "goldengate_connections"

    def run_checks(self) -> ServiceAuditResult:
        res = ServiceAuditResult(service=self.service)
        try:
            self._check_plaintext_credentials(res)
        except Exception as e:
            res.errors.append(f"connections: {type(e).__name__}: {e}")
        return res

    def _check_plaintext_credentials(self, res: ServiceAuditResult) -> None:
        rows = self.get_rows(self.T_CONNECTIONS)
        for r in rows:
            cid = _safe_str(r.get("compartment_id"))
            conn_id = _safe_str(r.get("id"))
            if not cid or not conn_id:
                continue
            username = _safe_str(r.get("username"))
            if not username:
                continue
            # Vault-backed credentials reference a KMS key + vault; missing
            # either implies the secret is supplied/stored outside Vault.
            if _safe_str(r.get("vault_id")) and _safe_str(r.get("key_id")):
                continue
            loc = _loc_base(compartment_id=cid, entity_id=conn_id)
            res.findings.append(
                self.finding(
                    table_name=self.T_CONNECTIONS,
                    issue_code="GOLDENGATE_CONNECTION_PLAINTEXT_CREDENTIAL",
                    title="GoldenGate connection credential is not Vault-backed",
                    severity="MEDIUM",
                    description=_wrap_paragraph(
                        """
                        The GoldenGate connection defines a username but does not reference a Vault
                        secret (missing vault_id and/or key_id), indicating the credential is not
                        protected by OCI Vault.
                        """
                    ),
                    location=loc,
                    row=r,
                    recommended_module="modules run enum_goldengate --connections --get",
                    notes=_wrap_paragraph(
                        "Remediation: store connection credentials in OCI Vault and reference them via vault_id/key_id."
                    ),
                )
            )

# -----------------------------------------------------------------------------
# DataIntegration service auditor (gap-fill)
# -----------------------------------------------------------------------------

class DataIntegrationServiceAuditor(ServiceAuditor):
    service = "data_integration"

    T_WORKSPACES = "data_integration_workspaces"

    def run_checks(self) -> ServiceAuditResult:
        res = ServiceAuditResult(service=self.service)
        try:
            self._check_workspaces_not_private_network(res)
        except Exception as e:
            res.errors.append(f"workspaces_not_private_network: {type(e).__name__}: {e}")
        return res

    def _check_workspaces_not_private_network(self, res: ServiceAuditResult) -> None:
        rows = self.get_rows(self.T_WORKSPACES, where_conditions={"lifecycle_state": "ACTIVE"})
        for r in rows:
            cid = _safe_str(r.get("compartment_id"))
            wid = _safe_str(r.get("id"))
            if not cid or not wid:
                continue

            if not _falsy_str(r.get("is_private_network_enabled")):
                continue

            loc = _loc_base(compartment_id=cid, entity_id=wid)
            res.findings.append(
                self.finding(
                    table_name=self.T_WORKSPACES,
                    issue_code="DATAINTEGRATION_WORKSPACE_NOT_PRIVATE_NETWORK",
                    title="Data Integration workspace does not use a private network",
                    severity="MEDIUM",
                    description=_wrap_paragraph(
                        """
                        Workspace has private network connectivity disabled, so it relies on Data
                        Integration's default public network path to reach data sources rather than a
                        customer VCN/subnet with a dedicated private endpoint. Per Oracle's OCI Data
                        Integration docs, private network mode keeps data-source connectivity inside the
                        VCN and, once enabled at creation, cannot later be disabled -- making this a
                        stable, low-noise signal rather than a transient toggle.
                        """
                    ),
                    location=loc,
                    row=r,
                    recommended_module="modules run enum_dataintegration --workspaces --get",
                    notes=_wrap_paragraph(
                        """
                        Remediation: prefer private network connectivity where source connectivity
                        permits, mirroring the existing public-endpoint guidance for other services. This
                        is remediation guidance rather than an absolute violation, since some workspaces
                        legitimately only integrate public/SaaS sources.
                        """
                    ),
                )
            )


# -----------------------------------------------------------------------------
# analytics service auditor (gap-fill)
# -----------------------------------------------------------------------------

class AnalyticsServiceAuditor(ServiceAuditor):
    service = "analytics"

    T_INSTANCES = "analytics_instances"

    def run_checks(self) -> ServiceAuditResult:
        res = ServiceAuditResult(service=self.service)
        try:
            self._check_public_endpoint_no_access_control(res)
        except Exception as e:
            res.errors.append(f"public_endpoint_no_access_control: {type(e).__name__}: {e}")

        try:
            self._check_public_endpoint_open_cidr_allowlist(res)
        except Exception as e:
            res.errors.append(f"public_endpoint_open_cidr_allowlist: {type(e).__name__}: {e}")

        return res

    def _check_public_endpoint_no_access_control(self, res: ServiceAuditResult) -> None:
        rows = self.get_rows(self.T_INSTANCES, where_conditions={"lifecycle_state": "ACTIVE"})
        for r in rows:
            cid = _safe_str(r.get("compartment_id"))
            inst_id = _safe_str(r.get("id"))
            if not cid or not inst_id:
                continue

            net = as_json_dict(r.get("network_endpoint_details"))
            if _safe_str(net.get("network_endpoint_type")).upper() != "PUBLIC":
                continue

            whitelisted_ips = _as_json_list(net.get("whitelisted_ips"))
            whitelisted_vcns = _as_json_list(net.get("whitelisted_vcns"))
            whitelisted_services = _as_json_list(net.get("whitelisted_services"))

            if whitelisted_ips or whitelisted_vcns or whitelisted_services:
                continue

            loc = _loc_base(compartment_id=cid, entity_id=inst_id)
            res.findings.append(
                self.finding(
                    table_name=self.T_INSTANCES,
                    issue_code="ANALYTICS_PUBLIC_ENDPOINT_NO_ACCESS_CONTROL",
                    title="Public Analytics Cloud instance has no access control rules configured",
                    severity="MEDIUM",
                    description=_wrap_paragraph(
                        """
                        The instance uses a PUBLIC network endpoint (network_endpoint_details.network_endpoint_type)
                        with zero ingress access-control rules configured -- whitelisted_ips, whitelisted_vcns, and
                        whitelisted_services are all empty or null. Per OCI's own documentation, Public Access Type
                        combined with Access Control set to "Not Configured" means the instance is accessible through
                        the public endpoint without restriction: all networks, including the Internet, have access.
                        This is not merely weak protection -- it is equivalent to no access control at all.
                        """
                    ),
                    location=loc,
                    row=r,
                    recommended_module="modules run enum_analytics --instances",
                    notes=_wrap_paragraph(
                        """
                        Remediation: add ingress access-control rules (IP/CIDR, VCN, or Oracle-service allowlist, up
                        to 20 rules total) via UpdateAnalyticsInstance or the console, or migrate the instance to a
                        PRIVATE network endpoint if internet-facing access is not required.
                        """
                    ),
                )
            )

    def _check_public_endpoint_open_cidr_allowlist(self, res: ServiceAuditResult) -> None:
        rows = self.get_rows(self.T_INSTANCES, where_conditions={"lifecycle_state": "ACTIVE"})
        for r in rows:
            cid = _safe_str(r.get("compartment_id"))
            inst_id = _safe_str(r.get("id"))
            if not cid or not inst_id:
                continue

            net = as_json_dict(r.get("network_endpoint_details"))
            if _safe_str(net.get("network_endpoint_type")).upper() != "PUBLIC":
                continue

            whitelisted_ips = _as_json_list(net.get("whitelisted_ips"))
            if not whitelisted_ips or not any(_is_public_cidr(ip) for ip in whitelisted_ips):
                continue

            loc = _loc_base(compartment_id=cid, entity_id=inst_id)
            res.findings.append(
                self.finding(
                    table_name=self.T_INSTANCES,
                    issue_code="ANALYTICS_PUBLIC_ENDPOINT_OPEN_CIDR_ALLOWLIST",
                    title="Public Analytics Cloud instance allowlists 0.0.0.0/0 (or ::/0)",
                    severity="MEDIUM",
                    description=_wrap_paragraph(
                        """
                        The instance's public-endpoint ingress allowlist (whitelisted_ips) contains a wide-open
                        CIDR entry (0.0.0.0/0, ::/0, or an equivalent any/all wildcard), which is functionally
                        equivalent to having no access control despite an operator having explicitly configured a
                        rule. This is distinct from the "no rules at all" finding because the instance does have
                        entries in whitelisted_ips, so an emptiness check alone would not catch it.
                        """
                    ),
                    location=loc,
                    row=r,
                    recommended_module="modules run enum_analytics --instances",
                    notes=_wrap_paragraph(
                        """
                        Remediation: replace the 0.0.0.0/0-style entry with specific IP/CIDR ranges scoped to known
                        client networks, or remove public exposure entirely by migrating to a PRIVATE network
                        endpoint.
                        """
                    ),
                )
            )


# -----------------------------------------------------------------------------
# apiaccesscontrol service auditor (gap-fill)
# -----------------------------------------------------------------------------

# -----------------------------------------------------------------------------
# Privileged API Access Control service auditor
# -----------------------------------------------------------------------------

class ApiAccessControlServiceAuditor(ServiceAuditor):
    service = "apiaccesscontrol"

    T_CONTROLS = "apiaccesscontrol_controls"
    T_REQUESTS = "apiaccesscontrol_requests"

    _LIVE_STATES = ("APPROVED", "APPROVED_FOR_FUTURE", "DEPLOYED")
    _PENDING_STATES = ("CREATED", "APPROVAL_WAITING")

    def run_checks(self) -> ServiceAuditResult:
        res = ServiceAuditResult(service=self.service)
        try:
            self._check_requests_live_access(res)
        except Exception as e:
            res.errors.append(f"requests_live_access: {type(e).__name__}: {e}")

        try:
            self._check_requests_pending_approval(res)
        except Exception as e:
            res.errors.append(f"requests_pending_approval: {type(e).__name__}: {e}")

        try:
            self._check_controls_single_approver(res)
        except Exception as e:
            res.errors.append(f"controls_single_approver: {type(e).__name__}: {e}")

        return res

    def _request_loc(self, r: Dict[str, Any]) -> Dict[str, Any]:
        cid = _safe_str(r.get("compartment_id"))
        rid = _safe_str(r.get("id"))
        return _loc_base(
            compartment_id=cid,
            entity_id=rid,
            resource_id=(_safe_str(r.get("resource_id")) or None),
            resource_type=(_safe_str(r.get("resource_type")) or None),
        )

    def _check_requests_live_access(self, res: ServiceAuditResult) -> None:
        rows = self.get_rows(self.T_REQUESTS)
        for r in rows:
            cid = _safe_str(r.get("compartment_id"))
            rid = _safe_str(r.get("id"))
            if not cid or not rid:
                continue

            state = _safe_str(r.get("state")).upper()
            if state not in self._LIVE_STATES:
                continue

            res.findings.append(
                self.finding(
                    table_name=self.T_REQUESTS,
                    issue_code="APIACCESSCONTROL_REQUEST_ACCESS_LIVE",
                    title="Privileged API access request currently grants live/deployed access",
                    severity="MEDIUM",
                    description=_wrap_paragraph(
                        """
                        Request state is APPROVED, APPROVED_FOR_FUTURE, or DEPLOYED, meaning an operator/caller
                        currently holds -- or is imminently scheduled to hold -- live privileged API access to
                        resource_id for up to duration_in_hrs hours. OCI's Privileged API Access Control admin
                        guide instructs proactively revoking access if the justification is no longer valid or
                        a concern arises.
                        """
                    ),
                    location=self._request_loc(r),
                    row=r,
                    recommended_module="modules run enum_apiaccesscontrol --requests",
                    notes=_wrap_paragraph(
                        """
                        Remediation: correlate resource_id/resource_type and severity (SEV_1/SEV_2 warrant
                        faster triage) against expected change windows, and revoke unexpected or stale grants
                        if the justification no longer holds.
                        """
                    ),
                )
            )

    def _check_requests_pending_approval(self, res: ServiceAuditResult) -> None:
        rows = self.get_rows(self.T_REQUESTS)
        for r in rows:
            cid = _safe_str(r.get("compartment_id"))
            rid = _safe_str(r.get("id"))
            if not cid or not rid:
                continue

            state = _safe_str(r.get("state")).upper()
            if state not in self._PENDING_STATES:
                continue

            res.findings.append(
                self.finding(
                    table_name=self.T_REQUESTS,
                    issue_code="APIACCESSCONTROL_REQUEST_PENDING_APPROVAL",
                    title="Privileged API access request awaiting an approval decision",
                    severity="LOW",
                    description=_wrap_paragraph(
                        """
                        Request state is CREATED or APPROVAL_WAITING -- an open access-request decision not yet
                        acted on by an approver group. OCI's own admin guide calls out managing pending/
                        unattended requests and reminding approvers as a required operational practice, since an
                        unattended request can silently expire or be acted on too late.
                        """
                    ),
                    location=self._request_loc(r),
                    row=r,
                    recommended_module="modules run enum_apiaccesscontrol --requests",
                    notes=_wrap_paragraph(
                        """
                        Remediation: surface these for prompt approve/reject action by the designated approver
                        group rather than letting them age out.
                        """
                    ),
                )
            )

    def _check_controls_single_approver(self, res: ServiceAuditResult) -> None:
        rows = self.get_rows(self.T_CONTROLS, where_conditions={"lifecycle_state": "ACTIVE"})
        for r in rows:
            cid = _safe_str(r.get("compartment_id"))
            ctl_id = _safe_str(r.get("id"))
            if not cid or not ctl_id:
                continue

            approvers = _as_int(r.get("number_of_approvers"), default=1)
            if approvers > 1:
                continue

            loc = _loc_base(
                compartment_id=cid,
                entity_id=ctl_id,
                resource_type=(_safe_str(r.get("resource_type")) or None),
            )
            res.findings.append(
                self.finding(
                    table_name=self.T_CONTROLS,
                    issue_code="APIACCESSCONTROL_CONTROL_SINGLE_APPROVER",
                    title="Privileged API control does not require dual (second) approval",
                    severity="LOW",
                    description=_wrap_paragraph(
                        """
                        ACTIVE control has number_of_approvers <= 1, so only a single identity is needed to
                        approve a privileged access request -- no segregation-of-duties/dual-control. OCI
                        documents a "Requires Second Approval" setting (number_of_approvers=2) specifically to
                        require two distinct identities and block the cloud administrator from self-approving,
                        and states this is best practice for sensitive infrastructure such as Exadata.
                        """
                    ),
                    location=loc,
                    row=r,
                    recommended_module="modules run enum_apiaccesscontrol --controls",
                    notes=_wrap_paragraph(
                        """
                        Remediation: raise number_of_approvers to 2 for controls guarding high-value
                        resource_type entries so a single approver cannot unilaterally grant privileged access.
                        """
                    ),
                )
            )


# -----------------------------------------------------------------------------
# bds service auditor (gap-fill)
# -----------------------------------------------------------------------------

class BdsServiceAuditor(ServiceAuditor):
    service = "bds"

    T_BDS_INSTANCES = "bds_instances"

    def run_checks(self) -> ServiceAuditResult:
        res = ServiceAuditResult(service=self.service)
        try:
            self._check_cluster_not_secure(res)
        except Exception as e:
            res.errors.append(f"cluster_not_secure: {type(e).__name__}: {e}")

        return res

    def _check_cluster_not_secure(self, res: ServiceAuditResult) -> None:
        rows = self.get_rows(self.T_BDS_INSTANCES, where_conditions={"lifecycle_state": "ACTIVE"})
        for r in rows:
            cid = _safe_str(r.get("compartment_id")) or _safe_str(r.get("compartment_ocid"))
            bid = _safe_str(r.get("id"))
            if not cid or not bid:
                continue

            if _falsy_str(r.get("is_secure")):
                loc = _loc_base(compartment_id=cid, entity_id=bid)
                res.findings.append(
                    self.finding(
                        table_name=self.T_BDS_INSTANCES,
                        issue_code="BDS_CLUSTER_NOT_SECURE",
                        title="Big Data Service cluster created without Kerberos/Sentry/HDFS encryption (non-secure)",
                        severity="HIGH",
                        description=_wrap_paragraph(
                            """
                            The BDS cluster was provisioned without the 'Secure & highly available' option, so it
                            has no Kerberos authentication, no Apache Sentry authorization, and no HDFS Transparent
                            Encryption at rest. Any principal with network reachability to the cluster's Hadoop/Spark
                            services (HDFS, YARN, Hive) can act as an arbitrary Hadoop user with no authentication
                            required.
                            """
                        ),
                        location=loc,
                        row=r,
                        recommended_module="modules run enum_bds --bds-instances --get",
                        notes=_wrap_paragraph(
                            """
                            This setting cannot be changed on an existing cluster -- remediation requires
                            recreating the cluster with the 'Secure & highly available' option enabled
                            (is_secure=true). In the interim, restrict VCN/subnet security list and network
                            security group rules to limit network reachability to this cluster's Hadoop/Spark
                            service ports.
                            """
                        ),
                    )
                )


# -----------------------------------------------------------------------------
# certificates service auditor (gap-fill)
# -----------------------------------------------------------------------------

class CertificatesServiceAuditor(ServiceAuditor):
    service = "certificates"

    T_CERTIFICATES = "certificates"
    T_CERTIFICATE_AUTHORITIES = "certificate_authorities"

    _TERMINAL_LIFECYCLE_STATES = ("DELETED", "FAILED")

    _ROOT_CA_CONFIG_TYPES = (
        "ROOT_CA_GENERATED_INTERNALLY",
        "ROOT_CA_MANAGED_EXTERNALLY",
    )

    def run_checks(self) -> ServiceAuditResult:
        res = ServiceAuditResult(service=self.service)
        try:
            self._check_leaf_issued_by_root_ca(res)
        except Exception as e:
            res.errors.append(f"leaf_issued_by_root_ca: {type(e).__name__}: {e}")

        return res

    def _check_leaf_issued_by_root_ca(self, res: ServiceAuditResult) -> None:
        row_certificates = self.get_rows(self.T_CERTIFICATES)
        row_authorities = self.get_rows(self.T_CERTIFICATE_AUTHORITIES)

        # Index non-terminal CAs by id so certificates can resolve their issuer.
        ca_by_id: Dict[str, Dict[str, Any]] = {}
        for ca in row_authorities:
            ca_state = _safe_str(ca.get("lifecycle_state")).upper()
            if ca_state in self._TERMINAL_LIFECYCLE_STATES:
                continue
            ca_id = _safe_str(ca.get("id"))
            if not ca_id:
                continue
            ca_by_id[ca_id] = ca

        for cert in row_certificates:
            cert_state = _safe_str(cert.get("lifecycle_state")).upper()
            if cert_state in self._TERMINAL_LIFECYCLE_STATES:
                continue

            cid = _safe_str(cert.get("compartment_id")) or _safe_str(cert.get("compartment_ocid"))
            cert_id = _safe_str(cert.get("id"))
            issuer_id = _safe_str(cert.get("issuer_certificate_authority_id"))
            if not cid or not cert_id or not issuer_id:
                continue

            issuer_ca = ca_by_id.get(issuer_id)
            if not issuer_ca:
                continue

            issuer_config_type = _safe_str(issuer_ca.get("config_type")).upper()
            if issuer_config_type not in self._ROOT_CA_CONFIG_TYPES:
                continue

            loc = _loc_base(compartment_id=cid, entity_id=cert_id)
            res.findings.append(
                self.finding(
                    table_name=self.T_CERTIFICATES,
                    issue_code="CERTIFICATES_LEAF_ISSUED_BY_ROOT_CA",
                    title="Leaf certificate issued directly by a Root CA",
                    severity="MEDIUM",
                    description=_wrap_paragraph(
                        """
                        The certificate's issuer is a Root CA rather than an intermediate/issuing
                        (subordinate) CA. Root CAs are the trust anchor for the whole hierarchy and
                        OCI's own CA guidance states they should be used only to sign subordinate CA
                        certificates, kept under strict access controls, and not exercised for
                        routine leaf issuance. Direct root-to-leaf issuance widens the root's
                        usage/exposure surface and removes the ability to revoke or rotate a
                        compromised issuing path without invalidating the trust anchor itself.
                        """
                    ),
                    location=loc,
                    row=cert,
                    recommended_module="modules run enum_certificates --certificates --certificate_authorities",
                    notes=_wrap_paragraph(
                        """
                        Remediation: create a subordinate (issuing) CA under the root, reissue
                        affected certificates from it, and restrict the root CA to signing
                        subordinate CA certificates only. Issuer CA: {issuer_id} (config_type:
                        {issuer_config_type}).
                        """.format(issuer_id=issuer_id, issuer_config_type=issuer_config_type)
                    ),
                )
            )


# -----------------------------------------------------------------------------
# data_catalog service auditor (gap-fill)
# -----------------------------------------------------------------------------

class DataCatalogServiceAuditor(ServiceAuditor):
    service = "data_catalog"

    T_PRIVATE_ENDPOINTS = "data_catalog_private_endpoints"
    _DEAD_ENDPOINT_STATES = {"DELETED", "DELETING", "FAILED"}

    def run_checks(self) -> ServiceAuditResult:
        res = ServiceAuditResult(service=self.service)
        try:
            self._check_private_endpoint_subnet(res)
        except Exception as e:
            res.errors.append(f"private_endpoint_subnet: {type(e).__name__}: {e}")
        try:
            self._check_private_endpoint_dns_zones(res)
        except Exception as e:
            res.errors.append(f"private_endpoint_dns_zones: {type(e).__name__}: {e}")
        return res

    def _check_private_endpoint_subnet(self, res: ServiceAuditResult) -> None:
        rows = self.get_rows(self.T_PRIVATE_ENDPOINTS)
        for r in rows:
            if _safe_str(r.get("lifecycle_state")).upper() in self._DEAD_ENDPOINT_STATES:
                continue
            cid = _safe_str(r.get("compartment_id"))
            pe_id = _safe_str(r.get("id"))
            if not cid or not pe_id:
                continue

            subnet_id = _safe_str(r.get("subnet_id"))
            if subnet_id:
                continue

            loc = _loc_base(compartment_id=cid, entity_id=pe_id)
            res.findings.append(
                self.finding(
                    table_name=self.T_PRIVATE_ENDPOINTS,
                    issue_code="DATA_CATALOG_PRIVATE_ENDPOINT_NO_SUBNET",
                    title="Data Catalog private endpoint has no subnet reference",
                    severity="MEDIUM",
                    description=_wrap_paragraph(
                        """
                        The private endpoint row has no subnet_id, indicating incomplete or broken network
                        placement -- the private endpoint cannot securely reach VCN-hosted data sources
                        without a subnet binding.
                        """
                    ),
                    location=loc,
                    row=r,
                    recommended_module="modules run enum_data_catalog --private-endpoints --get",
                    notes=_wrap_paragraph(
                        """
                        Remediation: verify the private endpoint's subnet in the console/CLI and recreate it
                        bound to the intended private subnet if the reference is genuinely missing.
                        """
                    ),
                )
            )

    def _check_private_endpoint_dns_zones(self, res: ServiceAuditResult) -> None:
        rows = self.get_rows(self.T_PRIVATE_ENDPOINTS)
        for r in rows:
            if _safe_str(r.get("lifecycle_state")).upper() in self._DEAD_ENDPOINT_STATES:
                continue
            cid = _safe_str(r.get("compartment_id"))
            pe_id = _safe_str(r.get("id"))
            if not cid or not pe_id:
                continue

            dns_zones = _as_json_list(r.get("dns_zones"))
            if dns_zones:
                continue

            loc = _loc_base(compartment_id=cid, entity_id=pe_id)
            res.findings.append(
                self.finding(
                    table_name=self.T_PRIVATE_ENDPOINTS,
                    issue_code="DATA_CATALOG_PRIVATE_ENDPOINT_NO_DNS_ZONES",
                    title="Data Catalog private endpoint has no DNS zones configured",
                    severity="LOW",
                    description=_wrap_paragraph(
                        """
                        The private endpoint defines no DNS zones, so it cannot resolve any private FQDN/IP
                        for on-prem or VCN-hosted data sources -- the entire reason to attach a private
                        endpoint (avoiding public-network harvesting of data sources) is defeated if it
                        silently cannot resolve the intended hosts.
                        """
                    ),
                    location=loc,
                    row=r,
                    recommended_module="modules run enum_data_catalog --private-endpoints --get",
                    notes=_wrap_paragraph(
                        """
                        Remediation: add the DNS zones (VCN domain, subnet domain, or custom FQDNs) needed to
                        resolve the data source(s) this endpoint is meant to serve.
                        """
                    ),
                )
            )


# -----------------------------------------------------------------------------
# data_safe service auditor (gap-fill)
# -----------------------------------------------------------------------------

class DataSafeServiceAuditor(ServiceAuditor):
    service = "data_safe"

    T_TARGET_DATABASES = "data_safe_target_databases"
    T_SECURITY_ASSESSMENTS = "data_safe_security_assessments"
    T_USER_ASSESSMENTS = "data_safe_user_assessments"

    def run_checks(self) -> ServiceAuditResult:
        res = ServiceAuditResult(service=self.service)
        try:
            self._check_target_database_needs_attention(res)
        except Exception as e:
            res.errors.append(f"target_databases: {type(e).__name__}: {e}")

        try:
            self._check_security_assessment_baseline_deviation(res)
        except Exception as e:
            res.errors.append(f"security_assessments: {type(e).__name__}: {e}")

        try:
            self._check_user_assessment_baseline_deviation(res)
        except Exception as e:
            res.errors.append(f"user_assessments: {type(e).__name__}: {e}")

        return res

    def _check_target_database_needs_attention(self, res: ServiceAuditResult) -> None:
        rows = self.get_rows(self.T_TARGET_DATABASES)
        for r in rows:
            cid = _safe_str(r.get("compartment_id"))
            tid = _safe_str(r.get("id"))
            if not cid or not tid:
                continue

            state = _safe_str(r.get("lifecycle_state")).upper()
            if state not in ("NEEDS_ATTENTION", "FAILED"):
                continue

            loc = _loc_base(compartment_id=cid, entity_id=tid)
            res.findings.append(
                self.finding(
                    table_name=self.T_TARGET_DATABASES,
                    issue_code="DATA_SAFE_TARGET_NEEDS_ATTENTION",
                    title="Data Safe target database requires attention (monitoring degraded)",
                    severity="MEDIUM",
                    description=_wrap_paragraph(
                        """
                        The target database's Data Safe lifecycle_state is NEEDS_ATTENTION or FAILED,
                        meaning Data Safe cannot connect to or manage the registered database (per the
                        OCI TargetDatabase SDK model, this state reflects connectivity/credential/config
                        problems reported in lifecycle_details). While Data Safe is in this state,
                        security assessments, user assessments, and audit collection for that database
                        are stale or not running, creating a monitoring blind spot.
                        """
                    ),
                    location=loc,
                    row=r,
                    recommended_module="modules run enum_data_safe --target-databases --get",
                    notes=_wrap_paragraph(
                        """
                        Remediation: inspect lifecycle_details and re-validate the target's
                        connection/credentials (database user, wallet, ACL/network path) in the Data
                        Safe console.
                        """
                    ),
                )
            )

    def _check_security_assessment_baseline_deviation(self, res: ServiceAuditResult) -> None:
        rows = self.get_rows(self.T_SECURITY_ASSESSMENTS)
        for r in rows:
            cid = _safe_str(r.get("compartment_id"))
            aid = _safe_str(r.get("id"))
            if not cid or not aid:
                continue

            if _truthy_str(r.get("is_baseline")):
                continue
            if not _truthy_str(r.get("is_deviated_from_baseline")):
                continue

            loc = _loc_base(compartment_id=cid, entity_id=aid)
            res.findings.append(
                self.finding(
                    table_name=self.T_SECURITY_ASSESSMENTS,
                    issue_code="DATA_SAFE_SECURITY_ASSESSMENT_BASELINE_DEVIATION",
                    title="Security assessment has deviated from its established baseline",
                    severity="MEDIUM",
                    description=_wrap_paragraph(
                        """
                        OCI Data Safe itself flags this assessment as deviated from the admin-set
                        security baseline for the target database, per the service's automatic
                        baseline-comparison feature (Security Assessment Overview /
                        set-security-assessment-baseline). A true is_deviated_from_baseline value means
                        the target's security configuration has drifted since the baseline was captured
                        -- e.g. new risky settings, changed controls -- and warrants review of the
                        assessment's findings.
                        """
                    ),
                    location=loc,
                    row=r,
                    recommended_module="modules run enum_data_safe --security-assessments --get",
                    notes=_wrap_paragraph(
                        """
                        Remediation: open the assessment in the Data Safe console, review what changed
                        versus baseline, and either remediate the drift or update the baseline if the
                        change was intentional.
                        """
                    ),
                )
            )

    def _check_user_assessment_baseline_deviation(self, res: ServiceAuditResult) -> None:
        rows = self.get_rows(self.T_USER_ASSESSMENTS)
        for r in rows:
            cid = _safe_str(r.get("compartment_id"))
            aid = _safe_str(r.get("id"))
            if not cid or not aid:
                continue

            if _truthy_str(r.get("is_baseline")):
                continue
            if not _truthy_str(r.get("is_deviated_from_baseline")):
                continue

            loc = _loc_base(compartment_id=cid, entity_id=aid)
            res.findings.append(
                self.finding(
                    table_name=self.T_USER_ASSESSMENTS,
                    issue_code="DATA_SAFE_USER_ASSESSMENT_BASELINE_DEVIATION",
                    title="User assessment has deviated from its established baseline",
                    severity="MEDIUM",
                    description=_wrap_paragraph(
                        """
                        Same OCI-native baseline-drift signal as the security assessment check, but for
                        the User Assessment (privileged users, roles, profiles) feature of Data Safe. A
                        true is_deviated_from_baseline value means privileged-user posture on the target
                        database has changed since the baseline snapshot, which is a common indicator of
                        new or elevated user grants worth reviewing.
                        """
                    ),
                    location=loc,
                    row=r,
                    recommended_module="modules run enum_data_safe --user-assessments --get",
                    notes=_wrap_paragraph(
                        """
                        Remediation: review the user assessment's findings for newly-flagged
                        accounts/roles and confirm the change was authorized.
                        """
                    ),
                )
            )


# -----------------------------------------------------------------------------
# dbmulticloud service auditor (gap-fill)
# -----------------------------------------------------------------------------

class DbMulticloudServiceAuditor(ServiceAuditor):
    service = "db_multicloud"

    T_AWS_IDENTITY_CONNECTORS = "dbmulticloud_aws_identity_connectors"
    T_AZURE_CONNECTORS = "dbmulticloud_azure_connectors"

    def run_checks(self) -> ServiceAuditResult:
        res = ServiceAuditResult(service=self.service)
        try:
            self._check_aws_sts_public_endpoint(res)
        except Exception as e:
            res.errors.append(f"aws_sts_public_endpoint: {type(e).__name__}: {e}")

        try:
            self._check_azure_service_principal_identity(res)
        except Exception as e:
            res.errors.append(f"azure_service_principal_identity: {type(e).__name__}: {e}")

        return res

    def _check_aws_sts_public_endpoint(self, res: ServiceAuditResult) -> None:
        rows = self.get_rows(self.T_AWS_IDENTITY_CONNECTORS, where_conditions={"lifecycle_state": "ACTIVE"})
        for r in rows:
            cid = _safe_str(r.get("compartment_id"))
            eid = _safe_str(r.get("id"))
            if not cid or not eid:
                continue

            sts_private_endpoint = _safe_str(r.get("aws_sts_private_endpoint")).strip()
            if sts_private_endpoint:
                continue

            loc = _loc_base(compartment_id=cid, entity_id=eid)
            res.findings.append(
                self.finding(
                    table_name=self.T_AWS_IDENTITY_CONNECTORS,
                    issue_code="DBMULTICLOUD_AWS_STS_PUBLIC_ENDPOINT",
                    title="AWS identity connector uses the public AWS STS endpoint",
                    severity="MEDIUM",
                    description=_wrap_paragraph(
                        """
                        The connector's OIDC token exchange with AWS STS (used to federate OCI identity
                        into AWS IAM roles per service_role_details) traverses the public internet instead
                        of an AWS PrivateLink/VPC interface endpoint, since aws_sts_private_endpoint is
                        unset. AWS's own STS guidance recommends VPC interface endpoints so STS
                        AssumeRoleWithWebIdentity traffic stays on the AWS backbone rather than being
                        reachable from the public path.
                        """
                    ),
                    location=loc,
                    row=r,
                    recommended_module="modules run enum_dbmulticloud --aws-identity-connectors",
                    notes=_wrap_paragraph(
                        """
                        Remediation: provision an AWS STS VPC interface endpoint and set it on the
                        connector (aws_sts_private_endpoint) to keep the cross-cloud trust exchange
                        private.
                        """
                    ),
                )
            )

    def _check_azure_service_principal_identity(self, res: ServiceAuditResult) -> None:
        rows = self.get_rows(self.T_AZURE_CONNECTORS, where_conditions={"lifecycle_state": "ACTIVE"})
        for r in rows:
            cid = _safe_str(r.get("compartment_id"))
            eid = _safe_str(r.get("id"))
            if not cid or not eid:
                continue

            mechanism = _safe_str(r.get("azure_identity_mechanism")).strip().upper()
            if mechanism != "SERVICE_PRINCIPAL":
                continue

            loc = _loc_base(compartment_id=cid, entity_id=eid)
            res.findings.append(
                self.finding(
                    table_name=self.T_AZURE_CONNECTORS,
                    issue_code="DBMULTICLOUD_AZURE_SERVICE_PRINCIPAL_IDENTITY",
                    title="Azure connector authenticates via a static Service Principal instead of Arc managed identity",
                    severity="LOW",
                    description=_wrap_paragraph(
                        """
                        azure_identity_mechanism has exactly two valid values (ARC_AGENT,
                        SERVICE_PRINCIPAL); SERVICE_PRINCIPAL relies on a long-lived, rotatable client
                        secret/certificate credential rather than the Azure Arc-enabled server's
                        system-assigned managed identity. Microsoft's own Arc guidance recommends
                        managed-identity authentication where possible specifically because it removes
                        stored-credential/rotation risk.
                        """
                    ),
                    location=loc,
                    row=r,
                    recommended_module="modules run enum_dbmulticloud --azure-connectors",
                    notes=_wrap_paragraph(
                        """
                        Remediation: reconfigure the Oracle DB Azure Connector to use the ARC_AGENT
                        identity mechanism (system-assigned managed identity) instead of a Service
                        Principal secret.
                        """
                    ),
                )
            )


# -----------------------------------------------------------------------------
# delegate_access_control service auditor (gap-fill)
# -----------------------------------------------------------------------------

class DelegateAccessControlServiceAuditor(ServiceAuditor):
    service = "delegate_access_control"

    T_ACCESS_REQUESTS = "delegate_access_control_access_requests"

    def run_checks(self) -> ServiceAuditResult:
        res = ServiceAuditResult(service=self.service)
        try:
            self._check_access_request_preapproved_no_review(res)
        except Exception as e:
            res.errors.append(f"access_requests: {type(e).__name__}: {e}")

        try:
            self._check_access_request_revoke_or_expiry_failed(res)
        except Exception as e:
            res.errors.append(f"access_requests: {type(e).__name__}: {e}")

        return res

    def _check_access_request_preapproved_no_review(self, res: ServiceAuditResult) -> None:
        rows = self.get_rows(self.T_ACCESS_REQUESTS, where_conditions={"request_status": "PREAPPROVED"})
        for r in rows:
            cid = _safe_str(r.get("compartment_id"))
            rid = _safe_str(r.get("id"))
            if not cid or not rid:
                continue

            requester_type = _safe_str(r.get("requester_type")).upper()
            if requester_type != "OPERATOR":
                continue

            loc = _loc_base(compartment_id=cid, entity_id=rid, resource_id=_safe_str(r.get("resource_id")))
            res.findings.append(
                self.finding(
                    table_name=self.T_ACCESS_REQUESTS,
                    issue_code="DAC_ACCESS_REQUEST_PREAPPROVED_NO_REVIEW",
                    title="Operator access request was auto-approved without human review (PREAPPROVED)",
                    severity="MEDIUM",
                    description=_wrap_paragraph(
                        """
                        The Delegation Control governing this resource pre-approved every action in this
                        Service Provider Access Request, so it was auto-approved without an explicit customer
                        approver decision (per OCI docs: "If all of the Service Provider Actions listed ...
                        are in the pre-approved list ... the request is automatically approved"). Review the
                        governing Delegation Control's pre-approved-action list (delegation_control_id) and
                        narrow it so sensitive actions on this resource_type require explicit approval instead
                        of standing auto-approval.
                        """
                    ),
                    location=loc,
                    row=r,
                    recommended_module="modules run enum_delegate_access_control --delegation-controls --get",
                    notes=_wrap_paragraph(
                        """
                        Remediation: edit the referenced Delegation Control (delegation_control_id) and remove
                        sensitive actions from its pre-approved-action list, or disable auto-approval so
                        Service Provider Access Requests against this resource_type require an explicit
                        approver decision. Cross-reference requested_action_names on this request with the
                        Delegation Control's pre-approved list to see exactly what was auto-approved.
                        """
                    ),
                )
            )

    def _check_access_request_revoke_or_expiry_failed(self, res: ServiceAuditResult) -> None:
        failed_statuses = {"REVOKE_FAILED", "EXPIRY_FAILED", "CLOSE_FAILED", "UNDEPLOY_FAILED"}
        rows = self.get_rows(self.T_ACCESS_REQUESTS)
        for r in rows:
            cid = _safe_str(r.get("compartment_id"))
            rid = _safe_str(r.get("id"))
            if not cid or not rid:
                continue

            request_status = _safe_str(r.get("request_status")).upper()
            if request_status not in failed_statuses:
                continue

            loc = _loc_base(compartment_id=cid, entity_id=rid, resource_id=_safe_str(r.get("resource_id")))
            res.findings.append(
                self.finding(
                    table_name=self.T_ACCESS_REQUESTS,
                    issue_code="DAC_ACCESS_REQUEST_REVOKE_OR_EXPIRY_FAILED",
                    title="Delegated operator access failed to revoke/expire/close and may still be active",
                    severity="HIGH",
                    description=_wrap_paragraph(
                        """
                        This access request's teardown path failed (SDK-defined terminal-failure state),
                        meaning the granted operator/service-provider access to the resource may not have
                        been fully revoked or removed even though it was expected to end. Verify current
                        effective access on resource_id via the OCI console/CLI
                        (get_delegated_resource_access_request) and manually revoke/close the grant, then
                        investigate why automated revocation failed.
                        """
                    ),
                    location=loc,
                    row=r,
                    recommended_module="modules run enum_delegate_access_control --access-requests --get",
                    notes=_wrap_paragraph(
                        """
                        Remediation: treat this as a potentially still-active break-glass grant until proven
                        otherwise. Confirm via the console/CLI whether access on resource_id was actually torn
                        down, manually revoke it if not, and escalate the automated teardown failure to Oracle
                        support if it recurs.
                        """
                    ),
                )
            )


# -----------------------------------------------------------------------------
# events service auditor (gap-fill)
# -----------------------------------------------------------------------------

class EventsServiceAuditor(ServiceAuditor):
    service = "events"

    T_RULES = "events_rules"

    def run_checks(self) -> ServiceAuditResult:
        res = ServiceAuditResult(service=self.service)
        try:
            self._check_rule_no_effective_action(res)
        except Exception as e:
            res.errors.append(f"no_effective_action: {type(e).__name__}: {e}")

        try:
            self._check_security_monitoring_rule_disabled(res)
        except Exception as e:
            res.errors.append(f"security_monitoring_disabled: {type(e).__name__}: {e}")

        return res

    def _check_rule_no_effective_action(self, res: ServiceAuditResult) -> None:
        rows = self.get_rows(self.T_RULES)
        dead_action_states = ("FAILED", "INACTIVE", "DELETED", "DELETING")
        for r in rows:
            cid = _safe_str(r.get("compartment_id"))
            rid = _safe_str(r.get("id"))
            if not cid or not rid:
                continue

            if not _truthy_str(r.get("is_enabled")):
                continue

            lifecycle_state = _safe_str(r.get("lifecycle_state")).strip().upper()
            if lifecycle_state not in ("ACTIVE", ""):
                continue

            raw_actions = r.get("actions")
            if raw_actions is None or (isinstance(raw_actions, str) and not raw_actions.strip()):
                # Actions were never collected for this rule (a list-only enum pass, no
                # --get) -- there's nothing to safely assert about action health here,
                # so skip rather than flag on missing data.
                continue

            actions = _as_json_list(as_json_dict(raw_actions).get("actions"))
            effective = False
            for a in actions:
                if not isinstance(a, dict):
                    continue
                if not _truthy_str(a.get("is_enabled")):
                    continue
                a_state = _safe_str(a.get("lifecycle_state")).strip().upper()
                if a_state in dead_action_states:
                    continue
                effective = True
                break

            if effective:
                continue

            loc = _loc_base(compartment_id=cid, entity_id=rid)
            res.findings.append(
                self.finding(
                    table_name=self.T_RULES,
                    issue_code="EVENTS_RULE_NO_EFFECTIVE_ACTION",
                    title="Active Events rule has no enabled, healthy action to fire",
                    severity="LOW",
                    description=_wrap_paragraph(
                        """
                        The rule is enabled and active, meaning it will match its condition and attempt to
                        fire, but none of its attached actions are currently enabled and healthy (empty
                        action list, all actions individually disabled, or all actions in a
                        FAILED/INACTIVE/DELETED/DELETING lifecycle state). Matched events are silently
                        dropped, creating a monitoring/automation blind spot that looks configured but is
                        not functioning.
                        """
                    ),
                    location=loc,
                    row=r,
                    recommended_module="modules run enum_events --rules --get",
                    notes=_wrap_paragraph(
                        """
                        Remediation: re-enable at least one action or verify the downstream ONS topic,
                        stream, or function target still exists and is reachable.
                        """
                    ),
                )
            )

    def _check_security_monitoring_rule_disabled(self, res: ServiceAuditResult) -> None:
        rows = self.get_rows(self.T_RULES)
        security_tokens = ("identitycontrolplane", "virtualnetwork")
        for r in rows:
            cid = _safe_str(r.get("compartment_id"))
            rid = _safe_str(r.get("id"))
            if not cid or not rid:
                continue

            condition = _safe_str(r.get("condition")).strip().lower()
            if not condition:
                continue
            if not any(tok in condition for tok in security_tokens):
                continue

            lifecycle_state = _safe_str(r.get("lifecycle_state")).strip().upper()
            if _truthy_str(r.get("is_enabled")) and lifecycle_state != "INACTIVE":
                continue

            loc = _loc_base(compartment_id=cid, entity_id=rid)
            res.findings.append(
                self.finding(
                    table_name=self.T_RULES,
                    issue_code="EVENTS_RULE_SECURITY_MONITORING_DISABLED",
                    title="IAM/network control-plane monitoring rule is disabled",
                    severity="MEDIUM",
                    description=_wrap_paragraph(
                        """
                        The rule's condition targets identitycontrolplane (user/group/policy/identity
                        provider) or virtualnetwork (VCN/route table/security list/NSG/gateway) event
                        types -- the exact resource families the CIS OCI Foundations Benchmark (controls
                        3.3-3.12) recommends alerting on -- but the rule is currently disabled or
                        INACTIVE. Because the rule already exists with this scope, this flags a real
                        detection gap rather than a design opinion.
                        """
                    ),
                    location=loc,
                    row=r,
                    recommended_module="modules run enum_events --rules",
                    notes=_wrap_paragraph(
                        """
                        Remediation: re-enable the rule (or confirm an equivalent active rule already
                        covers the same event types) so IAM and network control-plane changes are still
                        alerted on.
                        """
                    ),
                )
            )


# -----------------------------------------------------------------------------
# fusion_apps service auditor (gap-fill)
# -----------------------------------------------------------------------------

class FusionAppsServiceAuditor(ServiceAuditor):
    service = "fusion_apps"

    T_ENVIRONMENTS = "fusion_apps_environments"

    def run_checks(self) -> ServiceAuditResult:
        res = ServiceAuditResult(service=self.service)
        try:
            self._check_break_glass_enabled(res)
        except Exception as e:
            res.errors.append(f"break_glass_enabled: {type(e).__name__}: {e}")

        try:
            self._check_break_glass_no_lockbox(res)
        except Exception as e:
            res.errors.append(f"break_glass_no_lockbox: {type(e).__name__}: {e}")

        return res

    def _check_break_glass_enabled(self, res: ServiceAuditResult) -> None:
        rows = self.get_rows(self.T_ENVIRONMENTS, where_conditions={"lifecycle_state": "ACTIVE"})
        for r in rows:
            cid = _safe_str(r.get("compartment_id"))
            eid = _safe_str(r.get("id"))
            if not cid or not eid:
                continue

            if not _truthy_str(r.get("is_break_glass_enabled")):
                continue

            loc = _loc_base(compartment_id=cid, entity_id=eid)
            res.findings.append(
                self.finding(
                    table_name=self.T_ENVIRONMENTS,
                    issue_code="FUSION_APPS_BREAK_GLASS_ENABLED",
                    title="Fusion environment has Break Glass (Oracle Support emergency access) enabled",
                    severity="LOW",
                    description=_wrap_paragraph(
                        """
                        Break Glass grants Oracle‑authorized support operators a temporary, credentialed access
                        path into this Fusion environment via Oracle Managed Access, and ships with auto‑approval
                        enabled by default per Oracle's own documentation. This is a legitimate, often‑purchased
                        support feature, not a bug, but it is a standing external‑access surface worth surfacing
                        as a posture item.
                        """
                    ),
                    location=loc,
                    row=r,
                    recommended_module="modules run enum_fusion_apps --fusion_environments --get",
                    notes=_wrap_paragraph(
                        """
                        Remediation: confirm the environment's Lockbox approval mode is not left on silent
                        auto‑approve, and that OCI Audit/Cloud Guard alerting is wired to any Break Glass session
                        per Oracle's published best practices.
                        """
                    ),
                )
            )

    def _check_break_glass_no_lockbox(self, res: ServiceAuditResult) -> None:
        rows = self.get_rows(self.T_ENVIRONMENTS, where_conditions={"lifecycle_state": "ACTIVE"})
        for r in rows:
            cid = _safe_str(r.get("compartment_id"))
            eid = _safe_str(r.get("id"))
            if not cid or not eid:
                continue

            if not _truthy_str(r.get("is_break_glass_enabled")):
                continue

            if _safe_str(r.get("lockbox_id")):
                continue

            loc = _loc_base(compartment_id=cid, entity_id=eid)
            res.findings.append(
                self.finding(
                    table_name=self.T_ENVIRONMENTS,
                    issue_code="FUSION_APPS_BREAK_GLASS_NO_LOCKBOX",
                    title="Break Glass enabled but environment has no associated Lockbox record",
                    severity="MEDIUM",
                    description=_wrap_paragraph(
                        """
                        Oracle provisions a Lockbox automatically alongside Break Glass so that emergency support
                        access routes through Oracle Managed Access' approval/audit workflow. An ACTIVE
                        environment with Break Glass on but no lockbox_id is an inconsistent state, implying the
                        emergency‑access path may not be governed by a trackable approval record.
                        """
                    ),
                    location=loc,
                    row=r,
                    recommended_module="modules run enum_fusion_apps --fusion_environments --get",
                    notes=_wrap_paragraph(
                        """
                        Remediation: verify Break Glass/Lockbox configuration in the environment's Security tab
                        in the Fusion console and re‑run enum_fusion_apps to confirm the field populates; treat a
                        persistent empty lockbox_id here as a provisioning gap to raise with Oracle Support.
                        """
                    ),
                )
            )


# -----------------------------------------------------------------------------
# generative_ai service auditor (gap-fill)
# -----------------------------------------------------------------------------

class GenerativeAiServiceAuditor(ServiceAuditor):
    service = "generative_ai"

    T_ENDPOINTS = "generative_ai_endpoints"

    def run_checks(self) -> ServiceAuditResult:
        res = ServiceAuditResult(service=self.service)
        try:
            self._check_endpoints_content_moderation_disabled(res)
        except Exception as e:
            res.errors.append(f"endpoints_content_moderation_disabled: {type(e).__name__}: {e}")

        return res

    def _check_endpoints_content_moderation_disabled(self, res: ServiceAuditResult) -> None:
        rows = self.get_rows(self.T_ENDPOINTS, where_conditions={"lifecycle_state": "ACTIVE"})
        for r in rows:
            cid = _safe_str(r.get("compartment_id")) or _safe_str(r.get("compartment_ocid"))
            eid = _safe_str(r.get("id"))
            if not cid or not eid:
                continue

            moderation_cfg = as_json_dict(r.get("content_moderation_config"))
            enabled = moderation_cfg.get("is_enabled") if moderation_cfg else None
            is_disabled = (not moderation_cfg) or _falsy_str(enabled) or not _truthy_str(enabled)

            if is_disabled:
                loc = _loc_base(compartment_id=cid, entity_id=eid)
                res.findings.append(
                    self.finding(
                        table_name=self.T_ENDPOINTS,
                        issue_code="GENAI_ENDPOINT_CONTENT_MODERATION_DISABLED",
                        title="Generative AI endpoint has content moderation guardrail disabled",
                        severity="MEDIUM",
                        description=_wrap_paragraph(
                            """
                            The endpoint's content_moderation_config (OCI Generative AI "AI Guardrails"
                            feature, ContentModerationConfig.is_enabled) is absent or explicitly disabled.
                            Per OCI documentation, content moderation guardrails are NOT applied by default
                            to foundational models, so this flags endpoints where nobody opted in.
                            """
                        ),
                        location=loc,
                        row=r,
                        recommended_module="modules run enum_generative_ai --endpoints",
                        notes=_wrap_paragraph(
                            """
                            Remediation: enable content moderation (INFORM or BLOCK mode) on customer-facing
                            or compliance-sensitive endpoints to reduce toxic/biased-output and policy risk.
                            This is a posture signal, not an exploit path -- it only reads the already-saved
                            is_enabled flag with no inference about intended use.
                            """
                        ),
                    )
                )


# -----------------------------------------------------------------------------
# generative_ai_agent service auditor (gap-fill)
# -----------------------------------------------------------------------------

class GenerativeAiAgentServiceAuditor(ServiceAuditor):
    service = "generative_ai_agent"

    T_AGENT_ENDPOINTS = "generative_ai_agent_agent_endpoints"

    def run_checks(self) -> ServiceAuditResult:
        res = ServiceAuditResult(service=self.service)
        try:
            self._check_endpoint_content_moderation_disabled(res)
        except Exception as e:
            res.errors.append(f"content_moderation: {type(e).__name__}: {e}")

        try:
            self._check_endpoint_prompt_injection_guardrail_disabled(res)
        except Exception as e:
            res.errors.append(f"prompt_injection_guardrail: {type(e).__name__}: {e}")

        try:
            self._check_endpoint_pii_guardrail_disabled(res)
        except Exception as e:
            res.errors.append(f"pii_guardrail: {type(e).__name__}: {e}")

        return res

    def _check_endpoint_content_moderation_disabled(self, res: ServiceAuditResult) -> None:
        rows = self.get_rows(self.T_AGENT_ENDPOINTS, where_conditions={"lifecycle_state": "ACTIVE"})
        for r in rows:
            cid = _safe_str(r.get("compartment_id"))
            eid = _safe_str(r.get("id"))
            if not cid or not eid:
                continue

            cm_cfg = as_json_dict(r.get("content_moderation_config"))
            enabled_on_input = cm_cfg.get("should_enable_on_input")
            enabled_on_output = cm_cfg.get("should_enable_on_output")

            if (not cm_cfg) or (not bool(enabled_on_input)) or (not bool(enabled_on_output)):
                loc = _loc_base(compartment_id=cid, entity_id=eid)
                res.findings.append(
                    self.finding(
                        table_name=self.T_AGENT_ENDPOINTS,
                        issue_code="GENERATIVE_AI_AGENT_ENDPOINT_CONTENT_MODERATION_DISABLED",
                        title="Agent endpoint has content moderation disabled on input and/or output",
                        severity="MEDIUM",
                        description=_wrap_paragraph(
                            """
                            The endpoint's content_moderation_config either does not exist or has
                            should_enable_on_input/should_enable_on_output set to false, so user prompts
                            and/or generated agent responses are not screened for toxic, biased, or
                            policy-violating content. OCI documentation explicitly recommends enabling
                            content moderation on both directions.
                            """
                        ),
                        location=loc,
                        row=r,
                        recommended_module="modules run enum_generative_ai_agent --agent-endpoints --get",
                        notes=_wrap_paragraph(
                            """
                            Remediation: update the endpoint to set should_enable_on_input=true and
                            should_enable_on_output=true in content_moderation_config.
                            """
                        ),
                    )
                )

    def _check_endpoint_prompt_injection_guardrail_disabled(self, res: ServiceAuditResult) -> None:
        rows = self.get_rows(self.T_AGENT_ENDPOINTS, where_conditions={"lifecycle_state": "ACTIVE"})
        for r in rows:
            cid = _safe_str(r.get("compartment_id"))
            eid = _safe_str(r.get("id"))
            if not cid or not eid:
                continue

            guardrail_cfg = as_json_dict(r.get("guardrail_config"))
            pi_cfg = as_json_dict(guardrail_cfg.get("prompt_injection_config"))
            input_mode = _safe_str(pi_cfg.get("input_guardrail_mode")).upper()

            if (not pi_cfg) or input_mode == "DISABLE" or not input_mode:
                loc = _loc_base(compartment_id=cid, entity_id=eid)
                res.findings.append(
                    self.finding(
                        table_name=self.T_AGENT_ENDPOINTS,
                        issue_code="GENERATIVE_AI_AGENT_ENDPOINT_PROMPT_INJECTION_GUARDRAIL_DISABLED",
                        title="Agent endpoint has no prompt-injection guardrail enabled",
                        severity="MEDIUM",
                        description=_wrap_paragraph(
                            """
                            The endpoint has no active prompt-injection guardrail (input_guardrail_mode is
                            DISABLE or the prompt_injection_config block is absent), so instructions hidden
                            in user input or retrieved knowledge-base content are not screened before
                            reaching the agent. Because agent endpoints can be wired to tools
                            (function-calling/SQL/HTTP), an unguarded prompt injection can potentially
                            trigger unintended tool invocation.
                            """
                        ),
                        location=loc,
                        row=r,
                        recommended_module="modules run enum_generative_ai_agent --agent-endpoints --get",
                        notes=_wrap_paragraph(
                            """
                            Remediation: set input_guardrail_mode to BLOCK (or at minimum INFORM) in
                            guardrail_config.prompt_injection_config.
                            """
                        ),
                    )
                )

    def _check_endpoint_pii_guardrail_disabled(self, res: ServiceAuditResult) -> None:
        rows = self.get_rows(self.T_AGENT_ENDPOINTS, where_conditions={"lifecycle_state": "ACTIVE"})
        for r in rows:
            cid = _safe_str(r.get("compartment_id"))
            eid = _safe_str(r.get("id"))
            if not cid or not eid:
                continue

            guardrail_cfg = as_json_dict(r.get("guardrail_config"))
            pii_cfg = as_json_dict(guardrail_cfg.get("personally_identifiable_information_config"))
            input_mode = _safe_str(pii_cfg.get("input_guardrail_mode")).upper()
            output_mode = _safe_str(pii_cfg.get("output_guardrail_mode")).upper()

            if (not pii_cfg) or (
                (input_mode == "DISABLE" or not input_mode)
                and (output_mode == "DISABLE" or not output_mode)
            ):
                loc = _loc_base(compartment_id=cid, entity_id=eid)
                res.findings.append(
                    self.finding(
                        table_name=self.T_AGENT_ENDPOINTS,
                        issue_code="GENERATIVE_AI_AGENT_ENDPOINT_PII_GUARDRAIL_DISABLED",
                        title="Agent endpoint has PII detection guardrail fully disabled",
                        severity="MEDIUM",
                        description=_wrap_paragraph(
                            """
                            The endpoint's guardrail_config has no active PII detection on either input or
                            output, so personally identifiable information in user prompts or generated
                            responses is not flagged, redacted, or blocked. This increases the risk of
                            sensitive personal data being exposed to end users or persisted in
                            session/trace logs.
                            """
                        ),
                        location=loc,
                        row=r,
                        recommended_module="modules run enum_generative_ai_agent --agent-endpoints --get",
                        notes=_wrap_paragraph(
                            """
                            Remediation: enable BLOCK or INFORM mode for
                            personally_identifiable_information_config.input_guardrail_mode and
                            output_guardrail_mode.
                            """
                        ),
                    )
                )


# -----------------------------------------------------------------------------
# governance_rules service auditor (gap-fill)
# -----------------------------------------------------------------------------

class GovernanceRulesServiceAuditor(ServiceAuditor):
    service = "governance_rules"

    T_RULES = "governance_rules_rules"
    T_TENANCY_ATTACHMENTS = "governance_rules_tenancy_attachments"

    def run_checks(self) -> ServiceAuditResult:
        res = ServiceAuditResult(service=self.service)
        try:
            self._check_tenancy_attachment_needs_attention(res)
        except Exception as e:
            res.errors.append(f"tenancy_attachment_needs_attention: {type(e).__name__}: {e}")

        try:
            self._check_rule_no_active_attachment(res)
        except Exception as e:
            res.errors.append(f"rule_no_active_attachment: {type(e).__name__}: {e}")

        return res

    def _check_tenancy_attachment_needs_attention(self, res: ServiceAuditResult) -> None:
        rows = self.get_rows(self.T_TENANCY_ATTACHMENTS, where_conditions={"lifecycle_state": "NEEDS_ATTENTION"})
        if not rows:
            return

        rule_rows = self.get_rows(self.T_RULES)
        rules_by_id = {_safe_str(rr.get("id")): rr for rr in rule_rows if _safe_str(rr.get("id"))}

        for r in rows:
            cid = _safe_str(r.get("compartment_id"))
            aid = _safe_str(r.get("id"))
            if not cid or not aid:
                continue

            governance_rule_id = _safe_str(r.get("governance_rule_id"))
            tenancy_id = _safe_str(r.get("tenancy_id"))
            rule = rules_by_id.get(governance_rule_id) or {}
            rule_type = _safe_str(rule.get("type")).upper()

            loc = _loc_base(
                compartment_id=cid,
                entity_id=aid,
                governance_rule_id=governance_rule_id or None,
                tenancy_id=tenancy_id or None,
                rule_type=rule_type or None,
            )

            res.findings.append(
                self.finding(
                    table_name=self.T_TENANCY_ATTACHMENTS,
                    issue_code="GOVRULES_TENANCY_ATTACHMENT_NEEDS_ATTENTION",
                    title="Governance rule failed to enforce on a member tenancy",
                    severity="MEDIUM",
                    description=_wrap_paragraph(
                        """
                        The tenancy attachment is in NEEDS_ATTENTION, meaning the parent tenancy's governance
                        rule (a QUOTA lockdown, TAG policy, or ALLOWED_REGIONS restriction) failed to apply to
                        the target member tenancy and is silently not enforced there. For example, an
                        ALLOWED_REGIONS rule that should block resource creation outside approved regions, or
                        a QUOTA rule meant to zero out a risky service, is not actually active on that
                        tenancy — the guardrail exists on paper but currently provides no real protection for
                        that member.
                        """
                    ),
                    location=loc,
                    row=r,
                    recommended_module="modules run enum_governance_rules --tenancy-attachments --get",
                    notes=_wrap_paragraph(
                        """
                        Remediation: inspect the attachment (GetTenancyAttachment) for the blocking cause —
                        often a pre-existing resource in the child tenancy that conflicts with the rule — and
                        retry via `oci governance-rule tenancy-attachment retry`, then re-run
                        `modules run enum_governance_rules --tenancy-attachments --get` to confirm enforcement
                        took effect.
                        """
                    ),
                )
            )

    def _check_rule_no_active_attachment(self, res: ServiceAuditResult) -> None:
        rule_rows = self.get_rows(self.T_RULES, where_conditions={"lifecycle_state": "ACTIVE"})
        if not rule_rows:
            return

        attachment_rows = self.get_rows(self.T_TENANCY_ATTACHMENTS)
        live_states = {"ACTIVE", "CREATING", "UPDATING", "NEEDS_ATTENTION"}
        live_rule_ids = set()
        for a in attachment_rows:
            if _safe_str(a.get("lifecycle_state")).upper() in live_states:
                rid = _safe_str(a.get("governance_rule_id"))
                if rid:
                    live_rule_ids.add(rid)

        for r in rule_rows:
            cid = _safe_str(r.get("compartment_id"))
            rid = _safe_str(r.get("id"))
            if not cid or not rid:
                continue
            if rid in live_rule_ids:
                continue

            rule_type = _safe_str(r.get("type")).upper()
            loc = _loc_base(compartment_id=cid, entity_id=rid, rule_type=rule_type or None)

            res.findings.append(
                self.finding(
                    table_name=self.T_RULES,
                    issue_code="GOVRULES_RULE_NO_ACTIVE_ATTACHMENT",
                    title="Governance rule defined but not attached to any tenancy",
                    severity="LOW",
                    description=_wrap_paragraph(
                        """
                        The governance rule is ACTIVE (a QUOTA, TAG, or ALLOWED_REGIONS template) but has no
                        live tenancy attachment — every attachment for this rule is DELETED, or none exist at
                        all. The rule provides no actual protection anywhere in the organization: it was
                        defined but never rolled out to a member tenancy, or its only attachment(s) were
                        later removed.
                        """
                    ),
                    location=loc,
                    row=r,
                    recommended_module="modules run enum_governance_rules --rules --tenancy-attachments --get",
                    notes=_wrap_paragraph(
                        """
                        Remediation: attach the rule to the intended member tenancies
                        (CreateTenancyAttachment) or delete the unused rule to reduce governance drift. Re-run
                        `modules run enum_governance_rules --rules --tenancy-attachments --get` to confirm the
                        current attachment state before deciding.
                        """
                    ),
                )
            )


# -----------------------------------------------------------------------------
# healthchecks service auditor (gap-fill)
# -----------------------------------------------------------------------------

class HealthChecksServiceAuditor(ServiceAuditor):
    service = "healthchecks"

    T_HTTP_MONITORS = "healthchecks_http_monitors"
    T_PING_MONITORS = "healthchecks_ping_monitors"

    # Curated remote-access / database / admin-management ports. An enabled
    # TCP ping monitor targeting one of these is self-reported evidence that
    # the operator has exposed that port to the public internet, since Health
    # Checks vantage points must be able to reach the monitored target from
    # outside OCI.
    _SENSITIVE_TCP_PORTS = {
        22: "SSH",
        23: "Telnet",
        135: "SMB/RPC",
        445: "SMB/RPC",
        1433: "MSSQL",
        1521: "Oracle DB",
        1522: "Oracle DB",
        2379: "etcd",
        3306: "MySQL",
        3389: "RDP",
        5432: "PostgreSQL",
        5985: "WinRM",
        5986: "WinRM",
        6379: "Redis",
        9200: "Elasticsearch",
        9300: "Elasticsearch",
        11211: "Memcached",
        27017: "MongoDB",
    }

    def run_checks(self) -> ServiceAuditResult:
        res = ServiceAuditResult(service=self.service)
        try:
            self._check_http_monitor_header_potential_secret(res)
        except Exception as e:
            res.errors.append(f"http_monitor_headers: {type(e).__name__}: {e}")

        try:
            self._check_monitor_sensitive_port_public_exposure(res)
        except Exception as e:
            res.errors.append(f"sensitive_port_exposure: {type(e).__name__}: {e}")

        return res

    def _check_http_monitor_header_potential_secret(self, res: ServiceAuditResult) -> None:
        rows = self.get_rows(self.T_HTTP_MONITORS)
        for r in rows:
            cid = _safe_str(r.get("compartment_id"))
            mid = _safe_str(r.get("id"))
            if not cid or not mid:
                continue

            headers = as_json_dict(r.get("headers"))
            if not headers:
                continue

            sensitive_hits: List[str] = []
            for k, v in headers.items():
                if not _contains_sensitive_key_name(k):
                    continue
                if v is None:
                    continue
                if _safe_str(v):
                    sensitive_hits.append(k)

            if not sensitive_hits:
                continue

            loc = _loc_base(compartment_id=cid, entity_id=mid)
            notes = (
                "Custom header keys that look credential-bearing: "
                + ", ".join(sorted(set(sensitive_hits))[:12])
            )
            res.findings.append(
                self.finding(
                    table_name=self.T_HTTP_MONITORS,
                    issue_code="HEALTHCHECKS_HTTP_MONITOR_HEADER_POTENTIAL_SECRET",
                    title="HTTP monitor custom header may contain a credential",
                    severity="MEDIUM",
                    description=_wrap_paragraph(
                        """
                        This Health Checks HTTP monitor defines a custom `headers` dict sent on every
                        public probe. Oracle's own API reference explicitly disallows the Authorization
                        header on monitors for this exact reason: monitor configuration is not a secrets
                        store, and it is readable by anyone holding the health-check-family "read" IAM
                        verb, a materially broader audience than whatever service the header is meant to
                        authenticate to. A custom header key that looks credential-bearing (for example
                        X-Api-Key, X-Auth-Token, or Cookie) is a common workaround for the Authorization
                        ban and typically indicates a live credential is stored in plaintext in the
                        monitor definition.
                        """
                    ),
                    location=loc,
                    row=r,
                    recommended_module="modules run enum_healthchecks --http-monitors --get",
                    notes=_wrap_paragraph(
                        notes
                        + ". Remediation: remove the credential-bearing header from the monitor and have"
                        " the monitored endpoint authenticate probes some other way (for example an"
                        " allow-listed vantage-point source range), or rotate the credential and store it"
                        " in OCI Vault instead of a plaintext monitor header."
                    ),
                )
            )

    def _check_monitor_sensitive_port_public_exposure(self, res: ServiceAuditResult) -> None:
        for table_name in (self.T_HTTP_MONITORS, self.T_PING_MONITORS):
            rows = self.get_rows(table_name)
            for r in rows:
                cid = _safe_str(r.get("compartment_id"))
                mid = _safe_str(r.get("id"))
                if not cid or not mid:
                    continue

                if not _truthy_str(r.get("is_enabled")):
                    continue

                protocol = _safe_str(r.get("protocol")).strip().upper()
                if protocol != "TCP":
                    continue

                port = _as_int(r.get("port"), default=-1)
                port_label = self._SENSITIVE_TCP_PORTS.get(port)
                if not port_label:
                    continue

                loc = _loc_base(compartment_id=cid, entity_id=mid)
                res.findings.append(
                    self.finding(
                        table_name=table_name,
                        issue_code="HEALTHCHECKS_MONITOR_SENSITIVE_PORT_PUBLIC_EXPOSURE",
                        title="Health check monitor probes a sensitive management/database port",
                        severity="MEDIUM",
                        description=_wrap_paragraph(
                            f"""
                            This enabled TCP monitor targets port {port} ({port_label}). Oracle's
                            "Securing Health Checks" documentation states that resources monitored by
                            this service "must be accessible from the public internet" for vantage-point
                            probes to succeed. An enabled TCP monitor configured against a well-known
                            remote-access, database, or admin-management port is therefore self-reported
                            evidence that the operator has intentionally exposed that sensitive port to
                            the public internet on the target host, a high-value target for credential
                            brute-force or exploitation if it lacks compensating controls.
                            """
                        ),
                        location=loc,
                        row=r,
                        recommended_module="modules run enum_healthchecks --ping-monitors --http-monitors --get",
                        notes=_wrap_paragraph(
                            f"""
                            Remediation: cross-check the monitor's targets against security-list/NSG data
                            for the target host. If port {port} does not need to be reachable from the
                            public internet, restrict it to a private/VPN-only path (bastion, private
                            endpoint, or VPN) and drop it from this public monitor, or replace it with an
                            HTTP(S) health monitor against a purpose-built, unauthenticated health
                            endpoint instead of the raw admin/database port.
                            """
                        ),
                    )
                )


# -----------------------------------------------------------------------------
# integration service auditor (gap-fill)
# -----------------------------------------------------------------------------

class IntegrationServiceAuditor(ServiceAuditor):
    service = "integration"

    T_INSTANCES = "integration_instances"

    def run_checks(self) -> ServiceAuditResult:
        res = ServiceAuditResult(service=self.service)
        try:
            self._check_instances_no_network_allowlist(res)
        except Exception as e:
            res.errors.append(f"instances_no_network_allowlist: {type(e).__name__}: {e}")
        try:
            self._check_file_server_exposed_no_allowlist(res)
        except Exception as e:
            res.errors.append(f"file_server_exposed_no_allowlist: {type(e).__name__}: {e}")
        return res

    @staticmethod
    def _is_public_no_allowlist(r: Dict[str, Any]) -> bool:
        ep = as_json_dict(r.get("network_endpoint_details"))
        if _safe_str(ep.get("network_endpoint_type")).upper() != "PUBLIC":
            return False
        if ep.get("allowlisted_http_ips"):
            return False
        if ep.get("allowlisted_http_vcns"):
            return False
        if _truthy_str(ep.get("is_integration_vcn_allowlisted")):
            return False
        # PublicEndpointDetails also carries independent runtime/design_time
        # ComponentAllowListDetails sub-objects (each with their own
        # allowlisted_http_ips/allowlisted_http_vcns), settable via
        # ChangeIntegrationInstanceNetworkEndpointDetails and mapping to the
        # instance's two separate endpoints (instance_url vs
        # instance_design_time_url) -- an instance can restrict access through
        # only these and leave the legacy top-level fields empty.
        for key in ("runtime", "design_time"):
            sub = as_json_dict(ep.get(key))
            if sub.get("allowlisted_http_ips") or sub.get("allowlisted_http_vcns"):
                return False
        return True

    def _check_instances_no_network_allowlist(self, res: ServiceAuditResult) -> None:
        rows = self.get_rows(self.T_INSTANCES, where_conditions={"lifecycle_state": "ACTIVE"})
        for r in rows:
            cid = _safe_str(r.get("compartment_id"))
            iid = _safe_str(r.get("id"))
            if not cid or not iid:
                continue

            if not self._is_public_no_allowlist(r):
                continue

            loc = _loc_base(compartment_id=cid, entity_id=iid)
            res.findings.append(
                self.finding(
                    table_name=self.T_INSTANCES,
                    issue_code="INTEGRATION_INSTANCE_NO_NETWORK_ALLOWLIST",
                    title="Integration instance has no IP/VCN allowlist restricting network access",
                    severity="MEDIUM",
                    description=_wrap_paragraph(
                        """
                        The instance's public endpoint (instance_url) has no allowlisted_http_ips,
                        allowlisted_http_vcns, or VCN allowlisting configured in network_endpoint_details, so it
                        is reachable from any internet address with only IDCS/user-credential auth as a gate.
                        OCI's own Integration Cloud documentation and CIS OCI Foundations Benchmark control 2.6
                        recommend restricting OIC access to approved corporate IPs, CIDRs, or VCNs.
                        """
                    ),
                    location=loc,
                    row=r,
                    recommended_module="modules run enum_integration --integration-instances --get",
                    notes=_wrap_paragraph(
                        """
                        Remediation: configure the allowlist (Instance Details > Network Access) or front the
                        instance with a WAF/service gateway, then re-run enum_integration --get to confirm the
                        change landed.
                        """
                    ),
                )
            )

    def _check_file_server_exposed_no_allowlist(self, res: ServiceAuditResult) -> None:
        rows = self.get_rows(self.T_INSTANCES, where_conditions={"lifecycle_state": "ACTIVE"})
        for r in rows:
            cid = _safe_str(r.get("compartment_id"))
            iid = _safe_str(r.get("id"))
            if not cid or not iid:
                continue

            if not _truthy_str(r.get("is_file_server_enabled")):
                continue

            if not self._is_public_no_allowlist(r):
                continue

            loc = _loc_base(compartment_id=cid, entity_id=iid)
            res.findings.append(
                self.finding(
                    table_name=self.T_INSTANCES,
                    issue_code="INTEGRATION_INSTANCE_FILE_SERVER_EXPOSED_NO_ALLOWLIST",
                    title="File Server is enabled on a publicly reachable instance with no network allowlist",
                    severity="MEDIUM",
                    description=_wrap_paragraph(
                        """
                        File Server is enabled (is_file_server_enabled) on top of the same unrestricted PUBLIC
                        endpoint (no allowlisted_http_ips, allowlisted_http_vcns, or is_integration_vcn_allowlisted
                        in network_endpoint_details). File Server adds a file-transfer surface used for
                        VB/PCS/OIC lookups and integrations, increasing the impact of the missing allowlist
                        beyond the base app/API surface.
                        """
                    ),
                    location=loc,
                    row=r,
                    recommended_module="modules run enum_integration --integration-instances --get",
                    notes=_wrap_paragraph(
                        """
                        Remediation: apply the same IP/VCN allowlist fix as
                        INTEGRATION_INSTANCE_NO_NETWORK_ALLOWLIST, or disable File Server
                        (is_file_server_enabled) if it is not actively used.
                        """
                    ),
                )
            )


# -----------------------------------------------------------------------------
# lockbox service auditor (gap-fill)
# -----------------------------------------------------------------------------

class LockboxServiceAuditor(ServiceAuditor):
    service = "lockbox"

    T_LOCKBOXES = "lockbox_lockboxes"
    T_APPROVAL_TEMPLATES = "lockbox_approval_templates"

    def run_checks(self) -> ServiceAuditResult:
        res = ServiceAuditResult(service=self.service)
        try:
            self._check_approval_template_auto_approval_enabled(res)
        except Exception as e:
            res.errors.append(f"approval_template_auto_approval_enabled: {type(e).__name__}: {e}")

        try:
            self._check_active_lockbox_no_approval_gate(res)
        except Exception as e:
            res.errors.append(f"active_lockbox_no_approval_gate: {type(e).__name__}: {e}")

        return res

    def _attached_approval_template_ids(self) -> set:
        """Approval template IDs referenced by at least one ACTIVE lockbox.

        An approval template is a standalone, reusable approver-policy definition --
        it only actually gates (or auto-approves) access to a real resource once a
        `Lockbox` (which always protects one specific `resource_id`) references it via
        `approval_template_id`. A template with auto-approval enabled but bound to no
        ACTIVE lockbox is configuration debt, not a live no-human-gate exposure (mirrors
        NetworkFirewallServiceAuditor's policy/firewall attachment split).
        """
        ids = set()
        for lb in self.get_rows(self.T_LOCKBOXES, where_conditions={"lifecycle_state": "ACTIVE"}):
            tid = _safe_str(lb.get("approval_template_id"))
            if tid:
                ids.add(tid)
        return ids

    def _check_approval_template_auto_approval_enabled(self, res: ServiceAuditResult) -> None:
        rows = self.get_rows(self.T_APPROVAL_TEMPLATES, where_conditions={"lifecycle_state": "ACTIVE"})
        attached = self._attached_approval_template_ids()
        for r in rows:
            cid = _safe_str(r.get("compartment_id"))
            tid = _safe_str(r.get("id"))
            if not cid or not tid:
                continue

            auto_approval_state = _safe_str(r.get("auto_approval_state")).upper()
            if auto_approval_state == "ENABLED":
                is_live = tid in attached
                loc = _loc_base(compartment_id=cid, entity_id=tid)
                res.findings.append(
                    self.finding(
                        table_name=self.T_APPROVAL_TEMPLATES,
                        issue_code="LOCKBOX_APPROVAL_TEMPLATE_AUTO_APPROVAL_ENABLED",
                        title="Approval template auto-approves Oracle operator access requests" if is_live
                        else "Approval template auto-approves Oracle operator access requests (not bound to any lockbox)",
                        severity="HIGH" if is_live else "LOW",
                        description=_wrap_paragraph(
                            """
                            The approval template has auto_approval_state set to ENABLED, meaning access requests
                            from Oracle‑authorized operators are approved automatically without any human reviewing
                            the configured approver_levels (up to three user/group approvers). This defeats the core
                            purpose of Lockbox/Managed Access -- a human‑in‑the‑loop gate on operator access to the
                            customer's resources.
                            """
                        ) + ("" if is_live else _wrap_paragraph(
                            """
                            This template is not currently referenced by any ACTIVE lockbox's approval_template_id,
                            so it is not auto-approving access to any real resource today. This is configuration
                            debt, not a live exposure -- it becomes an active risk the moment a lockbox is bound to it.
                            """
                        )),
                        location=loc,
                        row=r,
                        recommended_module="modules run enum_lockbox --approval-templates",
                        notes=_wrap_paragraph(
                            """
                            Remediation: set auto_approval_state to DISABLED unless auto‑approval is an explicit,
                            documented business decision. Also check LOCKBOX_ACTIVE_RESOURCE_HAS_NO_APPROVAL_GATE
                            findings to identify which lockboxes (and therefore which protected resources) reference
                            this approval_template_id.
                            """
                        ),
                    )
                )

    def _check_active_lockbox_no_approval_gate(self, res: ServiceAuditResult) -> None:
        templates = self.get_rows(self.T_APPROVAL_TEMPLATES)
        auto_approval_template_ids = {
            _safe_str(t.get("id"))
            for t in templates
            if _safe_str(t.get("auto_approval_state")).upper() == "ENABLED" and _safe_str(t.get("id"))
        }
        if not auto_approval_template_ids:
            return

        lockboxes = self.get_rows(self.T_LOCKBOXES, where_conditions={"lifecycle_state": "ACTIVE"})
        for lb in lockboxes:
            cid = _safe_str(lb.get("compartment_id"))
            lid = _safe_str(lb.get("id"))
            template_id = _safe_str(lb.get("approval_template_id"))
            if not cid or not lid or not template_id:
                continue

            if template_id in auto_approval_template_ids:
                resource_id = _safe_str(lb.get("resource_id")) or None
                loc = _loc_base(
                    compartment_id=cid,
                    entity_id=lid,
                    resource_id=resource_id,
                    approval_template_id=template_id,
                )
                res.findings.append(
                    self.finding(
                        table_name=self.T_LOCKBOXES,
                        issue_code="LOCKBOX_ACTIVE_RESOURCE_HAS_NO_APPROVAL_GATE",
                        title="Active Lockbox-protected resource has no human approval gate (bound to an auto-approval template)",
                        severity="HIGH",
                        description=_wrap_paragraph(
                            """
                            This ACTIVE lockbox's approval_template_id references an approval template with
                            auto_approval_state set to ENABLED, joining lockbox_lockboxes to
                            lockbox_approval_templates. That means the specific protected resource (resource_id)
                            currently grants Oracle‑operator access with zero human approval -- more actionable than
                            the template‑level finding because it names the exact exposed resource_id and
                            compartment_id.
                            """
                        ),
                        location=loc,
                        row=lb,
                        recommended_module="modules run enum_lockbox --lockboxes",
                        notes=_wrap_paragraph(
                            """
                            Remediation: rebind the lockbox to a manual‑approval template, or disable auto‑approval
                            on the referenced approval_template_id (see LOCKBOX_APPROVAL_TEMPLATE_AUTO_APPROVAL_ENABLED).
                            """
                        ),
                    )
                )


# -----------------------------------------------------------------------------
# management_agent service auditor (gap-fill)
# -----------------------------------------------------------------------------

class ManagementAgentServiceAuditor(ServiceAuditor):
    service = "management_agent"

    T_INSTALL_KEYS = "management_agent_install_keys"

    def run_checks(self) -> ServiceAuditResult:
        res = ServiceAuditResult(service=self.service)
        try:
            self._check_install_key_unlimited_unused(res)
        except Exception as e:
            res.errors.append(f"install_key_unlimited_unused: {type(e).__name__}: {e}")

        try:
            self._check_install_key_unlimited_in_use(res)
        except Exception as e:
            res.errors.append(f"install_key_unlimited_in_use: {type(e).__name__}: {e}")

        return res

    def _check_install_key_unlimited_unused(self, res: ServiceAuditResult) -> None:
        rows = self.get_rows(self.T_INSTALL_KEYS, where_conditions={"lifecycle_state": "ACTIVE"})
        for r in rows:
            cid = _safe_str(r.get("compartment_id"))
            kid = _safe_str(r.get("id"))
            if not cid or not kid:
                continue

            if not _truthy_str(r.get("is_unlimited")):
                continue
            if _as_int(r.get("current_key_install_count"), 0) > 0:
                continue

            loc = _loc_base(compartment_id=cid, entity_id=kid)
            res.findings.append(
                self.finding(
                    table_name=self.T_INSTALL_KEYS,
                    issue_code="MANAGEMENT_AGENT_INSTALL_KEY_UNLIMITED",
                    title="Management Agent install key allows unlimited agent installs",
                    severity="MEDIUM",
                    description=_wrap_paragraph(
                        """
                        The install key has no cap on the number of agents that can register with it
                        (isUnlimited is true) and is ACTIVE. Per Oracle's own guidance, if an unlimited
                        install key is compromised an attacker can enroll rogue agents anywhere the key
                        is scoped, and each enrolled agent can then be used to run commands on the
                        underlying host via Management Agent plugins/tasks. This key has not yet been
                        consumed (currentKeyInstallCount is 0).
                        """
                    ),
                    location=loc,
                    row=r,
                    recommended_module="modules run enum_management_agent --install_keys --get",
                    notes=_wrap_paragraph(
                        """
                        Remediation: delete this key and reissue one with allowedKeyInstallCount set to
                        the expected fleet size and a short timeToLive, or delete it immediately if it is
                        no longer needed for active rollout.
                        """
                    ),
                )
            )

    def _check_install_key_unlimited_in_use(self, res: ServiceAuditResult) -> None:
        rows = self.get_rows(self.T_INSTALL_KEYS, where_conditions={"lifecycle_state": "ACTIVE"})
        for r in rows:
            cid = _safe_str(r.get("compartment_id"))
            kid = _safe_str(r.get("id"))
            if not cid or not kid:
                continue

            if not _truthy_str(r.get("is_unlimited")):
                continue
            if _as_int(r.get("current_key_install_count"), 0) <= 0:
                continue

            loc = _loc_base(compartment_id=cid, entity_id=kid)
            res.findings.append(
                self.finding(
                    table_name=self.T_INSTALL_KEYS,
                    issue_code="MANAGEMENT_AGENT_INSTALL_KEY_UNLIMITED_IN_USE",
                    title="Unlimited Management Agent install key has already enrolled agents and remains active",
                    severity="MEDIUM",
                    description=_wrap_paragraph(
                        """
                        The install key is not just theoretically unlimited (isUnlimited is true) but has
                        confirmed live usage (currentKeyInstallCount > 0) while remaining ACTIVE with no
                        install cap. This is a proven, still-valid credential that can keep enrolling
                        agents indefinitely if leaked, for example if it was left behind in
                        config-management repos, golden images, or install scripts, letting an attacker
                        register a rogue agent that can then execute commands on the host it lands on.
                        """
                    ),
                    location=loc,
                    row=r,
                    recommended_module="modules run enum_management_agent --install_keys --get",
                    notes=_wrap_paragraph(
                        """
                        Remediation: rotate this key -- delete it and issue a replacement with a bounded
                        install count matching the completed rollout. Also audit
                        management_agent_agents for any host or display_name the deployer does not
                        recognize, since it may indicate a rogue agent was enrolled with this key.
                        """
                    ),
                )
            )


# -----------------------------------------------------------------------------
# monitoring service auditor (gap-fill)
# -----------------------------------------------------------------------------

class MonitoringServiceAuditor(ServiceAuditor):
    service = "monitoring"

    T_ALARMS = "monitoring_alarms"

    def run_checks(self) -> ServiceAuditResult:
        res = ServiceAuditResult(service=self.service)
        try:
            self._check_alarm_enabled_no_destinations(res)
        except Exception as e:
            res.errors.append(f"alarm_enabled_no_destinations: {type(e).__name__}: {e}")

        try:
            self._check_alarm_critical_disabled(res)
        except Exception as e:
            res.errors.append(f"alarm_critical_disabled: {type(e).__name__}: {e}")

        return res

    def _check_alarm_enabled_no_destinations(self, res: ServiceAuditResult) -> None:
        rows = self.get_rows(self.T_ALARMS, where_conditions={"lifecycle_state": "ACTIVE"})
        for r in rows:
            cid = _safe_str(r.get("compartment_id"))
            aid = _safe_str(r.get("id"))
            if not cid or not aid:
                continue

            if not _truthy_str(r.get("is_enabled")):
                continue

            destinations = _as_json_list(r.get("destinations"))
            if destinations:
                continue

            loc = _loc_base(compartment_id=cid, entity_id=aid, display_name=_safe_str(r.get("display_name")) or None)
            res.findings.append(
                self.finding(
                    table_name=self.T_ALARMS,
                    issue_code="MONITORING_ALARM_ENABLED_NO_DESTINATIONS",
                    title="Enabled alarm has no notification destinations",
                    severity="MEDIUM",
                    description=_wrap_paragraph(
                        """
                        The alarm is enabled and will evaluate its metric query, but has no configured
                        Notifications topic or Streaming destination, so a FIRING transition notifies no one.
                        OCI's CreateAlarmDetails requires at least one destination at creation, so an empty
                        list on a currently‑enabled alarm indicates the referenced topic/stream was later
                        deleted or the destination was cleared post‑creation.
                        """
                    ),
                    location=loc,
                    row=r,
                    recommended_module="modules run enum_monitoring --alarms",
                    notes=_wrap_paragraph(
                        """
                        Remediation: attach a valid Notifications topic or Streaming destination, or disable
                        the alarm if it is no longer needed.
                        """
                    ),
                )
            )

    def _check_alarm_critical_disabled(self, res: ServiceAuditResult) -> None:
        rows = self.get_rows(self.T_ALARMS, where_conditions={"lifecycle_state": "ACTIVE"})
        for r in rows:
            cid = _safe_str(r.get("compartment_id"))
            aid = _safe_str(r.get("id"))
            if not cid or not aid:
                continue

            severity = _safe_str(r.get("severity")).strip().upper()
            if severity != "CRITICAL":
                continue

            if not _falsy_str(r.get("is_enabled")):
                continue

            loc = _loc_base(compartment_id=cid, entity_id=aid, display_name=_safe_str(r.get("display_name")) or None)
            res.findings.append(
                self.finding(
                    table_name=self.T_ALARMS,
                    issue_code="MONITORING_ALARM_CRITICAL_DISABLED",
                    title="Critical-severity alarm is disabled",
                    severity="LOW",
                    description=_wrap_paragraph(
                        """
                        The alarm is configured with CRITICAL severity -- OCI's highest alarm severity,
                        intended for conditions requiring immediate action -- but is currently disabled, so
                        it will never fire regardless of the underlying metric condition. This is a narrow,
                        low‑noise check (only the CRITICAL subset, not all disabled alarms) since routine,
                        non‑critical alarms are commonly toggled off during maintenance.
                        """
                    ),
                    location=loc,
                    row=r,
                    recommended_module="modules run enum_monitoring --alarms",
                    notes=_wrap_paragraph(
                        """
                        Remediation: re-enable the alarm or confirm the disablement is intentional and
                        time-boxed.
                        """
                    ),
                )
            )


# -----------------------------------------------------------------------------
# ocvp service auditor (gap-fill)
# -----------------------------------------------------------------------------

class OcvpServiceAuditor(ServiceAuditor):
    service = "ocvp"

    T_CLUSTERS = "ocvp_clusters"

    def run_checks(self) -> ServiceAuditResult:
        res = ServiceAuditResult(service=self.service)
        try:
            self._check_clusters_shielded_instance(res)
        except Exception as e:
            res.errors.append(f"clusters_shielded_instance: {type(e).__name__}: {e}")

        return res

    def _check_clusters_shielded_instance(self, res: ServiceAuditResult) -> None:
        rows = self.get_rows(self.T_CLUSTERS, where_conditions={"lifecycle_state": "ACTIVE"})
        for r in rows:
            cid = _safe_str(r.get("compartment_id"))
            cluster_id = _safe_str(r.get("id"))
            if not cid or not cluster_id:
                continue

            # Falsy covers False/0/None/missing without mistaking a truthy value for disabled.
            if _truthy_str(r.get("is_shielded_instance_enabled")):
                continue

            loc = _loc_base(compartment_id=cid, entity_id=cluster_id)
            res.findings.append(
                self.finding(
                    table_name=self.T_CLUSTERS,
                    issue_code="OCVP_CLUSTER_SHIELDED_INSTANCE_DISABLED",
                    title="VMware Cluster Missing Shielded ESXi Instance Protection",
                    severity="MEDIUM",
                    description=_wrap_paragraph(
                        """
                        The ESXi cluster does not have Shielded Instance protection (Secure Boot +
                        TPM-based measured boot) enabled. OCI documents this as a STIG-aligned
                        firmware hardening control that defends against boot-level rootkits/malware
                        and ransomware on the ESXi host fleet.

                        Shielded Instances can only be turned on at cluster-creation time and cannot
                        be enabled retroactively, so an ACTIVE cluster with this flag falsy will
                        remain unprotected until it is rebuilt.
                        """
                    ),
                    location=loc,
                    row=r,
                    recommended_module="modules run enum_ocvp --clusters",
                    notes=_wrap_paragraph(
                        """
                        Remediation: provision a replacement cluster with Shielded Instances enabled
                        and migrate workloads to it; this setting cannot be retrofitted onto the
                        existing cluster. esxi_hosts_count and vmware_software_version on the row
                        provide sizing/version context for planning the rebuild.
                        """
                    ),
                )
            )


# -----------------------------------------------------------------------------
# opensearch service auditor (gap-fill)
# -----------------------------------------------------------------------------

class OpensearchServiceAuditor(ServiceAuditor):
    service = "opensearch"

    T_CLUSTERS = "opensearch_clusters"

    def run_checks(self) -> ServiceAuditResult:
        res = ServiceAuditResult(service=self.service)
        try:
            self._check_clusters_security_mode(res)
        except Exception as e:
            res.errors.append(f"clusters_security_mode: {type(e).__name__}: {e}")
        try:
            self._check_public_cluster_endpoints(res)
        except Exception as e:
            res.errors.append(f"public_cluster_endpoints: {type(e).__name__}: {e}")
        return res

    def _check_clusters_security_mode(self, res: ServiceAuditResult) -> None:
        rows = self.get_rows(self.T_CLUSTERS, where_conditions={"lifecycle_state": "ACTIVE"})
        for r in rows:
            cid = _safe_str(r.get("compartment_id"))
            cluster_id = _safe_str(r.get("id"))
            if not cid or not cluster_id:
                continue

            mode = _safe_str(r.get("security_mode")).strip().upper()
            if mode not in ("DISABLED", "PERMISSIVE"):
                continue

            loc = _loc_base(compartment_id=cid, entity_id=cluster_id, subnet_id=_safe_str(r.get("subnet_id")) or None)

            if mode == "DISABLED":
                res.findings.append(
                    self.finding(
                        table_name=self.T_CLUSTERS,
                        issue_code="OPENSEARCH_CLUSTER_SECURITY_DISABLED",
                        title="OpenSearch cluster has security mode DISABLED (no authentication)",
                        severity="CRITICAL",
                        description=_wrap_paragraph(
                            """
                            The cluster's security_mode is DISABLED, meaning OpenSearch and OpenSearch
                            Dashboards accept connections with no username/password authentication at all,
                            and traffic is transmitted over plaintext HTTP. Any principal with network
                            reachability to the cluster's private endpoint can read/write all indices.
                            """
                        ),
                        location=loc,
                        row=r,
                        recommended_module="modules run enum_opensearch --opensearch-clusters",
                        notes=_wrap_paragraph(
                            """
                            Remediation: update the cluster to at least PERMISSIVE and then ENFORCING
                            (oci opensearch cluster update --security-mode). Note the transition is
                            one-directional and enforcing cannot be reverted.
                            """
                        ),
                    )
                )
            else:
                res.findings.append(
                    self.finding(
                        table_name=self.T_CLUSTERS,
                        issue_code="OPENSEARCH_CLUSTER_SECURITY_PERMISSIVE",
                        title="OpenSearch cluster has security mode PERMISSIVE (auth bypass on direct connections)",
                        severity="HIGH",
                        description=_wrap_paragraph(
                            """
                            The cluster's security_mode is PERMISSIVE. OpenSearch Dashboards requires a
                            username/password, but direct connections to the OpenSearch API endpoint can
                            still be made without credentials, so data-plane access is effectively
                            unauthenticated for anyone with network reachability.
                            """
                        ),
                        location=loc,
                        row=r,
                        recommended_module="modules run enum_opensearch --opensearch-clusters",
                        notes=_wrap_paragraph(
                            """
                            Remediation: ENFORCING is the OCI-recommended mode and the only mode available
                            for newly created clusters; upgrade PERMISSIVE clusters to ENFORCING (irreversible).
                            """
                        ),
                    )
                )

    def _check_public_cluster_endpoints(self, res: ServiceAuditResult) -> None:
        rows = self.get_rows(self.T_CLUSTERS, where_conditions={"lifecycle_state": "ACTIVE"})
        for r in rows:
            cid = _safe_str(r.get("compartment_id"))
            cluster_id = _safe_str(r.get("id"))
            if not cid or not cluster_id:
                continue

            ip = _safe_str(r.get("opensearch_private_ip")).strip()
            if not ip:
                continue
            if not (_is_ipv4(ip) and not _is_private_ipv4(ip)):
                continue

            loc = _loc_base(compartment_id=cid, entity_id=cluster_id, subnet_id=_safe_str(r.get("subnet_id")) or None)
            res.findings.append(
                self.finding(
                    table_name=self.T_CLUSTERS,
                    issue_code="OPENSEARCH_CLUSTER_PUBLIC_ENDPOINT_IP",
                    title="OpenSearch cluster endpoint IP appears publicly routable",
                    severity="HIGH",
                    description=_wrap_paragraph(
                        """
                        opensearch_private_ip is populated but is not within any RFC1918 private range,
                        indicating the cluster's data-plane endpoint may be reachable outside the VCN.
                        Search with OpenSearch is designed to expose the cluster only via private endpoints
                        inside its VCN/subnet; a non-private address here should be treated as a network-
                        exposure misconfiguration and investigated (subnet/NSG/route table review) alongside
                        the compute/networking auditors.
                        """
                    ),
                    location=loc,
                    row=r,
                    recommended_module="modules run enum_opensearch --opensearch-clusters",
                    notes=_wrap_paragraph(
                        """
                        Remediation: confirm the cluster's subnet is private (no internet gateway route) and
                        that no NAT/public load balancer fronts the OpenSearch or Dashboard endpoints.
                        """
                    ),
                )
            )


# -----------------------------------------------------------------------------
# operator_access_control service auditor (gap-fill)
# -----------------------------------------------------------------------------

class OperatorAccessControlServiceAuditor(ServiceAuditor):
    service = "operator_access_control"

    T_OPERATOR_CONTROLS = "oac_operator_controls"
    T_ASSIGNMENTS = "oac_operator_control_assignments"
    T_ACCESS_REQUESTS = "oac_access_requests"

    def run_checks(self) -> ServiceAuditResult:
        res = ServiceAuditResult(service=self.service)
        try:
            self._check_operator_control_fully_pre_approved(res)
        except Exception as e:
            res.errors.append(f"operator_control_fully_pre_approved: {type(e).__name__}: {e}")

        try:
            self._check_assignment_log_not_forwarded(res)
        except Exception as e:
            res.errors.append(f"assignment_log_not_forwarded: {type(e).__name__}: {e}")

        return res

    def _check_operator_control_fully_pre_approved(self, res: ServiceAuditResult) -> None:
        rows = self.get_rows(self.T_OPERATOR_CONTROLS, where_conditions={"lifecycle_state": "ASSIGNED"})
        for r in rows:
            cid = _safe_str(r.get("compartment_id"))
            oc_id = _safe_str(r.get("id"))
            if not cid or not oc_id:
                continue

            if not _truthy_str(r.get("is_fully_pre_approved")):
                continue

            loc = _loc_base(compartment_id=cid, entity_id=oc_id)
            res.findings.append(
                self.finding(
                    table_name=self.T_OPERATOR_CONTROLS,
                    issue_code="OAC_OPERATOR_CONTROL_FULLY_PRE_APPROVED",
                    title="Operator control auto-approves all Oracle operator access requests",
                    severity="HIGH",
                    description=_wrap_paragraph(
                        """
                        The operator control is configured with "Pre-Approve All Actions", so every access
                        request an Oracle operator raises against resources governed by this control is
                        auto-approved with no customer review, regardless of the action's risk. OCI's own
                        OperatorControl API docs state that if this is enabled, all access requests
                        associated with the operator control will be auto-approved, and the Operator Access
                        Control admin guide recommends selecting specific pre-approved actions rather than
                        blanket pre-approval.
                        """
                    ),
                    location=loc,
                    row=r,
                    recommended_module="modules run enum_operator_access_control --operator_controls",
                    notes=_wrap_paragraph(
                        """
                        Remediation: switch to a curated pre-approved action list (or require approvers)
                        so higher-risk operator actions still need human sign-off. Cross-reference active
                        assignments (oac_operator_control_assignments) and any auto-approved access
                        requests (oac_access_requests) tied to this control's resources.
                        """
                    ),
                )
            )

    def _check_assignment_log_not_forwarded(self, res: ServiceAuditResult) -> None:
        active_states = {"APPLIED", "CUSTOMERASSIGNED"}
        rows = self.get_rows(self.T_ASSIGNMENTS)
        for r in rows:
            cid = _safe_str(r.get("compartment_id"))
            assignment_id = _safe_str(r.get("id"))
            if not cid or not assignment_id:
                continue

            lifecycle_state = _safe_str(r.get("lifecycle_state")).upper()
            if lifecycle_state not in active_states:
                continue

            if _truthy_str(r.get("is_log_forwarded")):
                continue

            loc = _loc_base(compartment_id=cid, entity_id=assignment_id)
            res.findings.append(
                self.finding(
                    table_name=self.T_ASSIGNMENTS,
                    issue_code="OAC_ASSIGNMENT_LOG_NOT_FORWARDED",
                    title="Operator control assignment is not forwarding audit logs off-platform",
                    severity="MEDIUM",
                    description=_wrap_paragraph(
                        """
                        The assignment governing this resource is not forwarding Oracle operator audit logs
                        to a customer-controlled remote syslog server. Actions Oracle operators take on the
                        resource are therefore only visible in Oracle's own audit trail, not the customer's
                        SIEM/log pipeline. OCI's Operator Access Control admin guide documents log
                        forwarding as the recommended mechanism for monitoring operator activity and meeting
                        regulatory/compliance requirements.
                        """
                    ),
                    location=loc,
                    row=r,
                    recommended_module="modules run enum_operator_access_control --assignments",
                    notes=_wrap_paragraph(
                        """
                        Remediation: enable "Forward audit logs" and configure a remote syslog server on the
                        assignment so operator activity is captured outside Oracle's platform.
                        """
                    ),
                )
            )


# -----------------------------------------------------------------------------
# os_management_hub service auditor (gap-fill)
# -----------------------------------------------------------------------------

class OsManagementHubServiceAuditor(ServiceAuditor):
    service = "os_management_hub"

    T_MANAGED_INSTANCES = "osmh_managed_instances"
    T_SCHEDULED_JOBS = "osmh_scheduled_jobs"

    def run_checks(self) -> ServiceAuditResult:
        res = ServiceAuditResult(service=self.service)
        try:
            self._check_scheduled_job_broad_or_dynamic_target(res)
        except Exception as e:
            res.errors.append(f"scheduled_job_broad_or_dynamic_target: {type(e).__name__}: {e}")
        try:
            self._check_management_station_host(res)
        except Exception as e:
            res.errors.append(f"management_station_host: {type(e).__name__}: {e}")
        return res

    def _check_scheduled_job_broad_or_dynamic_target(self, res: ServiceAuditResult) -> None:
        rows = self.get_rows(self.T_SCHEDULED_JOBS)
        for r in rows:
            if _safe_str(r.get("lifecycle_state")).upper() == "DELETED":
                continue

            cid = _safe_str(r.get("compartment_id"))
            job_id = _safe_str(r.get("id"))
            if not cid or not job_id:
                continue

            managed_compartment_ids = _as_json_list(r.get("managed_compartment_ids"))
            dynamic_set_ids = _as_json_list(r.get("dynamic_set_ids"))
            if not managed_compartment_ids and not dynamic_set_ids:
                continue

            if managed_compartment_ids and dynamic_set_ids:
                target_mode = "managed_compartment_ids and dynamic_set_ids"
            elif managed_compartment_ids:
                target_mode = "managed_compartment_ids"
            else:
                target_mode = "dynamic_set_ids"

            loc = _loc_base(
                compartment_id=cid,
                entity_id=job_id,
                schedule_type=_safe_str(r.get("schedule_type")) or None,
                target_mode=target_mode,
            )
            res.findings.append(
                self.finding(
                    table_name=self.T_SCHEDULED_JOBS,
                    issue_code="OSMH_SCHEDULED_JOB_BROAD_OR_DYNAMIC_TARGET",
                    title="Scheduled job targets an entire compartment or a dynamic set instead of a fixed instance/group list",
                    severity="LOW",
                    description=_wrap_paragraph(
                        """
                        A scheduled job whose managed_compartment_ids or dynamic_set_ids is non-empty is not
                        bound to a fixed, reviewed instance/group list -- OCI docs confirm these targeting modes
                        are mutually exclusive with managed_instance_ids/managed_instance_group_ids and sweep in
                        any current or future managed instance matching the compartment or dynamic membership
                        rule. Anyone who can create/modify such a job (via an over-broad OS Management Hub IAM
                        grant) gets a package install/update/remove, module-stream, software-source-attach, or
                        lifecycle-promote execution primitive across the entire matched fleet rather than a
                        curated subset.
                        """
                    ),
                    location=loc,
                    row=r,
                    recommended_module="modules run enum_os_management_hub --scheduled-jobs --get",
                    notes=_wrap_paragraph(
                        """
                        Remediation: prefer explicit managed_instance_ids/managed_instance_group_ids scoping;
                        where compartment-wide or dynamic targeting is required, tightly restrict who can author
                        scheduled jobs and review the job's operations list to confirm the actual blast radius
                        is intended.
                        """
                    ),
                )
            )

    def _check_management_station_host(self, res: ServiceAuditResult) -> None:
        rows = self.get_rows(self.T_MANAGED_INSTANCES)
        for r in rows:
            cid = _safe_str(r.get("compartment_id"))
            instance_id = _safe_str(r.get("id"))
            if not cid or not instance_id:
                continue

            if not _truthy_str(r.get("is_management_station")):
                continue

            loc = _loc_base(
                compartment_id=cid,
                entity_id=instance_id,
                display_name=_safe_str(r.get("display_name")) or None,
            )
            res.findings.append(
                self.finding(
                    table_name=self.T_MANAGED_INSTANCES,
                    issue_code="OSMH_MANAGEMENT_STATION_HOST",
                    title="Managed instance is an OS Management Hub management station (mirror/proxy chokepoint)",
                    severity="LOW",
                    description=_wrap_paragraph(
                        """
                        is_management_station marks this instance as a management station: it proxies OCI
                        traffic and mirrors vendor/custom software-source repositories (yum/DNF) that are then
                        served to potentially many downstream on-prem or third-party-cloud instances. Compromise
                        of this single host threatens the integrity of every package distributed to its served
                        fleet, making it a high-value pivot target disproportionate to its instance count of one.
                        """
                    ),
                    location=loc,
                    row=r,
                    recommended_module="modules run enum_os_management_hub --managed-instances --get",
                    notes=_wrap_paragraph(
                        """
                        Remediation: harden and monitor management-station hosts ahead of ordinary managed
                        instances (restrict network reachability to only its proxy/mirror ports, keep GPG/HTTPS
                        validation enabled for any third-party sources it mirrors), and treat compromise of a
                        management station as a fleet-wide package-supply-chain incident, not a single-host one.
                        """
                    ),
                )
            )


# -----------------------------------------------------------------------------
# postgresql service auditor (gap-fill)
# -----------------------------------------------------------------------------

class PostgresqlServiceAuditor(ServiceAuditor):
    service = "postgresql"

    T_DB_SYSTEMS = "postgresql_db_systems"

    # Terminal/deleted-ish lifecycle states where network posture is moot.
    _TERMINAL_STATES = ("DELETING", "DELETED", "FAILED")

    def run_checks(self) -> ServiceAuditResult:
        res = ServiceAuditResult(service=self.service)
        try:
            self._check_db_systems_without_nsg(res)
        except Exception as e:
            res.errors.append(f"db_systems_without_nsg: {type(e).__name__}: {e}")
        return res

    def _check_db_systems_without_nsg(self, res: ServiceAuditResult) -> None:
        rows = self.get_rows(self.T_DB_SYSTEMS)
        for r in rows:
            cid = _safe_str(r.get("compartment_id"))
            dbid = _safe_str(r.get("id"))
            if not cid or not dbid:
                continue

            if _safe_str(r.get("lifecycle_state")).upper() in self._TERMINAL_STATES:
                continue

            network_details = as_json_dict(r.get("network_details"))
            nsg_ids = _as_json_list(network_details.get("nsg_ids"))
            if nsg_ids:
                continue

            loc = _loc_base(
                compartment_id=cid,
                entity_id=dbid,
                subnet_id=_safe_str(network_details.get("subnet_id")) or None,
            )
            res.findings.append(
                self.finding(
                    table_name=self.T_DB_SYSTEMS,
                    issue_code="POSTGRESQL_DB_SYSTEM_NO_NSG",
                    title="PostgreSQL DB system has no NSG restrictions",
                    severity="MEDIUM",
                    description=_wrap_paragraph(
                        """
                        The DB system's network_details.nsgIds list is empty, so network access to the
                        PostgreSQL endpoint (port 5432) relies solely on the subnet-wide Security List
                        rather than a dedicated Network Security Group. Oracle's own PostgreSQL
                        documentation recommends NSGs as the mechanism to scope inbound access to specific
                        client resources/NSGs; without one, any host permitted by the broader subnet
                        Security List can reach the database endpoint.
                        """
                    ),
                    location=loc,
                    row=r,
                    recommended_module="modules run enum_postgresql --db-systems --get",
                    notes=_wrap_paragraph(
                        """
                        Remediation: attach a restrictive NSG (allow only the specific application/client
                        NSGs on port 5432) via UpdateDbSystem network_details.nsgIds, in addition to or
                        instead of relying on the subnet Security List.
                        """
                    ),
                )
            )


# -----------------------------------------------------------------------------
# queue service auditor (gap-fill)
# -----------------------------------------------------------------------------

class QueueServiceAuditor(ServiceAuditor):
    service = "queue"

    T_QUEUES = "queues"

    def run_checks(self) -> ServiceAuditResult:
        res = ServiceAuditResult(service=self.service)
        try:
            self._check_queue_cmk(res)
        except Exception as e:
            res.errors.append(f"queue_cmk: {type(e).__name__}: {e}")
        return res

    def _check_queue_cmk(self, res: ServiceAuditResult) -> None:
        rows = self.get_rows(self.T_QUEUES, where_conditions={"lifecycle_state": "ACTIVE"})
        for r in rows:
            cid = _safe_str(r.get("compartment_id"))
            qid = _safe_str(r.get("id"))
            if not cid or not qid:
                continue

            # retention_in_seconds is a get-only field (absent from list_queues'
            # QueueSummary, present only on the full Queue model returned by
            # get_queue). Its presence proves this row was fetched with --get,
            # so an empty custom_encryption_key_id here reflects the queue's
            # real configuration rather than an unfetched field.
            if r.get("retention_in_seconds") in (None, ""):
                continue

            if _safe_str(r.get("custom_encryption_key_id")):
                continue

            loc = _loc_base(compartment_id=cid, entity_id=qid)
            res.findings.append(
                self.finding(
                    table_name=self.T_QUEUES,
                    issue_code="QUEUE_NO_CMK",
                    title="Queue has no customer-managed encryption key",
                    severity="LOW",
                    description=_wrap_paragraph(
                        """
                        Queue relies on Oracle's default provider-managed key instead of a customer-managed
                        key from Vault. OCI's official Queue security guidance recommends creating and
                        managing your own encryption keys in Vault rather than the auto-generated default,
                        so key rotation/disable/delete stays under the operator's control and IAM policies
                        can restrict who can manage it.
                        """
                    ),
                    location=loc,
                    row=r,
                    recommended_module="modules run enum_queue --queues --get",
                    notes=_wrap_paragraph(
                        """
                        Remediation: call UpdateQueue with a Vault key OCID for queues carrying sensitive
                        message payloads, and gate key lifecycle operations with a dedicated IAM policy.
                        """
                    ),
                )
            )


# -----------------------------------------------------------------------------
# service_connector service auditor (gap-fill)
# -----------------------------------------------------------------------------

class ServiceConnectorServiceAuditor(ServiceAuditor):
    service = "service_connector"

    T_SERVICE_CONNECTORS = "sch_service_connectors"

    def run_checks(self) -> ServiceAuditResult:
        res = ServiceAuditResult(service=self.service)
        try:
            self._check_connectors_failed(res)
        except Exception as e:
            res.errors.append(f"connectors_failed: {type(e).__name__}: {e}")

        try:
            self._check_connectors_needs_attention(res)
        except Exception as e:
            res.errors.append(f"connectors_needs_attention: {type(e).__name__}: {e}")

        return res

    def _check_connectors_failed(self, res: ServiceAuditResult) -> None:
        rows = self.get_rows(self.T_SERVICE_CONNECTORS, where_conditions={"lifecycle_state": "FAILED"})
        for r in rows:
            cid = _safe_str(r.get("compartment_id"))
            scid = _safe_str(r.get("id"))
            if not cid or not scid:
                continue

            loc = _loc_base(compartment_id=cid, entity_id=scid)
            res.findings.append(
                self.finding(
                    table_name=self.T_SERVICE_CONNECTORS,
                    issue_code="SCH_SERVICE_CONNECTOR_FAILED",
                    title="Service Connector pipeline is in FAILED state",
                    severity="MEDIUM",
                    description=_wrap_paragraph(
                        """
                        The connector's lifecycle_state is FAILED, meaning its source->task->target
                        data-movement pipeline is not running. Service Connector Hub is the mechanism
                        OCI's CIS Landing Zone guidance recommends for routing Audit, VCN Flow, and
                        Object Storage logs to a SIEM, so a FAILED connector can mean security-relevant
                        telemetry is silently not being delivered.
                        """
                    ),
                    location=loc,
                    row=r,
                    recommended_module="modules run enum_service_connector --service-connectors --get",
                    notes=_wrap_paragraph(
                        """
                        Remediation: inspect lifecycle_details on the row and the connector's service
                        logs (console/CLI) for the root cause -- commonly an authorization or target-
                        service error -- then repair or re-enable the connector. Confirm downstream log
                        delivery (SIEM/Object Storage/Stream) resumes once fixed.
                        """
                    ),
                )
            )

    def _check_connectors_needs_attention(self, res: ServiceAuditResult) -> None:
        rows = self.get_rows(self.T_SERVICE_CONNECTORS, where_conditions={"lifecycle_state": "NEEDS_ATTENTION"})
        for r in rows:
            cid = _safe_str(r.get("compartment_id"))
            scid = _safe_str(r.get("id"))
            if not cid or not scid:
                continue

            loc = _loc_base(compartment_id=cid, entity_id=scid)
            res.findings.append(
                self.finding(
                    table_name=self.T_SERVICE_CONNECTORS,
                    issue_code="SCH_SERVICE_CONNECTOR_NEEDS_ATTENTION",
                    title="Service Connector pipeline needs attention",
                    severity="LOW",
                    description=_wrap_paragraph(
                        """
                        The connector is in OCI's NEEDS_ATTENTION state, indicating partial/degraded
                        delivery (e.g. intermittent authorization errors, throttling, or per-run
                        failures) rather than total failure. lifecycle_details on the row typically
                        carries the specific error. Since Connector Hub commonly carries audit/flow-log
                        traffic to external monitoring, a degraded pipeline can produce gaps in log
                        completeness worth investigating even though the connector is technically still
                        enabled.
                        """
                    ),
                    location=loc,
                    row=r,
                    recommended_module="modules run enum_service_connector --service-connectors --get",
                    notes=_wrap_paragraph(
                        """
                        Remediation: review lifecycle_details and recent run history for the connector
                        to identify the intermittent failure mode, then correct the underlying
                        authorization/target-service/throttling issue. This is a degradation signal
                        rather than a hard failure.
                        """
                    ),
                )
            )


# -----------------------------------------------------------------------------
# streaming service auditor (gap-fill)
# -----------------------------------------------------------------------------

class StreamingServiceAuditor(ServiceAuditor):
    service = "streaming"

    T_STREAM_POOLS = "streaming_stream_pools"

    _ACTIVE_ISH_STATES = ("ACTIVE", "UPDATING")

    def run_checks(self) -> ServiceAuditResult:
        res = ServiceAuditResult(service=self.service)
        try:
            self._check_stream_pool_not_private(res)
        except Exception as e:
            res.errors.append(f"stream_pool_not_private: {type(e).__name__}: {e}")

        try:
            self._check_stream_pool_no_customer_managed_key(res)
        except Exception as e:
            res.errors.append(f"stream_pool_no_customer_managed_key: {type(e).__name__}: {e}")

        try:
            self._check_stream_pool_kafka_auto_create_topics(res)
        except Exception as e:
            res.errors.append(f"stream_pool_kafka_auto_create_topics: {type(e).__name__}: {e}")

        return res

    def _check_stream_pool_not_private(self, res: ServiceAuditResult) -> None:
        rows = self.get_rows(self.T_STREAM_POOLS)
        for r in rows:
            cid = _safe_str(r.get("compartment_id"))
            pid = _safe_str(r.get("id"))
            if not cid or not pid:
                continue
            if _safe_str(r.get("lifecycle_state")).upper() not in self._ACTIVE_ISH_STATES:
                continue

            if _truthy_str(r.get("is_private")):
                continue

            loc = _loc_base(compartment_id=cid, entity_id=pid)
            res.findings.append(
                self.finding(
                    table_name=self.T_STREAM_POOLS,
                    issue_code="STREAMING_STREAM_POOL_NOT_PRIVATE",
                    title="Stream pool endpoint is public (no private endpoint configured)",
                    severity="MEDIUM",
                    description=_wrap_paragraph(
                        """
                        The stream pool's is_private flag is not set, so its messages endpoint
                        (endpoint_fqdn) is publicly resolvable and reachable over the internet rather than
                        restricted to a VCN subnet, per OCI's own Streaming security documentation.
                        Producers/consumers therefore rely solely on IAM request signing and TLS rather than
                        network-level isolation to reach the pool.
                        """
                    ),
                    location=loc,
                    row=r,
                    recommended_module="modules run enum_streaming --stream_pools --get",
                    notes=_wrap_paragraph(
                        """
                        Remediation: recreate or migrate the pool with a private endpoint (subnet-scoped) for
                        sensitive workloads, or confirm public exposure is intentional. This is a posture
                        signal (mirrors the existing VAULT_KMS_VIRTUAL_PRIVATE_VAULT precedent of flagging a
                        common product default) rather than proof of an active compromise.
                        """
                    ),
                )
            )

    def _check_stream_pool_no_customer_managed_key(self, res: ServiceAuditResult) -> None:
        rows = self.get_rows(self.T_STREAM_POOLS)
        for r in rows:
            cid = _safe_str(r.get("compartment_id"))
            pid = _safe_str(r.get("id"))
            if not cid or not pid:
                continue
            if _safe_str(r.get("lifecycle_state")).upper() not in self._ACTIVE_ISH_STATES:
                continue

            cek = as_json_dict(r.get("custom_encryption_key"))
            if _safe_str(cek.get("kms_key_id")):
                continue

            loc = _loc_base(compartment_id=cid, entity_id=pid)
            res.findings.append(
                self.finding(
                    table_name=self.T_STREAM_POOLS,
                    issue_code="STREAMING_POOL_NO_CUSTOMER_MANAGED_KEY",
                    title="Stream pool uses Oracle-managed encryption key (no customer-managed key)",
                    severity="LOW",
                    description=_wrap_paragraph(
                        """
                        No customer-managed (Vault) key is configured, so the pool falls back to
                        Oracle-managed encryption at rest. This mirrors the existing VAULT_KMS_SOFTWARE_KEY
                        pattern: not a vulnerability by itself, but a weaker key-lifecycle control (no
                        customer rotate/disable/delete/audit) for compliance-sensitive streaming data.
                        """
                    ),
                    location=loc,
                    row=r,
                    recommended_module="modules run enum_streaming --stream_pools --get",
                    notes=_wrap_paragraph(
                        """
                        Remediation: assign a Vault master encryption key via custom_encryption_key when
                        data sensitivity or compliance requires customer key control.
                        """
                    ),
                )
            )

    def _check_stream_pool_kafka_auto_create_topics(self, res: ServiceAuditResult) -> None:
        rows = self.get_rows(self.T_STREAM_POOLS)
        for r in rows:
            cid = _safe_str(r.get("compartment_id"))
            pid = _safe_str(r.get("id"))
            if not cid or not pid:
                continue
            if _safe_str(r.get("lifecycle_state")).upper() not in self._ACTIVE_ISH_STATES:
                continue

            kafka = as_json_dict(r.get("kafka_settings"))
            if not kafka:
                continue
            if not _truthy_str(kafka.get("auto_create_topics_enable")):
                continue

            loc = _loc_base(compartment_id=cid, entity_id=pid)
            res.findings.append(
                self.finding(
                    table_name=self.T_STREAM_POOLS,
                    issue_code="STREAMING_POOL_KAFKA_AUTO_CREATE_TOPICS_ENABLED",
                    title="Stream pool Kafka compatibility has auto-create-topics enabled",
                    severity="LOW",
                    description=_wrap_paragraph(
                        """
                        The pool's Kafka-compatibility settings have auto_create_topics_enable turned on,
                        deviating from OCI's documented default of false. Any producer able to reach the
                        Kafka-compatible endpoint can implicitly provision new topics/streams, bypassing
                        explicit topic-provisioning controls and enabling resource-sprawl/DoS via unbounded
                        topic creation -- a well-known Kafka hardening item.
                        """
                    ),
                    location=loc,
                    row=r,
                    recommended_module="modules run enum_streaming --stream_pools --get",
                    notes=_wrap_paragraph(
                        """
                        Remediation: disable auto-create and provision topics/streams explicitly through
                        IAM-gated calls.
                        """
                    ),
                )
            )


# -----------------------------------------------------------------------------
# tagging service auditor (gap-fill)
# -----------------------------------------------------------------------------

class TaggingServiceAuditor(ServiceAuditor):
    service = "tagging"

    T_TAG_DEFAULTS = "tag_defaults"
    T_TAG_DEFINITIONS = "tag_definitions"

    def run_checks(self) -> ServiceAuditResult:
        res = ServiceAuditResult(service=self.service)
        try:
            self._check_tag_default_potential_secret_value(res)
        except Exception as e:
            res.errors.append(f"tag_defaults: {type(e).__name__}: {e}")

        try:
            self._check_tag_definition_freeform_tag_potential_secret(res)
        except Exception as e:
            res.errors.append(f"tag_definitions: {type(e).__name__}: {e}")

        return res

    def _check_tag_default_potential_secret_value(self, res: ServiceAuditResult) -> None:
        rows = self.get_rows(self.T_TAG_DEFAULTS)
        for r in rows:
            cid = _safe_str(r.get("compartment_id"))
            tdid = _safe_str(r.get("id"))
            if not cid or not tdid:
                continue

            tag_name = _safe_str(r.get("tag_definition_name"))
            if not tag_name or not _contains_sensitive_key_name(tag_name):
                continue

            value = _safe_str(r.get("value")).strip()
            if not value:
                continue

            loc = _loc_base(compartment_id=cid, entity_id=tdid)
            is_required = _truthy_str(r.get("is_required"))
            notes = (
                "Tag default key looks secret-bearing: " + tag_name
                + (". is_required is set, so this value is mandatorily applied." if is_required else "")
            )
            res.findings.append(
                self.finding(
                    table_name=self.T_TAG_DEFAULTS,
                    issue_code="TAGGING_TAG_DEFAULT_POTENTIAL_SECRET_VALUE",
                    title="Tag default carries a credential-shaped value that auto-applies to new resources",
                    severity="MEDIUM",
                    description=_wrap_paragraph(
                        """
                        OCI's Security Guide states tags must never hold confidential data and points to
                        OCI Vault instead. This tag default's key name reads as a credential (password,
                        secret, token, private key, or API key) and carries a non-empty literal value that
                        auto-populates onto every new resource created in this compartment/tenancy scope
                        unless explicitly overridden, and mandatorily so when is_required is set. That bakes
                        the secret into every future resource's tags.
                        """
                    ),
                    location=loc,
                    row=r,
                    recommended_module="modules run enum_tagging --tag-defaults",
                    notes=_wrap_paragraph(
                        notes
                        + ". Remediation: move the value into OCI Vault, blank or delete this tag default, "
                        "and rotate any secret it may have exposed."
                    ),
                )
            )

    def _check_tag_definition_freeform_tag_potential_secret(self, res: ServiceAuditResult) -> None:
        rows = self.get_rows(self.T_TAG_DEFINITIONS)
        for r in rows:
            cid = _safe_str(r.get("compartment_id"))
            tdid = _safe_str(r.get("id"))
            if not cid or not tdid:
                continue

            freeform = as_json_dict(r.get("freeform_tags"))
            if not freeform:
                continue

            sensitive_hits: List[str] = []
            for k, v in freeform.items():
                if not _contains_sensitive_key_name(k):
                    continue
                sv = _safe_str(v).strip()
                if sv:
                    sensitive_hits.append(k)

            if not sensitive_hits:
                continue

            loc = _loc_base(compartment_id=cid, entity_id=tdid)
            notes = (
                "freeform_tags include keys that look secret-bearing: "
                + ", ".join(sorted(set(sensitive_hits))[:12])
            )
            res.findings.append(
                self.finding(
                    table_name=self.T_TAG_DEFINITIONS,
                    issue_code="TAGGING_DEFINITION_FREEFORM_TAG_POTENTIAL_SECRET",
                    title="Tag definition's own freeform_tags contains a credential-shaped key/value",
                    severity="MEDIUM",
                    description=_wrap_paragraph(
                        """
                        OCI's Security Guide states tags must never hold confidential data and points to
                        OCI Vault instead. This tag definition resource carries its own freeform_tags with
                        a key that reads as a credential and a non-empty string value. Unlike a tag default,
                        this value is not auto-propagated to other resources -- it is visible only to anyone
                        who can read this one tag definition -- so it is lower urgency but still worth
                        flagging.
                        """
                    ),
                    location=loc,
                    row=r,
                    recommended_module="modules run enum_tagging --tag-definitions",
                    notes=_wrap_paragraph(
                        notes
                        + ". Remediation: move the value into OCI Vault and strip the key from freeform_tags."
                    ),
                )
            )


# -----------------------------------------------------------------------------
# tenant_manager service auditor (gap-fill)
# -----------------------------------------------------------------------------

class TenantManagerServiceAuditor(ServiceAuditor):
    service = "tenant_manager"

    T_DOMAINS = "tenant_manager_domains"

    _LAPSED_STATUSES = {
        "REVOKED",
        "REVOKING",
        "RELEASED",
        "RELEASING",
        "EXPIRING",
        "FAILED",
    }

    _STALE_PENDING_DAYS = 7

    def run_checks(self) -> ServiceAuditResult:
        res = ServiceAuditResult(service=self.service)
        try:
            self._check_domain_verification_lapsed(res)
        except Exception as e:
            res.errors.append(f"domain_verification_lapsed: {type(e).__name__}: {e}")

        try:
            self._check_domain_verification_stale_pending(res)
        except Exception as e:
            res.errors.append(f"domain_verification_stale_pending: {type(e).__name__}: {e}")

        return res

    def _check_domain_verification_lapsed(self, res: ServiceAuditResult) -> None:
        rows = self.get_rows(self.T_DOMAINS, where_conditions={"lifecycle_state": "ACTIVE"})
        for r in rows:
            cid = _safe_str(r.get("compartment_id"))
            did = _safe_str(r.get("id"))
            if not cid or not did:
                continue

            status = _safe_str(r.get("status")).strip().upper()
            if status not in self._LAPSED_STATUSES:
                continue

            domain_name = _safe_str(r.get("domain_name")) or None
            loc = _loc_base(compartment_id=cid, entity_id=did, domain_name=domain_name)
            res.findings.append(
                self.finding(
                    table_name=self.T_DOMAINS,
                    issue_code="TENANT_MANAGER_DOMAIN_VERIFICATION_LAPSED",
                    title="Tenant Manager domain claim is revoked, released, or expiring (not Active)",
                    severity="MEDIUM",
                    description=_wrap_paragraph(
                        """
                        The domain claim's lifecycle_state is still ACTIVE but its TXT-record ownership
                        verification status is no longer Active (observed status: %s). A Tenant Manager
                        domain claim exists to prove ownership of a corporate email domain and, while
                        Active, blocks outsiders from creating new OCI tenancies using email addresses
                        from that domain -- new sign-ups from the domain are intercepted and brought under
                        this organization's governance. Once the claim is revoked, released, or expiring,
                        that protection is void and anyone with an email address on the domain can create
                        an unmanaged shadow tenancy outside this organization's oversight.
                        """
                        % (status or "UNKNOWN")
                    ),
                    location=loc,
                    row=r,
                    recommended_module="modules run enum_tenant_manager --domains",
                    notes=_wrap_paragraph(
                        """
                        Remediation: re-add the domain's TXT record in DNS and re-verify ownership in
                        Tenant Manager, or confirm the domain is intentionally being released/retired.
                        If unintentional, treat this as a priority fix -- the exposure window starts the
                        moment the claim leaves the Active state.
                        """
                    ),
                )
            )

    def _check_domain_verification_stale_pending(self, res: ServiceAuditResult) -> None:
        rows = self.get_rows(self.T_DOMAINS, where_conditions={"lifecycle_state": "ACTIVE"})
        for r in rows:
            cid = _safe_str(r.get("compartment_id"))
            did = _safe_str(r.get("id"))
            if not cid or not did:
                continue

            status = _safe_str(r.get("status")).strip().upper()
            if status != "PENDING":
                continue

            age_days = _age_days(r.get("time_created"))
            if age_days is None or age_days <= self._STALE_PENDING_DAYS:
                continue

            domain_name = _safe_str(r.get("domain_name")) or None
            loc = _loc_base(compartment_id=cid, entity_id=did, domain_name=domain_name)
            res.findings.append(
                self.finding(
                    table_name=self.T_DOMAINS,
                    issue_code="TENANT_MANAGER_DOMAIN_VERIFICATION_STALE_PENDING",
                    title="Tenant Manager domain stuck in Pending verification past the expected window",
                    severity="LOW",
                    description=_wrap_paragraph(
                        """
                        This domain claim has been sitting in PENDING verification for roughly %.1f days
                        (time_created). OCI documents a 72-hour verification/remediation window after
                        which an unverified domain claim is revoked; a claim still Pending well beyond
                        that (a 7-day threshold is used here to absorb clock skew and normal DNS
                        propagation delay) indicates the TXT record was never added to DNS or that
                        verification stalled. Until verification completes, the domain is not protected:
                        outsiders can still sign up for OCI using this domain's email addresses without
                        this organization's governance oversight.
                        """
                        % age_days
                    ),
                    location=loc,
                    row=r,
                    recommended_module="modules run enum_tenant_manager --domains",
                    notes=_wrap_paragraph(
                        """
                        Remediation: add the provided TXT record to the domain's DNS registrar to complete
                        verification, or remove the stale claim if the domain is no longer being onboarded.
                        """
                    ),
                )
            )


# -----------------------------------------------------------------------------
# visual_builder service auditor (gap-fill)
# -----------------------------------------------------------------------------

class VisualBuilderServiceAuditor(ServiceAuditor):
    service = "visual_builder"

    T_VB_INSTANCES = "visual_builder_instances"

    def run_checks(self) -> ServiceAuditResult:
        res = ServiceAuditResult(service=self.service)
        try:
            self._check_instance_public_unrestricted(res)
        except Exception as e:
            res.errors.append(f"instance_public_unrestricted: {type(e).__name__}: {e}")
        try:
            self._check_allowlist_any(res)
        except Exception as e:
            res.errors.append(f"allowlist_any: {type(e).__name__}: {e}")
        return res

    def _check_instance_public_unrestricted(self, res: ServiceAuditResult) -> None:
        rows = self.get_rows(self.T_VB_INSTANCES, where_conditions={"lifecycle_state": "ACTIVE"})
        for r in rows:
            cid = _safe_str(r.get("compartment_id"))
            vid = _safe_str(r.get("id"))
            if not cid or not vid:
                continue

            ned = as_json_dict(r.get("network_endpoint_details"))
            if _safe_str(ned.get("network_endpoint_type")).upper() != "PUBLIC":
                continue

            allowed_ips = _as_json_list(ned.get("allowlisted_http_ips"))
            allowed_vcns = _as_json_list(ned.get("allowlisted_http_vcns"))
            if allowed_ips or allowed_vcns:
                continue

            loc = _loc_base(compartment_id=cid, entity_id=vid)
            res.findings.append(
                self.finding(
                    table_name=self.T_VB_INSTANCES,
                    issue_code="VISUAL_BUILDER_INSTANCE_PUBLIC_UNRESTRICTED",
                    title="Visual Builder instance has unrestricted public network access (Default mode)",
                    severity="MEDIUM",
                    description=_wrap_paragraph(
                        """
                        The instance uses a PUBLIC network endpoint with no allowlisted_http_ips and no
                        allowlisted_http_vcns configured. Oracle's own Visual Builder admin documentation
                        defines this exact combination as the "Default" access mode: unrestricted network
                        access reachable from the entire public internet with no IP or VCN restriction.
                        Visual Builder instances host app-dev/runtime consoles and deployed web/REST
                        endpoints, so this is a meaningful internet-facing exposure.
                        """
                    ),
                    location=loc,
                    row=r,
                    recommended_module="modules run enum_visual_builder --vb-instances",
                    notes=_wrap_paragraph(
                        """
                        Remediation: switch the instance to "Secure access from allowed IPs and VCNs only"
                        (populate allowlisted_http_ips/allowlisted_http_vcns) or to a private endpoint
                        (network_endpoint_type=PRIVATE bound to a VCN/subnet).
                        """
                    ),
                )
            )

    def _check_allowlist_any(self, res: ServiceAuditResult) -> None:
        rows = self.get_rows(self.T_VB_INSTANCES, where_conditions={"lifecycle_state": "ACTIVE"})
        for r in rows:
            cid = _safe_str(r.get("compartment_id"))
            vid = _safe_str(r.get("id"))
            if not cid or not vid:
                continue

            ned = as_json_dict(r.get("network_endpoint_details"))
            if _safe_str(ned.get("network_endpoint_type")).upper() != "PUBLIC":
                continue

            allowed_ips = _as_json_list(ned.get("allowlisted_http_ips"))
            if not allowed_ips:
                continue

            if any(_is_public_cidr(x) for x in allowed_ips):
                loc = _loc_base(compartment_id=cid, entity_id=vid)
                res.findings.append(
                    self.finding(
                        table_name=self.T_VB_INSTANCES,
                        issue_code="VISUAL_BUILDER_ALLOWLIST_ANY",
                        title="Visual Builder public-endpoint IP allowlist includes an any-address CIDR",
                        severity="MEDIUM",
                        description=_wrap_paragraph(
                            """
                            The PUBLIC endpoint's allowlisted_http_ips contains 0.0.0.0/0 (or an equivalent
                            any-address entry), which functionally negates the allowlist and reopens the
                            instance to the entire internet even though it appears to be in "restricted"
                            allowlist mode.
                            """
                        ),
                        location=loc,
                        row=r,
                        recommended_module="modules run enum_visual_builder --vb-instances",
                        notes=_wrap_paragraph(
                            """
                            Remediation: replace the any-address entry with specific administrative/corporate
                            CIDR ranges, or move to a private endpoint (network_endpoint_type=PRIVATE bound to
                            a VCN/subnet).
                            """
                        ),
                    )
                )


# -----------------------------------------------------------------------------
# vulnerability_scanning service auditor (gap-fill)
# -----------------------------------------------------------------------------

class VulnerabilityScanningServiceAuditor(ServiceAuditor):
    service = "vulnerability_scanning"

    T_HOST_SCAN_TARGETS = "vulnerability_scanning_host_scan_targets"
    T_CONTAINER_SCAN_TARGETS = "vulnerability_scanning_container_scan_targets"
    T_VULNERABILITIES = "vulnerability_scanning_vulnerabilities"

    def run_checks(self) -> ServiceAuditResult:
        res = ServiceAuditResult(service=self.service)
        try:
            self._check_host_scan_target_failed(res)
        except Exception as e:
            res.errors.append(f"host_scan_target_failed: {type(e).__name__}: {e}")

        try:
            self._check_container_scan_target_failed(res)
        except Exception as e:
            res.errors.append(f"container_scan_target_failed: {type(e).__name__}: {e}")

        try:
            self._check_open_high_severity_vulnerability(res)
        except Exception as e:
            res.errors.append(f"open_high_severity_vulnerability: {type(e).__name__}: {e}")

        return res

    def _check_host_scan_target_failed(self, res: ServiceAuditResult) -> None:
        rows = self.get_rows(self.T_HOST_SCAN_TARGETS, where_conditions={"lifecycle_state": "FAILED"})
        for r in rows:
            cid = _safe_str(r.get("compartment_id"))
            tid = _safe_str(r.get("id"))
            if not cid or not tid:
                continue

            loc = _loc_base(
                compartment_id=cid,
                entity_id=tid,
                target_compartment_id=_safe_str(r.get("target_compartment_id")) or None,
            )
            res.findings.append(
                self.finding(
                    table_name=self.T_HOST_SCAN_TARGETS,
                    issue_code="VULN_SCANNING_HOST_SCAN_TARGET_FAILED",
                    title="Host scan target is in FAILED lifecycle state",
                    severity="MEDIUM",
                    description=_wrap_paragraph(
                        """
                        Host scan target lifecycle_state is FAILED, a terminal SDK error state distinct from
                        the transient CREATING/UPDATING states. While the target remains FAILED, the compute
                        instances covered by target_compartment_id/instance_ids are not actually being scanned
                        for OS vulnerabilities -- a silent scanning coverage gap rather than a temporary blip.
                        """
                    ),
                    location=loc,
                    row=r,
                    recommended_module="modules run enum_vulnerability_scanning --host-scan-targets",
                    notes=_wrap_paragraph(
                        """
                        Remediation: review the target for the underlying error (common causes: missing
                        service gateway or disabled traffic-forwarding for private-subnet agent scanning, a
                        disabled Vulnerability Scanning plugin on the agent, or a missing IAM policy), then
                        recreate the target and re-run enum_vulnerability_scanning --host-scan-targets to
                        confirm it returns to ACTIVE.
                        """
                    ),
                )
            )

    def _check_container_scan_target_failed(self, res: ServiceAuditResult) -> None:
        rows = self.get_rows(self.T_CONTAINER_SCAN_TARGETS, where_conditions={"lifecycle_state": "FAILED"})
        for r in rows:
            cid = _safe_str(r.get("compartment_id"))
            tid = _safe_str(r.get("id"))
            if not cid or not tid:
                continue

            loc = _loc_base(
                compartment_id=cid,
                entity_id=tid,
                target_registry=_safe_str(r.get("target_registry")) or None,
            )
            res.findings.append(
                self.finding(
                    table_name=self.T_CONTAINER_SCAN_TARGETS,
                    issue_code="VULN_SCANNING_CONTAINER_SCAN_TARGET_FAILED",
                    title="Container scan target is in FAILED lifecycle state",
                    severity="MEDIUM",
                    description=_wrap_paragraph(
                        """
                        Container scan target lifecycle_state is FAILED, a terminal SDK error state rather
                        than a transient CREATING/UPDATING one. While FAILED, images in target_registry are
                        not being scanned for known CVEs -- a registry-scanning blind spot, not a temporary
                        interruption.
                        """
                    ),
                    location=loc,
                    row=r,
                    recommended_module="modules run enum_vulnerability_scanning --container-scan-targets",
                    notes=_wrap_paragraph(
                        """
                        Remediation: verify the target/recipe configuration and IAM policy for the registry,
                        recreate the target, and re-run enum_vulnerability_scanning --container-scan-targets
                        to confirm ACTIVE state before relying on this registry's scan coverage.
                        """
                    ),
                )
            )

    def _check_open_high_severity_vulnerability(self, res: ServiceAuditResult) -> None:
        rows = self.get_rows(
            self.T_VULNERABILITIES,
            where_conditions={"lifecycle_state": "ACTIVE", "state": "OPEN"},
        )
        for r in rows:
            cid = _safe_str(r.get("compartment_id"))
            vid = _safe_str(r.get("id"))
            if not cid or not vid:
                continue

            severity = _safe_str(r.get("severity")).upper()
            if severity not in ("CRITICAL", "HIGH"):
                continue

            finding_severity = "CRITICAL" if severity == "CRITICAL" else "HIGH"
            impacted = r.get("impacted_resources_count")
            impacted_txt = _safe_str(impacted) if impacted not in (None, "") else "an unknown number of"

            loc = _loc_base(compartment_id=cid, entity_id=vid)
            res.findings.append(
                self.finding(
                    table_name=self.T_VULNERABILITIES,
                    issue_code="VULN_SCANNING_OPEN_HIGH_SEVERITY_VULNERABILITY",
                    title="Open CRITICAL/HIGH severity vulnerability detected and unresolved",
                    severity=finding_severity,
                    description=_wrap_paragraph(
                        f"""
                        Vulnerability state is OPEN (as opposed to FIXED/NOT_APPLICABLE) with a scanner-reported
                        severity of {severity or 'UNKNOWN'}, impacting {impacted_txt} resource(s) in this
                        compartment. This is a direct read of the Vulnerability Scanning service's own verdict
                        (lifecycle_state ACTIVE, state OPEN, severity CRITICAL/HIGH), not an inference, so it is
                        resistant to false positives.
                        """
                    ),
                    location=loc,
                    row=r,
                    recommended_module="modules run enum_vulnerability_scanning --vulnerabilities",
                    notes=_wrap_paragraph(
                        """
                        Remediation: patch/update the affected package or image referenced by
                        vulnerability_reference (see cve_description for details), prioritizing CRITICAL
                        findings first, then re-run enum_vulnerability_scanning --vulnerabilities to confirm
                        state moves to FIXED.
                        """
                    ),
                )
            )


# -----------------------------------------------------------------------------
# waas service auditor (gap-fill)
# -----------------------------------------------------------------------------

class WaasServiceAuditor(ServiceAuditor):
    service = "waas"

    T_CERTIFICATES = "waas_certificates"
    T_POLICIES = "waas_waas_policies"

    # Lifecycle states where a WAAS policy is not (or no longer) fronting traffic.
    _DEAD_POLICY_STATES = {"DELETED", "DELETING", "FAILED"}

    def _attached_certificate_ids(self) -> set:
        """Certificate IDs referenced by at least one non-dead WAAS policy's HTTPS config.

        A WAAS certificate is a standalone object in the certificate store -- it only
        terminates TLS for real traffic once a policy's `policy_config.certificate_id`
        references it. `policy_config` is only populated when the policy row was
        enumerated with `--get` (list_waas_policies summaries omit it), so a policy
        enumerated without `--get` is silently treated as having no attached cert
        (matches WafServiceAuditor's `actions[]`/--get gate).
        """
        ids = set()
        for p in self.get_rows(self.T_POLICIES):
            if _safe_str(p.get("lifecycle_state")).upper() in self._DEAD_POLICY_STATES:
                continue
            pc = as_json_dict(p.get("policy_config"))
            cert_id = _safe_str(pc.get("certificate_id"))
            if cert_id:
                ids.add(cert_id)
        return ids

    def run_checks(self) -> ServiceAuditResult:
        res = ServiceAuditResult(service=self.service)
        try:
            self._check_certificate_expiry(res)
        except Exception as e:
            res.errors.append(f"certificate_expiry: {type(e).__name__}: {e}")

        try:
            self._check_certificate_trust_verification_disabled(res)
        except Exception as e:
            res.errors.append(f"certificate_trust_verification_disabled: {type(e).__name__}: {e}")

        return res

    @staticmethod
    def _parse_not_valid_after(value: Any) -> Any:
        from datetime import datetime, timezone

        s = _safe_str(value).strip()
        if not s:
            return None
        try:
            dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
        except Exception:
            return None
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt

    def _check_certificate_expiry(self, res: ServiceAuditResult) -> None:
        from datetime import datetime, timedelta, timezone

        rows = self.get_rows(self.T_CERTIFICATES, where_conditions={"lifecycle_state": "ACTIVE"})
        attached = self._attached_certificate_ids()
        now = datetime.now(timezone.utc)
        soon_cutoff = now + timedelta(days=30)
        not_attached_suffix = _wrap_paragraph(
            """
            This certificate is not currently referenced by any active WAAS policy's
            `policy_config.certificate_id`, so it is not terminating TLS traffic today.
            This is configuration debt, not a live exposure -- it becomes an active risk
            the moment the certificate is bound to a policy's HTTPS config.
            """
        )

        for r in rows:
            cid = _safe_str(r.get("compartment_id"))
            certid = _safe_str(r.get("id"))
            if not cid or not certid:
                continue

            not_after = self._parse_not_valid_after(r.get("time_not_valid_after"))
            if not_after is None:
                continue

            is_live = certid in attached
            loc = _loc_base(compartment_id=cid, entity_id=certid)

            if not_after < now:
                res.findings.append(
                    self.finding(
                        table_name=self.T_CERTIFICATES,
                        issue_code="WAAS_CERTIFICATE_EXPIRED",
                        title="WAAS certificate is expired but still ACTIVE" if is_live
                        else "WAAS certificate is expired but still ACTIVE (not attached to a policy)",
                        severity="MEDIUM" if is_live else "LOW",
                        description=_wrap_paragraph(
                            """
                            The certificate's time_not_valid_after is in the past while lifecycle_state is still
                            ACTIVE, meaning an expired TLS certificate remains attached to a WAAS resource. Public
                            clients hitting the fronted domain will see certificate-invalid warnings, training
                            users to click through TLS errors and opening a MITM/downgrade risk.
                            """
                        ) + ("" if is_live else not_attached_suffix),
                        location=loc,
                        row=r,
                        recommended_module="modules run enum_waas --certificates --get",
                        notes=_wrap_paragraph(
                            """
                            Remediation: rotate/replace the certificate (upload a new cert and update the
                            policy's SSL config), then remove the expired one.
                            """
                        ),
                    )
                )
                continue

            if not_after < soon_cutoff:
                res.findings.append(
                    self.finding(
                        table_name=self.T_CERTIFICATES,
                        issue_code="WAAS_CERTIFICATE_EXPIRING_SOON",
                        title="WAAS certificate expires within 30 days" if is_live
                        else "WAAS certificate expires within 30 days (not attached to a policy)",
                        severity="MEDIUM" if is_live else "LOW",
                        description=_wrap_paragraph(
                            """
                            The certificate is still valid but time_not_valid_after falls within the next 30 days,
                            so it will expire without rotation. Flags upcoming TLS breakage/outage risk before it
                            becomes an active MITM/trust-warning exposure.
                            """
                        ) + ("" if is_live else not_attached_suffix),
                        location=loc,
                        row=r,
                        recommended_module="modules run enum_waas --certificates --get",
                        notes=_wrap_paragraph(
                            "Remediation: schedule certificate renewal ahead of the expiry date."
                        ),
                    )
                )

    def _check_certificate_trust_verification_disabled(self, res: ServiceAuditResult) -> None:
        rows = self.get_rows(self.T_CERTIFICATES, where_conditions={"lifecycle_state": "ACTIVE"})
        attached = self._attached_certificate_ids()
        for r in rows:
            cid = _safe_str(r.get("compartment_id"))
            certid = _safe_str(r.get("id"))
            if not cid or not certid:
                continue

            if not _truthy_str(r.get("is_trust_verification_disabled")):
                continue

            is_live = certid in attached
            loc = _loc_base(compartment_id=cid, entity_id=certid)
            res.findings.append(
                self.finding(
                    table_name=self.T_CERTIFICATES,
                    issue_code="WAAS_CERTIFICATE_TRUST_VERIFICATION_DISABLED",
                    title="WAAS certificate has trust verification disabled (self-signed)" if is_live
                    else "WAAS certificate has trust verification disabled (self-signed, not attached to a policy)",
                    severity="MEDIUM" if is_live else "LOW",
                    description=_wrap_paragraph(
                        """
                        is_trust_verification_disabled=true means chain-of-trust verification was skipped when
                        the certificate was uploaded, which OCI documents as indicating the certificate is most
                        likely self-signed. A self-signed cert fronting a public WAAS domain causes browser trust
                        warnings for end users and offers no CA-backed identity assurance, undermining the
                        purpose of TLS termination at the WAF edge.
                        """
                    ) + ("" if is_live else _wrap_paragraph(
                        """
                        This certificate is not currently referenced by any active WAAS policy's
                        `policy_config.certificate_id`, so it is not terminating TLS traffic today.
                        """
                    )),
                    location=loc,
                    row=r,
                    recommended_module="modules run enum_waas --certificates --get",
                    notes=_wrap_paragraph(
                        """
                        Remediation: replace with a CA-issued certificate for any domain serving public traffic;
                        self-signed certs should be limited to internal/test policies only.
                        """
                    ),
                )
            )


# -----------------------------------------------------------------------------
# waf service auditor (gap-fill)
# -----------------------------------------------------------------------------

class WafServiceAuditor(ServiceAuditor):
    service = "waf"

    T_POLICIES = "web_app_firewall_policies"
    T_FIREWALLS = "web_app_firewalls"

    # Lifecycle states where a WebAppFirewall deployment is not (or no longer)
    # enforcing traffic -- a policy referenced only by deployments in these states
    # is not live.
    _DEAD_FIREWALL_STATES = {"DELETED", "DELETING", "FAILED"}

    def _attached_policy_ids(self) -> set:
        """Policy IDs referenced by at least one non-dead WebAppFirewall deployment.

        A WAF policy is a standalone rules container in OCI -- it only enforces
        traffic once a separate `WebAppFirewall` resource is deployed in front of a
        load balancer/backend referencing it (`web_app_firewall_policy_id`). A policy
        with a weak default action or detect-only rate limiting but no live
        deployment attached poses no current traffic-path risk (mirrors
        NetworkFirewallServiceAuditor's policy/firewall attachment split).
        """
        ids = set()
        for fw in self.get_rows(self.T_FIREWALLS):
            if _safe_str(fw.get("lifecycle_state")).upper() in self._DEAD_FIREWALL_STATES:
                continue
            pid = _safe_str(fw.get("web_app_firewall_policy_id"))
            if pid:
                ids.add(pid)
        return ids

    def run_checks(self) -> ServiceAuditResult:
        res = ServiceAuditResult(service=self.service)
        try:
            self._check_default_action_not_blocking(res)
        except Exception as e:
            res.errors.append(f"default_action_not_blocking: {type(e).__name__}: {e}")

        try:
            self._check_rate_limit_action_check_only(res)
        except Exception as e:
            res.errors.append(f"rate_limit_action_check_only: {type(e).__name__}: {e}")

        return res

    def _check_default_action_not_blocking(self, res: ServiceAuditResult) -> None:
        rows = self.get_rows(self.T_POLICIES, where_conditions={"lifecycle_state": "ACTIVE"})
        attached = self._attached_policy_ids()
        for r in rows:
            cid = _safe_str(r.get("compartment_id"))
            pid = _safe_str(r.get("id"))
            if not cid or not pid:
                continue

            # actions[] is only populated when the row was enumerated with --get
            # (list_web_app_firewall_policies summaries never carry it) -- gate here
            # to avoid false positives from summary-only enumeration.
            actions = _as_json_list(r.get("actions"))
            if not actions:
                continue

            rac = as_json_dict(r.get("request_access_control"))
            default_action_name = _safe_str(rac.get("default_action_name")).strip()
            if not default_action_name:
                continue

            default_action = None
            for a in actions:
                if isinstance(a, dict) and _safe_str(a.get("name")) == default_action_name:
                    default_action = a
                    break
            if default_action is None:
                continue

            action_type = _safe_str(default_action.get("type")).upper()
            if action_type not in ("ALLOW", "CHECK"):
                continue

            is_live = pid in attached
            loc = _loc_base(compartment_id=cid, entity_id=pid, default_action_name=default_action_name)
            res.findings.append(
                self.finding(
                    table_name=self.T_POLICIES,
                    issue_code="WAF_POLICY_DEFAULT_ACTION_NOT_BLOCKING",
                    title="WAF policy default action does not block unmatched requests" if is_live
                    else "WAF policy default action does not block unmatched requests (policy not currently deployed)",
                    severity="MEDIUM" if is_live else "LOW",
                    description=_wrap_paragraph(
                        f"""
                        The policy's default action ("{default_action_name}", type {action_type}) is applied to
                        any request that matches none of the configured request access-control rules.
                        {action_type} is not a blocking action -- ALLOW passes the request through untouched and
                        CHECK only logs it -- so unmatched traffic reaches the origin unblocked. This violates
                        OCI's own recommended deny-by-default WAF posture.
                        """
                    ) + ("" if is_live else _wrap_paragraph(
                        """
                        This policy is not currently referenced by any active WebAppFirewall deployment
                        (`web_app_firewalls`), so it is not enforcing traffic today. This is configuration debt,
                        not a live exposure -- it becomes an active risk the moment the policy is deployed.
                        """
                    )),
                    location=loc,
                    row=r,
                    recommended_module="modules run enum_waf --firewall-policies --get",
                    notes=_wrap_paragraph(
                        """
                        Remediation: set the Default Action for request access control to a RETURN_HTTP_RESPONSE
                        action (e.g. HTTP 403/400) so traffic not covered by an explicit allow rule is blocked,
                        then re-run enum_waf --get to confirm.
                        """
                    ),
                )
            )

    def _check_rate_limit_action_check_only(self, res: ServiceAuditResult) -> None:
        rows = self.get_rows(self.T_POLICIES, where_conditions={"lifecycle_state": "ACTIVE"})
        attached = self._attached_policy_ids()
        for r in rows:
            cid = _safe_str(r.get("compartment_id"))
            pid = _safe_str(r.get("id"))
            if not cid or not pid:
                continue

            # Same --get gate as above: actions[] (and therefore rate-limiting rule ->
            # action resolution) is only populated on a full get_web_app_firewall_policy row.
            actions = _as_json_list(r.get("actions"))
            if not actions:
                continue

            rrl = as_json_dict(r.get("request_rate_limiting"))
            rules = _as_json_list(rrl.get("rules"))
            if not rules:
                continue

            actions_by_name = {
                _safe_str(a.get("name")): a
                for a in actions
                if isinstance(a, dict) and _safe_str(a.get("name"))
            }

            for rule in rules:
                if not isinstance(rule, dict):
                    continue

                rule_name = _safe_str(rule.get("name"))
                action_name = _safe_str(rule.get("action_name")).strip()
                if not action_name:
                    continue

                action = actions_by_name.get(action_name)
                if action is None:
                    continue

                # Rate-limiting rule actions are only ever CHECK or RETURN_HTTP_RESPONSE per
                # the OCI API, so CHECK unambiguously means the rule is detect-only.
                if _safe_str(action.get("type")).upper() != "CHECK":
                    continue

                is_live = pid in attached
                loc = _loc_base(
                    compartment_id=cid,
                    entity_id=pid,
                    rate_limit_rule_name=rule_name or None,
                    action_name=action_name,
                )
                res.findings.append(
                    self.finding(
                        table_name=self.T_POLICIES,
                        issue_code="WAF_POLICY_RATE_LIMIT_ACTION_CHECK_ONLY",
                        title="WAF rate-limiting rule is detect-only, not enforced" if is_live
                        else "WAF rate-limiting rule is detect-only, not enforced (policy not currently deployed)",
                        severity="LOW",
                        description=_wrap_paragraph(
                            f"""
                            Rate-limiting rule "{rule_name or action_name}" is bound to action "{action_name}"
                            (type CHECK), so requests that exceed the configured rate are logged but never
                            throttled or blocked. Rate-limiting rule actions are only ever CHECK or
                            RETURN_HTTP_RESPONSE, so CHECK unambiguously means the rule provides visibility
                            only -- not the brute-force/DoS/scraping mitigation it appears to implement.
                            """
                        ) + ("" if is_live else _wrap_paragraph(
                            """
                            This policy is not currently referenced by any active WebAppFirewall deployment
                            (`web_app_firewalls`), so this rule is not evaluating traffic today.
                            """
                        )),
                        location=loc,
                        row=r,
                        recommended_module="modules run enum_waf --firewall-policies --get",
                        notes=_wrap_paragraph(
                            """
                            Remediation: rebind the rule's action_name to a RETURN_HTTP_RESPONSE action (e.g.
                            HTTP 429) once validated in CHECK mode, then re-run enum_waf --get to confirm.
                            """
                        ),
                    )
                )


# -----------------------------------------------------------------------------
# wlms service auditor (gap-fill)
# -----------------------------------------------------------------------------

class WlmsServiceAuditor(ServiceAuditor):
    service = "wlms"

    T_WLS_DOMAINS = "wlms_wls_domains"
    T_MANAGED_INSTANCES = "wlms_managed_instances"

    def run_checks(self) -> ServiceAuditResult:
        res = ServiceAuditResult(service=self.service)
        try:
            self._check_domain_patch_readiness_error(res)
        except Exception as e:
            res.errors.append(f"domain_patch_readiness_error: {type(e).__name__}: {e}")

        try:
            self._check_domain_patch_readiness_unknown(res)
        except Exception as e:
            res.errors.append(f"domain_patch_readiness_unknown: {type(e).__name__}: {e}")

        try:
            self._check_managed_instance_plugin_inactive(res)
        except Exception as e:
            res.errors.append(f"managed_instance_plugin_inactive: {type(e).__name__}: {e}")

        return res

    def _check_domain_patch_readiness_error(self, res: ServiceAuditResult) -> None:
        rows = self.get_rows(self.T_WLS_DOMAINS, where_conditions={"lifecycle_state": "ACTIVE"})
        for r in rows:
            cid = _safe_str(r.get("compartment_id"))
            did = _safe_str(r.get("id"))
            if not cid or not did:
                continue

            readiness = _safe_str(r.get("patch_readiness_status")).upper()
            if readiness == "ERROR":
                loc = _loc_base(compartment_id=cid, entity_id=did)
                res.findings.append(
                    self.finding(
                        table_name=self.T_WLS_DOMAINS,
                        issue_code="WLMS_DOMAIN_PATCH_READINESS_ERROR",
                        title="WebLogic domain cannot be patched through WLMS (patch readiness ERROR)",
                        severity="MEDIUM",
                        description=_wrap_paragraph(
                            """
                            The domain's patch_readiness_status is ERROR while the domain itself is ACTIVE,
                            meaning WLMS cannot currently orchestrate a patch apply against it (Oracle's WLMS
                            docs require a Passed/OK readiness state before patching can proceed). This is a
                            platform‑visible blocker to remediating known WebLogic Server CVEs via the managed
                            patching path.
                            """
                        ),
                        location=loc,
                        row=r,
                        recommended_module="modules run enum_wlms --wls-domains --get",
                        notes=_wrap_paragraph(
                            """
                            Remediation: review lifecycle_details and the domain's patch‑readiness detail in
                            the console/CLI (`oci wlms wls-domain get`) to resolve the underlying scan failure
                            (agent connectivity, OPatch/middleware‑home integrity, disk space) so patches can
                            be applied.
                            """
                        ),
                    )
                )

    def _check_domain_patch_readiness_unknown(self, res: ServiceAuditResult) -> None:
        rows = self.get_rows(self.T_WLS_DOMAINS, where_conditions={"lifecycle_state": "ACTIVE"})
        for r in rows:
            cid = _safe_str(r.get("compartment_id"))
            did = _safe_str(r.get("id"))
            if not cid or not did:
                continue

            readiness = _safe_str(r.get("patch_readiness_status")).upper()
            if readiness == "UNKNOWN":
                loc = _loc_base(compartment_id=cid, entity_id=did)
                res.findings.append(
                    self.finding(
                        table_name=self.T_WLS_DOMAINS,
                        issue_code="WLMS_DOMAIN_PATCH_READINESS_UNKNOWN",
                        title="WebLogic domain has never completed a patch-readiness scan",
                        severity="LOW",
                        description=_wrap_paragraph(
                            """
                            patch_readiness_status is UNKNOWN on an ACTIVE domain, indicating no readiness
                            scan has completed, so the platform has no basis for confirming this domain is
                            patchable. Left unresolved, the domain effectively sits outside the managed‑
                            patching workflow.
                            """
                        ),
                        location=loc,
                        row=r,
                        recommended_module="modules run enum_wlms --wls-domains --get",
                        notes=_wrap_paragraph(
                            """
                            Remediation: trigger/verify a patch‑readiness scan (`oci wlms wls-domain ...
                            scan` or console "View patch readiness details") and re‑enumerate.
                            """
                        ),
                    )
                )

    def _check_managed_instance_plugin_inactive(self, res: ServiceAuditResult) -> None:
        rows = self.get_rows(self.T_MANAGED_INSTANCES, where_conditions={"plugin_status": "INACTIVE"})
        for r in rows:
            cid = _safe_str(r.get("compartment_id"))
            mid = _safe_str(r.get("id"))
            if not cid or not mid:
                continue

            loc = _loc_base(compartment_id=cid, entity_id=mid)
            res.findings.append(
                    self.finding(
                        table_name=self.T_MANAGED_INSTANCES,
                        issue_code="WLMS_MANAGED_INSTANCE_PLUGIN_INACTIVE",
                        title="WLMS agent plugin inactive on managed instance",
                        severity="LOW",
                        description=_wrap_paragraph(
                            """
                            The managed‑instance's WLMS agent plugin_status is INACTIVE (the only other value
                            is ACTIVE per the OCI CLI spec), meaning the host is not currently reporting to
                            WLMS. WebLogic servers on this host are outside patch orchestration and
                            configuration visibility until the agent resumes reporting.
                            """
                        ),
                        location=loc,
                        row=r,
                        recommended_module="modules run enum_wlms --managed-instances --get",
                        notes=_wrap_paragraph(
                            """
                            Remediation: check the WLS Management Agent service on the host (connectivity,
                            agent process health) and confirm it resumes ACTIVE status.
                            """
                        ),
                    )
                )




# =============================================================================
# Runner
# =============================================================================

DEFAULT_SERVICE_AUDITORS: List[type[ServiceAuditor]] = [
    AnalyticsServiceAuditor,
    ApiAccessControlServiceAuditor,
    BdsServiceAuditor,
    CertificatesServiceAuditor,
    DataCatalogServiceAuditor,
    DataIntegrationServiceAuditor,
    DataSafeServiceAuditor,
    DbMulticloudServiceAuditor,
    DelegateAccessControlServiceAuditor,
    EventsServiceAuditor,
    FusionAppsServiceAuditor,
    GenerativeAiAgentServiceAuditor,
    GenerativeAiServiceAuditor,
    GovernanceRulesServiceAuditor,
    HealthChecksServiceAuditor,
    IntegrationServiceAuditor,
    LockboxServiceAuditor,
    ManagementAgentServiceAuditor,
    MonitoringServiceAuditor,
    OcvpServiceAuditor,
    OpensearchServiceAuditor,
    OperatorAccessControlServiceAuditor,
    OsManagementHubServiceAuditor,
    PostgresqlServiceAuditor,
    QueueServiceAuditor,
    ServiceConnectorServiceAuditor,
    StreamingServiceAuditor,
    TaggingServiceAuditor,
    TenantManagerServiceAuditor,
    VisualBuilderServiceAuditor,
    VulnerabilityScanningServiceAuditor,
    WaasServiceAuditor,
    WafServiceAuditor,
    WlmsServiceAuditor,
    ApiGatewayServiceAuditor,
    ArtifactRegistryServiceAuditor,
    BastionServiceAuditor,
    BlockchainServiceAuditor,
    BlockStorageServiceAuditor,
    CacheServiceAuditor,
    CloudGuardServiceAuditor,
    ComputeServiceAuditor,
    ComputeInstanceAgentServiceAuditor,
    ContainerRegistryServiceAuditor,
    DataScienceServiceAuditor,
    DatabaseServiceAuditor,
    DevOpsServiceAuditor,
    DNSServiceAuditor,
    EmailServiceAuditor,
    FileStorageServiceAuditor,
    FunctionsServiceAuditor,
    GoldenGateServiceAuditor,
    IdentityServiceAuditor,
    IdentityDomainsServiceAuditor,
    IoTServiceAuditor,
    KubernetesServiceAuditor,
    LoggingServiceAuditor,
    ManagedKafkaServiceAuditor,
    NetworkFirewallServiceAuditor,
    NetworkLoadBalancerServiceAuditor,
    NetworkingServiceAuditor,
    NotificationsServiceAuditor,
    ObjectStorageServiceAuditor,
    ResourceManagerServiceAuditor,
    VaultServiceAuditor,
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


# =============================================================================
# Module entrypoint
# =============================================================================

def _parse_args(user_args: List[str]) -> argparse.Namespace:
    service_hint = ",".join(cls.service for cls in DEFAULT_SERVICE_AUDITORS)
    p = argparse.ArgumentParser(
        description="Run a DB-driven configuration audit across saved OCI resources",
        allow_abbrev=False,
    )
    p.add_argument(
        "--services",
        default=None,
        help=f"Comma-separated list of services to include (e.g. {service_hint}). Default: all.",
    )
    p.add_argument(
        "--max-per-service",
        type=int,
        default=50,
        help="Max grouped findings to print per service.",
    )
    p.add_argument(
        "-v",
        "--debug",
        action="store_true",
        help="Enable verbose debug output (auditors may add more later).",
    )
    return p.parse_args(user_args)


def run_module(user_args, session):
    args = _parse_args(list(user_args))

    include_services: Optional[List[str]] = None
    if args.services:
        include_services = [s.strip() for s in args.services.split(",") if s.strip()]

    report = run_audit(session=session, debug=bool(args.debug), include_services=include_services)
    print_audit_report(report, max_findings_per_service=int(args.max_per_service))

    return report.to_dict()
