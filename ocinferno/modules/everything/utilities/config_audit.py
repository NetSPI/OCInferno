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

from prettytable import PrettyTable

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

def _safe_str(x: Any) -> str:
    return x if isinstance(x, str) else ""


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

    t = PrettyTable()
    t.field_names = fields
    t.align = "l"

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
        t.add_row(row_out)

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


def _as_json_dict(v: Any) -> Dict[str, Any]:
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
                        recommended_module="modules run enum_vault --vaults --save",
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

                log_configuration = json.loads(log.get("configuration"))
                log_bucket_name = log_configuration["source"]["resource"]
                log_source_category = log_configuration["source"]["category"]

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


class ComputeServiceAuditor(ServiceAuditor):
    service = "compute"

    TABLE_INSTANCES = "compute_instances"

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
            
            cid = _safe_str(r.get("compartment_id"))
            instance_id = _safe_str(r.get("id"))

            platform_config = json.loads(r.get("platform_config"))

            measured_boot = platform_config["is_measured_boot_enabled"]
            secure_boot = platform_config["is_secure_boot_enabled"]
            tpm_module = platform_config["is_trusted_platform_module_enabled"]

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
                        recommended_module="modules run enum_kubernetes --clusters",
                        notes=_wrap_paragraph(
                            "Remediation: enable shielded instance settings where supported. "
                        ),
                    )
                )


    def _check_confidential_computing(self, res: ServiceAuditResult) -> None:
        
        rows = self.get_rows(self.TABLE_INSTANCES)
        for r in rows:
            
            cid = _safe_str(r.get("compartment_id"))
            instance_id = _safe_str(r.get("id"))

            platform_config = json.loads(r.get("platform_config"))

            confiential_computing = platform_config["is_memory_encryption_enabled"]

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
                        recommended_module="modules run enum_kubernetes --clusters",
                        notes=_wrap_paragraph(
                            "Remediation: enable memory encryption on supported shapes. "
                        ),
                    )
                )

    def _check_imds_service(self, res: ServiceAuditResult) -> None:
        rows = self.get_rows(self.TABLE_INSTANCES)
        for r in rows:
            
            cid = _safe_str(r.get("compartment_id"))
            instance_id = _safe_str(r.get("id"))
            instance_options = json.loads(r.get("instance_options"))
 
            imds_legacy_enabled = not instance_options["are_legacy_imds_endpoints_disabled"]

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
                        recommended_module="modules run enum_kubernetes --clusters",
                        notes=_wrap_paragraph(
                            "Remediation: disable legacy IMDS endpoints (use IMDSv2 only). "
                        ),
                    )
                )

    def _check_in_transit_encryption(self, res: ServiceAuditResult) -> None:
        
        rows = self.get_rows(self.TABLE_INSTANCES)
        for r in rows:
            
            cid = _safe_str(r.get("compartment_id"))
            instance_id = _safe_str(r.get("id"))
            launch_options = json.loads(r.get("launch_options"))

            is_pv_encryption_in_transit_enabled = launch_options["is_pv_encryption_in_transit_enabled"]

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
                        recommended_module="modules run enum_kubernetes --clusters",
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
        rows = self.get_rows(self.TABLE_CLUSTERS)
        for r in rows:
            cid = _safe_str(r.get("compartment_id"))
            cluster_id = _safe_str(r.get("id"))
            if not cid or not cluster_id:
                continue

            ep_cfg = r.get("endpoint_config") if isinstance(r.get("endpoint_config"), dict) else {}
            eps = r.get("endpoints") if isinstance(r.get("endpoints"), dict) else {}

            is_pub = ep_cfg.get("is_public_ip_enabled")
            pub_ep = eps.get("public_endpoint")

            if bool(is_pub) and _safe_str(pub_ep):
                loc = _loc_base(compartment_id=cid, entity_id=cluster_id)
                res.findings.append(
                    self.finding(
                        table_name=self.TABLE_CLUSTERS,
                        issue_code="KUBERNETES_ENGINE_PUBLIC_ENDPOINT",
                        title="The cluster has a public endpoint for the management plane",
                        severity="HIGH",
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
        rows = self.get_rows(self.T_REPOSITORIES)
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
        rows = self.get_rows(self.T_REPOSITORIES)
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

    @staticmethod
    def _as_dict(v: Any) -> Dict[str, Any]:
        if isinstance(v, dict):
            return v
        if isinstance(v, str):
            s = v.strip()
            if not s:
                return {}
            try:
                x = json.loads(s)
                return x if isinstance(x, dict) else {}
            except Exception:
                return {}
        return {}

    @staticmethod
    def _as_str_list(v: Any) -> List[str]:
        if isinstance(v, list):
            return [str(x).strip().lower() for x in v if str(x).strip()]
        if isinstance(v, str) and v.strip():
            return [v.strip().lower()]
        return []

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
        for r in rows:
            action = _safe_str(r.get("action")).upper()
            if action != "ALLOW":
                continue

            cond = self._as_dict(r.get("condition"))
            src = self._as_str_list(cond.get("source_address"))
            dst = self._as_str_list(cond.get("destination_address"))
            app = self._as_str_list(cond.get("application"))
            svc = self._as_str_list(cond.get("service"))
            url = self._as_str_list(cond.get("url"))

            if src or dst or app or svc or url:
                continue

            res.findings.append(
                self.finding(
                    table_name=self.T_RULES,
                    issue_code="NETWORK_FIREWALL_ALLOW_WITHOUT_MATCH_CRITERIA",
                    title="Allow rule has no match criteria",
                    severity="CRITICAL",
                    description=_wrap_paragraph(
                        """
                        ALLOW rule has no match criteria (no src/dst/app/service/url). This can behave as an
                        overly broad allow in policy evaluation.
                        """
                    ),
                    location=self._rule_loc(r),
                    row=r,
                    recommended_module="modules run enum_networkfirewall --firewalls --get --save",
                    notes=_wrap_paragraph(
                        "Remediation: add explicit source/destination/service/application/url conditions. "
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
                    recommended_module="modules run enum_networkfirewall --firewalls --get --save",
                    notes=_wrap_paragraph(
                        "Remediation: set inspection to INTRUSION_DETECTION or INTRUSION_PREVENTION. "
                    ),
                )
            )

    def _check_allow_any_any(self, res: ServiceAuditResult) -> None:
        rows = self.get_rows(self.T_RULES)
        any_tokens = {"any", "all", "*"}
        for r in rows:
            action = _safe_str(r.get("action")).upper()
            if action != "ALLOW":
                continue

            cond = self._as_dict(r.get("condition"))
            src = set(self._as_str_list(cond.get("source_address")))
            dst = set(self._as_str_list(cond.get("destination_address")))
            svc = set(self._as_str_list(cond.get("service")))

            if not src or not dst:
                continue
            if src.isdisjoint(any_tokens) or dst.isdisjoint(any_tokens):
                continue
            if svc and svc.isdisjoint(any_tokens):
                continue

            res.findings.append(
                self.finding(
                    table_name=self.T_RULES,
                    issue_code="NETWORK_FIREWALL_ALLOW_ANY_ANY",
                    title="Allow rule appears to permit any-to-any traffic",
                    severity="CRITICAL",
                    description=_wrap_paragraph(
                        """
                        Rule appears to allow ANY‑to‑ANY traffic. Broad allow rules can bypass segmentation
                        controls and increase blast radius.
                        """
                    ),
                    location=self._rule_loc(r),
                    row=r,
                    recommended_module="modules run enum_networkfirewall --firewalls --get --save",
                    notes=_wrap_paragraph(
                        "Remediation: narrow to explicit address/service objects and limit to required flows. "
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
                        severity="HIGH",
                        description=_wrap_paragraph(f"MFA appears disabled or unspecified (mfa_enabled_category={mfa_cat!r})."),
                        location=loc,
                        row=r,
                        recommended_module="modules run enum_identity --domains --save",
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
                    recommended_module="modules run enum_identity --domains --save",
                    notes=_wrap_paragraph(
                        "Remediation: assign users to least‑privilege groups and enforce consistent policies. "
                    ),
                )
            )

    def _check_api_key_assignment(self, res: ServiceAuditResult) -> None:
        rows = self.get_rows(self.T_API_KEYS)
        user_keys: Dict[str, List[Dict[str, Any]]] = {}

        for r in rows:
            user_obj = _as_json_dict(r.get("user"))
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

                user_key = _as_json_dict(key_specifics.get("user"))
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
                        recommended_module="modules run enum_identity --domains --save",
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
                    recommended_module="modules run enum_identity --domains --save",
                    notes=_wrap_paragraph(
                        "Remediation: increase min length, enforce complexity, reduce expiry window, "
                        "increase password history, and tighten lockout thresholds. "
                    ),
                )
            )


class ApiGatewayServiceAuditor(ServiceAuditor):
    service = "api_gateway"

    T_GATEWAYS = "apigw_gateways"

    def run_checks(self) -> ServiceAuditResult:
        res = ServiceAuditResult(service=self.service)
        try:
            self._check_public_gateways(res)
        except Exception as e:
            res.errors.append(f"gateways: {type(e).__name__}: {e}")
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
                    recommended_module="modules run enum_apigateway --gateways --get --save",
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
                        recommended_module="modules run enum_apigateway --gateways --get --save",
                        notes=_wrap_paragraph(
                            "Remediation: attach restrictive NSGs and limit ingress paths."
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
        rows = self.get_rows(self.T_BASTIONS)
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
                        recommended_module="modules run enum_core_network --bastion --get --save",
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
                    recommended_module="modules run enum_core_block_storage --volumes --get --save",
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
                    recommended_module="modules run enum_core_block_storage --boot-volumes --get --save",
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
        for r in rows:
            cid = _safe_str(r.get("compartment_id"))
            sid = _safe_str(r.get("id"))
            if not cid or not sid:
                continue

            ingress = _as_json_list(r.get("ingress_security_rules"))
            egress = _as_json_list(r.get("egress_security_rules"))
            loc = _loc_base(compartment_id=cid, entity_id=sid, vcn_id=_safe_str(r.get("vcn_id")) or None)

            for rule in ingress:
                if not isinstance(rule, dict):
                    continue
                source = rule.get("source")
                if not _is_public_cidr(source):
                    continue
                proto = rule.get("protocol")
                tcp_opts = _as_json_dict(rule.get("tcp_options"))
                dst_port = _as_json_dict(tcp_opts.get("destination_port_range"))
                port_min = _as_int(dst_port.get("min"), default=-1)
                port_max = _as_int(dst_port.get("max"), default=-1)

                if _is_protocol_any(proto):
                    res.findings.append(
                        self.finding(
                            table_name=self.T_SECURITY_LISTS,
                            issue_code="VCN_SECURITY_LIST_INGRESS_ANY_ANY",
                            title="Security list ingress allows any protocol from internet",
                            severity="HIGH",
                            description=_wrap_paragraph(
                                "Ingress rule allows 0.0.0.0/0 (or equivalent) with any protocol."
                            ),
                            location=loc,
                            row=r,
                            recommended_module="modules run enum_core_network --security-lists --get --save",
                            notes=_wrap_paragraph("Remediation: restrict source CIDRs and allowed protocols/ports."),
                        )
                    )
                    continue

                if _safe_str(proto) in ("6", "TCP", "tcp"):
                    if port_min == 22 and port_max == 22:
                        res.findings.append(
                            self.finding(
                                table_name=self.T_SECURITY_LISTS,
                                issue_code="VCN_SECURITY_LIST_SSH_OPEN_TO_INTERNET",
                                title="Security list exposes SSH (22) to internet",
                                severity="HIGH",
                                description=_wrap_paragraph(
                                    "Ingress rule exposes SSH from any-address CIDR."
                                ),
                                location=loc,
                                row=r,
                                recommended_module="modules run enum_core_network --security-lists --get --save",
                                notes=_wrap_paragraph("Remediation: restrict SSH ingress to approved admin CIDRs."),
                            )
                        )
                    if port_min == 3389 and port_max == 3389:
                        res.findings.append(
                            self.finding(
                                table_name=self.T_SECURITY_LISTS,
                                issue_code="VCN_SECURITY_LIST_RDP_OPEN_TO_INTERNET",
                                title="Security list exposes RDP (3389) to internet",
                                severity="HIGH",
                                description=_wrap_paragraph(
                                    "Ingress rule exposes RDP from any-address CIDR."
                                ),
                                location=loc,
                                row=r,
                                recommended_module="modules run enum_core_network --security-lists --get --save",
                                notes=_wrap_paragraph("Remediation: restrict RDP ingress to approved admin CIDRs."),
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
                            title="Security list egress allows any protocol to internet",
                            severity="LOW",
                            description=_wrap_paragraph(
                                "Egress rule allows any protocol to 0.0.0.0/0 (or equivalent)."
                            ),
                            location=loc,
                            row=r,
                            recommended_module="modules run enum_core_network --security-lists --get --save",
                            notes=_wrap_paragraph("Remediation: tighten egress to least privilege."),
                        )
                    )

    def _check_route_tables(self, res: ServiceAuditResult) -> None:
        rows = self.get_rows(self.T_ROUTE_TABLES)
        for r in rows:
            cid = _safe_str(r.get("compartment_id"))
            rid = _safe_str(r.get("id"))
            if not cid or not rid:
                continue
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
                        title="Route table has default route to internet gateway",
                        severity="MEDIUM",
                        description=_wrap_paragraph(
                            "Route table contains a default route (0.0.0.0/0 or equivalent) to an internet gateway."
                        ),
                        location=loc,
                        row=r,
                        recommended_module="modules run enum_core_network --route-tables --get --save",
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
            prohibit = _safe_str(r.get("prohibit_public_ip_on_vnic")).strip().lower()
            allows_public_ip = prohibit in ("false", "0", "no", "off")
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
                    recommended_module="modules run enum_core_network --subnets --get --save",
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
        rows = self.get_rows(self.T_NLBS)
        for r in rows:
            cid = _safe_str(r.get("compartment_id"))
            nid = _safe_str(r.get("id"))
            if not cid or not nid:
                continue
            is_private = _safe_str(r.get("is_private")).strip().lower()
            public = is_private in ("false", "0", "no", "off")
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
                    recommended_module="modules run enum_network_load_balancers --get --save",
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
                        recommended_module="modules run enum_network_load_balancers --get --save",
                        notes=_wrap_paragraph("Remediation: attach restrictive NSGs and explicit ingress policy."),
                    )
                )


class LoggingServiceAuditor(ServiceAuditor):
    service = "logging"

    T_LOGS = "logging_logs"

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
            cid = _safe_str(r.get("compartment_id"))
            lid = _safe_str(r.get("id"))
            if not cid or not lid:
                continue
            is_enabled = _safe_str(r.get("is_enabled")).strip().lower()
            if is_enabled in ("true", "1", "yes", "on"):
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
                    recommended_module="modules run enum_logging --logs --get --save",
                    notes=_wrap_paragraph("Remediation: enable log collection for security-relevant sources."),
                )
            )

    def _check_retention_duration(self, res: ServiceAuditResult) -> None:
        rows = self.get_rows(self.T_LOGS)
        for r in rows:
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
                    recommended_module="modules run enum_logging --logs --get --save",
                    notes=_wrap_paragraph("Remediation: align log retention with incident response and compliance needs."),
                )
            )


class ResourceManagerServiceAuditor(ServiceAuditor):
    service = "resource_manager"

    T_STACKS = "resource_manager_stacks"
    T_CONFIG_SOURCE_PROVIDER = "resource_configuration_source_provider"
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
            self._check_private_endpoint_source_ips(res)
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

            vars_obj = _as_json_dict(r.get("variables"))
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
                    severity="CRITICAL",
                    description=_wrap_paragraph(
                        """
                        Stack variable keys indicate potential secret material (for example password/token/private key).
                        Plaintext stack variables can leak in stack exports and job artifacts.
                        """
                    ),
                    location=loc,
                    row=r,
                    recommended_module="modules run enum_resourcemanager --stacks --jobs --get --download --save",
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
                        recommended_module="modules run enum_resourcemanager --config-source-providers --get --save",
                        notes=_wrap_paragraph(
                            "Remediation: store credentials in OCI Vault and reference them via secret OCIDs."
                        ),
                    )
                )

    def _check_private_endpoint_source_ips(self, res: ServiceAuditResult) -> None:
        rows = self.get_rows(self.T_PRIVATE_ENDPOINTS)
        for r in rows:
            cid = _safe_str(r.get("compartment_id"))
            peid = _safe_str(r.get("id"))
            if not cid or not peid:
                continue
            source_ips = _as_json_list(r.get("source_ips"))
            if not source_ips:
                continue
            if any(_is_public_cidr(x) for x in source_ips):
                loc = _loc_base(compartment_id=cid, entity_id=peid)
                res.findings.append(
                    self.finding(
                        table_name=self.T_PRIVATE_ENDPOINTS,
                        issue_code="ORM_PRIVATE_ENDPOINT_SOURCE_IP_ANY",
                        title="Resource Manager private endpoint allows any-address source IP",
                        severity="HIGH",
                        description=_wrap_paragraph(
                            "Private endpoint source IP list includes any-address CIDR."
                        ),
                        location=loc,
                        row=r,
                        recommended_module="modules run enum_resourcemanager --private-endpoints --get --save",
                        notes=_wrap_paragraph(
                            "Remediation: restrict source IPs to specific administration/network ranges."
                        ),
                    )
                )


class DatabaseServiceAuditor(ServiceAuditor):
    service = "database"

    T_MYSQL = "db_mysql_db_systems"
    T_ORACLE = "db_oracle_db_systems"
    T_POSTGRES = "db_psql_db_systems"

    def run_checks(self) -> ServiceAuditResult:
        res = ServiceAuditResult(service=self.service)
        try:
            self._check_mysql_encryption_and_secure_connections(res)
        except Exception as e:
            res.errors.append(f"mysql: {type(e).__name__}: {e}")
        try:
            self._check_oracle_kms_key(res)
        except Exception as e:
            res.errors.append(f"oracle: {type(e).__name__}: {e}")
        try:
            self._check_postgres_network_details(res)
        except Exception as e:
            res.errors.append(f"postgres: {type(e).__name__}: {e}")
        return res

    def _check_mysql_encryption_and_secure_connections(self, res: ServiceAuditResult) -> None:
        rows = self.get_rows(self.T_MYSQL)
        for r in rows:
            cid = _safe_str(r.get("compartment_id"))
            dbid = _safe_str(r.get("id"))
            if not cid or not dbid:
                continue
            loc = _loc_base(compartment_id=cid, entity_id=dbid)

            encrypt_data = _safe_str(r.get("encrypt_data")).strip().lower()
            if encrypt_data and _falsy_str(encrypt_data):
                res.findings.append(
                    self.finding(
                        table_name=self.T_MYSQL,
                        issue_code="MYSQL_ENCRYPT_DATA_DISABLED",
                        title="MySQL DB system has data encryption disabled",
                        severity="HIGH",
                        description=_wrap_paragraph(
                            "MySQL DB system reports `encrypt_data` as disabled."
                        ),
                        location=loc,
                        row=r,
                        recommended_module="modules run enum_databases --mysql --get --save",
                        notes=_wrap_paragraph("Remediation: enable encryption at rest for MySQL DB systems."),
                    )
                )

            secure_connections = _safe_str(r.get("secure_connections")).strip().lower()
            if secure_connections and _falsy_str(secure_connections):
                res.findings.append(
                    self.finding(
                        table_name=self.T_MYSQL,
                        issue_code="MYSQL_SECURE_CONNECTIONS_DISABLED",
                        title="MySQL DB system has secure connections disabled",
                        severity="HIGH",
                        description=_wrap_paragraph(
                            "MySQL DB system reports `secure_connections` as disabled."
                        ),
                        location=loc,
                        row=r,
                        recommended_module="modules run enum_databases --mysql --get --save",
                        notes=_wrap_paragraph("Remediation: enforce TLS-secured client connections."),
                    )
                )

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
                    recommended_module="modules run enum_databases --oracle --get --save",
                    notes=_wrap_paragraph("Remediation: use CMK-backed encryption where policy/compliance requires it."),
                )
            )

    def _check_postgres_network_details(self, res: ServiceAuditResult) -> None:
        rows = self.get_rows(self.T_POSTGRES)
        for r in rows:
            cid = _safe_str(r.get("compartment_id"))
            dbid = _safe_str(r.get("id"))
            if not cid or not dbid:
                continue
            net = _as_json_dict(r.get("network_details"))
            if not net:
                continue
            public_flag = net.get("is_public")
            if public_flag is True or _truthy_str(public_flag):
                loc = _loc_base(compartment_id=cid, entity_id=dbid)
                res.findings.append(
                    self.finding(
                        table_name=self.T_POSTGRES,
                        issue_code="POSTGRES_DB_PUBLIC_NETWORK",
                        title="PostgreSQL DB system appears publicly exposed",
                        severity="HIGH",
                        description=_wrap_paragraph(
                            "PostgreSQL network details indicate public exposure."
                        ),
                        location=loc,
                        row=r,
                        recommended_module="modules run enum_databases --postgres --get --save",
                        notes=_wrap_paragraph(
                            "Remediation: prefer private networking and restrict ingress with NSGs/security lists."
                        ),
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
        rows = self.get_rows(self.T_SUBSCRIPTIONS)
        for r in rows:
            cid = _safe_str(r.get("compartment_id"))
            sid = _safe_str(r.get("id"))
            if not cid or not sid:
                continue
            protocol = _safe_str(r.get("protocol")).strip().upper()
            if protocol != "HTTP":
                continue
            loc = _loc_base(compartment_id=cid, entity_id=sid, topic_id=_safe_str(r.get("topic_id")) or None)
            res.findings.append(
                self.finding(
                    table_name=self.T_SUBSCRIPTIONS,
                    issue_code="NOTIFICATION_HTTP_SUBSCRIPTION",
                    title="Notification subscription uses HTTP (plaintext)",
                    severity="MEDIUM",
                    description=_wrap_paragraph(
                        "Subscription protocol is HTTP, which does not provide TLS protection in transit."
                    ),
                    location=loc,
                    row=r,
                    recommended_module="modules run enum_notifications --subscriptions --get --save",
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
                    severity="HIGH",
                    description=_wrap_paragraph(
                        "Invoke endpoint starts with HTTP (plaintext) instead of HTTPS."
                    ),
                    location=loc,
                    row=r,
                    recommended_module="modules run enum_functions --functions --get --save",
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
                    recommended_module="modules run enum_functions --apps --get --save",
                    notes=_wrap_paragraph("Remediation: use TLS-protected log destinations."),
                )
            )


class FileStorageServiceAuditor(ServiceAuditor):
    service = "file_storage"

    T_EXPORTS = "file_storage_exports"
    T_MOUNT_TARGETS = "file_storage_mount_targets"

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
        return res

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
                        recommended_module="modules run enum_filestorage --exports --get --save",
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
                    recommended_module="modules run enum_filestorage --mount-targets --get --save",
                    notes=_wrap_paragraph("Remediation: attach NSGs and limit ingress to required clients only."),
                )
            )


class IdentityServiceAuditor(ServiceAuditor):
    service = "identity"

    T_API_KEYS = "identity_user_api_keys"

    def run_checks(self) -> ServiceAuditResult:
        res = ServiceAuditResult(service=self.service)
        try:
            self._check_multiple_api_keys_per_user(res)
        except Exception as e:
            res.errors.append(f"api_keys: {type(e).__name__}: {e}")
        return res

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
                        recommended_module="modules run enum_identity --api-keys --save",
                        notes=_wrap_paragraph("Remediation: rotate/revoke stale keys and enforce key hygiene."),
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
        rows = self.get_rows(self.T_REPOSITORIES)
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
                    recommended_module="modules run enum_artifactregistry --repositories --get --save",
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
                    recommended_module="modules run enum_datascience --private-endpoints --get --save",
                    notes=_wrap_paragraph(
                        "Remediation: ensure private endpoints are bound to intended private subnets."
                    ),
                )
            )


class BlockchainServiceAuditor(ServiceAuditor):
    service = "blockchain"

    T_PLATFORMS = "blockchain_platforms"

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
                    severity="HIGH",
                    description=_wrap_paragraph(
                        "Blockchain platform service endpoint appears to use plaintext HTTP."
                    ),
                    location=loc,
                    row=r,
                    recommended_module="modules run enum_blockchain --platforms --get --save",
                    notes=_wrap_paragraph("Remediation: require HTTPS endpoints."),
                )
            )


class IoTServiceAuditor(ServiceAuditor):
    service = "iot"

    T_DOMAIN_GROUPS = "iot_domain_groups"
    T_DOMAINS = "iot_domains"

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
            cid = _safe_str(r.get("compartment_id"))
            gid = _safe_str(r.get("id"))
            if not cid or not gid:
                continue
            allow_list = _as_json_list(r.get("db_allow_listed_vcn_ids"))
            if allow_list:
                continue
            loc = _loc_base(compartment_id=cid, entity_id=gid)
            res.findings.append(
                self.finding(
                    table_name=self.T_DOMAIN_GROUPS,
                    issue_code="IOT_DOMAIN_GROUP_VCN_ALLOWLIST_EMPTY",
                    title="IoT domain group has empty DB VCN allow list",
                    severity="HIGH",
                    description=_wrap_paragraph(
                        "IoT domain group DB VCN allow list is empty, increasing risk of broad backend DB exposure."
                    ),
                    location=loc,
                    row=r,
                    recommended_module="modules run enum_iot --domain-groups --get --save",
                    notes=_wrap_paragraph("Remediation: restrict DB access to explicit approved VCN IDs."),
                )
            )

    def _check_domain_identity_allow_list(self, res: ServiceAuditResult) -> None:
        rows = self.get_rows(self.T_DOMAINS)
        for r in rows:
            cid = _safe_str(r.get("compartment_id"))
            did = _safe_str(r.get("id"))
            if not cid or not did:
                continue
            group_allow_list = _as_json_list(r.get("db_allow_listed_identity_group_names"))
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
                    recommended_module="modules run enum_iot --domains --get --save",
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
                        severity="HIGH",
                        description=_wrap_paragraph(
                            "Domain has no active DKIM configuration, which can weaken sender authenticity guarantees."
                        ),
                        location=loc,
                        row=r,
                        recommended_module="modules run enum_email --domains --dkims --save",
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
                        recommended_module="modules run enum_email --domains --spfs --save",
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
                    recommended_module="modules run enum_email --senders --save",
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
                    severity="HIGH",
                    description=_wrap_paragraph(
                        "One or more submit endpoints appear to use plaintext HTTP transport."
                    ),
                    location=loc,
                    row=r,
                    recommended_module="modules run enum_email --email-configuration --save",
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
        rows = self.get_rows(self.T_CLUSTERS)
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
                    recommended_module="modules run enum_all --save",
                    notes=_wrap_paragraph("Remediation: attach restrictive NSGs to cache clusters."),
                )
            )

    def _check_public_cluster_endpoints(self, res: ServiceAuditResult) -> None:
        rows = self.get_rows(self.T_CLUSTERS)
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
            for field in endpoint_fields:
                ip = _safe_str(r.get(field)).strip()
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
                    recommended_module="modules run enum_all --save",
                    notes=_wrap_paragraph("Remediation: place cache endpoints on private subnets only."),
                )
            )

    def _check_weak_user_auth_mode(self, res: ServiceAuditResult) -> None:
        rows = self.get_rows(self.T_USERS)
        for r in rows:
            cid = _safe_str(r.get("compartment_id"))
            uid = _safe_str(r.get("id"))
            if not cid or not uid:
                continue

            mode = _safe_str(r.get("authentication_mode")).strip().upper()
            if mode not in ("", "NONE", "NO_AUTH", "DISABLED"):
                continue
            loc = _loc_base(compartment_id=cid, entity_id=uid)
            res.findings.append(
                self.finding(
                    table_name=self.T_USERS,
                    issue_code="CACHE_USER_WEAK_AUTH_MODE",
                    title="Cache user authentication mode appears weak or disabled",
                    severity="HIGH",
                    description=_wrap_paragraph(
                        f"Cache user authentication_mode is {mode or 'EMPTY'}."
                    ),
                    location=loc,
                    row=r,
                    recommended_module="modules run enum_all --save",
                    notes=_wrap_paragraph("Remediation: enforce password/token-based authentication modes."),
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
        rows = self.get_rows(self.T_CLUSTERS)
        for r in rows:
            cid = _safe_str(r.get("compartment_id"))
            cluster_id = _safe_str(r.get("id"))
            if not cid or not cluster_id:
                continue

            urls = _safe_str(r.get("kafka_bootstrap_urls"))
            if not urls:
                continue
            parts = [p.strip().lower() for p in urls.replace(";", ",").split(",") if p.strip()]
            plaintext = any(":9092" in p or p.startswith("plaintext://") for p in parts)
            if not plaintext:
                continue

            loc = _loc_base(compartment_id=cid, entity_id=cluster_id)
            res.findings.append(
                self.finding(
                    table_name=self.T_CLUSTERS,
                    issue_code="KAFKA_PLAINTEXT_BOOTSTRAP_URL",
                    title="Managed Kafka bootstrap URL indicates plaintext listener",
                    severity="HIGH",
                    description=_wrap_paragraph(
                        "Bootstrap URL appears to include plaintext listener semantics (for example port 9092)."
                    ),
                    location=loc,
                    row=r,
                    recommended_module="modules run enum_managedkafka --clusters --get --save",
                    notes=_wrap_paragraph(
                        "Remediation: prefer TLS-enabled listeners and enforce authenticated client access."
                    ),
                )
            )

    def _check_missing_auth_secret(self, res: ServiceAuditResult) -> None:
        rows = self.get_rows(self.T_CLUSTERS)
        for r in rows:
            cid = _safe_str(r.get("compartment_id"))
            cluster_id = _safe_str(r.get("id"))
            if not cid or not cluster_id:
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
                    recommended_module="modules run enum_managedkafka --clusters --get --save",
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
                    severity="HIGH",
                    description=_wrap_paragraph(
                        "Repository URL appears to use plaintext HTTP transport."
                    ),
                    location=loc,
                    row=r,
                    recommended_module="modules run enum_devops --repositories --get --save",
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
                    recommended_module="modules run enum_cloudguard --targets --save",
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
                    recommended_module="modules run enum_cloudguard --data-sources --save",
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
                    recommended_module="modules run enum_core_compute --instance-agent-plugins --get --save",
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
                    recommended_module="modules run enum_core_compute --instance-agent-commands --instance-agent-command-executions --get --download --save",
                    notes=_wrap_paragraph("Remediation: monitor and restrict who can submit instance agent commands."),
                )
            )



# =============================================================================
# Runner
# =============================================================================

DEFAULT_SERVICE_AUDITORS: List[type[ServiceAuditor]] = [
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
