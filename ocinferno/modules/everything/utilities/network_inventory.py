#!/usr/bin/env python3
"""Cross-service network-inventory extraction.

Sweeps every saved service table in the workspace DB and pulls out every network
identifier pentesters care about -- IPv4/IPv6 addresses, CIDR blocks, URLs, and
FQDNs/hostnames -- from anywhere they appear (plain columns *or* nested JSON like
``ip_addresses``, ``endpoints``, ``connection_urls``, ``network_endpoint_details``).

For JSON dict columns that hold key/value configuration (``config``, ``variables``,
``parameters``) the JSON keys are used as the column name for host-column detection,
so an env var named ``DATABASE_HOST`` or ``API_ENDPOINT`` extracts its FQDN value.

Pure logic (no session/DB/network) so it is unit-testable; the module wrapper feeds
it rows via ``session.get_resource_fields`` and persists/prints the results.
"""
from __future__ import annotations

import ipaddress
import json
import re
from typing import Any, Dict, List, Tuple

# --- extraction regexes ---
_IPV4_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
_CIDR_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}(?![\w/])")
_IPV6_RE = re.compile(r"(?<![\w:])(?:[0-9A-Fa-f]{1,4}:){2,7}[0-9A-Fa-f]{1,4}(?![\w:])")

# http/https plus common connection-string schemes that hold navigable hostnames
_URL_RE = re.compile(
    r"\b(?:https?|tcp|udp|postgres(?:ql)?|mysql|redis(?:s)?|mongodb(?:\+srv)?|amqps?|jdbc:[a-z]+|ldaps?|ftps?|ssh)"
    r"://[^\s\"'<>,\]}\\]+",
    re.I,
)

# FQDNs only from host-ish columns (keeps description/free-text noise out).
_HOST_COL_RE = re.compile(
    r"fqdn|host|hostname|endpoint|dns|domain|url|address|_ip$|^ip_|scan_"
    r"|server|target|proxy|backend|upstream|base_url|connect|remote",
    re.I,
)

# Reference-OCID columns worth surfacing for network pivoting (subnet/vcn/nsg).
_NET_REF_COLS = re.compile(r"subnet_id|subnet_ids|vcn_id|network_security_group|nsg", re.I)

# Config-like columns whose values are JSON dicts of name→value pairs.
# When one of these holds a JSON dict we re-extract using each key as the column name.
_CONFIG_EXPAND_COLS = re.compile(
    r"^(config|variables|parameters|environment|env_vars|"
    r"job_configuration_details|"           # DS jobs: DEFAULT type env vars
    r"job_environment_configuration_details|"  # DS jobs: CONTAINER type env/image
    r"job_infrastructure_configuration_details|"  # DS jobs: subnet_id, shape
    r"notebook_session_config_details|"
    r"freeform_tags|defined_tags|"          # user-supplied tags: surface any host/URL/IP values
    r"build_pipeline_parameters|deploy_pipeline_parameters)$",
    re.I,
)

KIND_IP = "ip"
KIND_CIDR = "cidr"
KIND_URL = "url"
KIND_FQDN = "fqdn"
KIND_NET_REF = "net_ref"

ALL_KINDS = (KIND_IP, KIND_CIDR, KIND_URL, KIND_FQDN, KIND_NET_REF)


# --- service label mapping ---

def _service_label(table: str) -> str:
    """Human-readable service name derived from the DB table name."""
    _EXACT = {
        "db_mysql_db_systems": "MySQL",
        "db_psql_db_systems": "PostgreSQL",
        "db_autonomous_databases": "Autonomous DB",
        "db_db_systems": "Oracle DB",
        "mysql_db_systems": "MySQL",
        "postgresql_db_systems": "PostgreSQL",
        "sch_service_connectors": "Service Connector",
    }
    if table in _EXACT:
        return _EXACT[table]
    _PREFIXES = [
        ("compute_", "Compute"),
        ("network_load_balancer", "Network LB"),
        ("load_balancer", "Load Balancer"),
        ("virtual_network_", "Networking"),
        ("functions_", "Functions"),
        ("api_gateway_", "API Gateway"),
        ("object_storage_", "Object Storage"),
        ("kubernetes_", "Kubernetes"),
        ("data_science_", "Data Science"),
        ("data_flow_", "Data Flow"),
        ("data_catalog_", "Data Catalog"),
        ("data_integration_", "Data Integration"),
        ("devops_", "DevOps"),
        ("mysql_", "MySQL"),
        ("postgresql_", "PostgreSQL"),
        ("database_", "Database"),
        ("resource_manager_", "Resource Manager"),
        ("analytics_", "Analytics"),
        ("integration_", "Integration"),
        ("bastion_", "Bastion"),
        ("vault_", "Vault"),
        ("cache_", "Cache"),
        ("streaming_", "Streaming"),
        ("events_", "Events"),
        ("log_", "Logging"),
        ("notifications_", "Notifications"),
        ("email_", "Email Delivery"),
        ("opensearch_", "OpenSearch"),
        ("nosql_", "NoSQL"),
        ("goldengate_", "GoldenGate"),
        ("waf_", "WAF"),
        ("cloudguard_", "Cloud Guard"),
        ("health_check", "Health Checks"),
        ("ocvp_", "OCVP"),
        ("wlms_", "WebLogic"),
        ("visual_builder_", "Visual Builder"),
        ("management_agent_", "Management Agent"),
        ("os_management_hub_", "OS Management"),
        ("lockbox_", "Lockbox"),
        ("ai_anomaly_", "AI Anomaly"),
        ("ai_vision_", "AI Vision"),
        ("ai_language_", "AI Language"),
        ("ai_document_", "AI Document"),
        ("generative_ai_", "Generative AI"),
        ("secret_", "Vault Secrets"),
        ("service_connector_", "Service Connector"),
        ("resource_search_", "Resource Search"),
    ]
    for prefix, label in _PREFIXES:
        if table.startswith(prefix) or table.startswith(prefix.rstrip("_")):
            return label
    return table.split("_")[0].title() if "_" in table else table.title()


# Human-readable label for a column name shown in the "context" output column.
_COL_FRIENDLY: Dict[str, str] = {
    "invoke_endpoint": "invoke URL",
    "syslog_url": "syslog URL",
    "base_url": "connection URL",
    "ip_address": "IP address",
    "public_ip": "public IP",
    "private_ip": "private IP",
    "hostname": "hostname",
    "hostname_label": "hostname",
    "endpoints": "endpoints",
    "connection_string": "connection string",
    "connection_url": "connection URL",
    "url": "URL",
    "fqdn": "FQDN",
    "scan_host": "scan target",
    "target_fqdn": "target FQDN",
    "access_token": "access token (URL)",
    "config": "app config (env var)",
    "variables": "tf variable",
    "freeform_tags": "freeform tag",
    "defined_tags": "defined tag",
    "job_environment_configuration_details": "job env var",
    "build_pipeline_parameters": "pipeline param",
    "deploy_pipeline_parameters": "pipeline param",
    "network_endpoint_details": "network endpoint",
    "network_details": "network details",
}


def _col_context(column: str, sub_key: str = "") -> str:
    """Return a human-readable context label for a column (and optional JSON sub-key)."""
    if sub_key:
        return f"{sub_key} (in {column})"
    return _COL_FRIENDLY.get(column, column.replace("_", " "))


# --- core extraction helpers ---

def _valid_ipv4(s: str) -> bool:
    try:
        return isinstance(ipaddress.ip_address(s), ipaddress.IPv4Address)
    except ValueError:
        return False


def _valid_ipv6(s: str) -> bool:
    try:
        return isinstance(ipaddress.ip_address(s), ipaddress.IPv6Address)
    except ValueError:
        return False


def _valid_cidr(s: str) -> bool:
    try:
        ipaddress.ip_network(s, strict=False)
        return True
    except ValueError:
        return False


def _is_noise_ip(ip: str) -> bool:
    """True for IPs that are never an interaction target: loopback (127/8),
    link-local incl. metadata 169.254.169.254, unspecified 0.0.0.0, broadcast,
    multicast, and reserved ranges."""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return True
    return bool(
        a.is_loopback or a.is_link_local or a.is_unspecified
        or a.is_multicast or a.is_reserved
        or (a.version == 4 and str(a) == "255.255.255.255")
    )


def _is_noise_cidr(c: str) -> bool:
    """True for CIDRs that aren't a target range: loopback/link-local/multicast/
    reserved networks and the 0.0.0.0/0 'any' wildcard (an exposure marker, not a host)."""
    try:
        n = ipaddress.ip_network(c, strict=False)
    except ValueError:
        return True
    if n.is_loopback or n.is_link_local or n.is_multicast or n.is_reserved:
        return True
    return int(n.network_address) == 0 and n.prefixlen == 0


def _ip_scope(ip: str) -> str:
    """'public' / 'private' reachability class for an IP (empty if unparseable)."""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return ""
    return "private" if (a.is_private or a.is_loopback or a.is_link_local) else "public"


def _cidr_scope(c: str) -> str:
    try:
        n = ipaddress.ip_network(c, strict=False)
    except ValueError:
        return ""
    return "private" if n.is_private else "public"


def _to_text(value: Any) -> str:
    """Flatten any column value (incl. JSON-encoded dict/list) to searchable text."""
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        return json.dumps(value)
    if isinstance(value, str):
        s = value.strip()
        if s[:1] in "[{":
            return s  # already compact JSON text; regexes search the raw string
        return s
    return str(value)


def _looks_like_ocid(token: str) -> bool:
    return token.lower().startswith("ocid1.")


def extract_from_value(column: str, value: Any) -> List[Dict[str, str]]:
    """Return [{kind, value, context}] network identifiers found in one column value.

    ``context`` is a human-readable label describing where the identifier came from,
    suitable for display alongside the value.
    """
    text = _to_text(value)
    if not text:
        return []

    out: List[Dict[str, str]] = []
    seen: set = set()

    def _add(kind: str, val: str, ctx: str = "") -> None:
        val = val.strip().rstrip(".,;)\"']")
        if not val or (kind, val) in seen:
            return
        # Drop non-target IPs/CIDRs (loopback, link-local/metadata, 0.0.0.0, broadcast).
        if kind == KIND_IP and _is_noise_ip(val):
            return
        if kind == KIND_CIDR and _is_noise_cidr(val):
            return
        seen.add((kind, val))
        scope = ""
        if kind == KIND_IP:
            scope = _ip_scope(val)
        elif kind == KIND_CIDR:
            scope = _cidr_scope(val)
        elif kind == KIND_FQDN and val.lower().endswith(".oraclevcn.com"):
            scope = "private"  # OCI private DNS zone
        out.append({"kind": kind, "value": val, "context": ctx or _col_context(column), "scope": scope})

    ctx = _col_context(column)

    # CIDRs first (so IPv4 pass doesn't half-match them), then IPs.
    for m in _CIDR_RE.findall(text):
        if _valid_cidr(m):
            _add(KIND_CIDR, m, ctx)
    cidr_text = _CIDR_RE.sub(" ", text)
    for m in _IPV4_RE.findall(cidr_text):
        if _valid_ipv4(m):
            _add(KIND_IP, m, ctx)
    for m in _IPV6_RE.findall(text):
        if _valid_ipv6(m):
            _add(KIND_IP, m, ctx)

    # URLs everywhere (http/https + common connection-string schemes); also mine host.
    for u in _URL_RE.findall(text):
        _add(KIND_URL, u, ctx)
        # Strip scheme and extract host for FQDN
        host = re.sub(r"^[a-z][a-z0-9+.-]*://", "", u, flags=re.I)
        # Strip userinfo (user:pass@host) and port
        host = host.split("/")[0].split("@")[-1].split(":")[0]
        if _FQDN_RE.fullmatch(host) and not _looks_like_ocid(host):
            _add(KIND_FQDN, host, ctx)

    # FQDNs only from host-ish columns.
    if _HOST_COL_RE.search(column):
        for f in _FQDN_RE.findall(text):
            if not _looks_like_ocid(f) and not _valid_ipv4(f):
                _add(KIND_FQDN, f, ctx)

    # Network-reference OCIDs (subnet/vcn/nsg) for pivoting.
    if _NET_REF_COLS.search(column):
        for tok in re.findall(r"ocid1\.[a-z0-9._-]+", text, re.I):
            _add(KIND_NET_REF, tok, ctx)

    return out


_FQDN_RE = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b", re.I)


def _expand_config_dict(column: str, value: Any) -> List[Tuple[str, Any, str]]:
    """For config-like columns holding a JSON dict, yield (sub_col, sub_value, ctx) tuples.

    If the value is not a JSON dict, returns [(column, value, '')] — the original pair.
    Handles nested dicts one level deep (e.g. job_environment_configuration_details has
    an ``environment_variables`` sub-dict).
    """
    text = _to_text(value)
    if not text or text[0] not in "{":
        return [(column, value, "")]
    try:
        d = json.loads(text)
    except Exception:
        return [(column, value, "")]
    if not isinstance(d, dict):
        return [(column, value, "")]

    pairs: List[Tuple[str, Any, str]] = []
    for k, v in d.items():
        ctx = _col_context(column, str(k))
        # One level of nesting: if the value is itself a dict, expand its keys too.
        if isinstance(v, dict):
            for kk, vv in v.items():
                pairs.append((kk, vv, _col_context(column, f"{k}.{kk}")))
        else:
            pairs.append((str(k), v, ctx))
    return pairs if pairs else [(column, value, "")]


def extract_from_rows(table_name: str, rows: List[Dict[str, Any]]) -> List[Dict[str, str]]:
    """Extract all network identifiers from one table's rows."""
    service = _service_label(table_name)
    records: List[Dict[str, str]] = []
    for row in rows or []:
        if not isinstance(row, dict):
            continue
        rid = _resource_id(row)
        rname = _resource_name(row)
        comp = str(row.get("compartment_id") or "")
        for column, value in row.items():
            if column in ("workspace_id",):
                continue

            # For config/variables/parameter columns: expand JSON dicts key-by-key.
            if _CONFIG_EXPAND_COLS.match(column):
                sub_pairs = _expand_config_dict(column, value)
                for sub_col, sub_val, sub_ctx in sub_pairs:
                    for hit in extract_from_value(sub_col, sub_val):
                        # Override context if _expand_config_dict gave a richer one
                        ctx = sub_ctx or hit.get("context", column)
                        records.append({
                            "kind": hit["kind"],
                            "value": hit["value"],
                            "context": ctx,
                            "scope": hit.get("scope", ""),
                            "source_table": table_name,
                            "service": service,
                            "resource_id": rid,
                            "resource_name": rname,
                            "compartment_id": comp,
                            "column_name": column,
                        })
            else:
                for hit in extract_from_value(column, value):
                    records.append({
                        "kind": hit["kind"],
                        "value": hit["value"],
                        "context": hit.get("context", column),
                        "scope": hit.get("scope", ""),
                        "source_table": table_name,
                        "service": service,
                        "resource_id": rid,
                        "resource_name": rname,
                        "compartment_id": comp,
                        "column_name": column,
                    })
    return records


def _resource_id(row: Dict[str, Any]) -> str:
    for key in ("id", "name", "display_name", "bucket_name", "hostname_label", "email_address"):
        v = row.get(key)
        if v:
            return str(v)
    return ""


def _resource_name(row: Dict[str, Any]) -> str:
    for key in ("display_name", "name", "bucket_name", "hostname", "hostname_label", "email_address"):
        v = row.get(key)
        if v:
            return str(v)
    return ""


def dedupe(records: List[Dict[str, str]]) -> List[Dict[str, str]]:
    seen: set = set()
    out: List[Dict[str, str]] = []
    for r in records:
        key = (r["kind"], r["value"], r["source_table"], r["resource_id"], r["column_name"])
        if key in seen:
            continue
        seen.add(key)
        out.append(r)
    return out


def summarize(records: List[Dict[str, str]]) -> Dict[str, int]:
    counts: Dict[str, int] = {k: 0 for k in ALL_KINDS}
    distinct: Dict[str, set] = {k: set() for k in ALL_KINDS}
    # public/private counts cover only navigable endpoints (IP/CIDR/URL/FQDN).
    navigable = {KIND_IP, KIND_CIDR, KIND_URL, KIND_FQDN}
    public = private = 0
    for r in records:
        counts[r["kind"]] = counts.get(r["kind"], 0) + 1
        distinct.setdefault(r["kind"], set()).add(r["value"])
        if r["kind"] in navigable:
            scope = r.get("scope", "")
            if scope == "public":
                public += 1
            elif scope == "private":
                private += 1
    summary = {f"{k}_rows": counts.get(k, 0) for k in ALL_KINDS}
    summary.update({f"{k}_distinct": len(distinct.get(k, set())) for k in ALL_KINDS})
    summary["public_endpoints"] = public
    summary["private_endpoints"] = private
    return summary
