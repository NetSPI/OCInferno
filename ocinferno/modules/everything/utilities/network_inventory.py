#!/usr/bin/env python3
"""Cross-service network-inventory extraction.

Sweeps every saved service table in the workspace DB and pulls out every network
identifier attackers care about -- IPv4/IPv6 addresses, CIDR blocks, URLs, and
FQDNs/hostnames -- from anywhere they appear (plain columns *or* nested JSON like
``ip_addresses``, ``endpoints``, ``connection_urls``, ``network_endpoint_details``).

Pure logic (no session/DB/network) so it is unit-testable; the module wrapper feeds
it rows via ``session.get_resource_fields`` and persists/prints the results.
"""
from __future__ import annotations

import ipaddress
import json
import re
from typing import Any, Dict, List

# --- extraction regexes ---
_IPV4_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
_CIDR_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}(?![\w/])")
_IPV6_RE = re.compile(r"(?<![\w:])(?:[0-9A-Fa-f]{1,4}:){2,7}[0-9A-Fa-f]{1,4}(?![\w:])")
_URL_RE = re.compile(r"\bhttps?://[^\s\"'<>,\]}\\]+", re.I)
_FQDN_RE = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b", re.I)

# Columns whose NAME implies a host/endpoint -> trust FQDN extraction there (keeps
# FQDN noise out of free-text columns like `description`).
_HOST_COL_RE = re.compile(r"fqdn|host|hostname|endpoint|dns|domain|url|address|_ip$|^ip_|scan_", re.I)

# Reference-OCID columns worth surfacing for network pivoting (subnet/vcn/nsg).
_NET_REF_COLS = re.compile(r"subnet_id|subnet_ids|vcn_id|network_security_group|nsg", re.I)

KIND_IP = "ip"
KIND_CIDR = "cidr"
KIND_URL = "url"
KIND_FQDN = "fqdn"
KIND_NET_REF = "net_ref"

ALL_KINDS = (KIND_IP, KIND_CIDR, KIND_URL, KIND_FQDN, KIND_NET_REF)


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


def _to_text(value: Any) -> str:
    """Flatten any column value (incl. JSON-encoded dict/list) to searchable text."""
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        return json.dumps(value)
    if isinstance(value, str):
        s = value.strip()
        # DB stores nested structures as JSON text; expand so hosts/ips inside are seen.
        if s[:1] in "[{":
            try:
                return json.dumps(json.loads(s))
            except Exception:
                return s
        return s
    return str(value)


def _looks_like_ocid(token: str) -> bool:
    return token.lower().startswith("ocid1.")


def extract_from_value(column: str, value: Any) -> List[Dict[str, str]]:
    """Return [{kind, value}] network identifiers found in one column value."""
    text = _to_text(value)
    if not text:
        return []

    out: List[Dict[str, str]] = []
    seen: set = set()

    def _add(kind: str, val: str) -> None:
        val = val.strip().rstrip(".,;)\"']")
        if not val or (kind, val) in seen:
            return
        seen.add((kind, val))
        out.append({"kind": kind, "value": val})

    # CIDRs first (so the IPv4 pass doesn't half-match them), then IPs.
    for m in _CIDR_RE.findall(text):
        if _valid_cidr(m):
            _add(KIND_CIDR, m)
    cidr_text = _CIDR_RE.sub(" ", text)
    for m in _IPV4_RE.findall(cidr_text):
        if _valid_ipv4(m):
            _add(KIND_IP, m)
    for m in _IPV6_RE.findall(text):
        if _valid_ipv6(m):
            _add(KIND_IP, m)

    # URLs everywhere; also mine the URL host as an FQDN.
    for u in _URL_RE.findall(text):
        _add(KIND_URL, u)
        host = re.sub(r"^https?://", "", u, flags=re.I).split("/")[0].split("@")[-1].split(":")[0]
        if _FQDN_RE.fullmatch(host):
            _add(KIND_FQDN, host)

    # FQDNs only from host-ish columns (keeps description/free-text noise out).
    if _HOST_COL_RE.search(column):
        for f in _FQDN_RE.findall(text):
            if not _looks_like_ocid(f) and not _valid_ipv4(f):
                _add(KIND_FQDN, f)

    # Network-reference OCIDs (subnet/vcn/nsg) for pivoting.
    if _NET_REF_COLS.search(column):
        for tok in re.findall(r"ocid1\.[a-z0-9._-]+", text, re.I):
            _add(KIND_NET_REF, tok)

    return out


def _resource_id(row: Dict[str, Any]) -> str:
    for key in ("id", "name", "display_name", "bucket_name", "email_address"):
        v = row.get(key)
        if v:
            return str(v)
    return ""


def _resource_name(row: Dict[str, Any]) -> str:
    for key in ("display_name", "name", "bucket_name", "hostname", "email_address"):
        v = row.get(key)
        if v:
            return str(v)
    return ""


def extract_from_rows(table_name: str, rows: List[Dict[str, Any]]) -> List[Dict[str, str]]:
    """Extract all network identifiers from one table's rows."""
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
            for hit in extract_from_value(column, value):
                records.append({
                    "kind": hit["kind"],
                    "value": hit["value"],
                    "source_table": table_name,
                    "resource_id": rid,
                    "resource_name": rname,
                    "compartment_id": comp,
                    "column_name": column,
                })
    return records


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
    for r in records:
        counts[r["kind"]] = counts.get(r["kind"], 0) + 1
        distinct.setdefault(r["kind"], set()).add(r["value"])
    summary = {f"{k}_rows": counts.get(k, 0) for k in ALL_KINDS}
    summary.update({f"{k}_distinct": len(distinct.get(k, set())) for k in ALL_KINDS})
    return summary
