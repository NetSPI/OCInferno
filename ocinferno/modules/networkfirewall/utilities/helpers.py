#!/usr/bin/env python3

from argparse import Namespace
from typing import Any, Dict, List, Optional

import oci
from ocinferno.core.utils.module_helpers import ids_from_db, parse_csv_args, save_rows
from ocinferno.core.utils.service_runtime import _init_client


def build_network_firewall_client(session, region: Optional[str] = None):
    """Initialize a Network Firewall client with shared signer/proxy/session behavior."""
    client = _init_client(
        oci.network_firewall.NetworkFirewallClient,
        session=session,
        service_name="Network Firewall",
    )
    target_region = region or getattr(session, "region", None)
    if target_region:
        try:
            client.base_client.set_region(target_region)
        except Exception:
            pass
    return client


class NetworkFirewallFirewallsResource:
    TABLE_NAME = "network_firewall_firewalls"
    COLUMNS = ["id", "display_name", "lifecycle_state", "subnet_id", "ipv4_address", "network_firewall_policy_id"]

    def __init__(self, session, region: Optional[str] = None):
        self.session = session
        self.client = build_network_firewall_client(session=session, region=region)

    # List firewalls in a compartment.
    def list(self, *, compartment_id: str) -> List[Dict[str, Any]]:
        resp = oci.pagination.list_call_get_all_results(self.client.list_network_firewalls, compartment_id=compartment_id)
        return oci.util.to_dict(resp.data) or []

    # Get one firewall by OCID.
    def get(self, *, resource_id: str) -> Dict[str, Any]:
        resp = self.client.get_network_firewall(network_firewall_id=resource_id)
        return oci.util.to_dict(resp.data) or {}

    # Save firewall rows.
    def save(self, rows: List[Dict[str, Any]]) -> None:
        save_rows(self.session, self.TABLE_NAME, rows)

    # No binary download endpoint for firewall rows.
    def download(self, *, resource_id: str, out_path: str) -> bool:  # pragma: no cover - placeholder
        _ = (resource_id, out_path)
        return False


class NetworkFirewallPoliciesResource:
    TABLE_NAME = "network_firewall_policies"
    COLUMNS = ["id", "display_name", "lifecycle_state", "time_created", "time_updated"]

    def __init__(self, session, region: Optional[str] = None):
        self.session = session
        self.client = build_network_firewall_client(session=session, region=region)

    # List firewall policies in a compartment.
    def list(self, *, compartment_id: str) -> List[Dict[str, Any]]:
        resp = oci.pagination.list_call_get_all_results(self.client.list_network_firewall_policies, compartment_id=compartment_id)
        return oci.util.to_dict(resp.data) or []

    # Get one firewall policy by OCID.
    def get(self, *, resource_id: str) -> Dict[str, Any]:
        resp = self.client.get_network_firewall_policy(network_firewall_policy_id=resource_id)
        return oci.util.to_dict(resp.data) or {}

    # Save policy rows.
    def save(self, rows: List[Dict[str, Any]]) -> None:
        save_rows(self.session, self.TABLE_NAME, rows)

    # No binary download endpoint for policy rows.
    def download(self, *, resource_id: str, out_path: str) -> bool:  # pragma: no cover - placeholder
        _ = (resource_id, out_path)
        return False


class NetworkFirewallSecurityRulesResource:
    TABLE_NAME = "network_firewall_security_rules"
    TABLE_POLICIES = "network_firewall_policies"
    COLUMNS = ["network_firewall_policy_id", "name", "action", "inspection", "priority_order"]

    def __init__(self, session, region: Optional[str] = None):
        self.session = session
        self.client = build_network_firewall_client(session=session, region=region)

    # Resolve policy IDs from CLI, cache, or live listing.
    def resolve_policy_ids(self, comp_id: Optional[str], args: Namespace) -> List[str]:
        cli_ids = parse_csv_args(list(getattr(args, "policy_ids", []) or []))
        if cli_ids:
            return cli_ids

        cached = ids_from_db(self.session, table_name=self.TABLE_POLICIES, compartment_id=comp_id)
        if cached:
            return cached

        if not comp_id:
            return []
        try:
            rows = self.list_policies(compartment_id=comp_id) or []
            return parse_csv_args([row.get("id") for row in rows if isinstance(row, dict) and row.get("id")])
        except Exception:
            return []

    # Deduplicate security rules by (policy, name).
    @staticmethod
    def unique_security_rule_rows(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        seen = set()
        for row in rows or []:
            key = (row.get("network_firewall_policy_id"), row.get("name"))
            if key in seen:
                continue
            seen.add(key)
            out.append(row)
        return out

    # List policy rows for policy-id resolution.
    def list_policies(self, *, compartment_id: str) -> List[Dict[str, Any]]:
        resp = oci.pagination.list_call_get_all_results(self.client.list_network_firewall_policies, compartment_id=compartment_id)
        return oci.util.to_dict(resp.data) or []

    # List security rules under one policy.
    def list(self, *, policy_id: str) -> List[Dict[str, Any]]:
        resp = oci.pagination.list_call_get_all_results(self.client.list_security_rules, network_firewall_policy_id=policy_id)
        return oci.util.to_dict(resp.data) or []

    # Get one security rule by policy + rule name.
    def get(self, *, policy_id: str, security_rule_name: str) -> Dict[str, Any]:
        resp = self.client.get_security_rule(network_firewall_policy_id=policy_id, security_rule_name=security_rule_name)
        return oci.util.to_dict(resp.data) or {}

    # Save security-rule rows.
    def save(self, rows: List[Dict[str, Any]]) -> None:
        save_rows(self.session, self.TABLE_NAME, rows)

    # No binary download endpoint for rule rows.
    def download(self, *, resource_id: str, out_path: str) -> bool:  # pragma: no cover - placeholder
        _ = (resource_id, out_path)
        return False


normalize_csv_args = parse_csv_args
db_ids = ids_from_db
