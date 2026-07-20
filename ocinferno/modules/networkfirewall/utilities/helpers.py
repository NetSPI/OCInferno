#!/usr/bin/env python3

from argparse import Namespace
from typing import Any, Dict, List, Optional

import oci
from ocinferno.core.resource import OciListResource
from ocinferno.core.utils.module_helpers import ids_from_db, parse_csv_args, save_rows


class NetworkFirewallFirewallsResource(OciListResource):
    CLIENT_CLS = oci.network_firewall.NetworkFirewallClient
    SERVICE_NAME = "Network Firewall"
    TABLE_NAME = "network_firewall_firewalls"
    LIST_METHOD = "list_network_firewalls"
    GET_METHOD = "get_network_firewall"
    GET_ID_PARAM = "network_firewall_id"
    COLUMNS = ["id", "display_name", "lifecycle_state", "subnet_id", "ipv4_address", "network_firewall_policy_id"]

class NetworkFirewallPoliciesResource(OciListResource):
    CLIENT_CLS = oci.network_firewall.NetworkFirewallClient
    SERVICE_NAME = "Network Firewall"
    TABLE_NAME = "network_firewall_policies"
    LIST_METHOD = "list_network_firewall_policies"
    GET_METHOD = "get_network_firewall_policy"
    GET_ID_PARAM = "network_firewall_policy_id"
    COLUMNS = ["id", "display_name", "lifecycle_state", "time_created", "time_updated"]

class NetworkFirewallSecurityRulesResource(OciListResource):
    # Nested under a policy: list_security_rules is scoped by network_firewall_policy_id
    # ALONE (no compartment_id), so LIST_SCOPE_KWARG remaps it.
    CLIENT_CLS = oci.network_firewall.NetworkFirewallClient
    SERVICE_NAME = "Network Firewall"
    TABLE_NAME = "network_firewall_security_rules"
    TABLE_POLICIES = "network_firewall_policies"
    LIST_METHOD = "list_security_rules"
    LIST_SCOPE_KWARG = "network_firewall_policy_id"
    COLUMNS = ["network_firewall_policy_id", "name", "action", "inspection", "priority_order"]

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

    # Get one security rule by policy + rule name.
    def get(self, *, policy_id: str, security_rule_name: str) -> Dict[str, Any]:
        resp = self.client.get_security_rule(network_firewall_policy_id=policy_id, security_rule_name=security_rule_name)
        return oci.util.to_dict(resp.data) or {}

    # Save security-rule rows.
    def save(self, rows: List[Dict[str, Any]]) -> None:
        save_rows(self.session, self.TABLE_NAME, rows)

    # No binary download endpoint for rule rows.

normalize_csv_args = parse_csv_args
db_ids = ids_from_db
