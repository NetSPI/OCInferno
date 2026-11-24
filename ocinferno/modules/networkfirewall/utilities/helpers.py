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

class NetworkFirewallPolicyObjectsResource:
    """Address lists, services and service lists of a firewall policy, with their CONTENTS (the list calls only return
    names), so the reachability engine can evaluate security-rule conditions."""
    KINDS = {
        "address_lists": ("network_firewall_address_lists", "list_address_lists", "get_address_list", "address_list_name"),
        "services": ("network_firewall_services", "list_services", "get_service", "service_name"),
        "service_lists": ("network_firewall_service_lists", "list_service_lists", "get_service_list", "service_list_name"),
    }

    def __init__(self, session, kind: str):
        self.session, self.kind = session, kind
        self.TABLE_NAME, self._list, self._get, self._key = self.KINDS[kind]
        self.client = NetworkFirewallPoliciesResource(session=session).client

    def list(self, *, policy_ids: List[str], compartment_id: Optional[str] = None) -> List[Dict[str, Any]]:
        rows = []
        for pid in policy_ids:
            try:
                items = oci.util.to_dict(oci.pagination.list_call_get_all_results(getattr(self.client, self._list),
                                                                                  network_firewall_policy_id=pid).data) or []
            except oci.exceptions.ServiceError:
                continue
            for it in items:
                try:
                    full = oci.util.to_dict(getattr(self.client, self._get)(network_firewall_policy_id=pid, **{self._key: it["name"]}).data) or it
                except oci.exceptions.ServiceError:
                    full = it
                full["network_firewall_policy_id"] = pid
                if compartment_id:
                    full.setdefault("compartment_id", compartment_id)
                rows.append(full)
        return rows

    def save(self, rows: List[Dict[str, Any]]) -> None:
        save_rows(self.session, self.TABLE_NAME, rows)


db_ids = ids_from_db
