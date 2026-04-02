#!/usr/bin/env python3
from __future__ import annotations

from ocinferno.core.console import UtilityTools
from ocinferno.core.utils.module_helpers import fill_missing_fields, unique_rows_by_id
from ocinferno.modules.networkfirewall.utilities.helpers import (
    NetworkFirewallFirewallsResource,
    NetworkFirewallPoliciesResource,
    NetworkFirewallSecurityRulesResource,
    normalize_csv_args,
)
from ocinferno.core.utils.service_runtime import (
    append_cached_component_counts,
    parse_wrapper_args,
    resolve_selected_components,
)


COMPONENTS = [
    ("firewalls", "firewalls", "Enumerate network firewalls"),
    ("policies", "policies", "Enumerate network firewall policies"),
    ("security_rules", "security_rules", "Enumerate network firewall security rules"),
]


CACHE_TABLES = {
    "firewalls": ("network_firewall_firewalls", "compartment_id"),
    "policies": ("network_firewall_policies", "compartment_id"),
    "security_rules": ("network_firewall_security_rules", "compartment_id"),
}


def _component_error_summary(err: Exception) -> str:
    status = getattr(err, "status", None)
    code = getattr(err, "code", None)
    msg = getattr(err, "message", None)
    if status is not None or code is not None:
        return f"status={status}, code={code}, message={msg or str(err)}"
    return f"{type(err).__name__}: {err}"


def _parse_args(user_args):
    def _add_extra_args(parser):
        parser.add_argument("--firewall-id", default="", help="Get a specific Network Firewall by OCID")
        parser.add_argument(
            "--policy-ids",
            action="append",
            default=[],
            help="Network Firewall Policy OCIDs (repeatable, comma-separated supported).",
        )

    return parse_wrapper_args(
        user_args=user_args,
        description="Enumerate Network Firewall resources",
        components=COMPONENTS,
        add_extra_args=_add_extra_args,
    )


def run_module(user_args, session):
    args, _ = _parse_args(user_args)

    component_order = [key for key, _suffix, _help in COMPONENTS]
    selected = resolve_selected_components(args, component_order)
    resource_map = {
        "firewalls": NetworkFirewallFirewallsResource(session=session),
        "policies": NetworkFirewallPoliciesResource(session=session),
        "security_rules": NetworkFirewallSecurityRulesResource(session=session),
    }
    results = []
    for key, _method_suffix, _help_text in COMPONENTS:
        if not selected.get(key, False):
            continue
        try:
            if key == "firewalls":
                firewalls_resource = resource_map[key]
                compartment_id = getattr(session, "compartment_id", None)
                firewall_id = (args.firewall_id or "").strip()
                if not compartment_id and not firewall_id:
                    raise ValueError("Need session.compartment_id unless --firewall-id is provided")

                if firewall_id:
                    row = firewalls_resource.get(resource_id=firewall_id) or {}
                    rows = [row] if row else []
                else:
                    rows = firewalls_resource.list(compartment_id=compartment_id or "") or []

                rows = [row for row in rows if isinstance(row, dict)]
                for row in rows:
                    row.setdefault("compartment_id", compartment_id)

                if args.get:
                    for row in rows:
                        row_id = row.get("id")
                        if not row_id:
                            continue
                        meta = firewalls_resource.get(resource_id=row_id) or {}
                        fill_missing_fields(row, meta)

                if rows:
                    UtilityTools.print_limited_table(rows, firewalls_resource.COLUMNS)

                if args.save:
                    firewalls_resource.save(rows)

                results.append({"ok": True, "firewalls": len(rows), "saved": bool(args.save), "get": bool(args.get)})
            elif key == "policies":
                policies_resource = resource_map[key]
                compartment_id = getattr(session, "compartment_id", None)
                policy_ids = normalize_csv_args(list(args.policy_ids or []))

                if not compartment_id and not policy_ids:
                    raise ValueError("Need session.compartment_id unless --policy-ids are provided")

                rows = []
                if policy_ids:
                    for policy_id in policy_ids:
                        item = policies_resource.get(resource_id=policy_id) or {}
                        if item:
                            rows.append(item)
                else:
                    rows = policies_resource.list(compartment_id=compartment_id or "") or []

                rows = unique_rows_by_id([row for row in rows if isinstance(row, dict)])
                for row in rows:
                    row.setdefault("compartment_id", compartment_id)

                if args.get:
                    for row in rows:
                        policy_id = row.get("id")
                        if not policy_id:
                            continue
                        meta = policies_resource.get(resource_id=policy_id) or {}
                        fill_missing_fields(row, meta)

                if rows:
                    UtilityTools.print_limited_table(rows, policies_resource.COLUMNS)

                if args.save:
                    policies_resource.save(rows)

                results.append({"ok": True, "policies": len(rows), "saved": bool(args.save), "get": bool(args.get)})
            elif key == "security_rules":
                security_rules_resource = resource_map[key]
                compartment_id = getattr(session, "compartment_id", None)
                if not compartment_id and not args.policy_ids:
                    raise ValueError("Need session.compartment_id unless --policy-ids are provided")

                policy_ids = security_rules_resource.resolve_policy_ids(compartment_id, args)
                rows = []
                for policy_id in policy_ids:
                    listed = security_rules_resource.list(policy_id=policy_id) or []
                    for row in listed:
                        if not isinstance(row, dict):
                            continue
                        row.setdefault("network_firewall_policy_id", policy_id)
                        row.setdefault("compartment_id", compartment_id)
                        rows.append(row)

                rows = security_rules_resource.unique_security_rule_rows(rows)

                if args.get:
                    for row in rows:
                        policy_id = row.get("network_firewall_policy_id")
                        rule_name = row.get("name")
                        if not policy_id or not rule_name:
                            continue
                        meta = security_rules_resource.get(policy_id=policy_id, security_rule_name=rule_name) or {}
                        fill_missing_fields(row, meta)

                if rows:
                    UtilityTools.print_limited_table(rows, security_rules_resource.COLUMNS)

                if args.save:
                    security_rules_resource.save(rows)

                results.append(
                    {
                        "ok": True,
                        "security_rules": len(rows),
                        "policy_ids": policy_ids,
                        "saved": bool(args.save),
                        "get": bool(args.get),
                    }
                )
        except Exception as err:
            print(f"[*] enum_networkfirewall.{key}: skipped ({_component_error_summary(err)}).")
            results.append({"ok": False, "component": key, "error": _component_error_summary(err)})

    append_cached_component_counts(
        results=results,
        session=session,
        selected=selected,
        component_order=component_order,
        cache_tables=CACHE_TABLES,
    )

    return {"ok": True, "components": results}
