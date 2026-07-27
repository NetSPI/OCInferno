#!/usr/bin/env python3
from __future__ import annotations

from ocinferno.core.console import UtilityTools
from ocinferno.core.utils.enum_framework import nested_list_fn
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
    run_standard_enum_component,
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


from ocinferno.core.utils.service_runtime import component_soft_skip_or_error


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
    debug = bool(getattr(session, "debug", False))

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

                # --firewall-id scopes to a single get(); otherwise list per compartment.
                def _list_firewalls(cid, _fid=firewall_id, _res=firewalls_resource):
                    if _fid:
                        row = _res.get(resource_id=_fid) or {}
                        return [row] if row else []
                    return _res.list(compartment_id=cid or "") or []

                results.append(run_standard_enum_component(
                    user_args=args, session=session, component_key="firewalls",
                    list_rows=_list_firewalls,
                    get_row=lambda row, _res=firewalls_resource: _res.get(resource_id=row.get("id")),
                    save_rows_fn=firewalls_resource.save,
                    print_columns=firewalls_resource.COLUMNS,
                    module_name="enum_networkfirewall",
                    require_compartment=False,
                ))
            elif key == "policies":
                policies_resource = resource_map[key]
                compartment_id = getattr(session, "compartment_id", None)
                policy_ids = normalize_csv_args(list(args.policy_ids or []))

                if not compartment_id and not policy_ids:
                    raise ValueError("Need session.compartment_id unless --policy-ids are provided")

                # --policy-ids scopes to get()-per-id; otherwise list per compartment. Dedup either way.
                def _list_policies(cid, _ids=policy_ids, _res=policies_resource):
                    if _ids:
                        got = []
                        for pid in _ids:
                            try:
                                got.append(_res.get(resource_id=pid) or {})
                            except Exception as err:
                                UtilityTools.dlog(debug, "get policy failed", policy_id=pid, err=f"{type(err).__name__}: {err}")
                        rows = [r for r in got if r]
                    else:
                        rows = _res.list(compartment_id=cid or "") or []
                    return unique_rows_by_id([r for r in rows if isinstance(r, dict)])

                results.append(run_standard_enum_component(
                    user_args=args, session=session, component_key="policies",
                    list_rows=_list_policies,
                    get_row=lambda row, _res=policies_resource: _res.get(resource_id=row.get("id")),
                    save_rows_fn=policies_resource.save,
                    print_columns=policies_resource.COLUMNS,
                    module_name="enum_networkfirewall",
                    require_compartment=False,
                ))
            elif key == "security_rules":
                security_rules_resource = resource_map[key]
                compartment_id = getattr(session, "compartment_id", None)
                if not compartment_id and not args.policy_ids:
                    raise ValueError("Need session.compartment_id unless --policy-ids are provided")

                policy_ids = security_rules_resource.resolve_policy_ids(compartment_id, args)
                # resolve_policy_ids already covers manual --policy-ids/DB-cache/live-list; reuse
                # its result via manual_parent_ids so nested_list_fn only does the fan-out+stamp.
                list_rows = nested_list_fn(
                    parent_resource_cls=NetworkFirewallPoliciesResource,
                    parent_id_field="network_firewall_policy_id",
                    manual_parent_ids=policy_ids,
                    child_takes_compartment=False,
                )(session, args, security_rules_resource)
                rows = security_rules_resource.unique_security_rule_rows(list_rows(compartment_id))

                if args.get:
                    for row in rows:
                        policy_id = row.get("network_firewall_policy_id")
                        rule_name = row.get("name")
                        if not policy_id or not rule_name:
                            continue
                        meta = security_rules_resource.get(policy_id=policy_id, security_rule_name=rule_name) or {}
                        fill_missing_fields(row, meta)

                if rows:
                    UtilityTools.print_limited_table(rows, security_rules_resource.COLUMNS, title="Networkfirewall - Security Rules")

                security_rules_resource.save(rows)

                results.append(
                    {
                        "ok": True,
                        "security_rules": len(rows),
                        "policy_ids": policy_ids,
                        "saved": True,
                        "get": bool(args.get),
                    }
                )
        except Exception as err:
            results.append(component_soft_skip_or_error(err, component=key, module_name="enum_networkfirewall"))

    append_cached_component_counts(
        results=results,
        session=session,
        selected=selected,
        component_order=component_order,
        cache_tables=CACHE_TABLES,
    )

    return {"ok": True, "components": results}
