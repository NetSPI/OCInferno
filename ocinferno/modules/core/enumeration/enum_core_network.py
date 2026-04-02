#!/usr/bin/env python3
from __future__ import annotations

import argparse
from typing import Any, Dict, Sequence

import oci
from ocinferno.core.console import UtilityTools
from ocinferno.modules.core.utilities.virtual_network_helpers import (
    DhcpOptionsResource,
    DrgAttachmentsResource,
    DrgsResource,
    InternetGatewaysResource,
    NatGatewaysResource,
    NetworkSecurityGroupsResource,
    RouteTablesResource,
    SecurityListsResource,
    ServiceGatewaysResource,
    SubnetsResource,
    VcnsResource,
    VirtualNetworkResourceClient,
    print_section_table,
)
from ocinferno.core.utils.module_helpers import fill_missing_fields, cached_table_count, resolve_component_flags


def _parse_args(user_args: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Enumerate OCI Core Networking Resources", allow_abbrev=False)

    parser.add_argument("--vcns", action="store_true", help="Enumerate VCNs")
    parser.add_argument("--subnets", action="store_true", help="Enumerate subnets")
    parser.add_argument("--route-tables", dest="route_tables", action="store_true", help="Enumerate route tables")
    parser.add_argument("--security-lists", dest="security_lists", action="store_true", help="Enumerate security lists")
    parser.add_argument("--nsgs", dest="network_security_groups", action="store_true", help="Enumerate network security groups")
    parser.add_argument("--internet-gateways", dest="internet_gateways", action="store_true", help="Enumerate internet gateways")
    parser.add_argument("--nat-gateways", dest="nat_gateways", action="store_true", help="Enumerate NAT gateways")
    parser.add_argument("--service-gateways", dest="service_gateways", action="store_true", help="Enumerate service gateways")
    parser.add_argument("--drgs", action="store_true", help="Enumerate DRGs")
    parser.add_argument("--drg-attachments", dest="drg_attachments", action="store_true", help="Enumerate DRG attachments")
    parser.add_argument("--dhcp-options", dest="dhcp_options", action="store_true", help="Enumerate DHCP options")

    parser.add_argument("--vcn-id", default="", help="Filter by VCN OCID (used by VCN-scoped resources)")
    parser.add_argument("--drg-id", default="", help="Filter by DRG OCID (used by DRG attachments)")

    # --get/--save are runner-level common flags; parse module-specific args only.
    args, _ = parser.parse_known_args(list(user_args))
    raw_args = {str(x) for x in (list(user_args) if user_args is not None else [])}
    args.get = "--get" in raw_args
    args.save = "--save" in raw_args
    return args


def run_module(user_args, session) -> Dict[str, Any]:
    args = _parse_args(user_args)
    debug = bool(getattr(session, "debug", False) or getattr(session, "individual_run_debug", False))

    comp_id = getattr(session, "compartment_id", None)
    if not comp_id:
        raise ValueError("session.compartment_id is not set. Select a compartment first.")

    flags = resolve_component_flags(
        args,
        [
            "vcns",
            "subnets",
            "route_tables",
            "security_lists",
            "network_security_groups",
            "internet_gateways",
            "nat_gateways",
            "service_gateways",
            "drgs",
            "drg_attachments",
            "dhcp_options",
        ],
    )
    ops = VirtualNetworkResourceClient(session=session)
    summary: Dict[str, int] = {}

    vcn_id = (args.vcn_id or "").strip() or None
    drg_id = (args.drg_id or "").strip() or None

    component_specs = [
        {"key": "vcns", "resource": VcnsResource(ops), "cache_table": "virtual_network_vcns", "list_kwargs": {}},
        {"key": "subnets", "resource": SubnetsResource(ops), "cache_table": "virtual_network_subnets", "list_kwargs": {"vcn_id": vcn_id}},
        {"key": "route_tables", "resource": RouteTablesResource(ops), "cache_table": "virtual_network_route_tables", "list_kwargs": {"vcn_id": vcn_id}},
        {"key": "security_lists", "resource": SecurityListsResource(ops), "cache_table": "virtual_network_security_lists", "list_kwargs": {"vcn_id": vcn_id}},
        {
            "key": "network_security_groups",
            "resource": NetworkSecurityGroupsResource(ops),
            "cache_table": "virtual_network_network_security_groups",
            "list_kwargs": {"vcn_id": vcn_id},
        },
        {
            "key": "internet_gateways",
            "resource": InternetGatewaysResource(ops),
            "cache_table": "virtual_network_internet_gateways",
            "list_kwargs": {"vcn_id": vcn_id},
        },
        {"key": "nat_gateways", "resource": NatGatewaysResource(ops), "cache_table": "virtual_network_nat_gateways", "list_kwargs": {"vcn_id": vcn_id}},
        {
            "key": "service_gateways",
            "resource": ServiceGatewaysResource(ops),
            "cache_table": "virtual_network_service_gateways",
            "list_kwargs": {"vcn_id": vcn_id},
        },
        {"key": "drgs", "resource": DrgsResource(ops), "cache_table": "virtual_network_drgs", "list_kwargs": {}},
        {
            "key": "drg_attachments",
            "resource": DrgAttachmentsResource(ops),
            "cache_table": "virtual_network_drg_attachments",
            "list_kwargs": {"drg_id": drg_id},
        },
        {"key": "dhcp_options", "resource": DhcpOptionsResource(ops), "cache_table": "virtual_network_dhcp_options", "list_kwargs": {"vcn_id": vcn_id}},
    ]

    # Resource loop: network components (VCNs, subnets, gateways, DRGs, ACL objects).
    for spec in component_specs:
        key = spec["key"]
        resource = spec["resource"]
        cache_table = spec["cache_table"]
        list_kwargs = dict(spec["list_kwargs"])

        if not flags.get(key, False):
            summary[key] = cached_table_count(
                session,
                table_name=cache_table,
                compartment_id=comp_id,
                compartment_field="compartment_id",
            ) or 0
            continue

        try:
            rows = resource.list(compartment_id=comp_id, **list_kwargs) or []
        except oci.exceptions.ServiceError as e:
            UtilityTools.dlog(True, f"list_{key} failed", status=getattr(e, "status", None), code=getattr(e, "code", None))
            rows = []
        except Exception as e:
            UtilityTools.dlog(True, f"list_{key} failed", err=f"{type(e).__name__}: {e}")
            rows = []

        if rows and args.get:
            for row in UtilityTools.progress_iter(rows, label=f"GET {key}"):
                rid = (row or {}).get("id")
                if not rid:
                    continue
                try:
                    meta = resource.get(resource_id=rid) or {}
                except Exception as e:
                    UtilityTools.dlog(debug, f"get_{key} failed", resource_id=rid, err=f"{type(e).__name__}: {e}")
                    continue
                if isinstance(meta, dict):
                    meta["get_run"] = True
                    fill_missing_fields(row, meta)

        if rows:
            print_section_table(resource.SECTION_TITLE, rows, resource.COLUMNS)
            if args.save:
                resource.save(rows)

        summary[key] = len(rows)

    return {"ok": True, **summary}
