#!/usr/bin/env python3
from __future__ import annotations

import oci
from ocinferno.core.console import UtilityTools
from ocinferno.core.utils.module_helpers import fill_missing_fields
from ocinferno.modules.dns.utilities.helpers import (
    DnsPrivateResolversResource,
    DnsZoneRecordsResource,
    DnsZonesResource,
)
from ocinferno.core.utils.service_runtime import (
    append_cached_component_counts,
    parse_wrapper_args,
    resolve_selected_components,
)


COMPONENTS = [
    ("zones", "zones", "Enumerate zones"),
    ("zone_records", "zone_records", "Enumerate zone-records"),
    ("private_resolvers", "private_resolvers", "Enumerate private-resolvers"),
]


CACHE_TABLES = {
    "zones": ("dns_zones", "compartment_id"),
    "zone_records": ("dns_zone_records", "compartment_id"),
    "private_resolvers": ("dns_private_resolvers", "compartment_id"),
}


def _parse_args(user_args):
    return parse_wrapper_args(
        user_args=user_args,
        description="Enumerate DNS resources",
        components=COMPONENTS,
    )


def run_module(user_args, session):
    args, _ = _parse_args(user_args)
    debug = bool(getattr(session, "individual_run_debug", False) or getattr(session, "debug", False))

    component_order = [key for key, _suffix, _help in COMPONENTS]
    selected = resolve_selected_components(args, component_order)
    compartment_id = getattr(session, "compartment_id", None)
    if not compartment_id:
        raise ValueError("session.compartment_id is not set")

    resource_map = {
        "zones": DnsZonesResource(session=session),
        "zone_records": DnsZoneRecordsResource(session=session),
        "private_resolvers": DnsPrivateResolversResource(session=session),
    }
    results = []
    for key, _method_suffix, _help_text in COMPONENTS:
        if not selected.get(key, False):
            continue
        if key == "zones":
            zones_resource = resource_map[key]
            rows = zones_resource.list(compartment_id=compartment_id) or []
            rows = [row for row in rows if isinstance(row, dict)]
            for row in rows:
                row.setdefault("compartment_id", compartment_id)

            if args.get:
                for row in rows:
                    zone_id = row.get("id")
                    if not zone_id:
                        continue
                    meta = zones_resource.get(resource_id=zone_id) or {}
                    fill_missing_fields(row, meta)

            if rows:
                UtilityTools.print_limited_table(rows, zones_resource.COLUMNS)

            if args.save:
                zones_resource.save(rows)

            results.append({"ok": True, "zones": len(rows), "saved": bool(args.save), "get": bool(args.get)})
        elif key == "zone_records":
            zone_records_resource = resource_map[key]
            zones = zone_records_resource.list_zones(compartment_id=compartment_id) or []
            zones = [zone for zone in zones if isinstance(zone, dict)]

            rows = []
            for zone in zones:
                zone_id = zone.get("id")
                zone_name = zone.get("name")
                if not zone_id and not zone_name:
                    continue
                target = str(zone_id or zone_name)
                try:
                    listed = zone_records_resource.list(zone_name_or_id=target) or []
                except Exception as err:
                    UtilityTools.dlog(debug, "list_rrsets failed", zone=target, err=f"{type(err).__name__}: {err}")
                    continue
                for row in listed:
                    if not isinstance(row, dict):
                        continue
                    row.setdefault("compartment_id", compartment_id)
                    row.setdefault("zone_id", zone_id)
                    row.setdefault("zone_name", zone_name)
                    rows.append(row)

            if args.get:
                for zone in zones:
                    zone_id = zone.get("id")
                    if not zone_id:
                        continue
                    try:
                        meta = zone_records_resource.get_zone(zone_name_or_id=zone_id) or {}
                    except Exception as err:
                        UtilityTools.dlog(debug, "get_zone failed", zone_id=zone_id, err=f"{type(err).__name__}: {err}")
                        continue
                    for row in rows:
                        if row.get("zone_id") == zone_id:
                            fill_missing_fields(row, {"zone_lifecycle_state": meta.get("lifecycle_state")})

            if rows:
                UtilityTools.print_limited_table(rows, zone_records_resource.COLUMNS)

            if args.save:
                zone_records_resource.save(rows)

            results.append({"ok": True, "zone_records": len(rows), "saved": bool(args.save), "get": bool(args.get)})
        elif key == "private_resolvers":
            resolvers_resource = resource_map[key]
            rows = resolvers_resource.list(compartment_id=compartment_id) or []
            rows = [row for row in rows if isinstance(row, dict)]
            for row in rows:
                row.setdefault("compartment_id", compartment_id)

            if args.get:
                for row in rows:
                    resolver_id = row.get("id")
                    if not resolver_id:
                        continue
                    meta = resolvers_resource.get(resource_id=resolver_id) or {}
                    fill_missing_fields(row, meta)

            if rows:
                UtilityTools.print_limited_table(rows, resolvers_resource.COLUMNS)

            if args.save:
                resolvers_resource.save(rows)

            results.append({"ok": True, "private_resolvers": len(rows), "saved": bool(args.save), "get": bool(args.get)})

    append_cached_component_counts(
        results=results,
        session=session,
        selected=selected,
        component_order=component_order,
        cache_tables=CACHE_TABLES,
    )

    return {"ok": True, "components": results}
