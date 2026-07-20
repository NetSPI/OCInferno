#!/usr/bin/env python3
from __future__ import annotations

from ocinferno.core.console import UtilityTools
from ocinferno.core.utils.module_helpers import fill_missing_fields
from ocinferno.modules.dns.utilities.helpers import (
    DnsPrivateResolversResource,
    DnsZoneRecordsResource,
    DnsZonesResource,
)
from ocinferno.core.utils.service_runtime import (
    SOFT_SKIP_STATUSES,
    append_cached_component_counts,
    make_parse_args,
    resolve_selected_components,
    run_standard_enum_component,
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


_parse_args = make_parse_args("Enumerate DNS resources", COMPONENTS)


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
            results.append(run_standard_enum_component(
                user_args=args, session=session, component_key="zones",
                list_rows=lambda cid: zones_resource.list(compartment_id=cid),
                get_row=lambda row: zones_resource.get(resource_id=row.get("id")),
                save_rows_fn=zones_resource.save,
                print_columns=zones_resource.COLUMNS,
                module_name="enum_dns",
                soft_skip_statuses=SOFT_SKIP_STATUSES,
            ))
        elif key == "zone_records":
            zone_records_resource = resource_map[key]
            # DNS is often not authorized/enabled for a given compartment -> a bare
            # list_zones would raise a 404 NotAuthorizedOrNotFound and crash the module;
            # treat it (and 401/403) as an empty result, like the per-zone calls below.
            try:
                zones = zone_records_resource.list_zones(compartment_id=compartment_id) or []
            except Exception as err:
                if getattr(err, "status", None) in SOFT_SKIP_STATUSES:
                    UtilityTools.dlog(debug, "list_zones unavailable for scope", status=getattr(err, "status", None))
                    results.append({"ok": True, "zone_records": 0, "saved": True, "get": bool(args.get), "skipped": True})
                    continue
                UtilityTools.dlog(True, "list_zones failed", err=f"{type(err).__name__}: {err}")
                results.append({"ok": False, "component": "zone_records", "error": f"{type(err).__name__}: {err}"})
                continue
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
                UtilityTools.print_limited_table(rows, zone_records_resource.COLUMNS, title="Dns - Zone Records")

            zone_records_resource.save(rows)

            results.append({"ok": True, "zone_records": len(rows), "saved": True, "get": bool(args.get)})
        elif key == "private_resolvers":
            resolvers_resource = resource_map[key]
            results.append(run_standard_enum_component(
                user_args=args, session=session, component_key="private_resolvers",
                list_rows=lambda cid: resolvers_resource.list(compartment_id=cid),
                get_row=lambda row: resolvers_resource.get(resource_id=row.get("id")),
                save_rows_fn=resolvers_resource.save,
                print_columns=resolvers_resource.COLUMNS,
                module_name="enum_dns",
                soft_skip_statuses=SOFT_SKIP_STATUSES,
            ))

    append_cached_component_counts(
        results=results,
        session=session,
        selected=selected,
        component_order=component_order,
        cache_tables=CACHE_TABLES,
    )

    return {"ok": True, "components": results}
