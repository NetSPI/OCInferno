#!/usr/bin/env python3
from __future__ import annotations

import argparse

from ocinferno.core.utils.module_helpers import fill_missing_fields, unique_rows_by_id
from ocinferno.modules.desktops.utilities.helpers import (
    DesktopsDesktopsResource,
    DesktopsPoolDesktopsResource,
    DesktopsPoolVolumesResource,
    DesktopsPoolsResource,
    DesktopsWorkRequestsResource,
)
from ocinferno.core.utils.service_runtime import (
    append_cached_component_counts,
    parse_wrapper_args,
    resolve_selected_components,
)


COMPONENTS = [
    ("desktops", "desktops", "Enumerate desktops"),
    ("pools", "pools", "Enumerate desktop pools"),
    ("pool_desktops", "pool_desktops", "Enumerate desktops within pools"),
    ("pool_volumes", "pool_volumes", "Enumerate desktop pool volumes"),
    ("work_requests", "work_requests", "Enumerate desktop service work requests"),
]


CACHE_TABLES = {
    "desktops": ("desktops_desktops", "compartment_id"),
    "pools": ("desktops_pools", "compartment_id"),
    "pool_desktops": ("desktops_pool_desktops", "compartment_id"),
    "pool_volumes": ("desktops_pool_volumes", "compartment_id"),
    "work_requests": ("desktops_work_requests", "compartment_id"),
}


def _component_error_summary(err: Exception) -> str:
    status = getattr(err, "status", None)
    code = getattr(err, "code", None)
    msg = getattr(err, "message", None)
    if status is not None or code is not None:
        return f"status={status}, code={code}, message={msg or str(err)}"
    return f"{type(err).__name__}: {err}"


def _parse_args(user_args):
    def _add_extra_args(parser: argparse.ArgumentParser) -> None:
        parser.add_argument("--pool-ids", action="append", default=[], help="Desktop pool OCID scope (repeatable, CSV supported)")

    return parse_wrapper_args(
        user_args=user_args,
        description="Enumerate OCI Desktop resources",
        components=COMPONENTS,
        add_extra_args=_add_extra_args,
    )


def run_module(user_args, session):
    args, _ = _parse_args(user_args)

    component_order = [key for key, _suffix, _help in COMPONENTS]
    selected = resolve_selected_components(args, component_order)
    resource_map = {
        "desktops": DesktopsDesktopsResource(session=session),
        "pools": DesktopsPoolsResource(session=session),
        "pool_desktops": DesktopsPoolDesktopsResource(session=session),
        "pool_volumes": DesktopsPoolVolumesResource(session=session),
        "work_requests": DesktopsWorkRequestsResource(session=session),
    }
    results = []
    for key, _method_suffix, _help_text in COMPONENTS:
        if not selected.get(key, False):
            continue
        try:
            if key == "pool_desktops":
                pool_desktops_resource = resource_map[key]
                compartment_id = getattr(session, "compartment_id", None)
                if not compartment_id:
                    raise ValueError("session.compartment_id is not set")

                pool_ids = pool_desktops_resource.resolve_pool_ids(args, comp_id=compartment_id)
                rows = []
                for pool_id in pool_ids:
                    listed = pool_desktops_resource.list(compartment_id=compartment_id, desktop_pool_id=pool_id) or []
                    for row in listed:
                        if not isinstance(row, dict):
                            continue
                        row.setdefault("desktop_pool_id", pool_id)
                        row.setdefault("compartment_id", compartment_id)
                        rows.append(row)

                rows = unique_rows_by_id(rows)

                if args.get:
                    for row in rows:
                        desktop_id = row.get("id")
                        if not desktop_id:
                            continue
                        meta = pool_desktops_resource.get(resource_id=desktop_id) or {}
                        fill_missing_fields(row, meta)

                if rows:
                    from ocinferno.core.console import UtilityTools

                    UtilityTools.print_limited_table(rows, pool_desktops_resource.COLUMNS)

                if args.save:
                    pool_desktops_resource.save(rows)

                results.append({"ok": True, "pool_desktops": len(rows), "saved": bool(args.save), "get": bool(args.get), "pool_ids": pool_ids})
            elif key == "pool_volumes":
                pool_volumes_resource = resource_map[key]
                compartment_id = getattr(session, "compartment_id", None)
                if not compartment_id:
                    raise ValueError("session.compartment_id is not set")

                pool_ids = pool_volumes_resource.resolve_pool_ids(args, comp_id=compartment_id)
                rows = []
                for pool_id in pool_ids:
                    listed = pool_volumes_resource.list(desktop_pool_id=pool_id, compartment_id=compartment_id) or []
                    for row in listed:
                        if not isinstance(row, dict):
                            continue
                        row.setdefault("desktop_pool_id", pool_id)
                        row.setdefault("compartment_id", compartment_id)
                        row["record_hash"] = pool_volumes_resource.record_hash(row, prefix=f"{pool_id}:")
                        rows.append(row)

                if rows:
                    from ocinferno.core.console import UtilityTools

                    UtilityTools.print_limited_table(rows, pool_volumes_resource.COLUMNS)

                if args.save:
                    pool_volumes_resource.save(rows)

                results.append({"ok": True, "pool_volumes": len(rows), "saved": bool(args.save), "get": False, "pool_ids": pool_ids})
            else:
                resource = resource_map[key]
                compartment_id = getattr(session, "compartment_id", None)
                if not compartment_id:
                    raise ValueError("session.compartment_id is not set")

                rows = resource.list(compartment_id=compartment_id) or []
                rows = unique_rows_by_id([row for row in rows if isinstance(row, dict)])
                for row in rows:
                    row.setdefault("compartment_id", compartment_id)

                if args.get:
                    for row in rows:
                        resource_id = row.get("id")
                        if not resource_id:
                            continue
                        meta = resource.get(resource_id=resource_id) or {}
                        fill_missing_fields(row, meta)

                if rows:
                    from ocinferno.core.console import UtilityTools

                    UtilityTools.print_limited_table(rows, resource.COLUMNS)

                if args.save:
                    resource.save(rows)

                results.append({"ok": True, key: len(rows), "saved": bool(args.save), "get": bool(args.get)})
        except Exception as err:
            print(f"[*] enum_desktops.{key}: skipped ({_component_error_summary(err)}).")
            results.append({"ok": False, "component": key, "error": _component_error_summary(err)})

    append_cached_component_counts(
        results=results,
        session=session,
        selected=selected,
        component_order=component_order,
        cache_tables=CACHE_TABLES,
    )

    return {"ok": True, "components": results}
