#!/usr/bin/env python3
from __future__ import annotations

import oci
from ocinferno.core.console import UtilityTools
from ocinferno.core.utils.module_helpers import fill_missing_fields
from ocinferno.modules.databases.utilities.helpers import (
    DatabasesCacheClustersResource,
    DatabasesCacheUsersResource,
    DatabasesMysqlResource,
    DatabasesPostgresResource,
)
from ocinferno.core.utils.service_runtime import (
    append_cached_component_counts,
    parse_wrapper_args,
    resolve_selected_components,
)


COMPONENTS = [
    ("cache_clusters", "cache_clusters", "Enumerate cache-clusters"),
    ("cache_users", "cache_users", "Enumerate cache-users"),
    ("mysql", "mysql", "Enumerate mysql"),
    ("postgres", "postgres", "Enumerate postgres"),
]


CACHE_TABLES = {
    "cache_clusters": ("cache_clusters", "compartment_id"),
    "cache_users": ("cache_users", "compartment_id"),
    "mysql": ("db_mysql_db_systems", "compartment_id"),
    "postgres": ("db_psql_db_systems", "compartment_id"),
}


def _parse_args(user_args):
    return parse_wrapper_args(
        user_args=user_args,
        description="Enumerate Databases resources",
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
        "cache_clusters": DatabasesCacheClustersResource(session=session),
        "cache_users": DatabasesCacheUsersResource(session=session),
        "mysql": DatabasesMysqlResource(session=session),
        "postgres": DatabasesPostgresResource(session=session),
    }
    results = []
    for key, _method_suffix, _help_text in COMPONENTS:
        if not selected.get(key, False):
            continue
        resource = resource_map[key]
        try:
            rows = resource.list(compartment_id=compartment_id) or []
        except oci.exceptions.ServiceError as err:
            UtilityTools.dlog(
                True,
                f"list_{key} failed",
                status=getattr(err, "status", None),
                code=getattr(err, "code", None),
                msg=getattr(err, "message", str(err)),
            )
            results.append({"ok": False, key: 0, "saved": False, "get": bool(args.get)})
            continue

        rows = [row for row in rows if isinstance(row, dict)]
        for row in rows:
            row.setdefault("compartment_id", compartment_id)

        if args.get:
            for row in rows:
                resource_id = row.get("id")
                if not resource_id:
                    continue
                try:
                    meta = resource.get(resource_id=resource_id) or {}
                except Exception as err:
                    UtilityTools.dlog(debug, f"get_{key} failed", resource_id=resource_id, err=f"{type(err).__name__}: {err}")
                    continue
                fill_missing_fields(row, meta)

        if rows:
            UtilityTools.print_limited_table(rows, getattr(resource, "COLUMNS", []))

        if args.save:
            resource.save(rows)

        results.append({"ok": True, key: len(rows), "saved": bool(args.save), "get": bool(args.get)})

    append_cached_component_counts(
        results=results,
        session=session,
        selected=selected,
        component_order=component_order,
        cache_tables=CACHE_TABLES,
    )

    return {"ok": True, "components": results}
