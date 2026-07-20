#!/usr/bin/env python3
from __future__ import annotations

from ocinferno.modules.databases.utilities.helpers import (
    DatabasesAutonomousResource,
    DatabasesCacheClustersResource,
    DatabasesCacheUsersResource,
    DatabasesDbSystemsResource,
    DatabasesMysqlResource,
    DatabasesPostgresResource,
)
from ocinferno.core.utils.service_runtime import (
    append_cached_component_counts,
    make_parse_args,
    resolve_selected_components,
    run_standard_enum_component,
)


COMPONENTS = [
    ("autonomous_databases", "autonomous_databases", "Enumerate Autonomous Databases (ADB)"),
    ("db_systems", "db_systems", "Enumerate Base Database DB Systems (VM/BM/Exadata)"),
    ("cache_clusters", "cache_clusters", "Enumerate cache-clusters"),
    ("cache_users", "cache_users", "Enumerate cache-users"),
    ("mysql", "mysql", "Enumerate mysql"),
    ("postgres", "postgres", "Enumerate postgres"),
]


CACHE_TABLES = {
    "autonomous_databases": ("db_autonomous_databases", "compartment_id"),
    "db_systems": ("db_db_systems", "compartment_id"),
    "cache_clusters": ("cache_clusters", "compartment_id"),
    "cache_users": ("cache_users", "compartment_id"),
    "mysql": ("db_mysql_db_systems", "compartment_id"),
    "postgres": ("db_psql_db_systems", "compartment_id"),
}


_parse_args = make_parse_args("Enumerate Databases resources", COMPONENTS)


def run_module(user_args, session):
    args, _ = _parse_args(user_args)

    component_order = [key for key, _suffix, _help in COMPONENTS]
    selected = resolve_selected_components(args, component_order)
    compartment_id = getattr(session, "compartment_id", None)
    if not compartment_id:
        raise ValueError("session.compartment_id is not set")

    resource_map = {
        "autonomous_databases": DatabasesAutonomousResource(session=session),
        "db_systems": DatabasesDbSystemsResource(session=session),
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
        results.append(run_standard_enum_component(
            user_args=args, session=session, component_key=key,
            list_rows=lambda cid, r=resource: r.list(compartment_id=cid),
            get_row=lambda row, r=resource: r.get(resource_id=row.get("id")),
            save_rows_fn=resource.save,
            print_columns=getattr(resource, "COLUMNS", []),
            module_name="enum_databases",
        ))

    append_cached_component_counts(
        results=results,
        session=session,
        selected=selected,
        component_order=component_order,
        cache_tables=CACHE_TABLES,
    )

    return {"ok": True, "components": results}
