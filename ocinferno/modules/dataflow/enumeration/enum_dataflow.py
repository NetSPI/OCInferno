#!/usr/bin/env python3
from __future__ import annotations

import oci
from ocinferno.core.console import UtilityTools
from ocinferno.core.utils.module_helpers import fill_missing_fields
from ocinferno.modules.dataflow.utilities.helpers import (
    DataFlowApplicationsResource,
    DataFlowPoolsResource,
    DataFlowPrivateEndpointsResource,
    DataFlowRunsResource,
    DataFlowSqlEndpointsResource,
    DataFlowWorkRequestsResource,
)
from ocinferno.core.utils.service_runtime import (
    append_cached_component_counts,
    parse_wrapper_args,
    resolve_selected_components,
)


COMPONENTS = [
    ("applications", "applications", "Enumerate Data Flow applications"),
    ("runs", "runs", "Enumerate Data Flow runs"),
    ("pools", "pools", "Enumerate Data Flow pools"),
    ("private_endpoints", "private_endpoints", "Enumerate Data Flow private endpoints"),
    ("sql_endpoints", "sql_endpoints", "Enumerate Data Flow SQL endpoints"),
    ("work_requests", "work_requests", "Enumerate Data Flow work requests"),
]


CACHE_TABLES = {
    "applications": ("dataflow_applications", "compartment_id"),
    "runs": ("dataflow_runs", "compartment_id"),
    "pools": ("dataflow_pools", "compartment_id"),
    "private_endpoints": ("dataflow_private_endpoints", "compartment_id"),
    "sql_endpoints": ("dataflow_sql_endpoints", "compartment_id"),
    "work_requests": ("dataflow_work_requests", "compartment_id"),
}


def _parse_args(user_args):
    return parse_wrapper_args(
        user_args,
        description="Enumerate OCI Data Flow resources",
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
        "applications": DataFlowApplicationsResource(session=session),
        "runs": DataFlowRunsResource(session=session),
        "pools": DataFlowPoolsResource(session=session),
        "private_endpoints": DataFlowPrivateEndpointsResource(session=session),
        "sql_endpoints": DataFlowSqlEndpointsResource(session=session),
        "work_requests": DataFlowWorkRequestsResource(session=session),
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
