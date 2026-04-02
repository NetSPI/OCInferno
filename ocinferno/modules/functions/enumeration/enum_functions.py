#!/usr/bin/env python3
from __future__ import annotations

import argparse

import oci
from ocinferno.core.console import UtilityTools
from ocinferno.core.utils.module_helpers import fill_missing_fields, unique_rows_by_id
from ocinferno.modules.functions.utilities.helpers import FunctionsAppsResource, FunctionsFunctionsResource
from ocinferno.core.utils.service_runtime import (
    append_cached_component_counts,
    parse_wrapper_args,
    resolve_selected_components,
)


COMPONENTS = [
    ("apps", "apps", "Enumerate function applications"),
    ("functions", "functions", "Enumerate functions"),
]


CACHE_TABLES = {
    "apps": ("functions_apps", "compartment_id"),
    "functions": ("functions_functions", "compartment_id"),
}


def _parse_args(user_args):
    def _add_extra_args(parser: argparse.ArgumentParser) -> None:
        parser.add_argument(
            "--app-ids",
            action="append",
            default=[],
            help="Functions application OCIDs scope (repeatable, comma-separated supported).",
        )

    return parse_wrapper_args(
        user_args=user_args,
        description="Enumerate Functions resources",
        components=COMPONENTS,
        add_extra_args=_add_extra_args,
    )


def run_module(user_args, session):
    args, _ = _parse_args(user_args)
    debug = bool(getattr(session, "individual_run_debug", False) or getattr(session, "debug", False))
    compartment_id = getattr(session, "compartment_id", None)

    component_order = [key for key, _suffix, _help in COMPONENTS]
    selected = resolve_selected_components(args, component_order)
    results = []

    apps_resource = FunctionsAppsResource(session=session)
    functions_resource = FunctionsFunctionsResource(session=session)

    # Resource loop: function applications.
    if selected.get("apps", False):
        if not compartment_id:
            raise ValueError("session.compartment_id is not set")
        try:
            rows = apps_resource.list(compartment_id=compartment_id) or []
        except oci.exceptions.ServiceError as err:
            UtilityTools.dlog(True, "list_applications failed", status=getattr(err, "status", None), code=getattr(err, "code", None), msg=str(err))
            results.append({"ok": False, "apps": 0})
        else:
            rows = [row for row in rows if isinstance(row, dict)]
            for row in rows:
                row.setdefault("compartment_id", compartment_id)

            if args.get:
                for row in rows:
                    application_id = row.get("id")
                    if not application_id:
                        continue
                    try:
                        meta = apps_resource.get(resource_id=application_id) or {}
                    except Exception as err:
                        UtilityTools.dlog(debug, "get_application failed", application_id=application_id, err=f"{type(err).__name__}: {err}")
                        continue
                    fill_missing_fields(row, meta)

            if rows:
                UtilityTools.print_limited_table(rows, apps_resource.COLUMNS)

            if args.save:
                apps_resource.save(rows)

            results.append({"ok": True, "apps": len(rows), "saved": bool(args.save), "get": bool(args.get)})
    # Resource loop: functions (scoped by application IDs).
    if selected.get("functions", False):
        if not compartment_id and not args.app_ids:
            raise ValueError("Need session.compartment_id unless --app-ids are provided")

        app_ids = functions_resource.list_app_ids(compartment_id=compartment_id, args=args)
        rows = []
        for app_id in app_ids:
            try:
                listed = functions_resource.list(application_id=app_id) or []
            except Exception as err:
                UtilityTools.dlog(debug, "list_functions failed", application_id=app_id, err=f"{type(err).__name__}: {err}")
                continue
            for row in listed:
                if not isinstance(row, dict):
                    continue
                row.setdefault("application_id", app_id)
                row.setdefault("compartment_id", compartment_id)
                rows.append(row)

        rows = unique_rows_by_id(rows)

        if args.get:
            for row in rows:
                function_id = row.get("id")
                if not function_id:
                    continue
                try:
                    meta = functions_resource.get(resource_id=function_id) or {}
                except Exception as err:
                    UtilityTools.dlog(debug, "get_function failed", function_id=function_id, err=f"{type(err).__name__}: {err}")
                    continue
                fill_missing_fields(row, meta)

        if rows:
            UtilityTools.print_limited_table(rows, functions_resource.COLUMNS)

        if args.save:
            functions_resource.save(rows)

        results.append(
            {
                "ok": True,
                "functions": len(rows),
                "saved": bool(args.save),
                "get": bool(args.get),
                "app_ids": app_ids,
            }
        )

    append_cached_component_counts(
        results=results,
        session=session,
        selected=selected,
        component_order=component_order,
        cache_tables=CACHE_TABLES,
    )

    return {"ok": True, "components": results}
