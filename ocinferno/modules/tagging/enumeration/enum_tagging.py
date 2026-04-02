#!/usr/bin/env python3
from __future__ import annotations

import argparse

import oci
from ocinferno.core.console import UtilityTools
from ocinferno.modules.tagging.utilities.helpers import (
    TaggingTagDefaultsResource,
    TaggingTagDefinitionsResource,
    TaggingTagNamespacesResource,
)
from ocinferno.core.utils.service_runtime import (
    append_cached_component_counts,
    parse_wrapper_args,
    resolve_selected_components,
)


COMPONENTS = [
    ("namespaces", "namespaces", "Enumerate namespaces"),
    ("definitions", "definitions", "Enumerate tag definitions"),
    ("defaults", "defaults", "Enumerate defaults"),
]


CACHE_TABLES = {
    "namespaces": ("tag_namespaces", "compartment_id"),
    "definitions": ("tag_definitions", "compartment_id"),
    "defaults": ("tag_defaults", "compartment_id"),
}


def _parse_args(user_args):
    def _add_extra_args(parser: argparse.ArgumentParser) -> None:
        parser.add_argument("--include-subcompartments", action="store_true", help="Include subcompartments")

    return parse_wrapper_args(
        user_args=user_args,
        description="Enumerate Tagging resources",
        components=COMPONENTS,
        add_extra_args=_add_extra_args,
        include_get=False,
    )


def run_module(user_args, session):
    args, _ = _parse_args(user_args)
    debug = bool(getattr(session, "individual_run_debug", False) or getattr(session, "debug", False))
    component_order = [key for key, _suffix, _help in COMPONENTS]
    selected = resolve_selected_components(args, component_order)
    compartment_id = getattr(session, "compartment_id", None)
    if not compartment_id:
        raise ValueError("session.compartment_id is not set")
    results = []

    namespaces_resource = TaggingTagNamespacesResource(session=session)
    definitions_resource = TaggingTagDefinitionsResource(session=session)
    defaults_resource = TaggingTagDefaultsResource(session=session)

    if selected.get("namespaces", False):
        try:
            rows = namespaces_resource.list(
                compartment_id=compartment_id,
                include_subcompartments=bool(args.include_subcompartments),
            )
        except oci.exceptions.ServiceError as err:
            UtilityTools.dlog(True, "list_tag_namespaces failed", status=err.status, code=err.code)
            results.append({"ok": False, "namespaces": 0})
        else:
            rows = [row for row in rows if isinstance(row, dict)]
            for row in rows:
                row.setdefault("compartment_id", compartment_id)

            if rows:
                UtilityTools.print_limited_table(rows, namespaces_resource.COLUMNS)

            if args.save:
                namespaces_resource.save(rows)

            results.append({"ok": True, "namespaces": len(rows), "saved": bool(args.save)})
    if selected.get("definitions", False):
        try:
            namespaces = definitions_resource.list_namespaces(
                compartment_id=compartment_id,
                include_subcompartments=bool(args.include_subcompartments),
            )
        except oci.exceptions.ServiceError as err:
            UtilityTools.dlog(True, "list_tag_namespaces failed", status=err.status, code=err.code)
            results.append({"ok": False, "definitions": 0})
        else:
            namespace_rows = [row for row in namespaces if isinstance(row, dict) and row.get("id")]
            out_rows = []
            for namespace in namespace_rows:
                namespace_id = str(namespace.get("id") or "").strip()
                namespace_compartment_id = str(namespace.get("compartment_id") or compartment_id)
                if not namespace_id:
                    continue
                try:
                    listed = definitions_resource.list(
                        compartment_id=namespace_compartment_id,
                        tag_namespace_id=namespace_id,
                        include_subcompartments=False,
                    )
                except oci.exceptions.ServiceError as err:
                    UtilityTools.dlog(debug, "list_tag_definitions failed", namespace_id=namespace_id, status=err.status, code=err.code)
                    continue

                for row in listed or []:
                    if not isinstance(row, dict):
                        continue
                    row.setdefault("compartment_id", namespace_compartment_id)
                    row.setdefault("tag_namespace_id", namespace_id)
                    row.setdefault("tag_namespace_name", namespace.get("name"))
                    out_rows.append(row)

            if out_rows:
                UtilityTools.print_limited_table(out_rows, definitions_resource.COLUMNS)

            if args.save:
                definitions_resource.save(out_rows)

            results.append({"ok": True, "definitions": len(out_rows), "saved": bool(args.save)})
    if selected.get("defaults", False):
        try:
            rows = defaults_resource.list(
                compartment_id=compartment_id,
                include_subcompartments=bool(args.include_subcompartments),
            )
        except oci.exceptions.ServiceError as err:
            UtilityTools.dlog(True, "list_tag_defaults failed", status=err.status, code=err.code)
            results.append({"ok": False, "defaults": 0})
        else:
            rows = [row for row in rows if isinstance(row, dict)]
            for row in rows:
                row.setdefault("compartment_id", compartment_id)

            if rows:
                UtilityTools.print_limited_table(rows, defaults_resource.COLUMNS)

            if args.save:
                defaults_resource.save(rows)

            results.append({"ok": True, "defaults": len(rows), "saved": bool(args.save)})

    append_cached_component_counts(
        results=results,
        session=session,
        selected=selected,
        component_order=component_order,
        cache_tables=CACHE_TABLES,
    )

    return {"ok": True, "components": results}
