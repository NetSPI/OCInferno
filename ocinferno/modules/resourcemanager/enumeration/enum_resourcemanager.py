#!/usr/bin/env python3
from __future__ import annotations

import argparse

from ocinferno.core.console import UtilityTools
from ocinferno.core.utils.module_helpers import fill_missing_fields
from ocinferno.modules.resourcemanager.utilities.helpers import (
    ResourceManagerConfigSourceProvidersResource,
    ResourceManagerJobsResource,
    ResourceManagerPrivateEndpointsResource,
    ResourceManagerStacksResource,
    ResourceManagerTemplatesResource,
)
from ocinferno.core.utils.service_runtime import (
    append_cached_component_counts,
    parse_wrapper_args,
    resolve_selected_components,
)


COMPONENTS = [
    ("stacks", "stacks", "Enumerate stacks"),
    ("jobs", "jobs", "Enumerate jobs"),
    ("private_endpoints", "private_endpoints", "Enumerate private-endpoints"),
    ("config_source_providers", "config_source_providers", "Enumerate config-source-providers"),
    ("templates", "templates", "Enumerate templates"),
]


CACHE_TABLES = {
    "stacks": ("resource_manager_stacks", "compartment_id"),
    "jobs": ("resource_manager_jobs", "compartment_id"),
    "templates": ("resource_manager_templates", "compartment_id"),
    "private_endpoints": ("resource_manager_private_endpoints", "compartment_id"),
    "config_source_providers": ("resource_manager_config_source_providers", "compartment_id"),
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
        parser.add_argument("--template-id", default="", help="Get a specific template by OCID")
        parser.add_argument("--template-category-id", default="", help="Filter templates by template category")

    return parse_wrapper_args(
        user_args=user_args,
        description="Enumerate ResourceManager resources",
        components=COMPONENTS,
        add_extra_args=_add_extra_args,
        include_download=True,
    )


def run_module(user_args, session):
    args, _ = _parse_args(user_args)

    component_order = [key for key, _suffix, _help in COMPONENTS]
    selected = resolve_selected_components(args, component_order)

    resource_map = {
        "stacks": ResourceManagerStacksResource(session=session),
        "jobs": ResourceManagerJobsResource(session=session),
        "private_endpoints": ResourceManagerPrivateEndpointsResource(session=session),
        "config_source_providers": ResourceManagerConfigSourceProvidersResource(session=session),
        "templates": ResourceManagerTemplatesResource(session=session),
    }
    results = []
    for key, _method_suffix, _help_text in COMPONENTS:
        if not selected.get(key, False):
            continue
        try:
            if key == "templates":
                templates_resource = resource_map[key]
                template_id = str(getattr(args, "template_id", "") or "").strip()
                template_category_id = str(getattr(args, "template_category_id", "") or "").strip() or None
                compartment_id = getattr(session, "compartment_id", None)

                if not compartment_id and not template_id:
                    raise ValueError("session.compartment_id is not set (or provide --template-id)")

                if template_id:
                    row = templates_resource.get(resource_id=template_id) or {}
                    rows = [row] if row else []
                else:
                    rows = templates_resource.list(compartment_id=compartment_id, template_category_id=template_category_id) or []

                if isinstance(rows, dict):
                    rows = rows.get("items") or []
                rows = [row for row in rows if isinstance(row, dict)]

                if args.get:
                    for row in rows:
                        row_id = row.get("id")
                        if not row_id:
                            continue
                        meta = templates_resource.get(resource_id=row_id) or {}
                        fill_missing_fields(row, meta)

                downloaded = 0
                if args.download:
                    for row in rows:
                        template_row_id = row.get("id")
                        if not template_row_id:
                            continue
                        row_compartment_id = row.get("compartment_id") or compartment_id
                        if not row_compartment_id:
                            continue

                        base_subdirs = ["template-content", template_row_id]
                        tf_path = session.get_download_save_path(
                            service_name="resource-manager",
                            filename="template_tf_config.zip",
                            compartment_id=row_compartment_id,
                            subdirs=base_subdirs,
                        )
                        if templates_resource.download_tf_config(template_id=template_row_id, out_path=tf_path):
                            downloaded += 1

                        logo_path = session.get_download_save_path(
                            service_name="resource-manager",
                            filename="template_logo",
                            compartment_id=row_compartment_id,
                            subdirs=base_subdirs,
                        )
                        if templates_resource.download_logo(template_id=template_row_id, out_path=logo_path):
                            downloaded += 1

                if rows:
                    UtilityTools.print_limited_table(rows, templates_resource.COLUMNS)

                if args.save:
                    templates_resource.save(rows)

                results.append(
                    {
                        "ok": True,
                        "templates": len(rows),
                        "saved": bool(args.save),
                        "get": bool(args.get),
                        "download": bool(args.download),
                        "downloaded": int(downloaded),
                        "template_id": template_id,
                        "template_category_id": template_category_id or "",
                    }
                )
                continue

            compartment_id = getattr(session, "compartment_id", None)
            if not compartment_id:
                raise ValueError("session.compartment_id is not set")

            resource = resource_map[key]
            rows = resource.list(compartment_id=compartment_id) or []
            rows = [row for row in rows if isinstance(row, dict)]
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
                UtilityTools.print_limited_table(rows, resource.COLUMNS)

            if args.save:
                resource.save(rows)

            results.append({"ok": True, key: len(rows), "saved": bool(args.save), "get": bool(args.get)})
        except Exception as err:
            print(f"[*] enum_resourcemanager.{key}: skipped ({_component_error_summary(err)}).")
            results.append({"ok": False, "component": key, "error": _component_error_summary(err)})

    append_cached_component_counts(
        results=results,
        session=session,
        selected=selected,
        component_order=component_order,
        cache_tables=CACHE_TABLES,
    )

    return {"ok": True, "components": results}
