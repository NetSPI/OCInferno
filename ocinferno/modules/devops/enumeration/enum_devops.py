#!/usr/bin/env python3
from __future__ import annotations

import oci
from ocinferno.core.console import UtilityTools
from ocinferno.core.utils.module_helpers import fill_missing_fields, unique_rows_by_id
from ocinferno.modules.devops.utilities.helpers import (
    DevOpsBuildPipelinesResource,
    DevOpsConnectionsResource,
    DevOpsDeployPipelinesResource,
    DevOpsProjectsResource,
    DevOpsRepositoriesResource,
)
from ocinferno.core.utils.service_runtime import (
    append_cached_component_counts,
    parse_wrapper_args,
    resolve_selected_components,
)


COMPONENTS = [
    ("projects", "projects", "Enumerate projects"),
    ("connections", "connections", "Enumerate connections"),
    ("repositories", "repositories", "Enumerate repositories"),
    ("build_pipelines", "build_pipelines", "Enumerate build-pipelines"),
    ("deploy_pipelines", "deploy_pipelines", "Enumerate deploy-pipelines"),
]


CACHE_TABLES = {
    "projects": ("devops_projects", "compartment_id"),
    "connections": ("devops_connections", "compartment_id"),
    "repositories": ("devops_repositories", "compartment_id"),
    "build_pipelines": ("devops_build_pipelines", "compartment_id"),
    "deploy_pipelines": ("devops_deploy_pipelines", "compartment_id"),
}


def _parse_args(user_args):
    def _add_extra_args(parser):
        parser.add_argument("--project-id", dest="project_id", default="", help="Only enumerate deploy pipelines for this DevOps Project OCID")

    return parse_wrapper_args(
        user_args=user_args,
        description="Enumerate DevOps resources",
        components=COMPONENTS,
        add_extra_args=_add_extra_args,
    )


def run_module(user_args, session):
    args, _ = _parse_args(user_args)
    debug = bool(getattr(session, "individual_run_debug", False) or getattr(session, "debug", False))

    component_order = [key for key, _suffix, _help in COMPONENTS]
    selected = resolve_selected_components(args, component_order)

    resource_map = {
        "projects": DevOpsProjectsResource(session=session),
        "connections": DevOpsConnectionsResource(session=session),
        "repositories": DevOpsRepositoriesResource(session=session),
        "build_pipelines": DevOpsBuildPipelinesResource(session=session),
        "deploy_pipelines": DevOpsDeployPipelinesResource(session=session),
    }
    results = []
    for key, _method_suffix, _help_text in COMPONENTS:
        if not selected.get(key, False):
            continue
        if key == "deploy_pipelines":
            deploy_resource = resource_map[key]
            compartment_id = getattr(session, "compartment_id", None)
            if not compartment_id:
                raise ValueError("session.compartment_id is not set")

            project_id = str(getattr(args, "project_id", "") or "").strip()
            if project_id:
                project_ids = [project_id]
            else:
                try:
                    projects = deploy_resource.list_projects(compartment_id=compartment_id) or []
                except oci.exceptions.ServiceError as err:
                    UtilityTools.dlog(
                        True,
                        "list_projects failed (needed for deploy pipelines)",
                        status=getattr(err, "status", None),
                        code=getattr(err, "code", None),
                        msg=getattr(err, "message", str(err)),
                    )
                    projects = []
                project_ids = [row.get("id") for row in projects if isinstance(row, dict) and row.get("id")]

            if not project_ids:
                results.append({"ok": True, "deploy_pipelines": 0, "saved": False, "get": bool(args.get), "projects": 0})
                continue

            rows = []
            for pid in project_ids:
                try:
                    listed = deploy_resource.list(compartment_id=compartment_id, project_id=pid) or []
                except oci.exceptions.ServiceError as err:
                    UtilityTools.dlog(
                        True,
                        "list_deploy_pipelines failed",
                        project_id=pid,
                        status=getattr(err, "status", None),
                        code=getattr(err, "code", None),
                        msg=getattr(err, "message", str(err)),
                    )
                    continue
                for row in listed:
                    if not isinstance(row, dict):
                        continue
                    row.setdefault("project_id", pid)
                    row.setdefault("compartment_id", compartment_id)
                    rows.append(row)

            rows = unique_rows_by_id(rows)

            if args.get:
                for row in rows:
                    resource_id = row.get("id")
                    if not resource_id:
                        continue
                    try:
                        meta = deploy_resource.get(resource_id=resource_id) or {}
                    except Exception as err:
                        UtilityTools.dlog(debug, "get_deploy_pipeline failed", resource_id=resource_id, err=f"{type(err).__name__}: {err}")
                        continue
                    fill_missing_fields(row, meta)

            if rows:
                UtilityTools.print_limited_table(rows, deploy_resource.COLUMNS)

            if args.save:
                deploy_resource.save(rows)

            results.append(
                {
                    "ok": True,
                    "projects": len(project_ids),
                    "deploy_pipelines": len(rows),
                    "saved": bool(args.save),
                    "get": bool(args.get),
                }
            )
            continue

        compartment_id = getattr(session, "compartment_id", None)
        if not compartment_id:
            raise ValueError("session.compartment_id is not set")

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
