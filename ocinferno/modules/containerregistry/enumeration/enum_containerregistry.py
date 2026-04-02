#!/usr/bin/env python3
from __future__ import annotations

import argparse

import oci
from ocinferno.core.console import UtilityTools
from ocinferno.core.utils.module_helpers import fill_missing_fields
from ocinferno.modules.containerregistry.utilities.helpers import (
    ContainerRegistryImagesResource,
    ContainerRegistryRepositoriesResource,
)
from ocinferno.core.utils.service_runtime import (
    append_cached_component_counts,
    parse_wrapper_args,
    resolve_selected_components,
)


COMPONENTS = [
    ("repositories", "repositories", "Enumerate container repositories"),
    ("images", "images", "Enumerate container images"),
]


CACHE_TABLES = {
    "repositories": ("cr_repositories", "compartment_id"),
    "images": ("cr_images", "compartment_id"),
}


def _parse_args(user_args):
    def _add_extra_args(parser: argparse.ArgumentParser) -> None:
        parser.add_argument("--repo-id", default="", help="Only enumerate images in this container repository OCID")

    return parse_wrapper_args(
        user_args=user_args,
        description="Enumerate Container Registry resources",
        components=COMPONENTS,
        add_extra_args=_add_extra_args,
    )


def run_module(user_args, session):
    args, _ = _parse_args(user_args)
    debug = bool(getattr(session, "individual_run_debug", False) or getattr(session, "debug", False))

    component_order = [key for key, _suffix, _help in COMPONENTS]
    selected = resolve_selected_components(args, component_order)
    results = []

    repositories_resource = ContainerRegistryRepositoriesResource(session=session)
    images_resource = ContainerRegistryImagesResource(session=session)

    if selected.get("repositories", False):
        compartment_id = getattr(session, "compartment_id", None)
        if not compartment_id:
            raise ValueError("session.compartment_id is not set")
        try:
            rows = repositories_resource.list(compartment_id=compartment_id) or []
        except oci.exceptions.ServiceError as err:
            UtilityTools.dlog(True, "list_container_repositories failed", status=getattr(err, "status", None), code=getattr(err, "code", None), msg=str(err))
            results.append({"ok": False, "repositories": 0})
        else:
            rows = [row for row in rows if isinstance(row, dict)]
            for row in rows:
                row.setdefault("compartment_id", compartment_id)

            if args.get:
                for row in rows:
                    repo_id = row.get("id")
                    if not repo_id:
                        continue
                    try:
                        meta = repositories_resource.get(resource_id=repo_id) or {}
                    except Exception as err:
                        UtilityTools.dlog(debug, "get_container_repository failed", repository_id=repo_id, err=f"{type(err).__name__}: {err}")
                        continue
                    fill_missing_fields(row, meta)

            if rows:
                UtilityTools.print_limited_table(rows, repositories_resource.COLUMNS)
            if args.save:
                repositories_resource.save(rows)

            results.append({"ok": True, "repositories": len(rows), "saved": bool(args.save), "get": bool(args.get)})
    if selected.get("images", False):
        compartment_id = getattr(session, "compartment_id", None)
        if not compartment_id:
            raise ValueError("session.compartment_id is not set")

        repo_id = (args.repo_id or "").strip()
        if repo_id:
            repository_ids = [repo_id]
        else:
            repository_ids = []
            try:
                repos = images_resource.list_repositories(compartment_id=compartment_id) or []
            except oci.exceptions.ServiceError as err:
                UtilityTools.dlog(
                    True,
                    "list_container_repositories failed",
                    status=getattr(err, "status", None),
                    code=getattr(err, "code", None),
                    msg=str(err),
                )
                results.append({"ok": False, "images": 0})
            else:
                repository_ids = [row.get("id") for row in repos if isinstance(row, dict) and row.get("id")]

        if repo_id or repository_ids:
            rows = []
            for repository_id in repository_ids:
                try:
                    listed = images_resource.list(compartment_id=compartment_id, repository_id=repository_id) or []
                except Exception as err:
                    UtilityTools.dlog(debug, "list_container_images failed", repository_id=repository_id, err=f"{type(err).__name__}: {err}")
                    continue
                for row in listed:
                    if not isinstance(row, dict):
                        continue
                    row.setdefault("repository_id", repository_id)
                    row.setdefault("compartment_id", compartment_id)
                    rows.append(row)

            if args.get:
                for row in rows:
                    image_id = row.get("id")
                    if not image_id:
                        continue
                    try:
                        meta = images_resource.get(resource_id=image_id) or {}
                    except Exception as err:
                        UtilityTools.dlog(debug, "get_container_image failed", image_id=image_id, err=f"{type(err).__name__}: {err}")
                        continue
                    fill_missing_fields(row, meta)

            if rows:
                UtilityTools.print_limited_table(rows, images_resource.COLUMNS)
            if args.save:
                images_resource.save(rows)

            results.append(
                {
                    "ok": True,
                    "repos": len(repository_ids),
                    "images": len(rows),
                    "saved": bool(args.save),
                    "get": bool(args.get),
                    "repo_id": repo_id,
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
