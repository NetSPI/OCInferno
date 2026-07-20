#!/usr/bin/env python3
from __future__ import annotations

import argparse

from ocinferno.core.console import UtilityTools
from ocinferno.core.utils.download_budget import DownloadBudget
from ocinferno.core.utils.enum_framework import nested_list_fn
from ocinferno.core.utils.module_helpers import fill_missing_fields, unique_rows_by_id
from ocinferno.modules.artifactregistry.utilities.helpers import (
    ArtifactRegistryArtifactsResource,
    ArtifactRegistryRepositoriesResource,
)
from ocinferno.core.utils.service_runtime import (
    append_cached_component_counts,
    parse_wrapper_args,
    resolve_selected_components,
    run_standard_enum_component,
)


COMPONENTS = [
    ("repositories", "repositories", "Enumerate repositories"),
    ("artifacts", "artifacts", "Enumerate artifacts"),
]


CACHE_TABLES = {
    "repositories": ("ar_repositories", "compartment_id"),
    "artifacts": ("ar_generic_artifact", "compartment_id"),
}


from ocinferno.core.utils.service_runtime import component_soft_skip_or_error


def _parse_args(user_args):
    def _add_extra_args(parser: argparse.ArgumentParser) -> None:
        parser.add_argument("--repo-id", default="", help="Only enumerate artifacts in this repository OCID")
        parser.add_argument("--path", default="", help="Only include artifacts matching this artifact_path")
        mode_group = parser.add_mutually_exclusive_group()
        mode_group.add_argument("--all", action="store_true", help="Download all versions")
        mode_group.add_argument("--latest", action="store_true", help="Download latest version per artifact path")
        parser.add_argument("--out-dir", default="", help="Override download output directory")
        parser.add_argument("--download-timeout", type=int, default=0, help="Per-download-type wall-clock cap in seconds (0 = unlimited)")

    return parse_wrapper_args(
        user_args=user_args,
        description="Enumerate Artifact Registry resources",
        components=COMPONENTS,
        add_extra_args=_add_extra_args,
        include_download=True,
    )


def run_module(user_args, session):
    args, _ = _parse_args(user_args)
    compartment_id = getattr(session, "compartment_id", None)

    session.download_time_budget = int(getattr(args, "download_timeout", 0) or 0)

    component_order = [key for key, _suffix, _help in COMPONENTS]
    selected = resolve_selected_components(args, component_order)

    results = []

    repositories_resource = ArtifactRegistryRepositoriesResource(session=session)
    artifacts_resource = ArtifactRegistryArtifactsResource(session=session)

    if selected.get("repositories", False):
        results.append(run_standard_enum_component(
            user_args=args, session=session, component_key="repositories",
            list_rows=lambda cid: repositories_resource.list(compartment_id=cid),
            get_row=lambda row: repositories_resource.get(resource_id=row.get("id")),
            save_rows_fn=repositories_resource.save,
            print_columns=repositories_resource.COLUMNS,
            module_name="enum_artifactregistry",
        ))
    if selected.get("artifacts", False):
        try:
            if not compartment_id:
                raise ValueError("session.compartment_id is not set")

            if args.repo_id:
                repository_ids = [args.repo_id]
            else:
                repositories = artifacts_resource.list_repositories(compartment_id=compartment_id) or []
                repository_ids = [row.get("id") for row in repositories if isinstance(row, dict) and row.get("id")]

            wanted_path = (args.path or "").strip()
            # repository_ids already resolved above (manual --repo-id or a live list); reuse it
            # via manual_parent_ids so nested_list_fn only does the fan-out + stamp.
            list_rows = nested_list_fn(
                parent_resource_cls=ArtifactRegistryRepositoriesResource,
                parent_id_field="repository_id",
                manual_parent_ids=repository_ids,
                child_takes_compartment=True,
            )(session, args, artifacts_resource)
            rows = list_rows(compartment_id)
            if wanted_path:
                rows = [row for row in rows if (row.get("artifact_path") or "") == wanted_path]

            rows = unique_rows_by_id(rows)

            if args.get:
                for row in rows:
                    artifact_id = row.get("id")
                    if not artifact_id:
                        continue
                    meta = artifacts_resource.get(resource_id=artifact_id) or {}
                    fill_missing_fields(row, meta)

            if rows:
                UtilityTools.print_limited_table(rows, artifacts_resource.COLUMNS)

            downloaded = 0
            failed = 0
            if args.download:
                targets = rows if args.all else artifacts_resource.pick_latest_per_path(rows)
                budget = DownloadBudget(session, label="artifact registry artifacts")
                for row in targets:
                    if budget.exceeded():  # per-type --download-timeout cap: stop and move on
                        break
                    repository_id = row.get("repository_id") or ""
                    artifact_path = row.get("artifact_path") or ""
                    version = row.get("version") or ""
                    artifact_id = row.get("id") or ""

                    if args.out_dir:
                        out_file = artifacts_resource.out_path(args.out_dir, repository_id or "repo", artifact_path or "artifact", version or "version")
                    else:
                        out_file = artifacts_resource.out_path_via_session(
                            session,
                            repository_id or "repo",
                            artifact_path or "artifact",
                            version or "version",
                            row.get("compartment_id") or compartment_id,
                        )

                    ok = False
                    if repository_id and artifact_path and version:
                        ok = artifacts_resource.download_by_path(
                            repository_id=repository_id,
                            artifact_path=artifact_path,
                            version=version,
                            out_file=out_file,
                        )
                    elif artifact_id:
                        ok = artifacts_resource.download_by_id(artifact_id=artifact_id, out_file=out_file)

                    if ok:
                        downloaded += 1
                    else:
                        failed += 1

            artifacts_resource.save(rows)

            results.append(
                {
                    "ok": True,
                    "repos": len(repository_ids),
                    "artifacts": len(rows),
                    "saved": True,
                    "get": bool(args.get),
                    "download": bool(args.download),
                    "all": bool(args.all),
                    "latest": bool(args.download and not args.all),
                    "path": wanted_path,
                    "downloaded": downloaded,
                    "failed": failed,
                    "out_dir": args.out_dir or "session-managed",
                    "repo_id": args.repo_id or "",
                }
            )
        except Exception as err:
            results.append(component_soft_skip_or_error(err, component="artifacts", module_name="enum_artifactregistry"))

    append_cached_component_counts(
        results=results,
        session=session,
        selected=selected,
        component_order=component_order,
        cache_tables=CACHE_TABLES,
    )

    return {"ok": True, "components": results}
