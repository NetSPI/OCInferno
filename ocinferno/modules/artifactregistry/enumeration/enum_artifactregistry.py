#!/usr/bin/env python3
from __future__ import annotations

import argparse

from ocinferno.core.console import UtilityTools
from ocinferno.core.utils.module_helpers import fill_missing_fields, unique_rows_by_id
from ocinferno.modules.artifactregistry.utilities.helpers import (
    ArtifactRegistryArtifactsResource,
    ArtifactRegistryRepositoriesResource,
)
from ocinferno.core.utils.service_runtime import (
    append_cached_component_counts,
    parse_wrapper_args,
    resolve_selected_components,
)


COMPONENTS = [
    ("repositories", "repositories", "Enumerate repositories"),
    ("artifacts", "artifacts", "Enumerate artifacts"),
]


CACHE_TABLES = {
    "repositories": ("ar_repositories", "compartment_id"),
    "artifacts": ("ar_generic_artifact", "compartment_id"),
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
        parser.add_argument("--repo-id", default="", help="Only enumerate artifacts in this repository OCID")
        parser.add_argument("--path", default="", help="Only include artifacts matching this artifact_path")
        mode_group = parser.add_mutually_exclusive_group()
        mode_group.add_argument("--all", action="store_true", help="Download all versions")
        mode_group.add_argument("--latest", action="store_true", help="Download latest version per artifact path")
        parser.add_argument("--out-dir", default="", help="Override download output directory")

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

    component_order = [key for key, _suffix, _help in COMPONENTS]
    selected = resolve_selected_components(args, component_order)

    results = []

    repositories_resource = ArtifactRegistryRepositoriesResource(session=session)
    artifacts_resource = ArtifactRegistryArtifactsResource(session=session)

    if selected.get("repositories", False):
        try:
            if not compartment_id:
                raise ValueError("session.compartment_id is not set")
            rows = repositories_resource.list(compartment_id=compartment_id) or []
            rows = unique_rows_by_id([row for row in rows if isinstance(row, dict)])
            for row in rows:
                row.setdefault("compartment_id", compartment_id)

            if args.get:
                for row in rows:
                    repository_id = row.get("id")
                    if not repository_id:
                        continue
                    meta = repositories_resource.get(resource_id=repository_id) or {}
                    fill_missing_fields(row, meta)

            if rows:
                UtilityTools.print_limited_table(rows, repositories_resource.COLUMNS)

            if args.save:
                repositories_resource.save(rows)

            results.append({"ok": True, "repositories": len(rows), "saved": bool(args.save), "get": bool(args.get)})
        except Exception as err:
            print(f"[*] enum_artifactregistry.repositories: skipped ({_component_error_summary(err)}).")
            results.append({"ok": False, "component": "repositories", "error": _component_error_summary(err)})
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
            rows = []
            for repository_id in repository_ids:
                listed = artifacts_resource.list(compartment_id=compartment_id, repository_id=repository_id) or []
                for row in listed:
                    if not isinstance(row, dict):
                        continue
                    row.setdefault("repository_id", repository_id)
                    row.setdefault("compartment_id", compartment_id)
                    if wanted_path and (row.get("artifact_path") or "") != wanted_path:
                        continue
                    rows.append(row)

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
                for row in targets:
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

            if args.save:
                artifacts_resource.save(rows)

            results.append(
                {
                    "ok": True,
                    "repos": len(repository_ids),
                    "artifacts": len(rows),
                    "saved": bool(args.save),
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
            print(f"[*] enum_artifactregistry.artifacts: skipped ({_component_error_summary(err)}).")
            results.append({"ok": False, "component": "artifacts", "error": _component_error_summary(err)})

    append_cached_component_counts(
        results=results,
        session=session,
        selected=selected,
        component_order=component_order,
        cache_tables=CACHE_TABLES,
    )

    return {"ok": True, "components": results}
