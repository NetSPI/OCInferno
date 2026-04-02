#!/usr/bin/env python3
from __future__ import annotations

import argparse

from ocinferno.modules.filestorage.utilities.helpers import (
    FileStorageExportSetsResource,
    FileStorageExportsResource,
    FileStorageFileSystemsResource,
    FileStorageMountTargetsResource,
    FileStorageSnapshotsResource,
)
from ocinferno.core.console import UtilityTools
from ocinferno.core.utils.module_helpers import fill_missing_fields
from ocinferno.core.utils.service_runtime import (
    append_cached_component_counts,
    parse_wrapper_args,
    resolve_selected_components,
)


COMPONENTS = [
    ("file_systems", "file_systems", "Enumerate file-systems"),
    ("mount_targets", "mount_targets", "Enumerate mount-targets"),
    ("export_sets", "export_sets", "Enumerate export-sets"),
    ("exports", "exports", "Enumerate exports"),
    ("snapshots", "snapshots", "Enumerate snapshots"),
]


CACHE_TABLES = {
    "file_systems": ("file_storage_file_systems", "compartment_id"),
    "mount_targets": ("file_storage_mount_targets", "compartment_id"),
    "export_sets": ("file_storage_export_sets", "compartment_id"),
    "exports": ("file_storage_exports", "compartment_id"),
    "snapshots": ("file_storage_snapshots", "compartment_id"),
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
        parser.add_argument("--limit", type=int, default=0, help="Limit results (0 = no limit)")
        parser.add_argument("--debug", action="store_true", help="Debug logging")
        parser.add_argument("--export-set-id", dest="export_set_id", default="", help="Only enumerate exports for this Export Set OCID")
        parser.add_argument("--file-system-id", dest="file_system_id", default="", help="Only enumerate snapshots for this File System OCID")

    return parse_wrapper_args(
        user_args=user_args,
        description="Enumerate File Storage resources",
        components=COMPONENTS,
        add_extra_args=_add_extra_args,
    )


def run_module(user_args, session):
    args, _ = _parse_args(user_args)

    component_order = [key for key, _suffix, _help in COMPONENTS]
    selected = resolve_selected_components(args, component_order)

    compartment_id = getattr(session, "compartment_id", None)
    if not compartment_id:
        raise ValueError("session.compartment_id is not set. Select a compartment in the module runner.")

    region = (getattr(session, "region", "") or "").strip()

    fs_resource = FileStorageFileSystemsResource(session=session)
    mt_resource = FileStorageMountTargetsResource(session=session)
    es_resource = FileStorageExportSetsResource(session=session)
    ex_resource = FileStorageExportsResource(session=session)
    snap_resource = FileStorageSnapshotsResource(session=session)

    availability_domains = fs_resource.list_availability_domains()

    results = []

    if selected.get("file_systems", False):
        try:
            rows = fs_resource.list(
                compartment_id=compartment_id,
                availability_domains=availability_domains,
                limit=max(0, int(args.limit or 0)),
                region=region,
            )

            if args.get:
                for row in rows:
                    rid = row.get("id")
                    if not rid:
                        continue
                    fill_missing_fields(row, fs_resource.get(resource_id=rid) or {})

            if rows:
                UtilityTools.print_limited_table(rows, fs_resource.COLUMNS)
            if args.save:
                fs_resource.save(rows)

            results.append(
                {
                    "ok": True,
                    "cid": compartment_id,
                    "file_systems": len(rows),
                    "saved": bool(args.save),
                    "get": bool(args.get),
                }
            )
        except Exception as err:
            print(f"[*] enum_filestorage.file_systems: skipped ({_component_error_summary(err)}).")
            results.append({"ok": False, "component": "file_systems", "error": _component_error_summary(err)})

    if selected.get("mount_targets", False):
        try:
            rows = mt_resource.list(
                compartment_id=compartment_id,
                availability_domains=availability_domains,
                limit=max(0, int(args.limit or 0)),
                region=region,
            )

            if args.get:
                for row in rows:
                    rid = row.get("id")
                    if not rid:
                        continue
                    fill_missing_fields(row, mt_resource.get(resource_id=rid) or {})

            if rows:
                UtilityTools.print_limited_table(rows, mt_resource.COLUMNS)
            if args.save:
                mt_resource.save(rows)

            results.append(
                {
                    "ok": True,
                    "cid": compartment_id,
                    "mount_targets": len(rows),
                    "saved": bool(args.save),
                    "get": bool(args.get),
                }
            )
        except Exception as err:
            print(f"[*] enum_filestorage.mount_targets: skipped ({_component_error_summary(err)}).")
            results.append({"ok": False, "component": "mount_targets", "error": _component_error_summary(err)})

    if selected.get("export_sets", False):
        try:
            rows = es_resource.list(
                compartment_id=compartment_id,
                availability_domains=availability_domains,
                limit=max(0, int(args.limit or 0)),
                region=region,
            )

            if args.get:
                for row in rows:
                    rid = row.get("id")
                    if not rid:
                        continue
                    fill_missing_fields(row, es_resource.get(resource_id=rid) or {})

            if rows:
                UtilityTools.print_limited_table(rows, es_resource.COLUMNS)
            if args.save:
                es_resource.save(rows)

            results.append(
                {
                    "ok": True,
                    "cid": compartment_id,
                    "export_sets": len(rows),
                    "saved": bool(args.save),
                    "get": bool(args.get),
                }
            )
        except Exception as err:
            print(f"[*] enum_filestorage.export_sets: skipped ({_component_error_summary(err)}).")
            results.append({"ok": False, "component": "export_sets", "error": _component_error_summary(err)})

    if selected.get("exports", False):
        try:
            resolved_export_sets = ex_resource.resolve_export_sets(
                compartment_id=compartment_id,
                availability_domains=availability_domains,
                export_set_id=str(args.export_set_id or "").strip(),
                region=region,
            )
            if isinstance(resolved_export_sets, tuple) and len(resolved_export_sets) == 2:
                export_set_ids, export_set_meta = resolved_export_sets
            else:
                export_set_ids, export_set_meta = [], {}
            rows = ex_resource.list(
                compartment_id=compartment_id,
                export_set_ids=export_set_ids,
                export_set_meta=export_set_meta,
                limit=max(0, int(args.limit or 0)),
                region=region,
            )

            if args.get:
                for row in rows:
                    rid = row.get("id")
                    if not rid:
                        continue
                    fill_missing_fields(row, ex_resource.get(resource_id=rid) or {})

            if rows:
                UtilityTools.print_limited_table(rows, ex_resource.COLUMNS)
            if args.save:
                ex_resource.save(rows)

            results.append(
                {
                    "ok": True,
                    "cid": compartment_id,
                    "exports": len(rows),
                    "export_sets": len(export_set_ids),
                    "saved": bool(args.save),
                    "get": bool(args.get),
                }
            )
        except Exception as err:
            print(f"[*] enum_filestorage.exports: skipped ({_component_error_summary(err)}).")
            results.append({"ok": False, "component": "exports", "error": _component_error_summary(err)})

    if selected.get("snapshots", False):
        try:
            resolved_file_systems = snap_resource.resolve_file_systems(
                compartment_id=compartment_id,
                availability_domains=availability_domains,
                file_system_id=str(args.file_system_id or "").strip(),
                region=region,
            )
            if isinstance(resolved_file_systems, tuple) and len(resolved_file_systems) == 2:
                file_system_ids, file_system_meta = resolved_file_systems
            else:
                file_system_ids, file_system_meta = [], {}
            rows = snap_resource.list(
                compartment_id=compartment_id,
                file_system_ids=file_system_ids,
                file_system_meta=file_system_meta,
                limit=max(0, int(args.limit or 0)),
                region=region,
            )

            if args.get:
                for row in rows:
                    rid = row.get("id")
                    if not rid:
                        continue
                    fill_missing_fields(row, snap_resource.get(resource_id=rid) or {})

            if rows:
                UtilityTools.print_limited_table(rows, snap_resource.COLUMNS)
            if args.save:
                snap_resource.save(rows)

            results.append(
                {
                    "ok": True,
                    "cid": compartment_id,
                    "snapshots": len(rows),
                    "file_systems": len(file_system_ids),
                    "saved": bool(args.save),
                    "get": bool(args.get),
                }
            )
        except Exception as err:
            print(f"[*] enum_filestorage.snapshots: skipped ({_component_error_summary(err)}).")
            results.append({"ok": False, "component": "snapshots", "error": _component_error_summary(err)})

    append_cached_component_counts(
        results=results,
        session=session,
        selected=selected,
        component_order=component_order,
        cache_tables=CACHE_TABLES,
    )

    return {"ok": True, "components": results}
