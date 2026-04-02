#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path

from ocinferno.modules.objectstorage.utilities.helpers import (
    ObjectStorageBucketsResource,
    ObjectStorageNamespacesResource,
    ObjectStorageObjectsResource,
)
from ocinferno.core.console import UtilityTools
from ocinferno.core.utils.module_helpers import fill_missing_fields, parse_csv_args, safe_path_component
from ocinferno.core.utils.service_runtime import (
    append_cached_component_counts,
    parse_wrapper_args,
    resolve_selected_components,
)


COMPONENTS = [
    ("namespaces", "namespaces", "Enumerate namespaces"),
    ("buckets", "buckets", "Enumerate buckets"),
    ("objects", "objects", "Enumerate objects"),
]


CACHE_TABLES = {
    "namespaces": ("object_storage_namespaces", "compartment_id"),
    "buckets": ("object_storage_buckets", "compartment_id"),
    "objects": ("object_storage_bucket_objects", "compartment_id"),
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
        parser.add_argument("--object-namespaces", action="append", default=[], help="Namespace scope for buckets/objects (repeatable, CSV supported)")
        parser.add_argument("--object-buckets", action="append", default=[], help="Bucket scope for objects (repeatable, CSV supported)")
        parser.add_argument("--limit", type=int, default=0, help="Limit matching objects per bucket (0 = no limit)")
        parser.add_argument("--threads", type=int, default=8, help="Download thread count (reserved)")
        parser.add_argument("--prefix", default="", help="Only include objects whose name starts with this prefix")
        parser.add_argument("--name-regex", default="", help="Only include objects whose name matches this regex")
        parser.add_argument("--min-bytes", type=int, default=0, help="Only include objects >= this size")
        parser.add_argument("--max-bytes", type=int, default=0, help="Only include objects <= this size")
        parser.add_argument("--newer-than", default="", help="Only include objects created on/after this ISO datetime")
        parser.add_argument("--older-than", default="", help="Only include objects created on/before this ISO datetime")
        parser.add_argument("--sse-c-key-b64", default=None, help="Base64-encoded AES-256 key for SSE-C objects")

    return parse_wrapper_args(
        user_args=user_args,
        description="Enumerate ObjectStorage resources",
        components=COMPONENTS,
        add_extra_args=_add_extra_args,
        include_download=True,
    )


def run_module(user_args, session):
    args, _ = _parse_args(user_args)

    component_order = [key for key, _suffix, _help in COMPONENTS]
    selected = resolve_selected_components(args, component_order)

    compartment_id = getattr(session, "compartment_id", None)
    if not compartment_id:
        raise ValueError(
            "session.compartment_id is not set.\n"
            "Select a compartment in the module runner (or run via module_actions prompt)."
        )

    namespaces_resource = ObjectStorageNamespacesResource(session=session)
    buckets_resource = ObjectStorageBucketsResource(session=session)
    objects_resource = ObjectStorageObjectsResource(session=session)

    results = []

    if selected.get("namespaces", False):
        try:
            rows = [r for r in (namespaces_resource.list(compartment_id=compartment_id) or []) if isinstance(r, dict)]

            if args.get:
                for row in rows:
                    namespace = row.get("namespace")
                    if not namespace:
                        continue
                    fill_missing_fields(row, namespaces_resource.get(resource_id=namespace) or {})

            if rows:
                UtilityTools.print_limited_table(rows, namespaces_resource.COLUMNS)
            if args.save:
                namespaces_resource.save(rows)

            results.append(
                {
                    "ok": True,
                    "namespaces": len(rows),
                    "saved": bool(args.save),
                    "get": bool(args.get),
                }
            )
        except Exception as err:
            print(f"[*] enum_objectstorage.namespaces: skipped ({_component_error_summary(err)}).")
            results.append(
                {
                    "ok": False,
                    "component": "namespaces",
                    "error": _component_error_summary(err),
                }
            )

    if selected.get("buckets", False):
        try:
            namespaces = buckets_resource.resolve_namespaces(namespace_args=getattr(args, "object_namespaces", []) or [])
            rows = [
                r
                for r in (
                    buckets_resource.list(
                        compartment_id=compartment_id,
                        namespaces=namespaces,
                    )
                    or []
                )
                if isinstance(r, dict)
            ]

            if args.get:
                for row in rows:
                    bucket_name = row.get("name")
                    namespace = row.get("namespace")
                    if not bucket_name or not namespace:
                        continue
                    fill_missing_fields(row, buckets_resource.get(resource_id=bucket_name, namespace=namespace) or {})

            if rows:
                UtilityTools.print_limited_table(rows, buckets_resource.COLUMNS)
            if args.save:
                buckets_resource.save(rows)

            results.append(
                {
                    "ok": True,
                    "buckets": len(rows),
                    "namespaces": len(namespaces),
                    "saved": bool(args.save),
                    "get": bool(args.get),
                }
            )
        except Exception as err:
            print(f"[*] enum_objectstorage.buckets: skipped ({_component_error_summary(err)}).")
            results.append(
                {
                    "ok": False,
                    "component": "buckets",
                    "error": _component_error_summary(err),
                }
            )

    if selected.get("objects", False):
        try:
            namespaces = parse_csv_args(getattr(args, "object_namespaces", []) or [])
            buckets = parse_csv_args(getattr(args, "object_buckets", []) or [])
            bucket_rows = objects_resource.resolve_bucket_rows(
                compartment_id=compartment_id,
                namespaces=namespaces,
                buckets=buckets,
            )

            rows = objects_resource.list(
                compartment_id=compartment_id,
                bucket_rows=bucket_rows,
                prefix=str(args.prefix or ""),
                name_regex=str(args.name_regex or ""),
                min_bytes=max(0, int(args.min_bytes or 0)),
                max_bytes=max(0, int(args.max_bytes or 0)),
                newer_than=str(args.newer_than or ""),
                older_than=str(args.older_than or ""),
                limit_per_bucket=max(0, int(args.limit or 0)),
            )

            if args.get:
                for row in rows:
                    namespace = row.get("namespace")
                    bucket_name = row.get("bucket_name")
                    object_name = row.get("name")
                    if not namespace or not bucket_name or not object_name:
                        continue
                    fill_missing_fields(
                        row,
                        objects_resource.get(namespace=namespace, bucket_name=bucket_name, object_name=object_name) or {},
                    )

            if rows:
                UtilityTools.print_limited_table(rows, objects_resource.COLUMNS)
            if args.save:
                objects_resource.save(rows)

            downloaded = 0
            failed = 0
            if args.download and rows:
                root = session.get_workspace_output_root(mkdir=True)
                comp_part = safe_path_component(str(compartment_id))

                for row in rows:
                    namespace = str(row.get("namespace") or "").strip()
                    bucket_name = str(row.get("bucket_name") or "").strip()
                    object_name = str(row.get("name") or "").strip()
                    region = str(row.get("region") or getattr(session, "region", "") or "").strip()
                    if not namespace or not bucket_name or not object_name:
                        continue

                    object_parts = [safe_path_component(p) for p in object_name.lstrip("/").split("/") if p]
                    if not object_parts:
                        object_parts = ["object.bin"]

                    base = (
                        root
                        / session.OUTPUT_DIR_NAMES["downloads"]
                        / safe_path_component("objectstorage")
                        / comp_part
                        / safe_path_component(namespace)
                        / safe_path_component(bucket_name)
                    )
                    if len(object_parts) > 1:
                        base = base.joinpath(*object_parts[:-1])
                    base.mkdir(parents=True, exist_ok=True)
                    out_path = Path(base) / object_parts[-1]

                    ok = objects_resource.download(
                        namespace=namespace,
                        bucket_name=bucket_name,
                        object_name=object_name,
                        out_path=out_path,
                        sse_c_key_b64=args.sse_c_key_b64,
                        region=region,
                    )
                    if ok:
                        downloaded += 1
                    else:
                        failed += 1

            results.append(
                {
                    "ok": True,
                    "cid": compartment_id,
                    "buckets_processed": len({(str(r.get('region') or ''), str(r.get('namespace') or ''), str(r.get('bucket_name') or '')) for r in rows}),
                    "objects": len(rows),
                    "saved": bool(args.save),
                    "download": bool(args.download),
                    "files_downloaded": downloaded,
                    "download_failed": failed,
                }
            )
        except Exception as err:
            print(f"[*] enum_objectstorage.objects: skipped ({_component_error_summary(err)}).")
            results.append(
                {
                    "ok": False,
                    "component": "objects",
                    "error": _component_error_summary(err),
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
