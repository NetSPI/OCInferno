#!/usr/bin/env python3
from __future__ import annotations

import argparse
from typing import Any, Dict

import oci
from ocinferno.core.console import UtilityTools
from ocinferno.modules.core.utilities.blockstorage_helpers import (
    BlockBootVolumeBackupsResource,
    BlockBootVolumesResource,
    BlockStorageResourceClient,
    BlockVolumeBackupsResource,
    BlockVolumesResource,
)
from ocinferno.core.utils.module_helpers import fill_missing_fields, cached_table_count, resolve_component_flags


def _parse_args(user_args):
    parser = argparse.ArgumentParser(description="Enumerate OCI Core Block Storage Resources", allow_abbrev=False)
    parser.add_argument("--volumes", action="store_true", help="Enumerate block volumes")
    parser.add_argument("--boot-volumes", dest="boot_volumes", action="store_true", help="Enumerate boot volumes")
    parser.add_argument("--volume-backups", dest="volume_backups", action="store_true", help="Enumerate volume backups")
    parser.add_argument("--boot-volume-backups", dest="boot_volume_backups", action="store_true", help="Enumerate boot volume backups")
    parser.add_argument("--availability-domain", default="", help="Availability domain (used for boot volumes)")
    # --get/--save are runner-level common flags; parse module-specific args only.
    args, _ = parser.parse_known_args(list(user_args))
    raw_args = {str(x) for x in (list(user_args) if user_args is not None else [])}
    args.get = "--get" in raw_args
    args.save = "--save" in raw_args
    return args


def run_module(user_args, session) -> Dict[str, Any]:
    args = _parse_args(user_args)
    debug = bool(getattr(session, "debug", False) or getattr(session, "individual_run_debug", False))

    comp_id = getattr(session, "compartment_id", None)
    if not comp_id:
        raise ValueError("session.compartment_id is not set. Select a compartment first.")

    flags = resolve_component_flags(args, ["volumes", "boot_volumes", "volume_backups", "boot_volume_backups"])
    ops = BlockStorageResourceClient(session=session)
    summary: Dict[str, int] = {}
    availability_domain = (args.availability_domain or "").strip() or None

    component_specs = [
        {
            "key": "volumes",
            "resource": BlockVolumesResource(ops),
            "list_kwargs": {},
            "cache_table": "blockstorage_volumes",
        },
        {
            "key": "boot_volumes",
            "resource": BlockBootVolumesResource(ops),
            "list_kwargs": {"availability_domain": availability_domain},
            "cache_table": "blockstorage_boot_volumes",
        },
        {
            "key": "volume_backups",
            "resource": BlockVolumeBackupsResource(ops),
            "list_kwargs": {},
            "cache_table": "blockstorage_volume_backups",
        },
        {
            "key": "boot_volume_backups",
            "resource": BlockBootVolumeBackupsResource(ops),
            "list_kwargs": {},
            "cache_table": "blockstorage_boot_volume_backups",
        },
    ]

    # Resource loop: volumes, boot volumes, and backup families.
    for spec in component_specs:
        key = spec["key"]
        resource = spec["resource"]
        cache_table = spec["cache_table"]
        list_kwargs = dict(spec["list_kwargs"])

        if not flags.get(key, False):
            summary[key] = cached_table_count(
                session,
                table_name=cache_table,
                compartment_id=comp_id,
                compartment_field="compartment_id",
            ) or 0
            continue

        try:
            rows = resource.list(compartment_id=comp_id, **list_kwargs) or []
        except oci.exceptions.ServiceError as e:
            UtilityTools.dlog(True, f"list_{key} failed", status=getattr(e, "status", None), code=getattr(e, "code", None))
            rows = []
        except Exception as e:
            UtilityTools.dlog(True, f"list_{key} failed", err=f"{type(e).__name__}: {e}")
            rows = []

        if rows and args.get:
            for row in UtilityTools.progress_iter(rows, label=f"GET {key}"):
                rid = (row or {}).get("id")
                if not rid:
                    continue
                try:
                    meta = resource.get(resource_id=rid) or {}
                except Exception as e:
                    UtilityTools.dlog(debug, f"get_{key} failed", resource_id=rid, err=f"{type(e).__name__}: {e}")
                    continue
                if isinstance(meta, dict):
                    meta["get_run"] = True
                    fill_missing_fields(row, meta)

        if rows:
            UtilityTools.print_limited_table(rows, resource.COLUMNS)
            if args.save:
                resource.save(rows)

        summary[key] = len(rows)

    return {"ok": True, **summary}
