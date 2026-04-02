#!/usr/bin/env python3
from __future__ import annotations

import argparse

from ocinferno.core.console import UtilityTools
from ocinferno.core.utils.module_helpers import dedupe_strs, fill_missing_fields, ids_from_db, parse_csv_args, unique_rows_by_id
from ocinferno.modules.blockchain.utilities.helpers import (
    BlockchainOsnsResource,
    BlockchainPatchesResource,
    BlockchainPeersResource,
    BlockchainPlatformsResource,
    BlockchainWorkRequestsResource,
)
from ocinferno.core.utils.service_runtime import (
    append_cached_component_counts,
    parse_wrapper_args,
    resolve_selected_components,
)


COMPONENTS = [
    ("platforms", "platforms", "Enumerate blockchain platforms"),
    ("peers", "peers", "Enumerate blockchain peers"),
    ("osns", "osns", "Enumerate blockchain orderer service nodes"),
    ("patches", "patches", "Enumerate blockchain platform patches"),
    ("work_requests", "work_requests", "Enumerate blockchain work requests"),
]


CACHE_TABLES = {
    "platforms": ("blockchain_platforms", "compartment_id"),
    "peers": ("blockchain_peers", "compartment_id"),
    "osns": ("blockchain_osns", "compartment_id"),
    "patches": ("blockchain_platform_patches", "compartment_id"),
    "work_requests": ("blockchain_work_requests", "compartment_id"),
}


def _parse_args(user_args):
    def _add_extra_args(parser: argparse.ArgumentParser) -> None:
        parser.add_argument(
            "--platform-ids",
            action="append",
            default=[],
            help="Blockchain platform OCID scope (repeatable, CSV supported)",
        )

    return parse_wrapper_args(
        user_args=user_args,
        description="Enumerate OCI Blockchain resources",
        components=COMPONENTS,
        add_extra_args=_add_extra_args,
    )


def run_module(user_args, session):
    args, _ = _parse_args(user_args)

    component_order = [key for key, _suffix, _help in COMPONENTS]
    selected = resolve_selected_components(args, component_order)

    compartment_id = getattr(session, "compartment_id", None)

    platforms_resource = BlockchainPlatformsResource(session=session)
    peers_resource = BlockchainPeersResource(session=session)
    osns_resource = BlockchainOsnsResource(session=session)
    patches_resource = BlockchainPatchesResource(session=session)
    work_requests_resource = BlockchainWorkRequestsResource(session=session)

    need_platform_scope = any(
        selected.get(key, False)
        for key in ("peers", "osns", "patches", "work_requests")
    )

    platform_ids: list[str] = []
    if need_platform_scope:
        platform_ids = dedupe_strs(parse_csv_args(getattr(args, "platform_ids", []) or []))
        if not platform_ids and compartment_id:
            platform_ids = dedupe_strs(
                ids_from_db(session, table_name="blockchain_platforms", compartment_id=compartment_id) or []
            )
        if not platform_ids and compartment_id:
            try:
                bootstrap_rows = platforms_resource.list(compartment_id=compartment_id) or []
                platform_ids = dedupe_strs(
                    [
                        row.get("id")
                        for row in bootstrap_rows
                        if isinstance(row, dict) and isinstance(row.get("id"), str)
                    ]
                )
            except Exception:
                platform_ids = []

    results = []

    if selected.get("platforms", False):
        if not compartment_id:
            raise ValueError("session.compartment_id is not set")

        rows = platforms_resource.list(compartment_id=compartment_id) or []
        rows = unique_rows_by_id([row for row in rows if isinstance(row, dict)])
        for row in rows:
            row.setdefault("compartment_id", compartment_id)

        if args.get:
            for row in rows:
                resource_id = row.get("id")
                if not resource_id:
                    continue
                meta = platforms_resource.get(resource_id=resource_id) or {}
                fill_missing_fields(row, meta)

        if rows:
            UtilityTools.print_limited_table(rows, platforms_resource.COLUMNS)
        if args.save:
            platforms_resource.save(rows)

        results.append(
            {
                "ok": True,
                "platforms": len(rows),
                "saved": bool(args.save),
                "get": bool(args.get),
            }
        )

    if selected.get("peers", False):
        if not platform_ids:
            results.append(
                {
                    "ok": True,
                    "peers": 0,
                    "saved": False,
                    "get": bool(args.get),
                    "platform_ids": [],
                }
            )
        else:
            rows = []
            for platform_id in platform_ids:
                listed = peers_resource.list(blockchain_platform_id=platform_id) or []
                for row in listed:
                    if not isinstance(row, dict):
                        continue
                    row.setdefault("blockchain_platform_id", platform_id)
                    if compartment_id:
                        row.setdefault("compartment_id", compartment_id)
                    rows.append(row)

            rows = unique_rows_by_id(rows)

            if args.get:
                for row in rows:
                    platform_id = row.get("blockchain_platform_id")
                    peer_id = row.get("id")
                    if not platform_id or not peer_id:
                        continue
                    meta = peers_resource.get(resource_id=peer_id, blockchain_platform_id=platform_id) or {}
                    fill_missing_fields(row, meta)

            if rows:
                UtilityTools.print_limited_table(rows, peers_resource.COLUMNS)
            if args.save:
                peers_resource.save(rows)

            results.append(
                {
                    "ok": True,
                    "peers": len(rows),
                    "saved": bool(args.save),
                    "get": bool(args.get),
                    "platform_ids": platform_ids,
                }
            )

    if selected.get("osns", False):
        if not platform_ids:
            results.append(
                {
                    "ok": True,
                    "osns": 0,
                    "saved": False,
                    "get": bool(args.get),
                    "platform_ids": [],
                }
            )
        else:
            rows = []
            for platform_id in platform_ids:
                listed = osns_resource.list(blockchain_platform_id=platform_id) or []
                for row in listed:
                    if not isinstance(row, dict):
                        continue
                    row.setdefault("blockchain_platform_id", platform_id)
                    if compartment_id:
                        row.setdefault("compartment_id", compartment_id)
                    rows.append(row)

            rows = unique_rows_by_id(rows)

            if args.get:
                for row in rows:
                    platform_id = row.get("blockchain_platform_id")
                    osn_id = row.get("id")
                    if not platform_id or not osn_id:
                        continue
                    meta = osns_resource.get(resource_id=osn_id, blockchain_platform_id=platform_id) or {}
                    fill_missing_fields(row, meta)

            if rows:
                UtilityTools.print_limited_table(rows, osns_resource.COLUMNS)
            if args.save:
                osns_resource.save(rows)

            results.append(
                {
                    "ok": True,
                    "osns": len(rows),
                    "saved": bool(args.save),
                    "get": bool(args.get),
                    "platform_ids": platform_ids,
                }
            )

    if selected.get("patches", False):
        if not platform_ids:
            results.append(
                {
                    "ok": True,
                    "patches": 0,
                    "saved": False,
                    "get": False,
                    "platform_ids": [],
                }
            )
        else:
            rows = []
            for platform_id in platform_ids:
                listed = patches_resource.list(blockchain_platform_id=platform_id) or []
                for row in listed:
                    if not isinstance(row, dict):
                        continue
                    row.setdefault("blockchain_platform_id", platform_id)
                    if compartment_id:
                        row.setdefault("compartment_id", compartment_id)
                    row["record_hash"] = patches_resource.record_hash(row, prefix=f"{platform_id}:")
                    rows.append(row)

            rows = unique_rows_by_id(rows)

            if rows:
                UtilityTools.print_limited_table(rows, patches_resource.COLUMNS)
            if args.save:
                patches_resource.save(rows)

            results.append(
                {
                    "ok": True,
                    "patches": len(rows),
                    "saved": bool(args.save),
                    "get": False,
                    "platform_ids": platform_ids,
                }
            )

    if selected.get("work_requests", False):
        if not compartment_id:
            raise ValueError("session.compartment_id is not set")

        if not platform_ids:
            results.append(
                {
                    "ok": True,
                    "work_requests": 0,
                    "saved": False,
                    "get": bool(args.get),
                    "platform_ids": [],
                }
            )
        else:
            rows = []
            for platform_id in platform_ids:
                listed = work_requests_resource.list(
                    compartment_id=compartment_id,
                    blockchain_platform_id=platform_id,
                ) or []
                for row in listed:
                    if not isinstance(row, dict):
                        continue
                    row.setdefault("blockchain_platform_id", platform_id)
                    row.setdefault("compartment_id", compartment_id)
                    rows.append(row)

            rows = unique_rows_by_id(rows)

            if args.get:
                for row in rows:
                    work_request_id = row.get("id")
                    if not work_request_id:
                        continue
                    meta = work_requests_resource.get(resource_id=work_request_id) or {}
                    fill_missing_fields(row, meta)

            if rows:
                UtilityTools.print_limited_table(rows, work_requests_resource.COLUMNS)
            if args.save:
                work_requests_resource.save(rows)

            results.append(
                {
                    "ok": True,
                    "work_requests": len(rows),
                    "saved": bool(args.save),
                    "get": bool(args.get),
                    "platform_ids": platform_ids,
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
