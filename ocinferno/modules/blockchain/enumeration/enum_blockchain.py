#!/usr/bin/env python3
from __future__ import annotations

import argparse

from ocinferno.core.utils.enum_framework import Component, component_arg_specs, nested_list_fn, run_components
from ocinferno.core.utils.module_helpers import dedupe_strs, ids_from_db, parse_csv_args
from ocinferno.core.utils.service_runtime import parse_wrapper_args, resolve_selected_components
from ocinferno.modules.blockchain.utilities.helpers import (
    BlockchainOsnsResource,
    BlockchainPatchesResource,
    BlockchainPeersResource,
    BlockchainPlatformsResource,
    BlockchainWorkRequestsResource,
)


_PLATFORM_SCOPED_KEYS = ("peers", "osns", "patches", "work_requests")


def _add_extra_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--platform-ids",
        action="append",
        default=[],
        help="Blockchain platform OCID scope (repeatable, CSV supported)",
    )


def _resolve_platform_ids(session, args) -> list:
    """Manual --platform-ids -> DB cache -> live list, resolved ONCE in run_module and
    shared (via nested_list_fn's manual_parent_ids) across peers/osns/patches/work_requests
    instead of each independently re-resolving the same platforms."""
    compartment_id = getattr(session, "compartment_id", None)
    platform_ids = dedupe_strs(parse_csv_args(getattr(args, "platform_ids", []) or []))
    if not platform_ids and compartment_id:
        platform_ids = dedupe_strs(
            ids_from_db(session, table_name="blockchain_platforms", compartment_id=compartment_id) or []
        )
    if not platform_ids and compartment_id:
        try:
            bootstrap_rows = BlockchainPlatformsResource(session=session).list(compartment_id=compartment_id) or []
            platform_ids = dedupe_strs(
                [row.get("id") for row in bootstrap_rows if isinstance(row, dict) and isinstance(row.get("id"), str)]
            )
        except Exception:
            platform_ids = []
    return platform_ids


def _platform_scoped_get_row_fn(session, args, resource):
    """peers/osns get() needs both the row id AND its blockchain_platform_id (not just
    resource_id like the default get_row_fn assumes)."""

    def _get(row):
        rid = row.get("id")
        platform_id = row.get("blockchain_platform_id")
        if not rid or not platform_id:
            return {}
        return resource.get(resource_id=rid, blockchain_platform_id=platform_id) or {}

    return _get


def _patches_list_fn(platform_ids):
    """Nested fan-out for patches, plus the record_hash stamp -- the one quirk that
    doesn't fit nested_list_fn directly (list-only rows, no ``id`` column)."""

    def _factory(session, args, resource):
        inner = nested_list_fn(
            parent_resource_cls=BlockchainPlatformsResource,
            parent_id_field="blockchain_platform_id",
            manual_parent_ids=platform_ids,
            child_takes_compartment=False,
        )(session, args, resource)

        def _list(compartment_id):
            rows = inner(compartment_id)
            for row in rows:
                row["record_hash"] = resource.record_hash(
                    row, prefix=f"{row.get('blockchain_platform_id', '')}:"
                )
            return rows

        return _list

    return _factory


def _build_components(platform_ids):
    return [
        Component("platforms", BlockchainPlatformsResource,
                  help_text="Enumerate blockchain platforms", cache_table="blockchain_platforms"),
        Component("peers", BlockchainPeersResource,
                  help_text="Enumerate blockchain peers", cache_table="blockchain_peers",
                  list_fn=nested_list_fn(
                      parent_resource_cls=BlockchainPlatformsResource,
                      parent_id_field="blockchain_platform_id",
                      manual_parent_ids=platform_ids,
                      child_takes_compartment=False,
                  ),
                  get_row_fn=_platform_scoped_get_row_fn),
        Component("osns", BlockchainOsnsResource,
                  help_text="Enumerate blockchain orderer service nodes", cache_table="blockchain_osns",
                  list_fn=nested_list_fn(
                      parent_resource_cls=BlockchainPlatformsResource,
                      parent_id_field="blockchain_platform_id",
                      manual_parent_ids=platform_ids,
                      child_takes_compartment=False,
                  ),
                  get_row_fn=_platform_scoped_get_row_fn),
        Component("patches", BlockchainPatchesResource,
                  help_text="Enumerate blockchain platform patches", cache_table="blockchain_platform_patches",
                  supports_get=False,
                  list_fn=_patches_list_fn(platform_ids)),
        Component("work_requests", BlockchainWorkRequestsResource,
                  help_text="Enumerate blockchain work requests", cache_table="blockchain_work_requests",
                  list_fn=nested_list_fn(
                      parent_resource_cls=BlockchainPlatformsResource,
                      parent_id_field="blockchain_platform_id",
                      manual_parent_ids=platform_ids,
                      child_takes_compartment=True,
                  )),
    ]


# Module-level shape (component keys/help text) for CLI-flag introspection; run_module
# always rebuilds a fresh list bound to the resolved platform_ids for the real run.
COMPONENTS = _build_components([])


def run_module(user_args, session):
    args, _ = parse_wrapper_args(
        user_args,
        description="Enumerate OCI Blockchain resources",
        components=component_arg_specs(COMPONENTS),
        add_extra_args=_add_extra_args,
    )
    component_order = [c.key for c in COMPONENTS]
    selected = resolve_selected_components(args, component_order)

    # Resolved once (not per-component) and shared by peers/osns/patches/work_requests.
    platform_ids: list = []
    if any(selected.get(key, False) for key in _PLATFORM_SCOPED_KEYS):
        platform_ids = _resolve_platform_ids(session, args)

    return run_components(
        user_args, session, _build_components(platform_ids),
        module_name="enum_blockchain",
        description="Enumerate OCI Blockchain resources",
        add_extra_args=_add_extra_args,
    )
