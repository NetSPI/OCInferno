#!/usr/bin/env python3
from __future__ import annotations

import argparse

from ocinferno.core.utils.enum_framework import Component, component_arg_specs, nested_list_fn, run_components
from ocinferno.core.utils.service_runtime import parse_wrapper_args, resolve_selected_components
from ocinferno.modules.desktops.utilities.helpers import (
    DesktopsDesktopsResource,
    DesktopsPoolDesktopsResource,
    DesktopsPoolsResource,
    DesktopsPoolVolumesResource,
    DesktopsWorkRequestsResource,
    resolve_desktop_pool_ids,
)


def _add_extra_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--pool-ids", action="append", default=[], help="Desktop pool OCID scope (repeatable, CSV supported)")


def _pool_volumes_list_fn(pool_ids):
    """Nested fan-out for pool_volumes, plus the record_hash stamp -- the one quirk
    that doesn't fit nested_list_fn directly (list-only rows, no ``id`` column)."""

    def _factory(session, args, resource):
        inner = nested_list_fn(
            parent_resource_cls=DesktopsPoolsResource,
            parent_id_field="desktop_pool_id",
            manual_parent_ids=pool_ids,
            child_takes_compartment=True,
        )(session, args, resource)

        def _list(compartment_id):
            rows = inner(compartment_id)
            for row in rows:
                row["record_hash"] = resource.record_hash(row, prefix=f"{row.get('desktop_pool_id', '')}:")
            return rows

        return _list

    return _factory


def _build_components(pool_ids):
    return [
        Component("desktops", DesktopsDesktopsResource, help_text="Enumerate desktops", cache_table="desktops_desktops"),
        Component("pools", DesktopsPoolsResource, help_text="Enumerate desktop pools", cache_table="desktops_pools"),
        Component("pool_desktops", DesktopsPoolDesktopsResource, help_text="Enumerate desktops within pools",
                  cache_table="desktops_pool_desktops",
                  list_fn=nested_list_fn(
                      parent_resource_cls=DesktopsPoolsResource,
                      parent_id_field="desktop_pool_id",
                      manual_parent_ids=pool_ids,
                      child_takes_compartment=True,
                  )),
        Component("pool_volumes", DesktopsPoolVolumesResource, help_text="Enumerate desktop pool volumes",
                  cache_table="desktops_pool_volumes",
                  supports_get=False,
                  list_fn=_pool_volumes_list_fn(pool_ids)),
        Component("work_requests", DesktopsWorkRequestsResource, help_text="Enumerate desktop service work requests",
                  cache_table="desktops_work_requests"),
    ]


# Module-level shape (component keys/help text) for CLI-flag introspection; run_module
# always rebuilds a fresh list bound to the resolved pool_ids for the real run.
COMPONENTS = _build_components([])


def run_module(user_args, session):
    args, _ = parse_wrapper_args(
        user_args,
        description="Enumerate OCI Desktop resources",
        components=component_arg_specs(COMPONENTS),
        add_extra_args=_add_extra_args,
    )
    component_order = [c.key for c in COMPONENTS]
    selected = resolve_selected_components(args, component_order)

    # Resolved once (not per-component) and shared by pool_desktops + pool_volumes.
    pool_ids: list = []
    if selected.get("pool_desktops", False) or selected.get("pool_volumes", False):
        compartment_id = getattr(session, "compartment_id", None)
        if compartment_id:
            debug = bool(getattr(session, "individual_run_debug", False) or getattr(session, "debug", False))
            pool_ids = resolve_desktop_pool_ids(session, args, comp_id=compartment_id, debug=debug)

    return run_components(
        user_args, session, _build_components(pool_ids),
        module_name="enum_desktops",
        description="Enumerate OCI Desktop resources",
        add_extra_args=_add_extra_args,
    )
