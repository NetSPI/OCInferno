#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path

from ocinferno.core.console import UtilityTools
from ocinferno.modules.resource_search.utilities.helpers import ResourceSearchInventoryResource
from ocinferno.core.utils.service_runtime import (
    component_error_summary,
    parse_wrapper_args,
)


COMPONENTS = [
    ("inventory", "inventory", "Search ALL resources tenancy-wide (asset inventory)"),
]

CACHE_TABLES = {
    "inventory": ("resource_search_inventory", "compartment_id"),
}

# The exported inventory schema OpenGraph's --from-inventory consumes.
INVENTORY_SCHEMA = "ocinferno-resource-inventory/1"


def _parse_args(user_args):
    def _add_extra_args(parser: argparse.ArgumentParser) -> None:
        parser.add_argument("--query", default="query all resources",
                            help="OCI structured search query (default: all resources)")
        parser.add_argument("--out", default="",
                            help="Also export the inventory to a JSON file (consumable by "
                                 "process_oracle_cloud_hound_data --from-inventory).")

    return parse_wrapper_args(
        user_args=user_args,
        description="Enumerate the tenancy-wide resource inventory via OCI Search",
        components=COMPONENTS,
        add_extra_args=_add_extra_args,
    )


def run_module(user_args, session):
    args, _ = _parse_args(user_args)

    resource = ResourceSearchInventoryResource(session=session)
    try:
        rows = [r for r in (resource.search_all(query=args.query) or []) if isinstance(r, dict)]
    except Exception as err:
        summary = component_error_summary(err)
        print(f"[*] enum_resource_search.inventory: skipped ({summary}).")
        return {"ok": True, "components": [{"ok": False, "component": "inventory", "error": summary}]}

    by_type = Counter(str(r.get("resource_type") or "?") for r in rows)
    print(f"[*] Resource Search inventory: {len(rows)} resources across {len(by_type)} type(s).")
    if rows:
        UtilityTools.print_limited_table(rows, resource.COLUMNS, title="Resource Search - Inventory")

    resource.save(rows)

    out = str(getattr(args, "out", "") or "").strip()
    if out:
        out_path = session.resolve_output_path(
            requested_path=out,
            service_name="resource_search",
            filename="oci_resource_inventory.json",
            compartment_id=getattr(session, "compartment_id", None),
            subdirs=["inventory"],
            target="export",
        )
        payload = {"schema": INVENTORY_SCHEMA, "resource_count": len(rows), "resources": rows}
        Path(out_path).write_text(json.dumps(payload, indent=2), encoding="utf-8")
        print(f"[*] wrote resource inventory ({len(rows)} resources) -> {out_path}")

    return {"ok": True, "components": [{"ok": True, "inventory": len(rows), "saved": True}]}
