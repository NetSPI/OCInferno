#!/usr/bin/env python3
from __future__ import annotations

import oci
from ocinferno.core.console import UtilityTools
from ocinferno.core.utils.module_helpers import fill_missing_fields
from ocinferno.modules.kubernetes.utilities.helpers import (
    KubernetesClustersResource,
    KubernetesNodePoolsResource,
    KubernetesVirtualNodePoolsResource,
)
from ocinferno.core.utils.service_runtime import (
    append_cached_component_counts,
    parse_wrapper_args,
    resolve_selected_components,
)


COMPONENTS = [
    ("clusters", "clusters", "Enumerate clusters"),
    ("node_pools", "node_pools", "Enumerate node-pools"),
    ("virtual_node_pools", "virtual_node_pools", "Enumerate virtual-node-pools"),
]


CACHE_TABLES = {
    "clusters": ("containerengine_clusters", "compartment_id"),
    "node_pools": ("containerengine_node_pools", "compartment_id"),
    "virtual_node_pools": ("containerengine_virtual_node_pools", "compartment_id"),
}


def _parse_args(user_args):
    def _add_extra_args(parser):
        parser.add_argument("--list-nodes", action="store_true", help="Also list virtual nodes for virtual node pools")
        parser.add_argument(
            "--vnp-ids",
            action="append",
            default=[],
            help="Virtual node pool OCIDs (repeatable, comma-separated supported).",
        )
        parser.add_argument("--save-nodes", action="store_true", help="When used with --list-nodes, also save virtual nodes")
        parser.add_argument("--debug", action="store_true", help="Debug logging")

    return parse_wrapper_args(
        user_args=user_args,
        description="Enumerate Kubernetes resources",
        components=COMPONENTS,
        add_extra_args=_add_extra_args,
    )


def run_module(user_args, session):
    args, _ = _parse_args(user_args)
    debug = bool(getattr(args, "debug", False) or getattr(session, "individual_run_debug", False) or getattr(session, "debug", False))

    component_order = [key for key, _suffix, _help in COMPONENTS]
    selected = resolve_selected_components(args, component_order)

    resource_map = {
        "clusters": KubernetesClustersResource(session=session),
        "node_pools": KubernetesNodePoolsResource(session=session),
        "virtual_node_pools": KubernetesVirtualNodePoolsResource(session=session),
    }
    results = []
    for key, _method_suffix, _help_text in COMPONENTS:
        if not selected.get(key, False):
            continue
        if key == "virtual_node_pools":
            vnp_resource = resource_map[key]
            compartment_id = getattr(session, "compartment_id", None)
            if not compartment_id:
                raise ValueError("session.compartment_id is not set")

            try:
                pools = vnp_resource.list(compartment_id=compartment_id) or []
            except oci.exceptions.ServiceError as err:
                if getattr(err, "status", None) == 404 and getattr(err, "code", None) == "NotAuthorizedOrNotFound":
                    print("[*] Skipping virtual node pools in this compartment (not authorized or not found).")
                    results.append(
                        {
                            "ok": True,
                            "virtual_node_pools": 0,
                            "virtual_nodes": 0,
                            "saved": False,
                            "get": bool(args.get),
                            "list_nodes": bool(args.list_nodes),
                            "skipped": True,
                        }
                    )
                    continue
                UtilityTools.dlog(
                    True,
                    "list_virtual_node_pools failed",
                    status=getattr(err, "status", None),
                    code=getattr(err, "code", None),
                    err=f"{type(err).__name__}: {err}",
                )
                results.append(
                    {"ok": False, "virtual_node_pools": 0, "virtual_nodes": 0, "saved": False, "get": bool(args.get), "list_nodes": bool(args.list_nodes)}
                )
                continue

            pools = [row for row in pools if isinstance(row, dict)]
            for pool in pools:
                pool.setdefault("compartment_id", compartment_id)

            if args.get:
                for pool in pools:
                    pool_id = pool.get("id")
                    if not pool_id:
                        continue
                    try:
                        meta = vnp_resource.get(resource_id=pool_id) or {}
                    except Exception as err:
                        UtilityTools.dlog(debug, "get_virtual_node_pool failed", virtual_node_pool_id=pool_id, err=f"{type(err).__name__}: {err}")
                        continue
                    fill_missing_fields(pool, meta)

            if pools:
                UtilityTools.print_limited_table(pools, vnp_resource.COLUMNS)

            if args.save:
                vnp_resource.save(pools)

            nodes_rows = []
            if args.list_nodes:
                vnp_ids = vnp_resource.resolve_vnp_ids(args, pools)
                for vnp_id in vnp_ids:
                    try:
                        listed = vnp_resource.list_nodes(virtual_node_pool_id=vnp_id) or []
                    except Exception as err:
                        UtilityTools.dlog(debug, "list_virtual_nodes failed", virtual_node_pool_id=vnp_id, err=f"{type(err).__name__}: {err}")
                        continue
                    for node in listed:
                        if not isinstance(node, dict):
                            continue
                        node.setdefault("compartment_id", compartment_id)
                        node.setdefault("virtual_node_pool_id", vnp_id)
                        nodes_rows.append(node)

                if nodes_rows:
                    UtilityTools.print_limited_table(nodes_rows, vnp_resource.NODE_COLUMNS)

                if args.save_nodes and nodes_rows:
                    vnp_resource.save_nodes(nodes_rows)

            results.append(
                {
                    "ok": True,
                    "virtual_node_pools": len(pools),
                    "virtual_nodes": len(nodes_rows),
                    "saved": bool(args.save),
                    "get": bool(args.get),
                    "list_nodes": bool(args.list_nodes),
                    "saved_nodes": bool(args.save_nodes),
                }
            )
            continue

        compartment_id = getattr(session, "compartment_id", None)
        if not compartment_id:
            raise ValueError("session.compartment_id is not set")

        resource = resource_map[key]
        rows = resource.list(compartment_id=compartment_id) or []
        rows = [row for row in rows if isinstance(row, dict)]
        for row in rows:
            row.setdefault("compartment_id", compartment_id)

        if args.get:
            for row in rows:
                resource_id = row.get("id")
                if not resource_id:
                    continue
                try:
                    meta = resource.get(resource_id=resource_id) or {}
                except Exception as err:
                    UtilityTools.dlog(debug, f"get_{key} failed", resource_id=resource_id, err=f"{type(err).__name__}: {err}")
                    continue
                fill_missing_fields(row, meta)

        if rows:
            UtilityTools.print_limited_table(rows, resource.COLUMNS)

        if args.save:
            resource.save(rows)

        results.append({"ok": True, key: len(rows), "saved": bool(args.save), "get": bool(args.get)})

    append_cached_component_counts(
        results=results,
        session=session,
        selected=selected,
        component_order=component_order,
        cache_tables=CACHE_TABLES,
    )

    return {"ok": True, "components": results}
