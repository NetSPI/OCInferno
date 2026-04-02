#!/usr/bin/env python3
from __future__ import annotations

from ocinferno.core.console import UtilityTools
from ocinferno.core.utils.module_helpers import fill_missing_fields, unique_rows_by_id
from ocinferno.modules.managedkafka.utilities.helpers import (
    ManagedKafkaClusterConfigsResource,
    ManagedKafkaClusterConfigVersionsResource,
    ManagedKafkaClustersResource,
    normalize_csv_args,
)
from ocinferno.core.utils.service_runtime import (
    append_cached_component_counts,
    parse_wrapper_args,
    resolve_selected_components,
)


COMPONENTS = [
    ("clusters", "clusters", "Enumerate kafka clusters"),
    ("cluster_configs", "cluster_configs", "Enumerate kafka cluster configs"),
    ("cluster_config_versions", "cluster_config_versions", "Enumerate kafka cluster config versions"),
]


CACHE_TABLES = {
    "clusters": ("kafka_clusters", "compartment_id"),
    "cluster_configs": ("kafka_cluster_configs", "compartment_id"),
    "cluster_config_versions": ("kafka_cluster_config_versions", "compartment_id"),
}


def _component_error_summary(err: Exception) -> str:
    status = getattr(err, "status", None)
    code = getattr(err, "code", None)
    msg = getattr(err, "message", None)
    if status is not None or code is not None:
        return f"status={status}, code={code}, message={msg or str(err)}"
    return f"{type(err).__name__}: {err}"


def _parse_args(user_args):
    def _add_extra_args(parser):
        parser.add_argument(
            "--cluster-ids",
            action="append",
            default=[],
            help="Kafka Cluster OCIDs (repeatable, comma-separated supported).",
        )
        parser.add_argument(
            "--cluster-config-ids",
            action="append",
            default=[],
            help="Kafka Cluster Config OCIDs scope (repeatable, comma-separated supported).",
        )

    return parse_wrapper_args(
        user_args=user_args,
        description="Enumerate Managed Kafka resources",
        components=COMPONENTS,
        add_extra_args=_add_extra_args,
    )


def run_module(user_args, session):
    args, _ = _parse_args(user_args)

    component_order = [key for key, _suffix, _help in COMPONENTS]
    selected = resolve_selected_components(args, component_order)
    resource_map = {
        "clusters": ManagedKafkaClustersResource(session=session),
        "cluster_configs": ManagedKafkaClusterConfigsResource(session=session),
        "cluster_config_versions": ManagedKafkaClusterConfigVersionsResource(session=session),
    }
    results = []
    for key, _method_suffix, _help_text in COMPONENTS:
        if not selected.get(key, False):
            continue
        try:
            if key == "clusters":
                clusters_resource = resource_map[key]
                compartment_id = getattr(session, "compartment_id", None)
                cluster_ids = normalize_csv_args(list(args.cluster_ids or []))

                if not compartment_id and not cluster_ids:
                    raise ValueError("Need session.compartment_id unless --cluster-ids are provided")

                if cluster_ids:
                    rows = [clusters_resource.get(resource_id=cluster_id) for cluster_id in cluster_ids]
                    rows = [row for row in rows if isinstance(row, dict) and row]
                else:
                    rows = clusters_resource.list(compartment_id=compartment_id) or []

                rows = unique_rows_by_id([row for row in rows if isinstance(row, dict)])
                for row in rows:
                    row.setdefault("compartment_id", compartment_id)

                if args.get:
                    for row in rows:
                        resource_id = row.get("id")
                        if not resource_id:
                            continue
                        meta = clusters_resource.get(resource_id=resource_id) or {}
                        fill_missing_fields(row, meta)

                if rows:
                    UtilityTools.print_limited_table(rows, clusters_resource.COLUMNS)

                if args.save:
                    clusters_resource.save(rows)

                results.append({"ok": True, "clusters": len(rows), "saved": bool(args.save), "get": bool(args.get)})
            elif key == "cluster_configs":
                cfg_resource = resource_map[key]
                compartment_id = getattr(session, "compartment_id", None)
                config_ids = normalize_csv_args(list(args.cluster_config_ids or []))

                if not compartment_id and not config_ids:
                    raise ValueError("Need session.compartment_id unless --cluster-config-ids are provided")

                if config_ids:
                    rows = [cfg_resource.get(resource_id=config_id) for config_id in config_ids]
                    rows = [row for row in rows if isinstance(row, dict) and row]
                else:
                    rows = cfg_resource.list(compartment_id=compartment_id) or []

                rows = unique_rows_by_id([row for row in rows if isinstance(row, dict)])
                for row in rows:
                    row.setdefault("compartment_id", compartment_id)

                if args.get:
                    for row in rows:
                        resource_id = row.get("id")
                        if not resource_id:
                            continue
                        meta = cfg_resource.get(resource_id=resource_id) or {}
                        fill_missing_fields(row, meta)

                if rows:
                    UtilityTools.print_limited_table(rows, cfg_resource.COLUMNS)

                if args.save:
                    cfg_resource.save(rows)

                results.append({"ok": True, "cluster_configs": len(rows), "saved": bool(args.save), "get": bool(args.get)})
            elif key == "cluster_config_versions":
                cfg_ver_resource = resource_map[key]
                compartment_id = getattr(session, "compartment_id", None)
                if not compartment_id and not args.cluster_config_ids:
                    raise ValueError("Need session.compartment_id unless --cluster-config-ids are provided")

                config_ids = cfg_ver_resource.resolve_cluster_config_ids(compartment_id, args)

                rows = []
                for config_id in config_ids:
                    listed = cfg_ver_resource.list(kafka_cluster_config_id=config_id) or []
                    for row in listed:
                        if not isinstance(row, dict):
                            continue
                        row.setdefault("config_id", config_id)
                        row.setdefault("compartment_id", compartment_id)
                        rows.append(row)

                rows = cfg_ver_resource.unique_cfg_version_rows(rows)

                if args.get:
                    for row in rows:
                        config_id = row.get("config_id")
                        version_number = row.get("version_number")
                        if not config_id:
                            continue
                        try:
                            version_int = int(version_number)
                        except Exception:
                            continue
                        meta = cfg_ver_resource.get(kafka_cluster_config_id=config_id, version_number=version_int) or {}
                        fill_missing_fields(row, meta)

                if rows:
                    UtilityTools.print_limited_table(rows, cfg_ver_resource.COLUMNS)

                if args.save:
                    cfg_ver_resource.save(rows)

                results.append(
                    {
                        "ok": True,
                        "cluster_config_versions": len(rows),
                        "cluster_config_ids": config_ids,
                        "saved": bool(args.save),
                        "get": bool(args.get),
                    }
                )
        except Exception as err:
            print(f"[*] enum_managedkafka.{key}: skipped ({_component_error_summary(err)}).")
            results.append({"ok": False, "component": key, "error": _component_error_summary(err)})

    append_cached_component_counts(
        results=results,
        session=session,
        selected=selected,
        component_order=component_order,
        cache_tables=CACHE_TABLES,
    )

    return {"ok": True, "components": results}
