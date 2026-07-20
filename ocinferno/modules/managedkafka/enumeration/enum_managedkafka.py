#!/usr/bin/env python3
from __future__ import annotations

from ocinferno.core.console import UtilityTools
from ocinferno.core.utils.enum_framework import nested_list_fn
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
    run_standard_enum_component,
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


from ocinferno.core.utils.service_runtime import component_soft_skip_or_error


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

                # --cluster-ids scopes to get()-per-id; otherwise list per compartment. Dedup either way.
                def _list_clusters(cid, _ids=cluster_ids, _res=clusters_resource):
                    if _ids:
                        got = [_res.get(resource_id=cid_) for cid_ in _ids]
                        rows = [r for r in got if isinstance(r, dict) and r]
                    else:
                        rows = _res.list(compartment_id=cid) or []
                    return unique_rows_by_id([r for r in rows if isinstance(r, dict)])

                results.append(run_standard_enum_component(
                    user_args=args, session=session, component_key="clusters",
                    list_rows=_list_clusters,
                    get_row=lambda row, _res=clusters_resource: _res.get(resource_id=row.get("id")),
                    save_rows_fn=clusters_resource.save,
                    print_columns=clusters_resource.COLUMNS,
                    module_name="enum_managedkafka",
                    require_compartment=False,
                ))
            elif key == "cluster_configs":
                cfg_resource = resource_map[key]
                compartment_id = getattr(session, "compartment_id", None)
                config_ids = normalize_csv_args(list(args.cluster_config_ids or []))

                if not compartment_id and not config_ids:
                    raise ValueError("Need session.compartment_id unless --cluster-config-ids are provided")

                # --cluster-config-ids scopes to get()-per-id; otherwise list per compartment. Dedup either way.
                def _list_cluster_configs(cid, _ids=config_ids, _res=cfg_resource):
                    if _ids:
                        got = [_res.get(resource_id=cid_) for cid_ in _ids]
                        rows = [r for r in got if isinstance(r, dict) and r]
                    else:
                        rows = _res.list(compartment_id=cid) or []
                    return unique_rows_by_id([r for r in rows if isinstance(r, dict)])

                results.append(run_standard_enum_component(
                    user_args=args, session=session, component_key="cluster_configs",
                    list_rows=_list_cluster_configs,
                    get_row=lambda row, _res=cfg_resource: _res.get(resource_id=row.get("id")),
                    save_rows_fn=cfg_resource.save,
                    print_columns=cfg_resource.COLUMNS,
                    module_name="enum_managedkafka",
                    require_compartment=False,
                ))
            elif key == "cluster_config_versions":
                cfg_ver_resource = resource_map[key]
                compartment_id = getattr(session, "compartment_id", None)
                if not compartment_id and not args.cluster_config_ids:
                    raise ValueError("Need session.compartment_id unless --cluster-config-ids are provided")

                config_ids = cfg_ver_resource.resolve_cluster_config_ids(compartment_id, args)

                # resolve_cluster_config_ids already covers manual --cluster-config-ids/DB-cache/
                # live-list; reuse its result via manual_parent_ids so nested_list_fn only fans out
                # + stamps. parent_id_field stays "config_id" (the existing row-stamp field name);
                # the real SDK kwarg is remapped separately via LIST_SCOPE_KWARG on the resource.
                list_rows = nested_list_fn(
                    parent_resource_cls=ManagedKafkaClusterConfigsResource,
                    parent_id_field="config_id",
                    manual_parent_ids=config_ids,
                    child_takes_compartment=False,
                )(session, args, cfg_ver_resource)
                rows = cfg_ver_resource.unique_cfg_version_rows(list_rows(compartment_id))

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

                cfg_ver_resource.save(rows)

                results.append(
                    {
                        "ok": True,
                        "cluster_config_versions": len(rows),
                        "cluster_config_ids": config_ids,
                        "saved": True,
                        "get": bool(args.get),
                    }
                )
        except Exception as err:
            results.append(component_soft_skip_or_error(err, component=key, module_name="enum_managedkafka"))

    append_cached_component_counts(
        results=results,
        session=session,
        selected=selected,
        component_order=component_order,
        cache_tables=CACHE_TABLES,
    )

    return {"ok": True, "components": results}
