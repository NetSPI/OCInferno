#!/usr/bin/env python3
from __future__ import annotations

from typing import Any, Dict, List, Optional

from ocinferno.core.console import UtilityTools
from ocinferno.core.utils import hierarchy as _hierarchy


def resource_type_label(table_name: str) -> str:
    mapping = {
        "object_storage_buckets": "buckets",
        "object_storage_bucket_objects": "blobs",
        "object_storage_namespaces": "namespaces",
        "blockstorage_volumes": "block_volumes",
        "blockstorage_boot_volumes": "boot_volumes",
        "blockstorage_volume_backups": "volume_backups",
        "blockstorage_boot_volume_backups": "boot_volume_backups",
        "compute_instances": "instances",
        "compute_images": "images",
        "compute_instance_configurations": "instance_configurations",
        "compute_instance_pools": "instance_pools",
        "compute_cluster_networks": "cluster_networks",
        "compute_compute_clusters": "compute_clusters",
        "virtual_network_vcns": "vcns",
        "virtual_network_subnets": "subnets",
        "virtual_network_route_tables": "route_tables",
        "virtual_network_security_lists": "security_lists",
        "virtual_network_network_security_groups": "network_security_groups",
        "virtual_network_internet_gateways": "internet_gateways",
        "virtual_network_nat_gateways": "nat_gateways",
        "virtual_network_service_gateways": "service_gateways",
        "virtual_network_drgs": "drgs",
        "virtual_network_drg_attachments": "drg_attachments",
        "virtual_network_dhcp_options": "dhcp_options",
        "container_registry_repositories": "container_repositories",
        "container_registry_images": "container_images",
        "ar_repositories": "artifact_repositories",
        "ar_generic_artifact": "artifact_images",
        "db_mysql_db_systems": "mysql_db_systems",
        "db_psql_db_systems": "postgres_db_systems",
        "cache_clusters": "cache_clusters",
        "cache_users": "cache_users",
        "functions_apps": "function_apps",
        "functions_functions": "functions",
        "kubernetes_clusters": "k8s_clusters",
        "kubernetes_node_pools": "k8s_node_pools",
        "kubernetes_virtual_node_pools": "k8s_virtual_node_pools",
        "file_storage_file_systems": "file_systems",
        "file_storage_mount_targets": "mount_targets",
        "file_storage_export_sets": "export_sets",
        "file_storage_exports": "exports",
        "file_storage_snapshots": "snapshots",
        "identity_domain_users": "idd_users",
        "identity_domain_groups": "idd_groups",
        "identity_domain_dynamic_groups": "idd_dynamic_groups",
        "blockchain_platforms": "bc_platforms",
        "blockchain_peers": "bc_peers",
        "blockchain_osns": "bc_osns",
        "blockchain_platform_patches": "bc_platform_patches",
        "blockchain_work_requests": "bc_work_requests",
        "data_science_projects": "ds_projects",
        "data_science_notebook_sessions": "ds_notebook_sessions",
        "data_science_models": "ds_models",
        "data_science_model_version_sets": "ds_model_version_sets",
        "data_science_model_groups": "ds_model_groups",
        "data_science_model_deployments": "ds_model_deployments",
        "data_science_jobs": "ds_jobs",
        "data_science_job_runs": "ds_job_runs",
        "data_science_pipelines": "ds_pipelines",
        "data_science_pipeline_runs": "ds_pipeline_runs",
        "data_science_schedules": "ds_schedules",
        "data_science_private_endpoints": "ds_private_endpoints",
        "data_science_work_requests": "ds_work_requests",
        "data_science_ml_applications": "ds_ml_applications",
        "desktops_desktops": "desktops",
        "desktops_pools": "desktop_pools",
        "desktops_pool_desktops": "pool_desktops",
        "desktops_pool_volumes": "pool_volumes",
        "desktops_work_requests": "desktop_work_requests",
    }
    return mapping.get(table_name, table_name)


def resource_type_area(resource_type: str) -> str:
    rt = str(resource_type or "").strip().lower()
    if not rt:
        return "Other"

    # Framework/control-plane tables (excluded from the stdout resource-count
    # breakdown entirely -- see _NON_RESOURCE_TABLES -- but the Excel export is a
    # full raw dump that may still list them; give them an honest label instead of
    # dumping them in "Other").
    if rt in ("enum_all_task_ledger", "opengraph_nodes", "opengraph_edges", "network_inventory"):
        return "Internal"

    # Explicit aliases first.
    areas = {
        "idd_users": "IAM",
        "idd_groups": "IAM",
        "idd_dynamic_groups": "IAM",
        "instances": "Compute",
        "images": "Compute",
        "buckets": "Storage",
        "blobs": "Storage",
        "namespaces": "Storage",
        "block_volumes": "Storage",
        "boot_volumes": "Storage",
        "volume_backups": "Storage",
        "boot_volume_backups": "Storage",
        "file_systems": "Storage",
        "mount_targets": "Storage",
        "export_sets": "Storage",
        "exports": "Storage",
        "snapshots": "Storage",
        "function_apps": "Functions",
        "functions": "Functions",
        "k8s_clusters": "Kubernetes",
        "k8s_node_pools": "Kubernetes",
        "k8s_virtual_node_pools": "Kubernetes",
        "mysql_db_systems": "Databases",
        "postgres_db_systems": "Databases",
        "cache_clusters": "Databases",
        "cache_users": "Databases",
        "container_repositories": "Registries",
        "container_images": "Registries",
        "artifact_repositories": "Registries",
        "artifact_images": "Registries",
        "tag_namespaces": "IAM",
        "tag_definitions": "IAM",
        "tag_defaults": "IAM",
        "vcns": "Network",
        "subnets": "Network",
        "route_tables": "Network",
        "security_lists": "Network",
        "network_security_groups": "Network",
        "internet_gateways": "Network",
        "nat_gateways": "Network",
        "service_gateways": "Network",
        "drgs": "Network",
        "drg_attachments": "Network",
        "dhcp_options": "Network",
        # resource_type_label() shortens these (stripping the "compute_"/"desktops_"
        # prefix the fallback rules below key off), so the short form needs its own
        # entry here -- otherwise callers that go through resource_type_label() first
        # (the stdout "Resource Breakdown" summary) fall through to "Other" even
        # though the raw table name would have matched a prefix rule fine (as the
        # Excel export, which calls resource_type_area() on the raw table name
        # directly, already does).
        "instance_configurations": "Compute",
        "instance_pools": "Compute",
        "cluster_networks": "Compute",
        "compute_clusters": "Compute",
        "desktops": "Desktops",
        "pool_desktops": "Desktops",
        "pool_volumes": "Desktops",
    }
    if rt in areas:
        return areas[rt]

    # Prefix/keyword inference for unmapped tables/resources.
    if rt.startswith("identity_domain_") or rt.startswith("identity_") or rt.startswith("tag_") or "iam" in rt:
        return "IAM"
    if rt.startswith("compute_"):
        return "Compute"
    if rt.startswith("containerengine_"):
        return "Kubernetes"
    if rt.startswith("object_storage_") or rt.startswith("file_storage_"):
        return "Storage"
    if rt.startswith("blockstorage_"):
        return "Storage"
    if rt.startswith("functions_"):
        return "Functions"
    if rt.startswith("kubernetes_") or rt.startswith("k8s_"):
        return "Kubernetes"
    if rt.startswith("db_") or rt.startswith("cache_") or "database" in rt:
        return "Databases"
    if rt.startswith("container_registry_") or rt.startswith("artifact_") or rt.startswith("ar_") or rt.startswith("cr_"):
        return "Registries"
    if rt.startswith("logging_") or rt.startswith("logs_"):
        return "Logging"
    if rt.startswith("virtual_network_") or rt.startswith("network_firewall_") or rt.startswith("network_load_balancer_") or rt.startswith("network_load_balancers") or rt.startswith("dns_"):
        return "Network"
    if rt.startswith("apigw_") or rt.startswith("api_gateway_"):
        return "API Gateway"
    if rt.startswith("vault_"):
        return "Vault"
    if rt.startswith("notification_"):
        return "Notifications"
    if rt.startswith("iot_"):
        return "IoT"
    if rt.startswith("resource_manager_"):
        return "Resource Manager"
    if rt.startswith("blockchain_") or rt.startswith("bc_"):
        return "Blockchain"
    if rt.startswith("data_science_") or rt.startswith("ds_"):
        return "Data Science"
    if rt.startswith("desktops_") or rt.startswith("desktop_"):
        return "Desktops"
    if rt == "resource_compartments" or rt in ("region_subscriptions",):
        return "IAM"

    # AI / ML
    if rt.startswith("ai_language_") or rt.startswith("generative_ai_"):
        return "AI/ML"
    # Security & governance-adjacent services
    if (
        rt.startswith("apiaccesscontrol_") or rt.startswith("audit_") or rt.startswith("bastion_")
        or rt.startswith("certificate") or rt.startswith("cloud_guard_") or rt.startswith("delegate_access_control_")
        or rt.startswith("lockbox_") or rt.startswith("oac_") or rt.startswith("vulnerability_scanning_")
        or rt.startswith("waas_") or rt.startswith("web_app_firewall")
    ):
        return "Security"
    # Analytics / data platform
    if (
        rt.startswith("analytics_") or rt.startswith("data_catalog_") or rt.startswith("data_integration_")
        or rt.startswith("dataflow_") or rt.startswith("opensearch_")
    ):
        return "Analytics"
    # DevOps / CI-CD
    if rt.startswith("devops_"):
        return "DevOps"
    # Monitoring & fleet management
    if (
        rt.startswith("monitoring_") or rt.startswith("management_agent_") or rt.startswith("osmh_")
        or rt.startswith("healthchecks_")
    ):
        return "Monitoring"
    # Messaging / eventing
    if (
        rt.startswith("streaming_") or rt.startswith("queue") or rt.startswith("sch_")
        or rt.startswith("kafka_") or rt.startswith("events_")
    ):
        return "Messaging"
    # Governance / tenancy administration
    if (
        rt.startswith("governance_rules_") or rt.startswith("tenant_manager_") or rt.startswith("cloud_migrations_")
        or rt.startswith("cloud_bridge_") or rt in ("resource_schedules", "resource_search_inventory")
    ):
        return "Governance"
    # Databases (extends the db_/cache_/"database" rule above with the remaining
    # DB-adjacent services that don't share those substrings)
    if (
        rt.startswith("dbmgmt_") or rt.startswith("dbmulticloud_") or rt.startswith("data_safe_")
        or rt.startswith("postgresql_") or rt.startswith("nosql_") or rt.startswith("redis_")
        or rt.startswith("goldengate_") or rt.startswith("bds_")
    ):
        return "Databases"
    # Compute-adjacent
    if rt.startswith("autoscaling_") or rt.startswith("container_instances"):
        return "Compute"
    if rt.startswith("ocvp_"):
        return "VMware"
    if rt.startswith("fusion_apps_"):
        return "Fusion Apps"
    if rt.startswith("integration_") or rt.startswith("oda_") or rt.startswith("visual_builder_"):
        return "Integration"
    if rt.startswith("email_"):
        return "Email"
    if rt.startswith("wlms_"):
        return "Middleware"
    if rt == "load_balancers":
        return "Network"
    if rt.startswith("resource_manager") or rt.startswith("resource_configuration_"):
        return "Resource Manager"

    return "Other"


# Framework/control-plane tables that carry a compartment_id but aren't themselves
# discoverable cloud resources -- counting them in the resource breakdown just adds
# noise (and, before area coverage was comprehensive, was a real source of confusing
# "Other" rows). Mirrors get_network_resources.py's _EXCLUDED_TABLES.
_NON_RESOURCE_TABLES = frozenset({
    "enum_all_task_ledger", "opengraph_nodes", "opengraph_edges", "network_inventory",
})


def summarize_resources_by_compartment(session, target_cids: List[str]) -> dict:
    dm = getattr(session, "data_master", None)
    conn = getattr(dm, "service_conn", None) if dm is not None else None
    if conn is None:
        return {"totals": [], "detailed": {}}

    target_set = {c for c in (target_cids or []) if isinstance(c, str) and c}
    counts = {c: 0 for c in target_set}
    detailed = {c: {} for c in target_set}

    cur = conn.cursor()
    cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")
    tables = [r[0] for r in cur.fetchall() if isinstance(r[0], str) and r[0] not in _NON_RESOURCE_TABLES]

    # A big scan (thousands of rows per table x up to ~280 tables) can take a real while
    # here with a GROUP BY aggregation per table -- in-place progress so this doesn't
    # read as a hang the way a fully silent sweep did.
    for table_name in UtilityTools.progress_iter(tables, label="enum_all summary: tables swept", min_items=20):
        try:
            cur.execute(f'PRAGMA table_info("{table_name}")')
            cols = {str(r[1]) for r in cur.fetchall() if len(r) > 1}
        except Exception:
            continue

        cid_col = None
        if "compartment_id" in cols:
            cid_col = "compartment_id"
        elif "compartment_ocid" in cols:
            cid_col = "compartment_ocid"

        if not cid_col:
            continue

        try:
            cur.execute(f'SELECT {cid_col}, COUNT(*) FROM "{table_name}" WHERE {cid_col} IS NOT NULL GROUP BY {cid_col}')
            resource_type = resource_type_label(table_name)
            for cid, cnt in cur.fetchall():
                if cid in target_set:
                    counts[cid] += int(cnt or 0)
                    detailed[cid][resource_type] = detailed[cid].get(resource_type, 0) + int(cnt or 0)
        except Exception:
            continue

    name_map: Dict[str, str] = {}
    try:
        cached_rows = getattr(session, "global_compartment_list", None) or []
        for r in cached_rows:
            if not isinstance(r, dict):
                continue
            cid = str(r.get("compartment_id") or r.get("id") or "").strip()
            name = str(r.get("name") or r.get("display_name") or "").strip()
            if cid and name and cid not in name_map:
                name_map[cid] = name
    except Exception:
        pass

    missing = [cid for cid in target_cids if isinstance(cid, str) and cid and cid not in name_map]
    if missing:
        try:
            rows_db = session.get_resource_fields(
                "resource_compartments",
                columns=["compartment_id", "id", "name", "display_name"],
            ) or []
            for r in rows_db:
                if not isinstance(r, dict):
                    continue
                cid = str(r.get("compartment_id") or r.get("id") or "").strip()
                name = str(r.get("name") or r.get("display_name") or "").strip()
                if cid and name and cid not in name_map:
                    name_map[cid] = name
        except Exception:
            pass

    rows = [
        {
            "compartment_name": name_map.get(cid, ""),
            "compartment_id": cid,
            "resource_count": counts.get(cid, 0),
        }
        for cid in target_cids
    ]
    rows.sort(key=lambda r: str(r.get("compartment_id", "")))
    return {"totals": rows, "detailed": detailed}


def print_compartment_tree(session, target_cids: List[str]) -> None:
    rows = getattr(session, "global_compartment_list", None) or []
    if not rows:
        return

    row_by_id: Dict[str, Dict[str, Any]] = {}
    for r in rows:
        if not isinstance(r, dict):
            continue
        cid = str(r.get("compartment_id") or r.get("id") or "").strip()
        if not cid:
            continue
        row_by_id[cid] = r

    target_set = {c for c in (target_cids or []) if isinstance(c, str) and c in row_by_id}
    if not target_set:
        return

    def _normalized_parent(r: Dict[str, Any]) -> Optional[str]:
        pid = r.get("parent_compartment_id")
        if isinstance(pid, str) and pid.strip().upper() == "N/A":
            return None
        return pid if isinstance(pid, str) and pid else None

    # Include ancestors for context so the tree shape matches compartment views.
    parent_by_id = {cid: (_normalized_parent(r) or "") for cid, r in row_by_id.items()}
    include_ids = set(target_set)
    for cid in target_set:
        include_ids.update(_hierarchy.ancestor_chain(parent_by_id, cid))

    nodes: Dict[str, Dict[str, Any]] = {}
    children: Dict[Optional[str], List[str]] = {}
    for cid in include_ids:
        r = row_by_id.get(cid) or {}
        pid = _normalized_parent(r)
        if pid is not None and pid not in include_ids:
            pid = None
        name = str(r.get("name") or r.get("display_name") or cid)
        is_tenant = UtilityTools.is_tenancy_ocid(cid)
        nodes[cid] = {"id": cid, "name": name, "parent": pid, "is_tenant": is_tenant}
        children.setdefault(pid, []).append(cid)

    for pid in list(children.keys()):
        children[pid] = sorted(children[pid], key=lambda c: str(nodes[c].get("name", "")).lower())

    roots = [cid for cid, n in nodes.items() if n.get("parent") is None or n.get("is_tenant")]
    roots = sorted(roots, key=lambda c: str(nodes[c].get("name", "")).lower())

    def label_of(cid: str) -> str:
        node = nodes[cid]
        base = f"{node['name']} ({node['id']})"
        if node.get("is_tenant"):
            base = f"{UtilityTools.BOLD}{UtilityTools.CYAN}{base} [TENANCY]{UtilityTools.RESET}"
        return base

    print("\n[*] Compartments/Tenancy Tree (scanned scope)")
    for ri, root in enumerate(roots):
        for line in _hierarchy.render_tree_lines([root], children, label_of):
            print(line)
        if ri < len(roots) - 1:
            print()
