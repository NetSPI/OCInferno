from __future__ import annotations

from argparse import Namespace
from typing import Any, Dict, List, Optional

import oci
from ocinferno.core.utils.module_helpers import dedupe_strs, parse_csv_args
from ocinferno.core.utils.service_runtime import _init_client


def build_container_engine_client(session, region: Optional[str] = None):
    """Initialize a Container Engine client with shared signer/proxy/session behavior."""
    client = _init_client(
        oci.container_engine.ContainerEngineClient,
        session=session,
        service_name="ContainerEngine",
    )
    target_region = region or getattr(session, "region", None)
    if target_region:
        try:
            client.base_client.set_region(target_region)
        except Exception:
            pass
    return client


class KubernetesClustersResource:
    TABLE_NAME = "containerengine_clusters"
    COLUMNS = ["id", "name", "lifecycle_state", "kubernetes_version", "time_created"]

    def __init__(self, session, region: Optional[str] = None):
        self.session = session
        self.client = build_container_engine_client(session=session, region=region)

    # List OKE clusters in a compartment.
    def list(self, *, compartment_id: str) -> List[Dict[str, Any]]:
        resp = oci.pagination.list_call_get_all_results(self.client.list_clusters, compartment_id=compartment_id)
        return oci.util.to_dict(resp.data) or []

    # Get one OKE cluster by OCID.
    def get(self, *, resource_id: str) -> Dict[str, Any]:
        resp = self.client.get_cluster(cluster_id=resource_id, should_include_oidc_config_file=False)
        return oci.util.to_dict(resp.data) or {}

    # Save cluster rows.
    def save(self, rows: List[Dict[str, Any]]) -> None:
        self.session.save_resources(rows or [], self.TABLE_NAME)

    # No binary download endpoint for cluster rows.
    def download(self, *, resource_id: str, out_path: str) -> bool:  # pragma: no cover - placeholder
        _ = (resource_id, out_path)
        return False


class KubernetesNodePoolsResource:
    TABLE_NAME = "containerengine_node_pools"
    COLUMNS = ["id", "name", "lifecycle_state", "cluster_id", "kubernetes_version"]

    def __init__(self, session, region: Optional[str] = None):
        self.session = session
        self.client = build_container_engine_client(session=session, region=region)

    # List OKE node pools in a compartment.
    def list(self, *, compartment_id: str) -> List[Dict[str, Any]]:
        resp = oci.pagination.list_call_get_all_results(self.client.list_node_pools, compartment_id=compartment_id)
        return oci.util.to_dict(resp.data) or []

    # Get one OKE node pool by OCID.
    def get(self, *, resource_id: str) -> Dict[str, Any]:
        return oci.util.to_dict(self.client.get_node_pool(node_pool_id=resource_id).data) or {}

    # Save node-pool rows.
    def save(self, rows: List[Dict[str, Any]]) -> None:
        self.session.save_resources(rows or [], self.TABLE_NAME)

    # No binary download endpoint for node-pool rows.
    def download(self, *, resource_id: str, out_path: str) -> bool:  # pragma: no cover - placeholder
        _ = (resource_id, out_path)
        return False


class KubernetesVirtualNodePoolsResource:
    TABLE_NAME = "containerengine_virtual_node_pools"
    TABLE_VIRTUAL_NODES = "containerengine_virtual_nodes"
    COLUMNS = ["id", "name", "cluster_id", "lifecycle_state", "time_created", "endpoint_config"]
    NODE_COLUMNS = ["id", "display_name", "virtual_node_pool_id", "lifecycle_state", "time_created", "availability_domain"]

    def __init__(self, session, region: Optional[str] = None):
        self.session = session
        self.client = build_container_engine_client(session=session, region=region)

    # Resolve VNP IDs from CLI, DB cache, or current list rows.
    def resolve_vnp_ids(self, args: Namespace, pools: List[Dict[str, Any]]) -> List[str]:
        cli_ids = parse_csv_args(getattr(args, "vnp_ids", []) or [])
        if cli_ids:
            return dedupe_strs(cli_ids)

        rows = self.session.get_resource_fields(
            self.TABLE_NAME,
            where_conditions={"compartment_id": self.session.compartment_id},
        ) or []
        db_ids = [row.get("id") for row in rows if isinstance(row, dict) and row.get("id")]
        if db_ids:
            return dedupe_strs(db_ids)

        return dedupe_strs([row.get("id") for row in pools if isinstance(row, dict) and row.get("id")])

    # List virtual node pools in a compartment.
    def list(self, *, compartment_id: str) -> List[Dict[str, Any]]:
        resp = oci.pagination.list_call_get_all_results(self.client.list_virtual_node_pools, compartment_id=compartment_id)
        return oci.util.to_dict(resp.data) or []

    # Get one virtual node pool by OCID.
    def get(self, *, resource_id: str) -> Dict[str, Any]:
        return oci.util.to_dict(self.client.get_virtual_node_pool(virtual_node_pool_id=resource_id).data) or {}

    # Save virtual-node-pool rows.
    def save(self, rows: List[Dict[str, Any]]) -> None:
        self.session.save_resources(rows or [], self.TABLE_NAME)

    # List virtual nodes under one virtual node pool.
    def list_nodes(self, *, virtual_node_pool_id: str) -> List[Dict[str, Any]]:
        resp = oci.pagination.list_call_get_all_results(self.client.list_virtual_nodes, virtual_node_pool_id=virtual_node_pool_id)
        return oci.util.to_dict(resp.data) or []

    # Get one virtual node by OCID.
    def get_node(self, *, virtual_node_id: str) -> Dict[str, Any]:
        return oci.util.to_dict(self.client.get_virtual_node(virtual_node_id=virtual_node_id).data) or {}

    # Save virtual-node rows.
    def save_nodes(self, rows: List[Dict[str, Any]]) -> None:
        self.session.save_resources(rows or [], self.TABLE_VIRTUAL_NODES)

    # No binary download endpoint for virtual-node-pool rows.
    def download(self, *, resource_id: str, out_path: str) -> bool:  # pragma: no cover - placeholder
        _ = (resource_id, out_path)
        return False
