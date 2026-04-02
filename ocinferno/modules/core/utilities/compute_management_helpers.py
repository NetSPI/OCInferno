#!/usr/bin/env python3
from __future__ import annotations

from typing import Any, Dict, List, Optional

import oci
from ocinferno.core.utils.module_helpers import fill_missing_fields
from ocinferno.core.utils.service_runtime import _init_client


class ComputeManagementResourceClient:
    """
    Reusable wrapper for OCI Compute Management via oci.core.ComputeManagementClient.

    Pattern:
      - list_* returns list[dict]
      - get_* returns dict
      - enum modules decide what to store
    """

    TABLE_INSTANCE_CONFIGS = "compute_instance_configurations"
    TABLE_INSTANCE_POOLS = "compute_instance_pools"
    TABLE_CLUSTER_NETWORKS = "compute_cluster_networks"
    TABLE_COMPUTE_CLUSTERS = "compute_compute_clusters"

    def __init__(self, session, region: Optional[str] = None):
        self.session = session
        self.client = _init_client(
            oci.core.ComputeManagementClient,
            session=session,
            service_name="Compute Management",
        )

        if region:
            try:
                self.client.base_client.set_region(region)
            except Exception:
                pass
        elif getattr(session, "region", None):
            try:
                self.client.base_client.set_region(session.region)
            except Exception:
                pass

    # --------------------
    # Instance Configurations
    # --------------------
    def list_instance_configurations(self, *, compartment_id: str) -> List[Dict[str, Any]]:
        resp = oci.pagination.list_call_get_all_results(
            self.client.list_instance_configurations,
            compartment_id=compartment_id,
        )
        return oci.util.to_dict(resp.data) or []

    def get_instance_configuration(self, *, instance_configuration_id: str) -> Dict[str, Any]:
        resp = self.client.get_instance_configuration(instance_configuration_id=instance_configuration_id)
        return oci.util.to_dict(resp.data) or {}

    # --------------------
    # Instance Pools
    # --------------------
    def list_instance_pools(self, *, compartment_id: str) -> List[Dict[str, Any]]:
        resp = oci.pagination.list_call_get_all_results(
            self.client.list_instance_pools,
            compartment_id=compartment_id,
        )
        return oci.util.to_dict(resp.data) or []

    def get_instance_pool(self, *, instance_pool_id: str) -> Dict[str, Any]:
        resp = self.client.get_instance_pool(instance_pool_id=instance_pool_id)
        return oci.util.to_dict(resp.data) or {}

    # --------------------
    # Cluster Networks
    # --------------------
    def list_cluster_networks(self, *, compartment_id: str) -> List[Dict[str, Any]]:
        resp = oci.pagination.list_call_get_all_results(
            self.client.list_cluster_networks,
            compartment_id=compartment_id,
        )
        return oci.util.to_dict(resp.data) or []

    def get_cluster_network(self, *, cluster_network_id: str) -> Dict[str, Any]:
        resp = self.client.get_cluster_network(cluster_network_id=cluster_network_id)
        return oci.util.to_dict(resp.data) or {}

    # --------------------
    # Compute Clusters
    # --------------------
    def list_compute_clusters(self, *, compartment_id: str) -> List[Dict[str, Any]]:
        if not hasattr(self.client, "list_compute_clusters"):
            return []
        resp = oci.pagination.list_call_get_all_results(
            self.client.list_compute_clusters,
            compartment_id=compartment_id,
        )
        return oci.util.to_dict(resp.data) or []

    def get_compute_cluster(self, *, compute_cluster_id: str) -> Dict[str, Any]:
        resp = self.client.get_compute_cluster(compute_cluster_id=compute_cluster_id)
        return oci.util.to_dict(resp.data) or {}


fill_missing = fill_missing_fields
