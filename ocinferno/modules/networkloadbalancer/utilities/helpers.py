#!/usr/bin/env python3
from __future__ import annotations

from typing import Any, Dict, List, Optional

import oci
from ocinferno.core.utils.module_helpers import fill_missing_fields
from ocinferno.core.utils.service_runtime import _init_client


def build_network_load_balancer_client(session, region: Optional[str] = None):
    """Build a configured OCI Network Load Balancer client."""
    client = _init_client(
        oci.network_load_balancer.NetworkLoadBalancerClient,
        session=session,
        service_name="Network Load Balancer",
    )
    target_region = region or getattr(session, "region", None)
    if target_region:
        try:
            client.base_client.set_region(target_region)
        except Exception:
            pass
    return client


fill_missing = fill_missing_fields


class NetworkLoadBalancersResource:
    TABLE_NAME = "network_load_balancers"
    COLUMNS = ["id", "display_name", "lifecycle_state", "subnet_id", "ip_addresses", "is_private"]

    def __init__(self, session, region: Optional[str] = None):
        self.session = session
        self.client = build_network_load_balancer_client(session=session, region=region)

    # List load balancers for a compartment.
    def list(self, *, compartment_id: str) -> List[Dict[str, Any]]:
        resp = oci.pagination.list_call_get_all_results(
            self.client.list_network_load_balancers,
            compartment_id=compartment_id,
        )
        return oci.util.to_dict(resp.data) or []

    # Get one load balancer by OCID.
    def get(self, *, nlb_id: str) -> Dict[str, Any]:
        resp = self.client.get_network_load_balancer(network_load_balancer_id=nlb_id)
        return oci.util.to_dict(resp.data) or {}

    # Save load balancer rows.
    def save(self, rows: List[Dict[str, Any]]) -> None:
        self.session.save_resources(rows or [], self.TABLE_NAME)
