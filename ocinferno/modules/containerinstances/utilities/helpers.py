from __future__ import annotations

from typing import Any, Dict, List, Optional

import oci
from ocinferno.core.utils.service_runtime import _init_client


def build_container_instances_client(session, region: Optional[str] = None):
    """Build a configured OCI Container Instances client."""
    client = _init_client(
        oci.container_instances.ContainerInstanceClient,
        session=session,
        service_name="ContainerInstances",
    )
    target_region = region or getattr(session, "region", None)
    if target_region:
        try:
            client.base_client.set_region(target_region)
        except Exception:
            pass
    return client


class ContainerInstancesResource:
    TABLE_NAME = "container_instances"
    COLUMNS = ["id", "display_name", "lifecycle_state", "time_created"]

    def __init__(self, session, region: Optional[str] = None):
        self.session = session
        self.client = build_container_instances_client(session=session, region=region)

    # List container instances in a compartment.
    def list(self, *, compartment_id: str) -> List[Dict[str, Any]]:
        resp = oci.pagination.list_call_get_all_results(
            self.client.list_container_instances,
            compartment_id=compartment_id,
        )
        return oci.util.to_dict(resp.data) or []

    # Get one container instance by OCID.
    def get(self, *, container_instance_id: str) -> Dict[str, Any]:
        resp = self.client.get_container_instance(container_instance_id=container_instance_id)
        return oci.util.to_dict(resp.data) or {}

    # Persist container instances to the service table.
    def save(self, rows: List[Dict[str, Any]]) -> None:
        self.session.save_resources(rows or [], self.TABLE_NAME)
