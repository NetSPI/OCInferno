from __future__ import annotations

from typing import Any, Dict, List, Optional

import oci
from ocinferno.core.utils.service_runtime import _init_client


def build_dataflow_client(session, region: Optional[str] = None):
    """Initialize a Data Flow client with shared signer/proxy/session behavior."""
    client = _init_client(
        oci.data_flow.DataFlowClient,
        session=session,
        service_name="DataFlow",
    )
    target_region = region or getattr(session, "region", None)
    if target_region:
        try:
            client.base_client.set_region(target_region)
        except Exception:
            pass
    return client


class DataFlowApplicationsResource:
    TABLE_NAME = "dataflow_applications"
    COLUMNS = ["id", "display_name", "lifecycle_state", "time_created"]

    def __init__(self, session, region: Optional[str] = None):
        self.session = session
        self.client = build_dataflow_client(session=session, region=region)

    # List applications in a compartment.
    def list(self, *, compartment_id: str) -> List[Dict[str, Any]]:
        resp = oci.pagination.list_call_get_all_results(self.client.list_applications, compartment_id=compartment_id)
        return oci.util.to_dict(resp.data) or []

    # Get a single application.
    def get(self, *, resource_id: str) -> Dict[str, Any]:
        return oci.util.to_dict(self.client.get_application(application_id=resource_id).data) or {}

    # Save application rows.
    def save(self, rows: List[Dict[str, Any]]) -> None:
        self.session.save_resources(rows or [], self.TABLE_NAME)


class DataFlowRunsResource:
    TABLE_NAME = "dataflow_runs"
    COLUMNS = ["id", "display_name", "lifecycle_state", "time_created"]

    def __init__(self, session, region: Optional[str] = None):
        self.session = session
        self.client = build_dataflow_client(session=session, region=region)

    # List runs in a compartment.
    def list(self, *, compartment_id: str) -> List[Dict[str, Any]]:
        resp = oci.pagination.list_call_get_all_results(self.client.list_runs, compartment_id=compartment_id)
        return oci.util.to_dict(resp.data) or []

    # Get a single run.
    def get(self, *, resource_id: str) -> Dict[str, Any]:
        return oci.util.to_dict(self.client.get_run(run_id=resource_id).data) or {}

    # Save run rows.
    def save(self, rows: List[Dict[str, Any]]) -> None:
        self.session.save_resources(rows or [], self.TABLE_NAME)


class DataFlowPoolsResource:
    TABLE_NAME = "dataflow_pools"
    COLUMNS = ["id", "display_name", "lifecycle_state", "time_created"]

    def __init__(self, session, region: Optional[str] = None):
        self.session = session
        self.client = build_dataflow_client(session=session, region=region)

    # List pools in a compartment.
    def list(self, *, compartment_id: str) -> List[Dict[str, Any]]:
        resp = oci.pagination.list_call_get_all_results(self.client.list_pools, compartment_id=compartment_id)
        return oci.util.to_dict(resp.data) or []

    # Get a single pool.
    def get(self, *, resource_id: str) -> Dict[str, Any]:
        return oci.util.to_dict(self.client.get_pool(pool_id=resource_id).data) or {}

    # Save pool rows.
    def save(self, rows: List[Dict[str, Any]]) -> None:
        self.session.save_resources(rows or [], self.TABLE_NAME)


class DataFlowPrivateEndpointsResource:
    TABLE_NAME = "dataflow_private_endpoints"
    COLUMNS = ["id", "display_name", "lifecycle_state", "time_created"]

    def __init__(self, session, region: Optional[str] = None):
        self.session = session
        self.client = build_dataflow_client(session=session, region=region)

    # List private endpoints in a compartment.
    def list(self, *, compartment_id: str) -> List[Dict[str, Any]]:
        resp = oci.pagination.list_call_get_all_results(self.client.list_private_endpoints, compartment_id=compartment_id)
        return oci.util.to_dict(resp.data) or []

    # Get one private endpoint.
    def get(self, *, resource_id: str) -> Dict[str, Any]:
        return oci.util.to_dict(self.client.get_private_endpoint(private_endpoint_id=resource_id).data) or {}

    # Save private endpoint rows.
    def save(self, rows: List[Dict[str, Any]]) -> None:
        self.session.save_resources(rows or [], self.TABLE_NAME)


class DataFlowSqlEndpointsResource:
    TABLE_NAME = "dataflow_sql_endpoints"
    COLUMNS = ["id", "display_name", "lifecycle_state", "time_created"]

    def __init__(self, session, region: Optional[str] = None):
        self.session = session
        self.client = build_dataflow_client(session=session, region=region)

    # List SQL endpoints in a compartment.
    def list(self, *, compartment_id: str) -> List[Dict[str, Any]]:
        resp = oci.pagination.list_call_get_all_results(self.client.list_sql_endpoints, compartment_id=compartment_id)
        return oci.util.to_dict(resp.data) or []

    # Get one SQL endpoint.
    def get(self, *, resource_id: str) -> Dict[str, Any]:
        return oci.util.to_dict(self.client.get_sql_endpoint(sql_endpoint_id=resource_id).data) or {}

    # Save SQL endpoint rows.
    def save(self, rows: List[Dict[str, Any]]) -> None:
        self.session.save_resources(rows or [], self.TABLE_NAME)


class DataFlowWorkRequestsResource:
    TABLE_NAME = "dataflow_work_requests"
    COLUMNS = ["id", "operation_type", "status", "time_accepted", "time_finished"]

    def __init__(self, session, region: Optional[str] = None):
        self.session = session
        self.client = build_dataflow_client(session=session, region=region)

    # List work requests in a compartment.
    def list(self, *, compartment_id: str) -> List[Dict[str, Any]]:
        resp = oci.pagination.list_call_get_all_results(self.client.list_work_requests, compartment_id=compartment_id)
        return oci.util.to_dict(resp.data) or []

    # Get one work request.
    def get(self, *, resource_id: str) -> Dict[str, Any]:
        return oci.util.to_dict(self.client.get_work_request(work_request_id=resource_id).data) or {}

    # Save work request rows.
    def save(self, rows: List[Dict[str, Any]]) -> None:
        self.session.save_resources(rows or [], self.TABLE_NAME)
