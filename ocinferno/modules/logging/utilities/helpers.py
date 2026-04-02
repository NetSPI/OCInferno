from __future__ import annotations

from typing import Any, Dict, List, Optional

import oci
from ocinferno.core.utils.service_runtime import _init_client


def build_logging_client(session, region: Optional[str] = None):
    """Build a configured OCI Logging Management client."""
    client = _init_client(
        oci.logging.LoggingManagementClient,
        session=session,
        service_name="Logging",
    )
    target_region = region or getattr(session, "region", None)
    if target_region:
        try:
            client.base_client.set_region(target_region)
        except Exception:
            pass
    return client


class LoggingLogGroupsResource:
    TABLE_NAME = "logging_log_groups"
    COLUMNS = ["id", "display_name", "lifecycle_state", "time_created"]

    def __init__(self, session, region: Optional[str] = None):
        self.session = session
        self.client = build_logging_client(session=session, region=region)

    # List log groups in a compartment.
    def list(self, *, compartment_id: str) -> List[Dict[str, Any]]:
        resp = oci.pagination.list_call_get_all_results(
            self.client.list_log_groups,
            compartment_id=compartment_id,
        )
        return oci.util.to_dict(resp.data) or []

    # Get one log group by OCID.
    def get(self, *, log_group_id: str) -> Dict[str, Any]:
        resp = self.client.get_log_group(log_group_id=log_group_id)
        return oci.util.to_dict(resp.data) or {}

    # Save log group rows.
    def save(self, rows: List[Dict[str, Any]]) -> None:
        self.session.save_resources(rows or [], self.TABLE_NAME)


class LoggingLogsResource:
    TABLE_NAME = "logging_logs"
    COLUMNS = ["id", "display_name", "lifecycle_state", "log_type", "time_created", "log_group_id"]

    def __init__(self, session, region: Optional[str] = None):
        self.session = session
        self.client = build_logging_client(session=session, region=region)

    # List logs under one log group.
    def list(self, *, log_group_id: str) -> List[Dict[str, Any]]:
        resp = oci.pagination.list_call_get_all_results(
            self.client.list_logs,
            log_group_id=log_group_id,
        )
        return oci.util.to_dict(resp.data) or []

    # Get one log by OCID.
    def get(self, *, log_group_id: str, log_id: str) -> Dict[str, Any]:
        resp = self.client.get_log(log_group_id=log_group_id, log_id=log_id)
        return oci.util.to_dict(resp.data) or {}

    # Save log rows.
    def save(self, rows: List[Dict[str, Any]]) -> None:
        self.session.save_resources(rows or [], self.TABLE_NAME)
