from __future__ import annotations

from typing import Any, Dict, List, Optional

import oci
from ocinferno.core.resource import OciListResource
from ocinferno.core.utils.service_runtime import _init_client
from ocinferno.core.utils.service_runtime import ResourceBase


def build_logging_client(session, region: Optional[str] = None):
    """Build a configured OCI Logging Management client."""
    return _init_client(
        oci.logging.LoggingManagementClient,
        session=session,
        service_name="Logging",
        region=region,
    )


class LoggingLogGroupsResource(OciListResource):
    CLIENT_CLS = oci.logging.LoggingManagementClient
    SERVICE_NAME = "Logging"
    LIST_METHOD = "list_log_groups"
    GET_METHOD = "get_log_group"
    GET_ID_PARAM = "log_group_id"
    TABLE_NAME = "logging_log_groups"
    COLUMNS = ["id", "display_name", "lifecycle_state", "time_created"]


class LoggingLogsResource(ResourceBase):
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
