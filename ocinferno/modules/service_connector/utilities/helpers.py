#!/usr/bin/env python3
from __future__ import annotations

import oci

from ocinferno.core.resource import OciListResource


class ServiceConnectorServiceConnectorsResource(OciListResource):
    """OCI Service Connectors -- source->task->target data pipelines. High value:
    reveals data-movement topology and offers an exfil/persistence surface (route
    logs/streams/object-storage to pentester-controlled targets)."""

    CLIENT_CLS = oci.sch.ServiceConnectorClient
    SERVICE_NAME = "Service Connector Hub"
    TABLE_NAME = "sch_service_connectors"
    LIST_METHOD = "list_service_connectors"
    GET_METHOD = "get_service_connector"
    GET_ID_PARAM = "service_connector_id"
    COLUMNS = ["id", "display_name", "lifecycle_state", "lifecycle_details", "time_created", "source", "target", "tasks"]
