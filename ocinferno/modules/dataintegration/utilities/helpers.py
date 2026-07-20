#!/usr/bin/env python3
from __future__ import annotations

import oci

from ocinferno.core.resource import OciListResource


class DataIntegrationWorkspacesResource(OciListResource):
    CLIENT_CLS = oci.data_integration.DataIntegrationClient
    SERVICE_NAME = "DataIntegration"
    TABLE_NAME = "data_integration_workspaces"
    LIST_METHOD = "list_workspaces"
    GET_METHOD = "get_workspace"
    GET_ID_PARAM = "workspace_id"
    COLUMNS = [
        "id",
        "display_name",
        "lifecycle_state",
        "time_created",
        "compartment_id",
        "description",
        "vcn_id",
        "subnet_id",
        "endpoint_name",
        "endpoint_id",
        "is_private_network_enabled",
        "dns_server_ip",
    ]
