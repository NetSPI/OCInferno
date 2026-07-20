#!/usr/bin/env python3
from __future__ import annotations

import oci

from ocinferno.core.resource import OciListResource


class IntegrationInstancesResource(OciListResource):
    CLIENT_CLS = oci.integration.IntegrationInstanceClient
    SERVICE_NAME = "IntegrationCloud"
    TABLE_NAME = "integration_instances"
    LIST_METHOD = "list_integration_instances"
    GET_METHOD = "get_integration_instance"
    GET_ID_PARAM = "integration_instance_id"
    COLUMNS = [
        "id",
        "display_name",
        "lifecycle_state",
        "time_created",
        "compartment_id",
        "integration_instance_type",
        "instance_url",
        "message_packs",
        "is_byol",
        "is_visual_builder_enabled",
        "network_endpoint_details",
        "is_file_server_enabled",
        "shape",
    ]
