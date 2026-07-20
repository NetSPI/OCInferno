#!/usr/bin/env python3
from __future__ import annotations

import oci

from ocinferno.core.resource import OciListResource


class VisualBuilderInstancesResource(OciListResource):
    CLIENT_CLS = oci.visual_builder.VbInstanceClient
    SERVICE_NAME = "Visual Builder"
    TABLE_NAME = "visual_builder_instances"
    LIST_METHOD = "list_vb_instances"
    GET_METHOD = "get_vb_instance"
    GET_ID_PARAM = "vb_instance_id"
    COLUMNS = [
        "id",
        "display_name",
        "lifecycle_state",
        "time_created",
        "compartment_id",
        "instance_url",
        "node_count",
        "is_visual_builder_enabled",
        "state_message",
        "network_endpoint_details",
        "consumption_model",
    ]
