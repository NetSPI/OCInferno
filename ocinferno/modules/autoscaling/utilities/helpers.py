#!/usr/bin/env python3
from __future__ import annotations

import oci

from ocinferno.core.resource import OciListResource


class AutoscalingConfigurationsResource(OciListResource):
    CLIENT_CLS = oci.autoscaling.AutoScalingClient
    SERVICE_NAME = "Autoscaling"
    TABLE_NAME = "autoscaling_configurations"
    LIST_METHOD = "list_auto_scaling_configurations"
    GET_METHOD = "get_auto_scaling_configuration"
    GET_ID_PARAM = "auto_scaling_configuration_id"
    COLUMNS = [
        "id",
        "display_name",
        "time_created",
        "compartment_id",
        "resource",
        "is_enabled",
        "cool_down_in_seconds",
        "freeform_tags",
        "defined_tags",
    ]
