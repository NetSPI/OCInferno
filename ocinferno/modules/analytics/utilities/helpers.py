#!/usr/bin/env python3
from __future__ import annotations

import oci

from ocinferno.core.resource import OciListResource


class AnalyticsInstancesResource(OciListResource):
    CLIENT_CLS = oci.analytics.AnalyticsClient
    SERVICE_NAME = "Analytics Cloud"
    TABLE_NAME = "analytics_instances"
    LIST_METHOD = "list_analytics_instances"
    GET_METHOD = "get_analytics_instance"
    GET_ID_PARAM = "analytics_instance_id"
    COLUMNS = [
        "id",
        "name",
        "description",
        "lifecycle_state",
        "time_created",
        "compartment_id",
        "feature_set",
        "capacity",
        "network_endpoint_details",
        "service_url",
        "email_notification",
        "license_type",
        "kms_key_id",
    ]
