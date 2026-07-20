#!/usr/bin/env python3
from __future__ import annotations

import oci

from ocinferno.core.resource import OciListResource


class MonitoringAlarmsResource(OciListResource):
    CLIENT_CLS = oci.monitoring.MonitoringClient
    SERVICE_NAME = "Monitoring"
    TABLE_NAME = "monitoring_alarms"
    LIST_METHOD = "list_alarms"
    GET_METHOD = "get_alarm"
    GET_ID_PARAM = "alarm_id"
    COLUMNS = [
        "id",
        "display_name",
        "lifecycle_state",
        "compartment_id",
        "namespace",
        "query",
        "severity",
        "is_enabled",
        "destinations",
        "metric_compartment_id",
        "resource_group",
        "pending_duration",
    ]
