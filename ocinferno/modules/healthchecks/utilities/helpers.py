#!/usr/bin/env python3
from __future__ import annotations

import oci

from ocinferno.core.resource import OciListResource


class HealthChecksHttpMonitorsResource(OciListResource):
    CLIENT_CLS = oci.healthchecks.HealthChecksClient
    SERVICE_NAME = "Health Checks"
    TABLE_NAME = "healthchecks_http_monitors"
    LIST_METHOD = "list_http_monitors"
    GET_METHOD = "get_http_monitor"
    GET_ID_PARAM = "monitor_id"
    COLUMNS = [
        "id",
        "display_name",
        "time_created",
        "compartment_id",
        "targets",
        "protocol",
        "port",
        "path",
        "headers",
        "vantage_point_names",
        "is_enabled",
        "results_url",
    ]


class HealthChecksPingMonitorsResource(OciListResource):
    CLIENT_CLS = oci.healthchecks.HealthChecksClient
    SERVICE_NAME = "Health Checks"
    TABLE_NAME = "healthchecks_ping_monitors"
    LIST_METHOD = "list_ping_monitors"
    GET_METHOD = "get_ping_monitor"
    GET_ID_PARAM = "monitor_id"
    COLUMNS = [
        "id",
        "display_name",
        "time_created",
        "compartment_id",
        "targets",
        "protocol",
        "port",
        "vantage_point_names",
        "is_enabled",
        "results_url",
    ]
