#!/usr/bin/env python3
from __future__ import annotations

import oci

from ocinferno.core.resource import OciListResource


class ApiAccessControlControlsResource(OciListResource):
    CLIENT_CLS = oci.apiaccesscontrol.PrivilegedApiControlClient
    SERVICE_NAME = "Privileged API Access Control"
    TABLE_NAME = "apiaccesscontrol_controls"
    LIST_METHOD = "list_privileged_api_controls"
    GET_METHOD = "get_privileged_api_control"
    GET_ID_PARAM = "privileged_api_control_id"
    COLUMNS = [
        "id",
        "display_name",
        "lifecycle_state",
        "time_created",
        "compartment_id",
        "resource_type",
        "number_of_approvers",
        "lifecycle_details",
        "time_updated",
    ]


class ApiAccessControlRequestsResource(OciListResource):
    CLIENT_CLS = oci.apiaccesscontrol.PrivilegedApiRequestsClient
    SERVICE_NAME = "Privileged API Access Control"
    TABLE_NAME = "apiaccesscontrol_requests"
    LIST_METHOD = "list_privileged_api_requests"
    GET_METHOD = "get_privileged_api_request"
    GET_ID_PARAM = "privileged_api_request_id"
    COLUMNS = [
        "id",
        "display_name",
        "lifecycle_state",
        "time_created",
        "compartment_id",
        "resource_id",
        "resource_type",
        "resource_name",
        "privileged_operation_list",
        "state",
        "severity",
        "duration_in_hrs",
    ]
