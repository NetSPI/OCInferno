#!/usr/bin/env python3
from __future__ import annotations

import oci

from ocinferno.core.resource import OciListResource


class OperatorAccessControlControlsResource(OciListResource):
    CLIENT_CLS = oci.operator_access_control.OperatorControlClient
    SERVICE_NAME = "Operator Access Control"
    TABLE_NAME = "oac_operator_controls"
    LIST_METHOD = "list_operator_controls"
    GET_METHOD = "get_operator_control"
    GET_ID_PARAM = "operator_control_id"
    COLUMNS = [
        "id",
        "operator_control_name",
        "lifecycle_state",
        "time_of_creation",
        "compartment_id",
        "is_fully_pre_approved",
        "resource_type",
        "number_of_approvers",
    ]


class OperatorAccessControlAssignmentsResource(OciListResource):
    CLIENT_CLS = oci.operator_access_control.OperatorControlAssignmentClient
    SERVICE_NAME = "Operator Access Control"
    TABLE_NAME = "oac_operator_control_assignments"
    LIST_METHOD = "list_operator_control_assignments"
    GET_METHOD = "get_operator_control_assignment"
    GET_ID_PARAM = "operator_control_assignment_id"
    COLUMNS = [
        "id",
        "resource_name",
        "lifecycle_state",
        "time_of_assignment",
        "compartment_id",
        "operator_control_id",
        "resource_id",
        "resource_type",
        "op_control_name",
        "is_enforced_always",
        "is_log_forwarded",
    ]


class OperatorAccessControlAccessRequestsResource(OciListResource):
    CLIENT_CLS = oci.operator_access_control.AccessRequestsClient
    SERVICE_NAME = "Operator Access Control"
    TABLE_NAME = "oac_access_requests"
    LIST_METHOD = "list_access_requests"
    GET_METHOD = "get_access_request"
    GET_ID_PARAM = "access_request_id"
    COLUMNS = [
        "id",
        "resource_name",
        "lifecycle_state",
        "time_of_creation",
        "compartment_id",
        "request_id",
        "resource_id",
        "resource_type",
        "access_reason_summary",
        "severity",
        "is_auto_approved",
        "duration",
    ]
