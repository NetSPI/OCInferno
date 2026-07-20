#!/usr/bin/env python3
from __future__ import annotations

import oci

from ocinferno.core.resource import OciListResource


class DelegateAccessControlAccessRequestsResource(OciListResource):
    CLIENT_CLS = oci.delegate_access_control.DelegateAccessControlClient
    SERVICE_NAME = "Delegate Access Control"
    TABLE_NAME = "delegate_access_control_access_requests"
    LIST_METHOD = "list_delegated_resource_access_requests"
    GET_METHOD = "get_delegated_resource_access_request"
    GET_ID_PARAM = "delegated_resource_access_request_id"
    COLUMNS = [
        "id",
        "display_name",
        "lifecycle_state",
        "time_created",
        "compartment_id",
        "resource_id",
        "resource_type",
        "requested_action_names",
        "requester_type",
        "severity",
        "request_status",
        "delegation_control_id",
    ]


class DelegateAccessControlDelegationControlsResource(OciListResource):
    CLIENT_CLS = oci.delegate_access_control.DelegateAccessControlClient
    SERVICE_NAME = "Delegate Access Control"
    TABLE_NAME = "delegate_access_control_delegation_controls"
    LIST_METHOD = "list_delegation_controls"
    GET_METHOD = "get_delegation_control"
    GET_ID_PARAM = "delegation_control_id"
    COLUMNS = [
        "id",
        "display_name",
        "lifecycle_state",
        "time_created",
        "compartment_id",
        "resource_type",
    ]


class DelegateAccessControlServiceProvidersResource(OciListResource):
    CLIENT_CLS = oci.delegate_access_control.DelegateAccessControlClient
    SERVICE_NAME = "Delegate Access Control"
    TABLE_NAME = "delegate_access_control_service_providers"
    LIST_METHOD = "list_service_providers"
    GET_METHOD = "get_service_provider"
    GET_ID_PARAM = "service_provider_id"
    COLUMNS = [
        "id",
        "name",
        "lifecycle_state",
        "time_created",
        "compartment_id",
        "service_provider_type",
        "service_types",
        "supported_resource_types",
    ]
