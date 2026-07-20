#!/usr/bin/env python3
from __future__ import annotations

import oci

from ocinferno.core.resource import OciListResource


class WlmsWlsDomainsResource(OciListResource):
    CLIENT_CLS = oci.wlms.WeblogicManagementServiceClient
    SERVICE_NAME = "WebLogic Management"
    TABLE_NAME = "wlms_wls_domains"
    LIST_METHOD = "list_wls_domains"
    GET_METHOD = "get_wls_domain"
    GET_ID_PARAM = "wls_domain_id"
    COLUMNS = [
        "id",
        "display_name",
        "lifecycle_state",
        "time_created",
        "compartment_id",
        "middleware_type",
        "weblogic_version",
        "patch_readiness_status",
        "lifecycle_details",
    ]


class WlmsManagedInstancesResource(OciListResource):
    CLIENT_CLS = oci.wlms.WeblogicManagementServiceClient
    SERVICE_NAME = "WebLogic Management"
    TABLE_NAME = "wlms_managed_instances"
    LIST_METHOD = "list_managed_instances"
    GET_METHOD = "get_managed_instance"
    GET_ID_PARAM = "managed_instance_id"
    COLUMNS = [
        "id",
        "display_name",
        "time_created",
        "compartment_id",
        "host_name",
        "server_count",
        "plugin_status",
    ]
