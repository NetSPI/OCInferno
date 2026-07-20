#!/usr/bin/env python3
from __future__ import annotations

import oci

from ocinferno.core.resource import OciListResource


class OdaInstancesResource(OciListResource):
    CLIENT_CLS = oci.oda.OdaClient
    SERVICE_NAME = "Digital Assistant"
    TABLE_NAME = "oda_instances"
    LIST_METHOD = "list_oda_instances"
    GET_METHOD = "get_oda_instance"
    GET_ID_PARAM = "oda_instance_id"
    COLUMNS = [
        "id",
        "display_name",
        "description",
        "lifecycle_state",
        "time_created",
        "compartment_id",
        "shape_name",
        "connector_url",
        "web_app_url",
        "is_role_based_access",
        "identity_domain",
    ]
