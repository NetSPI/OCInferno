#!/usr/bin/env python3
from __future__ import annotations

import oci

from ocinferno.core.resource import OciListResource


class BdsInstancesResource(OciListResource):
    CLIENT_CLS = oci.bds.BdsClient
    SERVICE_NAME = "Big Data"
    TABLE_NAME = "bds_instances"
    LIST_METHOD = "list_bds_instances"
    GET_METHOD = "get_bds_instance"
    GET_ID_PARAM = "bds_instance_id"
    COLUMNS = [
        "id",
        "display_name",
        "lifecycle_state",
        "time_created",
        "compartment_id",
        "cluster_version",
        "number_of_nodes",
        "is_high_availability",
        "is_secure",
        "is_cloud_sql_configured",
        "is_kafka_configured",
        "cluster_profile",
        "network_config",
        "kms_key_id",
        "secret_id",
        "bootstrap_script_url",
        "cloud_sql_details",
        "cluster_details",
        "created_by",
        "time_updated",
    ]
