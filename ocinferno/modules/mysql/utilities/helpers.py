#!/usr/bin/env python3
from __future__ import annotations

import oci

from ocinferno.core.resource import OciListResource


class MysqlDbSystemsResource(OciListResource):
    CLIENT_CLS = oci.mysql.DbSystemClient
    SERVICE_NAME = "MySQL"
    TABLE_NAME = "mysql_db_systems"
    LIST_METHOD = "list_db_systems"
    GET_METHOD = "get_db_system"
    GET_ID_PARAM = "db_system_id"
    COLUMNS = [
        "id",
        "display_name",
        "lifecycle_state",
        "time_created",
        "compartment_id",
        "mysql_version",
        "is_highly_available",
        "endpoints",
        # These fields are only available with --get (absent from DbSystemSummary):
        "subnet_id",
        "ip_address",
        "port",
        "data_storage_size_in_gbs",
        "is_heat_wave_cluster_attached",
    ]
