#!/usr/bin/env python3
from __future__ import annotations

import oci

from ocinferno.core.resource import OciListResource


class PostgresqlDbSystemsResource(OciListResource):
    CLIENT_CLS = oci.psql.PostgresqlClient
    SERVICE_NAME = "PostgreSQL"
    TABLE_NAME = "postgresql_db_systems"
    LIST_METHOD = "list_db_systems"
    GET_METHOD = "get_db_system"
    GET_ID_PARAM = "db_system_id"
    COLUMNS = [
        "id",
        "display_name",
        "lifecycle_state",
        "time_created",
        "compartment_id",
        "db_version",
        "instance_count",
        "shape",
        "network_details",
        "admin_username",
        "storage_details",
        "system_type",
    ]
