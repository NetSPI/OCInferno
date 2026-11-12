#!/usr/bin/env python3
from __future__ import annotations

import oci

from ocinferno.core.resource import OciListResource


class DatabasesAutonomousResource(OciListResource):
    """Autonomous Databases (ADB) via oci.database. High value: --get exposes
    connection_strings / connection_urls (APEX, SQL Dev Web, database console)."""

    CLIENT_CLS = oci.database.DatabaseClient
    SERVICE_NAME = "Database"
    TABLE_NAME = "db_autonomous_databases"
    LIST_METHOD = "list_autonomous_databases"
    GET_METHOD = "get_autonomous_database"
    GET_ID_PARAM = "autonomous_database_id"
    COLUMNS = ["id", "display_name", "db_name", "lifecycle_state", "db_workload", "is_free_tier", "time_created"]


class DatabasesDbSystemsResource(OciListResource):
    """Base Database Service DB Systems (VM/BM/Exadata) via oci.database. --get
    exposes shape, hostname, listener/scan details, and licensing."""

    CLIENT_CLS = oci.database.DatabaseClient
    SERVICE_NAME = "Database"
    TABLE_NAME = "db_db_systems"
    LIST_METHOD = "list_db_systems"
    GET_METHOD = "get_db_system"
    GET_ID_PARAM = "db_system_id"
    COLUMNS = ["id", "display_name", "lifecycle_state", "shape", "database_edition", "hostname", "time_created"]
