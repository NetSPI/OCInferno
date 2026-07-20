#!/usr/bin/env python3
from __future__ import annotations

import oci

from ocinferno.core.resource import OciListResource


class DatabaseMigrationConnectionsResource(OciListResource):
    CLIENT_CLS = oci.database_migration.DatabaseMigrationClient
    SERVICE_NAME = "Database Migration"
    TABLE_NAME = "database_migration_connections"
    LIST_METHOD = "list_connections"
    GET_METHOD = "get_connection"
    GET_ID_PARAM = "connection_id"
    COLUMNS = [
        "id",
        "display_name",
        "lifecycle_state",
        "time_created",
        "compartment_id",
        "connection_type",
        "vault_id",
        "key_id",
        "subnet_id",
        "nsg_ids",
        "ingress_ips",
    ]


class DatabaseMigrationMigrationsResource(OciListResource):
    CLIENT_CLS = oci.database_migration.DatabaseMigrationClient
    SERVICE_NAME = "Database Migration"
    TABLE_NAME = "database_migration_migrations"
    LIST_METHOD = "list_migrations"
    GET_METHOD = "get_migration"
    GET_ID_PARAM = "migration_id"
    COLUMNS = [
        "id",
        "display_name",
        "lifecycle_state",
        "time_created",
        "compartment_id",
        "type",
        "database_combination",
        "source_database_connection_id",
        "target_database_connection_id",
        "executing_job_id",
        "assessment_id",
    ]
