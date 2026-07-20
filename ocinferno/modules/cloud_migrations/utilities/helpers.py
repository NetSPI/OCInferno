#!/usr/bin/env python3
from __future__ import annotations

import oci

from ocinferno.core.resource import OciListResource


class CloudMigrationsMigrationsResource(OciListResource):
    CLIENT_CLS = oci.cloud_migrations.MigrationClient
    SERVICE_NAME = "Cloud Migrations"
    TABLE_NAME = "cloud_migrations_migrations"
    LIST_METHOD = "list_migrations"
    GET_METHOD = "get_migration"
    GET_ID_PARAM = "migration_id"
    COLUMNS = [
        "id",
        "display_name",
        "lifecycle_state",
        "time_created",
        "compartment_id",
        "migration_type",
        "is_completed",
        "replication_schedule_id",
        "lifecycle_details",
        "time_updated",
    ]
