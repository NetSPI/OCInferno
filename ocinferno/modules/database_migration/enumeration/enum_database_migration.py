#!/usr/bin/env python3
from __future__ import annotations

from ocinferno.core.utils.enum_framework import Component, run_components
from ocinferno.modules.database_migration.utilities.helpers import (
    DatabaseMigrationConnectionsResource,
    DatabaseMigrationMigrationsResource,
)

COMPONENTS = [
    Component("connections", DatabaseMigrationConnectionsResource, help_text="Enumerate connections", cache_table="database_migration_connections"),
    Component("migrations", DatabaseMigrationMigrationsResource, help_text="Enumerate migrations", cache_table="database_migration_migrations"),
]


def run_module(user_args, session):
    return run_components(
        user_args, session, COMPONENTS,
        module_name="enum_database_migration",
        description="Enumerate Database Migration resources",
    )
