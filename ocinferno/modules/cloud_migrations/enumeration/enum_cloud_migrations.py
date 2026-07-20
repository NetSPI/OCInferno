#!/usr/bin/env python3
from __future__ import annotations

from ocinferno.core.utils.enum_framework import Component, run_components
from ocinferno.modules.cloud_migrations.utilities.helpers import (
    CloudMigrationsMigrationsResource,
)

COMPONENTS = [
    Component("migrations", CloudMigrationsMigrationsResource, help_text="Enumerate migrations", cache_table="cloud_migrations_migrations"),
]


def run_module(user_args, session):
    return run_components(
        user_args, session, COMPONENTS,
        module_name="enum_cloud_migrations",
        description="Enumerate Cloud Migrations resources",
    )
