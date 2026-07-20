#!/usr/bin/env python3
from __future__ import annotations

from ocinferno.core.utils.enum_framework import Component, run_components
from ocinferno.modules.postgresql.utilities.helpers import PostgresqlDbSystemsResource

COMPONENTS = [
    Component("db_systems", PostgresqlDbSystemsResource, help_text="Enumerate db-systems", cache_table="postgresql_db_systems"),
]


def run_module(user_args, session):
    return run_components(
        user_args, session, COMPONENTS,
        module_name="enum_postgresql",
        description="Enumerate PostgreSQL resources",
    )
