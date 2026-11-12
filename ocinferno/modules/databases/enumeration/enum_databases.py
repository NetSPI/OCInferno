#!/usr/bin/env python3
from __future__ import annotations

from ocinferno.core.utils.enum_framework import Component, run_components
from ocinferno.modules.databases.utilities.helpers import (
    DatabasesAutonomousResource,
    DatabasesDbSystemsResource,
)

COMPONENTS = [
    Component("autonomous_databases", DatabasesAutonomousResource,
              help_text="Enumerate Autonomous Databases (ADB)", cache_table="db_autonomous_databases"),
    Component("db_systems", DatabasesDbSystemsResource,
              help_text="Enumerate Base Database DB Systems (VM/BM/Exadata)", cache_table="db_db_systems"),
]


def run_module(user_args, session):
    return run_components(user_args, session, COMPONENTS,
                         module_name="enum_databases",
                         description="Enumerate Databases resources")
