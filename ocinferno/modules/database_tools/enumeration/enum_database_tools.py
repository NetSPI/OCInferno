#!/usr/bin/env python3
from __future__ import annotations

from ocinferno.core.utils.enum_framework import Component, run_components
from ocinferno.modules.database_tools.utilities.helpers import (
    DatabaseToolsConnectionsResource,
    DatabaseToolsPrivateEndpointsResource,
)

COMPONENTS = [
    Component("connections", DatabaseToolsConnectionsResource, help_text="Enumerate Database Tools connections", cache_table="database_tools_connections"),
    Component("private_endpoints", DatabaseToolsPrivateEndpointsResource, help_text="Enumerate Database Tools private endpoints", cache_table="database_tools_private_endpoints"),
]


def run_module(user_args, session):
    return run_components(
        user_args, session, COMPONENTS,
        module_name="enum_database_tools",
        description="Enumerate Database Tools resources",
    )
