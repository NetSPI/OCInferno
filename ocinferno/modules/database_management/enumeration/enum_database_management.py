#!/usr/bin/env python3
from __future__ import annotations

from ocinferno.core.utils.enum_framework import Component, run_components
from ocinferno.modules.database_management.utilities.helpers import (
    DatabaseManagementCloudDbSystemsResource,
    DatabaseManagementManagedDatabasesResource,
    DatabaseManagementNamedCredentialsResource,
    DatabaseManagementPrivateEndpointsResource,
)

COMPONENTS = [
    Component("named_credentials", DatabaseManagementNamedCredentialsResource, help_text="Enumerate named credentials (stored DB credential references)", cache_table="dbmgmt_named_credentials"),
    Component("managed_databases", DatabaseManagementManagedDatabasesResource, help_text="Enumerate managed databases", cache_table="dbmgmt_managed_databases"),
    Component("cloud_db_systems", DatabaseManagementCloudDbSystemsResource, help_text="Enumerate cloud DB systems", cache_table="dbmgmt_cloud_db_systems"),
    Component("private_endpoints", DatabaseManagementPrivateEndpointsResource, help_text="Enumerate DB management private endpoints", cache_table="dbmgmt_private_endpoints"),
]


def run_module(user_args, session):
    return run_components(
        user_args, session, COMPONENTS,
        module_name="enum_database_management",
        description="Enumerate Database Management resources",
    )
