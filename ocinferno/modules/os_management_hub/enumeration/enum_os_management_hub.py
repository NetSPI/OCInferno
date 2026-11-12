#!/usr/bin/env python3
from __future__ import annotations

from ocinferno.core.utils.enum_framework import Component, run_components
from ocinferno.modules.os_management_hub.utilities.helpers import (
    OsManagementHubManagedInstanceGroupsResource,
    OsManagementHubManagedInstancesResource,
    OsManagementHubScheduledJobsResource,
)

COMPONENTS = [
    Component("managed_instances", OsManagementHubManagedInstancesResource,
              help_text="Enumerate managed instances (fleet of hosts you can run commands on)",
              cache_table="osmh_managed_instances"),
    Component("managed_instance_groups", OsManagementHubManagedInstanceGroupsResource,
              help_text="Enumerate managed instance groups (fleet handles)",
              cache_table="osmh_managed_instance_groups"),
    Component("scheduled_jobs", OsManagementHubScheduledJobsResource,
              help_text="Enumerate scheduled jobs (command-exec-at-scale surface)",
              cache_table="osmh_scheduled_jobs"),
]


def run_module(user_args, session):
    return run_components(user_args, session, COMPONENTS,
                         module_name="enum_os_management_hub",
                         description="Enumerate OS Management Hub resources")
