#!/usr/bin/env python3
from __future__ import annotations

import oci
from ocinferno.core.resource import OciListResource


class OsManagementHubManagedInstancesResource(OciListResource):
    """OS Management Hub managed instances -- the fleet of hosts the agent manages.
    High value: each is a machine you can run packages/commands on at scale."""

    CLIENT_CLS = oci.os_management_hub.ManagedInstanceClient
    SERVICE_NAME = "OS Management Hub"
    TABLE_NAME = "osmh_managed_instances"
    LIST_METHOD = "list_managed_instances"
    GET_METHOD = "get_managed_instance"
    GET_ID_PARAM = "managed_instance_id"
    COLUMNS = ["id", "display_name", "status", "os_family", "architecture", "managed_instance_group", "time_last_boot"]


class OsManagementHubManagedInstanceGroupsResource(OciListResource):
    """OS Management Hub managed instance groups -- named fleets targeted together.
    High value: a group is a single handle to push updates/jobs across many hosts."""

    CLIENT_CLS = oci.os_management_hub.ManagedInstanceGroupClient
    SERVICE_NAME = "OS Management Hub"
    TABLE_NAME = "osmh_managed_instance_groups"
    LIST_METHOD = "list_managed_instance_groups"
    GET_METHOD = "get_managed_instance_group"
    GET_ID_PARAM = "managed_instance_group_id"
    COLUMNS = ["id", "display_name", "lifecycle_state", "os_family", "arch_type", "managed_instance_count", "time_created"]


class OsManagementHubScheduledJobsResource(OciListResource):
    """OS Management Hub scheduled jobs -- operations run against instances/groups.
    High value: a command-execution-at-scale surface (install/update/run scripts)."""

    CLIENT_CLS = oci.os_management_hub.ScheduledJobClient
    SERVICE_NAME = "OS Management Hub"
    TABLE_NAME = "osmh_scheduled_jobs"
    LIST_METHOD = "list_scheduled_jobs"
    GET_METHOD = "get_scheduled_job"
    GET_ID_PARAM = "scheduled_job_id"
    COLUMNS = ["id", "display_name", "schedule_type", "lifecycle_state", "time_next_execution", "time_created"]
