#!/usr/bin/env python3
from __future__ import annotations

from ocinferno.core.utils.enum_framework import Component, run_components
from ocinferno.modules.resourcescheduler.utilities.helpers import ResourceSchedulesResource

COMPONENTS = [
    Component("schedules", ResourceSchedulesResource, help_text="Enumerate schedules", cache_table="resource_schedules"),
]


def run_module(user_args, session):
    return run_components(
        user_args, session, COMPONENTS,
        module_name="enum_resource_schedules",
        description="Enumerate OCI Resource Scheduler Schedules",
    )
