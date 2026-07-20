#!/usr/bin/env python3
from __future__ import annotations

from ocinferno.core.utils.enum_framework import Component, run_components
from ocinferno.modules.analytics.utilities.helpers import (
    AnalyticsInstancesResource,
)

COMPONENTS = [
    Component("instances", AnalyticsInstancesResource, help_text="Enumerate analytics instances", cache_table="analytics_instances"),
]


def run_module(user_args, session):
    return run_components(
        user_args, session, COMPONENTS,
        module_name="enum_analytics",
        description="Enumerate Analytics Cloud resources",
    )
