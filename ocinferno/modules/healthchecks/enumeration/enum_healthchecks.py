#!/usr/bin/env python3
from __future__ import annotations

from ocinferno.core.utils.enum_framework import Component, run_components
from ocinferno.modules.healthchecks.utilities.helpers import (
    HealthChecksHttpMonitorsResource,
    HealthChecksPingMonitorsResource,
)

COMPONENTS = [
    Component("http_monitors", HealthChecksHttpMonitorsResource, help_text="Enumerate HTTP monitors", cache_table="healthchecks_http_monitors"),
    Component("ping_monitors", HealthChecksPingMonitorsResource, help_text="Enumerate ping monitors", cache_table="healthchecks_ping_monitors"),
]


def run_module(user_args, session):
    return run_components(
        user_args, session, COMPONENTS,
        module_name="enum_healthchecks",
        description="Enumerate Health Checks resources",
    )
