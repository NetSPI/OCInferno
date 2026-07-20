#!/usr/bin/env python3
from __future__ import annotations

from ocinferno.core.utils.enum_framework import Component, run_components
from ocinferno.modules.monitoring.utilities.helpers import MonitoringAlarmsResource

COMPONENTS = [
    Component("alarms", MonitoringAlarmsResource, help_text="Enumerate alarms", cache_table="monitoring_alarms"),
]


def run_module(user_args, session):
    return run_components(
        user_args, session, COMPONENTS,
        module_name="enum_monitoring",
        description="Enumerate Monitoring resources",
    )
