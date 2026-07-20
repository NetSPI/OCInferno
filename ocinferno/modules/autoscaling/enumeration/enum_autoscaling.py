#!/usr/bin/env python3
from __future__ import annotations

from ocinferno.core.utils.enum_framework import Component, run_components
from ocinferno.modules.autoscaling.utilities.helpers import (
    AutoscalingConfigurationsResource,
)

COMPONENTS = [
    Component("autoscaling_configurations", AutoscalingConfigurationsResource, help_text="Enumerate auto-scaling configurations", cache_table="autoscaling_configurations"),
]


def run_module(user_args, session):
    return run_components(
        user_args, session, COMPONENTS,
        module_name="enum_autoscaling",
        description="Enumerate Autoscaling resources",
    )
