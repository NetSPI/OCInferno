#!/usr/bin/env python3
from __future__ import annotations

from ocinferno.core.utils.enum_framework import Component, run_components
from ocinferno.modules.integration.utilities.helpers import IntegrationInstancesResource

COMPONENTS = [
    Component("integration_instances", IntegrationInstancesResource, help_text="Enumerate integration-instances", cache_table="integration_instances"),
]


def run_module(user_args, session):
    return run_components(
        user_args, session, COMPONENTS,
        module_name="enum_integration",
        description="Enumerate Integration Cloud (OIC) resources",
    )
