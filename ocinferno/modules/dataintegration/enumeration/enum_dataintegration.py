#!/usr/bin/env python3
from __future__ import annotations

from ocinferno.core.utils.enum_framework import Component, run_components
from ocinferno.modules.dataintegration.utilities.helpers import DataIntegrationWorkspacesResource

COMPONENTS = [
    Component("workspaces", DataIntegrationWorkspacesResource, help_text="Enumerate workspaces", cache_table="data_integration_workspaces"),
]


def run_module(user_args, session):
    return run_components(
        user_args, session, COMPONENTS,
        module_name="enum_dataintegration",
        description="Enumerate Data Integration resources",
    )
