#!/usr/bin/env python3
from __future__ import annotations

from ocinferno.core.utils.enum_framework import Component, run_components
from ocinferno.modules.management_agent.utilities.helpers import (
    ManagementAgentAgentsResource,
    ManagementAgentInstallKeysResource,
)

COMPONENTS = [
    Component("agents", ManagementAgentAgentsResource, help_text="Enumerate management agents", cache_table="management_agent_agents"),
    Component("install_keys", ManagementAgentInstallKeysResource, help_text="Enumerate management agent install keys", cache_table="management_agent_install_keys"),
]


def run_module(user_args, session):
    return run_components(
        user_args, session, COMPONENTS,
        module_name="enum_management_agent",
        description="Enumerate Management Agent resources",
    )
