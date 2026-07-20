#!/usr/bin/env python3
from __future__ import annotations

from ocinferno.core.utils.enum_framework import Component, run_components
from ocinferno.modules.goldengate.utilities.helpers import (
    GoldenGateConnectionsResource,
    GoldenGateDeploymentsResource,
)

COMPONENTS = [
    Component("deployments", GoldenGateDeploymentsResource, help_text="Enumerate deployments", cache_table="goldengate_deployments"),
    Component("connections", GoldenGateConnectionsResource, help_text="Enumerate connections", cache_table="goldengate_connections"),
]


def run_module(user_args, session):
    return run_components(
        user_args, session, COMPONENTS,
        module_name="enum_goldengate",
        description="Enumerate GoldenGate resources",
    )
