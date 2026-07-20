#!/usr/bin/env python3
from __future__ import annotations

from ocinferno.core.utils.enum_framework import Component, run_components
from ocinferno.modules.service_connector.utilities.helpers import ServiceConnectorServiceConnectorsResource

COMPONENTS = [
    Component(
        "service_connectors", ServiceConnectorServiceConnectorsResource,
        help_text="Enumerate service connectors (source->task->target data pipelines)",
        cache_table="sch_service_connectors",
    ),
]


def run_module(user_args, session):
    return run_components(
        user_args, session, COMPONENTS,
        module_name="enum_service_connector",
        description="Enumerate Service Connector Hub resources",
    )
