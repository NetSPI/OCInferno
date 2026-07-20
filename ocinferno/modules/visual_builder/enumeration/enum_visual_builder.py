#!/usr/bin/env python3
from __future__ import annotations

from ocinferno.core.utils.enum_framework import Component, run_components
from ocinferno.modules.visual_builder.utilities.helpers import (
    VisualBuilderInstancesResource,
)

COMPONENTS = [
    Component("vb_instances", VisualBuilderInstancesResource, help_text="Enumerate Visual Builder instances", cache_table="visual_builder_instances"),
]


def run_module(user_args, session):
    return run_components(
        user_args, session, COMPONENTS,
        module_name="enum_visual_builder",
        description="Enumerate Visual Builder resources",
    )
