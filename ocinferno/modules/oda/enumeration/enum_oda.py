#!/usr/bin/env python3
from __future__ import annotations

from ocinferno.core.utils.enum_framework import Component, run_components
from ocinferno.modules.oda.utilities.helpers import (
    OdaInstancesResource,
)

COMPONENTS = [
    Component("oda_instances", OdaInstancesResource, help_text="Enumerate Digital Assistant instances", cache_table="oda_instances"),
]


def run_module(user_args, session):
    return run_components(
        user_args, session, COMPONENTS,
        module_name="enum_oda",
        description="Enumerate Digital Assistant resources",
    )
