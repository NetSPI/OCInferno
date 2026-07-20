#!/usr/bin/env python3
from __future__ import annotations

from ocinferno.core.utils.enum_framework import Component, run_components
from ocinferno.modules.apiaccesscontrol.utilities.helpers import (
    ApiAccessControlControlsResource,
    ApiAccessControlRequestsResource,
)

COMPONENTS = [
    Component("controls", ApiAccessControlControlsResource, help_text="Enumerate privileged API controls", cache_table="apiaccesscontrol_controls"),
    Component("requests", ApiAccessControlRequestsResource, help_text="Enumerate privileged API requests", cache_table="apiaccesscontrol_requests"),
]


def run_module(user_args, session):
    return run_components(
        user_args, session, COMPONENTS,
        module_name="enum_apiaccesscontrol",
        description="Enumerate Privileged API Access Control resources",
    )
