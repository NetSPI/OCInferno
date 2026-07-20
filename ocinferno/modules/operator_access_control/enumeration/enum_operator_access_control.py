#!/usr/bin/env python3
from __future__ import annotations

from ocinferno.core.utils.enum_framework import Component, run_components
from ocinferno.modules.operator_access_control.utilities.helpers import (
    OperatorAccessControlAccessRequestsResource,
    OperatorAccessControlAssignmentsResource,
    OperatorAccessControlControlsResource,
)

COMPONENTS = [
    Component("operator_controls", OperatorAccessControlControlsResource, help_text="Enumerate operator controls", cache_table="oac_operator_controls"),
    Component("assignments", OperatorAccessControlAssignmentsResource, help_text="Enumerate operator control assignments", cache_table="oac_operator_control_assignments"),
    Component("access_requests", OperatorAccessControlAccessRequestsResource, help_text="Enumerate access requests", cache_table="oac_access_requests"),
]


def run_module(user_args, session):
    return run_components(
        user_args, session, COMPONENTS,
        module_name="enum_operator_access_control",
        description="Enumerate Operator Access Control resources",
    )
