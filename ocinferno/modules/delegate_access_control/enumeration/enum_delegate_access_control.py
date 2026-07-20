#!/usr/bin/env python3
from __future__ import annotations

from ocinferno.core.utils.enum_framework import Component, run_components
from ocinferno.modules.delegate_access_control.utilities.helpers import (
    DelegateAccessControlAccessRequestsResource,
    DelegateAccessControlDelegationControlsResource,
    DelegateAccessControlServiceProvidersResource,
)

COMPONENTS = [
    Component("access_requests", DelegateAccessControlAccessRequestsResource, help_text="Enumerate delegated resource access requests", cache_table="delegate_access_control_access_requests"),
    Component("delegation_controls", DelegateAccessControlDelegationControlsResource, help_text="Enumerate delegation controls", cache_table="delegate_access_control_delegation_controls"),
    Component("service_providers", DelegateAccessControlServiceProvidersResource, help_text="Enumerate service providers", cache_table="delegate_access_control_service_providers"),
]


def run_module(user_args, session):
    return run_components(
        user_args, session, COMPONENTS,
        module_name="enum_delegate_access_control",
        description="Enumerate Delegate Access Control resources",
    )
