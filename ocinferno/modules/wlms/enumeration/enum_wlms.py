#!/usr/bin/env python3
from __future__ import annotations

from ocinferno.core.utils.enum_framework import Component, run_components
from ocinferno.modules.wlms.utilities.helpers import (
    WlmsManagedInstancesResource,
    WlmsWlsDomainsResource,
)

COMPONENTS = [
    Component("wls_domains", WlmsWlsDomainsResource, help_text="Enumerate WebLogic domains", cache_table="wlms_wls_domains"),
    Component("managed_instances", WlmsManagedInstancesResource, help_text="Enumerate managed instances", cache_table="wlms_managed_instances"),
]


def run_module(user_args, session):
    return run_components(
        user_args, session, COMPONENTS,
        module_name="enum_wlms",
        description="Enumerate WebLogic Management resources",
    )
