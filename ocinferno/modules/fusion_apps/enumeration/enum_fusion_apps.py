#!/usr/bin/env python3
from __future__ import annotations

from ocinferno.core.utils.enum_framework import Component, run_components
from ocinferno.modules.fusion_apps.utilities.helpers import (
    FusionAppsEnvironmentFamiliesResource,
    FusionAppsEnvironmentsResource,
)

COMPONENTS = [
    Component("fusion_environments", FusionAppsEnvironmentsResource, help_text="Enumerate Fusion (ERP/HCM/SCM) environments", cache_table="fusion_apps_environments"),
    Component("fusion_environment_families", FusionAppsEnvironmentFamiliesResource, help_text="Enumerate Fusion environment families", cache_table="fusion_apps_environment_families"),
]


def run_module(user_args, session):
    return run_components(
        user_args, session, COMPONENTS,
        module_name="enum_fusion_apps",
        description="Enumerate Fusion Applications resources",
    )
