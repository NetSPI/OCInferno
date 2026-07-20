#!/usr/bin/env python3
from __future__ import annotations

from ocinferno.core.utils.enum_framework import Component, run_components
from ocinferno.modules.data_safe.utilities.helpers import (
    DataSafeSecurityAssessmentsResource,
    DataSafeSensitiveDataModelsResource,
    DataSafeTargetDatabasesResource,
    DataSafeUserAssessmentsResource,
)

COMPONENTS = [
    Component("target_databases", DataSafeTargetDatabasesResource, help_text="Enumerate target databases", cache_table="data_safe_target_databases"),
    Component("security_assessments", DataSafeSecurityAssessmentsResource, help_text="Enumerate security assessments", cache_table="data_safe_security_assessments"),
    Component("user_assessments", DataSafeUserAssessmentsResource, help_text="Enumerate user assessments", cache_table="data_safe_user_assessments"),
    Component("sensitive_data_models", DataSafeSensitiveDataModelsResource, help_text="Enumerate sensitive data models", cache_table="data_safe_sensitive_data_models"),
]


def run_module(user_args, session):
    return run_components(
        user_args, session, COMPONENTS,
        module_name="enum_data_safe",
        description="Enumerate Data Safe resources",
    )
