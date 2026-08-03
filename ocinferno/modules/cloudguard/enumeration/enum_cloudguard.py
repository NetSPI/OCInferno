#!/usr/bin/env python3
from __future__ import annotations

from ocinferno.core.utils.enum_framework import Component, run_components
from ocinferno.modules.cloudguard.utilities.helpers import (
    CloudGuardDataSourcesResource,
    CloudGuardDetectorRecipesResource,
    CloudGuardManagedListsResource,
    CloudGuardProblemsResource,
    CloudGuardRecommendationsResource,
    CloudGuardResponderRecipesResource,
    CloudGuardSecurityPoliciesResource,
    CloudGuardSecurityRecipesResource,
    CloudGuardSecurityZonesResource,
    CloudGuardTargetsResource,
)

# Standard column set for resources whose summary model has display_name + time_created.
_PRINT_COLUMNS = ["id", "display_name", "lifecycle_state", "time_created"]

# ProblemSummary has no 'display_name' or 'time_created'; use the problem-specific fields.
_PROBLEM_COLUMNS = ["id", "resource_name", "risk_level", "lifecycle_state", "time_first_detected", "time_last_detected"]

# RecommendationSummary uses 'name' (not 'display_name') and has 'time_created'.
_RECOMMENDATION_COLUMNS = ["id", "name", "risk_level", "lifecycle_state", "time_created"]


COMPONENTS = [
    Component("targets", CloudGuardTargetsResource, help_text="Enumerate targets", cache_table="cloud_guard_targets", print_columns=_PRINT_COLUMNS),
    Component("problems", CloudGuardProblemsResource, help_text="Enumerate problems", cache_table="cloud_guard_problems", print_columns=_PROBLEM_COLUMNS),
    Component("recommendations", CloudGuardRecommendationsResource, help_text="Enumerate recommendations", cache_table="cloud_guard_recommendations", print_columns=_RECOMMENDATION_COLUMNS, supports_get=False),
    Component("detector_recipes", CloudGuardDetectorRecipesResource, help_text="Enumerate detector-recipes", cache_table="cloud_guard_detector_recipes", print_columns=_PRINT_COLUMNS),
    Component("responder_recipes", CloudGuardResponderRecipesResource, help_text="Enumerate responder-recipes", cache_table="cloud_guard_responder_recipes", print_columns=_PRINT_COLUMNS),
    Component("managed_lists", CloudGuardManagedListsResource, help_text="Enumerate managed-lists", cache_table="cloud_guard_managed_lists", print_columns=_PRINT_COLUMNS),
    Component("data_sources", CloudGuardDataSourcesResource, help_text="Enumerate data-sources", cache_table="cloud_guard_data_sources", print_columns=_PRINT_COLUMNS),
    Component("security_zones", CloudGuardSecurityZonesResource, help_text="Enumerate security-zones", cache_table="cloud_guard_security_zones", print_columns=_PRINT_COLUMNS),
    Component("security_recipes", CloudGuardSecurityRecipesResource, help_text="Enumerate security-recipes", cache_table="cloud_guard_security_recipes", print_columns=_PRINT_COLUMNS),
    Component("security_policies", CloudGuardSecurityPoliciesResource, help_text="Enumerate security-policies", cache_table="cloud_guard_security_policies", print_columns=_PRINT_COLUMNS),
]


def run_module(user_args, session):
    return run_components(
        user_args, session, COMPONENTS,
        module_name="enum_cloudguard",
        description="Enumerate CloudGuard resources",
    )
