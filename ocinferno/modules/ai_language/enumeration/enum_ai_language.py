#!/usr/bin/env python3
from __future__ import annotations

from ocinferno.core.utils.enum_framework import Component, run_components
from ocinferno.modules.ai_language.utilities.helpers import (
    AILanguageEndpointsResource,
    AILanguageModelsResource,
    AILanguageProjectsResource,
)

COMPONENTS = [
    Component("projects", AILanguageProjectsResource, help_text="Enumerate projects", cache_table="ai_language_projects"),
    Component("models", AILanguageModelsResource, help_text="Enumerate models", cache_table="ai_language_models"),
    Component("endpoints", AILanguageEndpointsResource, help_text="Enumerate endpoints", cache_table="ai_language_endpoints"),
]


def run_module(user_args, session):
    return run_components(
        user_args, session, COMPONENTS,
        module_name="enum_ai_language",
        description="Enumerate AI Language resources",
    )
