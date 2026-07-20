#!/usr/bin/env python3
from __future__ import annotations

from ocinferno.core.utils.enum_framework import Component, run_components
from ocinferno.modules.generative_ai.utilities.helpers import (
    GenerativeAiApiKeysResource,
    GenerativeAiDedicatedAiClustersResource,
    GenerativeAiEndpointsResource,
    GenerativeAiProjectsResource,
)

COMPONENTS = [
    Component("projects", GenerativeAiProjectsResource, help_text="Enumerate Generative AI projects", cache_table="generative_ai_projects"),
    Component("endpoints", GenerativeAiEndpointsResource, help_text="Enumerate Generative AI endpoints", cache_table="generative_ai_endpoints"),
    Component("dedicated_ai_clusters", GenerativeAiDedicatedAiClustersResource, help_text="Enumerate dedicated AI clusters", cache_table="generative_ai_dedicated_ai_clusters"),
    Component("api_keys", GenerativeAiApiKeysResource, help_text="Enumerate Generative AI API keys", cache_table="generative_ai_api_keys"),
]


def run_module(user_args, session):
    return run_components(
        user_args, session, COMPONENTS,
        module_name="enum_generative_ai",
        description="Enumerate Generative AI resources",
    )
