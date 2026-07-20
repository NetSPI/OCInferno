#!/usr/bin/env python3
from __future__ import annotations

from ocinferno.core.utils.enum_framework import Component, run_components
from ocinferno.modules.opensearch.utilities.helpers import OpensearchClustersResource

COMPONENTS = [
    Component("opensearch_clusters", OpensearchClustersResource, help_text="Enumerate opensearch-clusters", cache_table="opensearch_clusters"),
]


def run_module(user_args, session):
    return run_components(
        user_args, session, COMPONENTS,
        module_name="enum_opensearch",
        description="Enumerate OpenSearch resources",
    )
