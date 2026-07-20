#!/usr/bin/env python3
from __future__ import annotations

from ocinferno.core.utils.enum_framework import Component, run_components
from ocinferno.modules.cloud_bridge.utilities.helpers import (
    CloudBridgeAgentsResource,
    CloudBridgeAssetSourcesResource,
    CloudBridgeInventoriesResource,
)

COMPONENTS = [
    Component("inventories", CloudBridgeInventoriesResource, help_text="Enumerate inventories", cache_table="cloud_bridge_inventories"),
    Component("asset_sources", CloudBridgeAssetSourcesResource, help_text="Enumerate asset-sources", cache_table="cloud_bridge_asset_sources"),
    Component("agents", CloudBridgeAgentsResource, help_text="Enumerate agents", cache_table="cloud_bridge_agents"),
]


def run_module(user_args, session):
    return run_components(
        user_args, session, COMPONENTS,
        module_name="enum_cloud_bridge",
        description="Enumerate Cloud Bridge resources",
    )
