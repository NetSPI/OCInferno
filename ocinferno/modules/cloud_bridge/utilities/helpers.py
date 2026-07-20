#!/usr/bin/env python3
from __future__ import annotations

import oci

from ocinferno.core.resource import OciListResource


class CloudBridgeInventoriesResource(OciListResource):
    CLIENT_CLS = oci.cloud_bridge.InventoryClient
    SERVICE_NAME = "Cloud Bridge"
    TABLE_NAME = "cloud_bridge_inventories"
    LIST_METHOD = "list_inventories"
    GET_METHOD = "get_inventory"
    GET_ID_PARAM = "inventory_id"
    COLUMNS = [
        "id",
        "display_name",
        "lifecycle_state",
        "time_created",
        "compartment_id",
        "lifecycle_details",
        "time_updated",
    ]


class CloudBridgeAssetSourcesResource(OciListResource):
    CLIENT_CLS = oci.cloud_bridge.DiscoveryClient
    SERVICE_NAME = "Cloud Bridge"
    TABLE_NAME = "cloud_bridge_asset_sources"
    LIST_METHOD = "list_asset_sources"
    GET_METHOD = "get_asset_source"
    GET_ID_PARAM = "asset_source_id"
    COLUMNS = [
        "id",
        "display_name",
        "lifecycle_state",
        "time_created",
        "compartment_id",
        "type",
        "environment_type",
        "environment_id",
        "inventory_id",
        "assets_compartment_id",
    ]


class CloudBridgeAgentsResource(OciListResource):
    CLIENT_CLS = oci.cloud_bridge.OcbAgentSvcClient
    SERVICE_NAME = "Cloud Bridge"
    TABLE_NAME = "cloud_bridge_agents"
    LIST_METHOD = "list_agents"
    GET_METHOD = "get_agent"
    GET_ID_PARAM = "agent_id"
    COLUMNS = [
        "id",
        "display_name",
        "lifecycle_state",
        "time_created",
        "compartment_id",
        "agent_type",
        "agent_version",
        "os_version",
        "heart_beat_status",
        "environment_id",
        "time_last_sync_received",
    ]
