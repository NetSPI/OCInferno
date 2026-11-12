#!/usr/bin/env python3
from __future__ import annotations

import oci

from ocinferno.core.resource import OciListResource


class DataIntegrationWorkspacesResource(OciListResource):
    CLIENT_CLS = oci.data_integration.DataIntegrationClient
    SERVICE_NAME = "DataIntegration"
    TABLE_NAME = "data_integration_workspaces"
    LIST_METHOD = "list_workspaces"
    GET_METHOD = "get_workspace"
    GET_ID_PARAM = "workspace_id"
    COLUMNS = [
        "id",
        "display_name",
        "lifecycle_state",
        "time_created",
        "compartment_id",
        "description",
        "vcn_id",
        "subnet_id",
        "endpoint_name",
        "endpoint_id",
        "is_private_network_enabled",
        "dns_server_ip",
    ]


class DataIntegrationDataAssetsResource(OciListResource):
    """Data Integration data assets — hold connection host/endpoint details (and,
    in asset_properties/default_connection, user-supplied connection metadata that
    may reference credentials). Scoped by workspace_id, not compartment."""

    CLIENT_CLS = oci.data_integration.DataIntegrationClient
    SERVICE_NAME = "DataIntegration"
    TABLE_NAME = "data_integration_data_assets"
    LIST_METHOD = "list_data_assets"
    GET_METHOD = "get_data_asset"
    GET_ID_PARAM = "data_asset_key"
    LIST_SCOPE_KWARG = "workspace_id"
    COLUMNS = [
        "key",
        "name",
        "identifier",
        "description",
        "type",
        "external_key",
        "asset_properties",
        "default_connection",
        "di_workspace_id",
        "compartment_id",
    ]
