#!/usr/bin/env python3
from __future__ import annotations

from typing import Any, Dict

import oci

from ocinferno.core.resource import OciListResource


class DatabaseToolsConnectionsResource(OciListResource):
    CLIENT_CLS = oci.database_tools.DatabaseToolsClient
    SERVICE_NAME = "Database Tools"
    TABLE_NAME = "database_tools_connections"
    LIST_METHOD = "list_database_tools_connections"
    GET_METHOD = "get_database_tools_connection"
    GET_ID_PARAM = "database_tools_connection_id"
    COLUMNS = [
        "id",
        "display_name",
        "lifecycle_state",
        "time_created",
        "compartment_id",
        "type",
        "related_resource",
        "connection_string",
        "user_name",
        "user_password_secret_id",
        "runtime_endpoint",
    ]

    def _normalize_row(self, row: Dict[str, Any]) -> Dict[str, Any]:
        # The credential-ref fields (user_name/connection_string/related_resource/
        # user_password) only appear on the full GET model, not the list Summary.
        # `user_password` serializes as a nested Vault reference
        # ({"value_type": "SECRETID", "secret_id": "ocid1.vaultsecret..."}); flatten
        # the secret OCID up to `user_password_secret_id` for recon (no secret material).
        pw = row.get("user_password")
        if isinstance(pw, dict):
            row["user_password_secret_id"] = pw.get("secret_id")
        return row


class DatabaseToolsPrivateEndpointsResource(OciListResource):
    CLIENT_CLS = oci.database_tools.DatabaseToolsClient
    SERVICE_NAME = "Database Tools"
    TABLE_NAME = "database_tools_private_endpoints"
    LIST_METHOD = "list_database_tools_private_endpoints"
    GET_METHOD = "get_database_tools_private_endpoint"
    GET_ID_PARAM = "database_tools_private_endpoint_id"
    COLUMNS = [
        "id",
        "display_name",
        "lifecycle_state",
        "time_created",
        "compartment_id",
        "vcn_id",
        "subnet_id",
        "private_endpoint_ip",
        "endpoint_fqdn",
        "endpoint_service_id",
        "nsg_ids",
    ]
