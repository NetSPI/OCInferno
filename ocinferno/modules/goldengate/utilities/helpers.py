#!/usr/bin/env python3
from __future__ import annotations

import oci

from ocinferno.core.resource import OciListResource


class GoldenGateDeploymentsResource(OciListResource):
    CLIENT_CLS = oci.golden_gate.GoldenGateClient
    SERVICE_NAME = "GoldenGate"
    TABLE_NAME = "goldengate_deployments"
    LIST_METHOD = "list_deployments"
    GET_METHOD = "get_deployment"
    GET_ID_PARAM = "deployment_id"
    COLUMNS = [
        "id",
        "display_name",
        "lifecycle_state",
        "time_created",
        "compartment_id",
        "deployment_type",
        "deployment_url",
        "is_public",
        "subnet_id",
        "fqdn",
        "license_model",
        "ogg_data",
    ]


class GoldenGateConnectionsResource(OciListResource):
    CLIENT_CLS = oci.golden_gate.GoldenGateClient
    SERVICE_NAME = "GoldenGate"
    TABLE_NAME = "goldengate_connections"
    LIST_METHOD = "list_connections"
    GET_METHOD = "get_connection"
    GET_ID_PARAM = "connection_id"
    COLUMNS = [
        "id",
        "display_name",
        "lifecycle_state",
        "time_created",
        "compartment_id",
        "connection_type",
        "technology_type",
        "username",
        "host",
        "port",
        "database_name",
        "subnet_id",
        "vault_id",
        "key_id",
    ]
