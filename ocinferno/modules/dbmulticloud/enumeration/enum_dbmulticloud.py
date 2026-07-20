#!/usr/bin/env python3
from __future__ import annotations

from ocinferno.core.utils.enum_framework import Component, run_components
from ocinferno.modules.dbmulticloud.utilities.helpers import (
    DbMulticloudAwsIdentityConnectorResource,
    DbMulticloudAzureConnectorResource,
    DbMulticloudAzureVaultResource,
    DbMulticloudGcpIdentityConnectorResource,
)

COMPONENTS = [
    Component("aws_identity_connectors", DbMulticloudAwsIdentityConnectorResource, help_text="Enumerate AWS identity connectors", cache_table="dbmulticloud_aws_identity_connectors"),
    Component("gcp_identity_connectors", DbMulticloudGcpIdentityConnectorResource, help_text="Enumerate GCP identity connectors", cache_table="dbmulticloud_gcp_identity_connectors"),
    Component("azure_connectors", DbMulticloudAzureConnectorResource, help_text="Enumerate Azure connectors", cache_table="dbmulticloud_azure_connectors"),
    Component("azure_vaults", DbMulticloudAzureVaultResource, help_text="Enumerate Azure vaults", cache_table="dbmulticloud_azure_vaults"),
]


def run_module(user_args, session):
    return run_components(
        user_args, session, COMPONENTS,
        module_name="enum_dbmulticloud",
        description="Enumerate DB Multicloud resources",
    )
