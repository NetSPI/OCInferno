#!/usr/bin/env python3
from __future__ import annotations

import oci

from ocinferno.core.resource import OciListResource


class DbMulticloudAwsIdentityConnectorResource(OciListResource):
    CLIENT_CLS = oci.dbmulticloud.DbMulticloudAwsProviderClient
    SERVICE_NAME = "DB Multicloud"
    TABLE_NAME = "dbmulticloud_aws_identity_connectors"
    LIST_METHOD = "list_oracle_db_aws_identity_connectors"
    GET_METHOD = "get_oracle_db_aws_identity_connector"
    GET_ID_PARAM = "oracle_db_aws_identity_connector_id"
    COLUMNS = [
        "id",
        "display_name",
        "lifecycle_state",
        "time_created",
        "compartment_id",
        "aws_account_id",
        "aws_location",
        "aws_sts_private_endpoint",
        "issuer_url",
        "oidc_scope",
        "service_role_details",
        "resource_id",
    ]


class DbMulticloudGcpIdentityConnectorResource(OciListResource):
    CLIENT_CLS = oci.dbmulticloud.DbMulticloudGCPProviderClient
    SERVICE_NAME = "DB Multicloud"
    TABLE_NAME = "dbmulticloud_gcp_identity_connectors"
    LIST_METHOD = "list_oracle_db_gcp_identity_connectors"
    GET_METHOD = "get_oracle_db_gcp_identity_connector"
    GET_ID_PARAM = "oracle_db_gcp_identity_connector_id"
    COLUMNS = [
        "id",
        "display_name",
        "lifecycle_state",
        "time_created",
        "compartment_id",
        "project_id",
        "gcp_workload_identity_pool_id",
        "gcp_workload_identity_provider_id",
        "gcp_resource_service_agent_id",
        "gcp_identity_connectivity_status",
        "issuer_url",
        "resource_id",
    ]


class DbMulticloudAzureConnectorResource(OciListResource):
    CLIENT_CLS = oci.dbmulticloud.OracleDBAzureConnectorClient
    SERVICE_NAME = "DB Multicloud"
    TABLE_NAME = "dbmulticloud_azure_connectors"
    LIST_METHOD = "list_oracle_db_azure_connectors"
    GET_METHOD = "get_oracle_db_azure_connector"
    GET_ID_PARAM = "oracle_db_azure_connector_id"
    COLUMNS = [
        "id",
        "display_name",
        "lifecycle_state",
        "time_created",
        "compartment_id",
        "azure_subscription_id",
        "azure_tenant_id",
        "azure_resource_group",
        "azure_identity_mechanism",
        "azure_identity_connectivity_status",
        "private_endpoint_ip_address",
        "private_endpoint_dns_alias",
        "db_cluster_resource_id",
    ]


class DbMulticloudAzureVaultResource(OciListResource):
    CLIENT_CLS = oci.dbmulticloud.OracleDbAzureVaultClient
    SERVICE_NAME = "DB Multicloud"
    TABLE_NAME = "dbmulticloud_azure_vaults"
    LIST_METHOD = "list_oracle_db_azure_vaults"
    GET_METHOD = "get_oracle_db_azure_vault"
    GET_ID_PARAM = "oracle_db_azure_vault_id"
    COLUMNS = [
        "id",
        "display_name",
        "lifecycle_state",
        "time_created",
        "compartment_id",
        "azure_vault_id",
        "location",
        "oracle_db_azure_resource_group",
        "oracle_db_connector_id",
        "type",
        "properties",
    ]
