#!/usr/bin/env python3
from __future__ import annotations

import oci

from ocinferno.core.resource import OciListResource


class DatabaseManagementNamedCredentialsResource(OciListResource):
    CLIENT_CLS = oci.database_management.DbManagementClient
    SERVICE_NAME = "Database Management"
    TABLE_NAME = "dbmgmt_named_credentials"
    LIST_METHOD = "list_named_credentials"
    GET_METHOD = "get_named_credential"
    GET_ID_PARAM = "named_credential_id"
    COLUMNS = [
        "id",
        "name",
        "lifecycle_state",
        "time_created",
        "compartment_id",
        "scope",
        "type",
        "description",
        "lifecycle_details",
    ]


class DatabaseManagementManagedDatabasesResource(OciListResource):
    CLIENT_CLS = oci.database_management.DbManagementClient
    SERVICE_NAME = "Database Management"
    TABLE_NAME = "dbmgmt_managed_databases"
    LIST_METHOD = "list_managed_databases"
    GET_METHOD = "get_managed_database"
    GET_ID_PARAM = "managed_database_id"
    COLUMNS = [
        "id",
        "name",
        "time_created",
        "compartment_id",
        "database_type",
        "database_sub_type",
        "deployment_type",
        "management_option",
        "database_version",
        "db_system_id",
        "parent_container_id",
        "is_cluster",
    ]


class DatabaseManagementCloudDbSystemsResource(OciListResource):
    CLIENT_CLS = oci.database_management.DbManagementClient
    SERVICE_NAME = "Database Management"
    TABLE_NAME = "dbmgmt_cloud_db_systems"
    LIST_METHOD = "list_cloud_db_systems"
    GET_METHOD = "get_cloud_db_system"
    GET_ID_PARAM = "cloud_db_system_id"
    COLUMNS = [
        "id",
        "display_name",
        "lifecycle_state",
        "time_created",
        "compartment_id",
        "deployment_type",
        "dbaas_parent_infrastructure_id",
        "home_directory",
        "database_management_config",
    ]


class DatabaseManagementPrivateEndpointsResource(OciListResource):
    CLIENT_CLS = oci.database_management.DbManagementClient
    SERVICE_NAME = "Database Management"
    TABLE_NAME = "dbmgmt_private_endpoints"
    LIST_METHOD = "list_db_management_private_endpoints"
    GET_METHOD = "get_db_management_private_endpoint"
    GET_ID_PARAM = "db_management_private_endpoint_id"
    COLUMNS = [
        "id",
        "name",
        "lifecycle_state",
        "time_created",
        "compartment_id",
        "vcn_id",
        "subnet_id",
        "description",
    ]
