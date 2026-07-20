#!/usr/bin/env python3
from __future__ import annotations

import oci

from ocinferno.core.resource import OciListResource


class DataCatalogCatalogsResource(OciListResource):
    CLIENT_CLS = oci.data_catalog.DataCatalogClient
    SERVICE_NAME = "Data Catalog"
    TABLE_NAME = "data_catalog_catalogs"
    LIST_METHOD = "list_catalogs"
    GET_METHOD = "get_catalog"
    GET_ID_PARAM = "catalog_id"
    COLUMNS = [
        "id",
        "display_name",
        "lifecycle_state",
        "time_created",
        "compartment_id",
        "number_of_objects",
        "service_api_url",
        "service_console_url",
        "attached_catalog_private_endpoints",
    ]


class DataCatalogPrivateEndpointsResource(OciListResource):
    CLIENT_CLS = oci.data_catalog.DataCatalogClient
    SERVICE_NAME = "Data Catalog"
    TABLE_NAME = "data_catalog_private_endpoints"
    LIST_METHOD = "list_catalog_private_endpoints"
    GET_METHOD = "get_catalog_private_endpoint"
    GET_ID_PARAM = "catalog_private_endpoint_id"
    COLUMNS = [
        "id",
        "display_name",
        "lifecycle_state",
        "time_created",
        "compartment_id",
        "subnet_id",
        "dns_zones",
        "attached_catalogs",
    ]


class DataCatalogMetastoresResource(OciListResource):
    CLIENT_CLS = oci.data_catalog.DataCatalogClient
    SERVICE_NAME = "Data Catalog"
    TABLE_NAME = "data_catalog_metastores"
    LIST_METHOD = "list_metastores"
    GET_METHOD = "get_metastore"
    GET_ID_PARAM = "metastore_id"
    COLUMNS = [
        "id",
        "display_name",
        "lifecycle_state",
        "time_created",
        "compartment_id",
        "default_managed_table_location",
        "default_external_table_location",
    ]
