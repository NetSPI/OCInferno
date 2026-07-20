#!/usr/bin/env python3
from __future__ import annotations

from ocinferno.core.utils.enum_framework import Component, run_components
from ocinferno.modules.data_catalog.utilities.helpers import (
    DataCatalogCatalogsResource,
    DataCatalogMetastoresResource,
    DataCatalogPrivateEndpointsResource,
)

COMPONENTS = [
    Component("catalogs", DataCatalogCatalogsResource, help_text="Enumerate catalogs", cache_table="data_catalog_catalogs"),
    Component("private_endpoints", DataCatalogPrivateEndpointsResource, help_text="Enumerate catalog private endpoints", cache_table="data_catalog_private_endpoints"),
    Component("metastores", DataCatalogMetastoresResource, help_text="Enumerate metastores", cache_table="data_catalog_metastores"),
]


def run_module(user_args, session):
    return run_components(
        user_args, session, COMPONENTS,
        module_name="enum_data_catalog",
        description="Enumerate Data Catalog resources",
    )
