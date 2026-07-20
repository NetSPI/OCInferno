#!/usr/bin/env python3
from __future__ import annotations

import oci

from ocinferno.core.resource import OciListResource


class NosqlTablesResource(OciListResource):
    CLIENT_CLS = oci.nosql.NosqlClient
    SERVICE_NAME = "NoSQL"
    TABLE_NAME = "nosql_tables"
    LIST_METHOD = "list_tables"
    GET_METHOD = "get_table"
    # NoSQL get_table REQUIRES compartment_id in addition to the table id/name; the
    # enum Component passes it via a get_row_fn (OciListResource.get forwards **kwargs).
    GET_ID_PARAM = "table_name_or_id"
    COLUMNS = [
        "id",
        "name",
        "lifecycle_state",
        "time_created",
        "compartment_id",
        "table_limits",
        "ddl_statement",
        "is_multi_region",
        "is_auto_reclaimable",
    ]
