#!/usr/bin/env python3
from __future__ import annotations

import oci

from ocinferno.core.resource import OciListResource


class OpensearchClustersResource(OciListResource):
    CLIENT_CLS = oci.opensearch.OpensearchClusterClient
    SERVICE_NAME = "OpenSearch"
    TABLE_NAME = "opensearch_clusters"
    LIST_METHOD = "list_opensearch_clusters"
    GET_METHOD = "get_opensearch_cluster"
    GET_ID_PARAM = "opensearch_cluster_id"
    COLUMNS = [
        "id",
        "display_name",
        "lifecycle_state",
        "time_created",
        "compartment_id",
        "opensearch_fqdn",
        "opensearch_private_ip",
        "opendashboard_fqdn",
        "security_mode",
        "subnet_id",
        "vcn_id",
        "total_storage_gb",
        "software_version",
        "data_node_count",
    ]
