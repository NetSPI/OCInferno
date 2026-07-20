#!/usr/bin/env python3
from __future__ import annotations

import oci

from ocinferno.core.resource import OciListResource


class RedisClustersResource(OciListResource):
    CLIENT_CLS = oci.redis.RedisClusterClient
    SERVICE_NAME = "Redis"
    TABLE_NAME = "redis_clusters"
    LIST_METHOD = "list_redis_clusters"
    GET_METHOD = "get_redis_cluster"
    GET_ID_PARAM = "redis_cluster_id"
    COLUMNS = [
        "id",
        "display_name",
        "lifecycle_state",
        "time_created",
        "compartment_id",
        "primary_endpoint_ip_address",
        "primary_fqdn",
        "replicas_endpoint_ip_address",
        "replicas_fqdn",
        "node_count",
        "node_memory_in_gbs",
        "software_version",
        "subnet_id",
        "cluster_mode",
    ]
