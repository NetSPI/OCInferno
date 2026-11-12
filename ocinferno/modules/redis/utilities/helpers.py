#!/usr/bin/env python3
from __future__ import annotations

from typing import Any, Dict, List

import oci

from ocinferno.core.resource import OciListResource
from ocinferno.core.utils.service_runtime import ResourceBase, _init_client


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
        "nsg_ids",
        "discovery_endpoint_ip_address",
        "discovery_fqdn",
    ]


class RedisCacheUsersResource(ResourceBase):
    """OCI Cache (Redis) IAM users — credentials that grant access to Redis clusters."""

    TABLE_NAME = "cache_users"
    COLUMNS = ["id", "name", "lifecycle_state", "description"]

    def __init__(self, session, region=None):
        self.session = session
        self.client = _init_client(oci.redis.OciCacheUserClient, session=session, service_name="Cache")
        target_region = region or getattr(session, "config_current_default_region", None) or getattr(session, "region", None)
        if target_region:
            try:
                self.client.base_client.set_region(target_region)
            except Exception:
                pass

    def _resolve_client_method(self, *names: str):
        for name in names:
            fn = getattr(self.client, name, None)
            if callable(fn):
                return fn
        return None

    def list(self, *, compartment_id: str) -> List[Dict[str, Any]]:
        fn = self._resolve_client_method("list_oci_cache_users", "list_cache_users", "list_users")
        if fn is None:
            return []
        resp = oci.pagination.list_call_get_all_results(fn, compartment_id=compartment_id)
        return oci.util.to_dict(resp.data) or []

    def get(self, *, resource_id: str) -> Dict[str, Any]:
        fn = self._resolve_client_method("get_oci_cache_user", "get_cache_user", "get_user")
        if fn is None:
            return {}
        try:
            resp = fn(oci_cache_user_id=resource_id)
        except TypeError:
            try:
                resp = fn(user_id=resource_id)
            except (TypeError, oci.exceptions.ServiceError):
                return {}
        except oci.exceptions.ServiceError:
            return {}
        return oci.util.to_dict(resp.data) or {}
