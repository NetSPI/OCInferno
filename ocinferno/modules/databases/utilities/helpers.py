from __future__ import annotations

from typing import Any, Dict, List, Optional

import oci
from ocinferno.core.resource import OciListResource
from ocinferno.core.utils.service_runtime import _init_client
from ocinferno.core.utils.service_runtime import ResourceBase


def build_database_client(session, service: str, region: Optional[str] = None):
    """Initialize one database-service client with shared signer/proxy/session behavior."""
    service_map = {
        "mysql": (oci.mysql.DbSystemClient, "MySQL"),
        "postgresql": (oci.psql.PostgresqlClient, "PostgreSQL"),
        # "cache" is only ever requested by DatabasesCacheUsersResource below,
        # whose list_oci_cache_users/get_oci_cache_user calls live on
        # oci.redis.OciCacheUserClient -- confirmed via
        # oci/redis/oci_cache_user_client.py. RedisClusterClient (the cache
        # *cluster* client) has neither method; DatabasesCacheClustersResource
        # builds its own client directly via CLIENT_CLS and does not go
        # through this function, so this key has no other consumer.
        "cache": (oci.redis.OciCacheUserClient, "Cache"),
        "database": (oci.database.DatabaseClient, "Database"),
    }
    client_cls, service_name = service_map[service]
    client = _init_client(client_cls, session=session, service_name=service_name)
    target_region = region or getattr(session, "config_current_default_region", None) or getattr(session, "region", None)
    if target_region:
        try:
            client.base_client.set_region(target_region)
        except Exception:
            pass
    return client


class DatabasesCacheClustersResource(OciListResource):
    CLIENT_CLS = oci.redis.RedisClusterClient
    SERVICE_NAME = "Cache"
    TABLE_NAME = "cache_clusters"
    LIST_METHOD = "list_redis_clusters"
    GET_METHOD = "get_redis_cluster"
    GET_ID_PARAM = "redis_cluster_id"
    COLUMNS = ["id", "display_name", "lifecycle_state", "node_count"]

class DatabasesCacheUsersResource(ResourceBase):
    TABLE_NAME = "cache_users"
    COLUMNS = ["id", "display_name", "lifecycle_state", "description"]

    def __init__(self, session, region: Optional[str] = None):
        self.session = session
        self.client = build_database_client(session=session, service="cache", region=region)

    # Resolve SDK method name drift for list/get cache-user calls.
    def _resolve_client_method(self, *names: str):
        for name in names:
            fn = getattr(self.client, name, None)
            if callable(fn):
                return fn
        return None

    # List cache users in a compartment.
    def list(self, *, compartment_id: str) -> List[Dict[str, Any]]:
        fn = self._resolve_client_method("list_oci_cache_users", "list_cache_users", "list_users")
        if fn is None:
            return []
        resp = oci.pagination.list_call_get_all_results(fn, compartment_id=compartment_id)
        return oci.util.to_dict(resp.data) or []

    # Get one cache user by OCID.
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

    # No binary download endpoint for cache-user rows.

class DatabasesMysqlResource(OciListResource):
    CLIENT_CLS = oci.mysql.DbSystemClient
    SERVICE_NAME = "MySQL"
    TABLE_NAME = "db_mysql_db_systems"
    LIST_METHOD = "list_db_systems"
    GET_METHOD = "get_db_system"
    GET_ID_PARAM = "db_system_id"
    COLUMNS = ["id", "display_name", "lifecycle_state", "shape_name", "mysql_version", "time_created"]

class DatabasesPostgresResource(OciListResource):
    CLIENT_CLS = oci.psql.PostgresqlClient
    SERVICE_NAME = "PostgreSQL"
    TABLE_NAME = "db_psql_db_systems"
    LIST_METHOD = "list_db_systems"
    GET_METHOD = "get_db_system"
    GET_ID_PARAM = "db_system_id"
    COLUMNS = ["id", "display_name", "lifecycle_state", "shape", "db_version", "time_created"]

class DatabasesAutonomousResource(OciListResource):
    """Autonomous Databases (ADB) via oci.database. High value: --get exposes
    connection_strings / connection_urls (APEX, SQL Dev Web, database console)."""

    CLIENT_CLS = oci.database.DatabaseClient
    SERVICE_NAME = "Database"
    TABLE_NAME = "db_autonomous_databases"
    LIST_METHOD = "list_autonomous_databases"
    GET_METHOD = "get_autonomous_database"
    GET_ID_PARAM = "autonomous_database_id"
    COLUMNS = ["id", "display_name", "db_name", "lifecycle_state", "db_workload", "is_free_tier", "time_created"]


class DatabasesDbSystemsResource(OciListResource):
    """Base Database Service DB Systems (VM/BM/Exadata) via oci.database. --get
    exposes shape, hostname, listener/scan details, and licensing."""

    CLIENT_CLS = oci.database.DatabaseClient
    SERVICE_NAME = "Database"
    TABLE_NAME = "db_db_systems"
    LIST_METHOD = "list_db_systems"
    GET_METHOD = "get_db_system"
    GET_ID_PARAM = "db_system_id"
    COLUMNS = ["id", "display_name", "lifecycle_state", "shape", "database_edition", "hostname", "time_created"]

