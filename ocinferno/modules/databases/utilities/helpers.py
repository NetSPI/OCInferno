from __future__ import annotations

from typing import Any, Dict, List, Optional

import oci
from ocinferno.core.utils.service_runtime import _init_client


def build_database_client(session, service: str, region: Optional[str] = None):
    """Initialize one database-service client with shared signer/proxy/session behavior."""
    service_map = {
        "mysql": (oci.mysql.DbSystemClient, "MySQL"),
        "postgresql": (oci.psql.PostgresqlClient, "PostgreSQL"),
        "cache": (oci.redis.RedisClusterClient, "Cache"),
    }
    client_cls, service_name = service_map[service]
    client = _init_client(client_cls, session=session, service_name=service_name)
    target_region = region or getattr(session, "region", None)
    if target_region:
        try:
            client.base_client.set_region(target_region)
        except Exception:
            pass
    return client


class DatabasesCacheClustersResource:
    TABLE_NAME = "cache_clusters"
    COLUMNS = ["id", "display_name", "lifecycle_state", "node_count"]

    def __init__(self, session, region: Optional[str] = None):
        self.session = session
        self.client = build_database_client(session=session, service="cache", region=region)

    # List Redis cache clusters in a compartment.
    def list(self, *, compartment_id: str) -> List[Dict[str, Any]]:
        resp = oci.pagination.list_call_get_all_results(self.client.list_redis_clusters, compartment_id=compartment_id)
        return oci.util.to_dict(resp.data) or []

    # Get one cache cluster by OCID.
    def get(self, *, resource_id: str) -> Dict[str, Any]:
        return oci.util.to_dict(self.client.get_redis_cluster(redis_cluster_id=resource_id).data) or {}

    # Save cache-cluster rows.
    def save(self, rows: List[Dict[str, Any]]) -> None:
        self.session.save_resources(rows or [], self.TABLE_NAME)

    # No binary download endpoint for cache-cluster rows.
    def download(self, *, resource_id: str, out_path: str) -> bool:  # pragma: no cover - placeholder
        _ = (resource_id, out_path)
        return False


class DatabasesCacheUsersResource:
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
            resp = fn(user_id=resource_id)
        return oci.util.to_dict(resp.data) or {}

    # Save cache-user rows.
    def save(self, rows: List[Dict[str, Any]]) -> None:
        self.session.save_resources(rows or [], self.TABLE_NAME)

    # No binary download endpoint for cache-user rows.
    def download(self, *, resource_id: str, out_path: str) -> bool:  # pragma: no cover - placeholder
        _ = (resource_id, out_path)
        return False


class DatabasesMysqlResource:
    TABLE_NAME = "db_mysql_db_systems"
    COLUMNS = ["id", "display_name", "lifecycle_state", "shape_name", "mysql_version", "time_created"]

    def __init__(self, session, region: Optional[str] = None):
        self.session = session
        self.client = build_database_client(session=session, service="mysql", region=region)

    # List MySQL DB systems in a compartment.
    def list(self, *, compartment_id: str) -> List[Dict[str, Any]]:
        resp = oci.pagination.list_call_get_all_results(self.client.list_db_systems, compartment_id=compartment_id)
        return oci.util.to_dict(resp.data) or []

    # Get one MySQL DB system by OCID.
    def get(self, *, resource_id: str) -> Dict[str, Any]:
        return oci.util.to_dict(self.client.get_db_system(db_system_id=resource_id).data) or {}

    # Save MySQL rows.
    def save(self, rows: List[Dict[str, Any]]) -> None:
        self.session.save_resources(rows or [], self.TABLE_NAME)

    # No binary download endpoint for MySQL rows.
    def download(self, *, resource_id: str, out_path: str) -> bool:  # pragma: no cover - placeholder
        _ = (resource_id, out_path)
        return False


class DatabasesPostgresResource:
    TABLE_NAME = "db_psql_db_systems"
    COLUMNS = ["id", "display_name", "lifecycle_state", "shape", "db_version", "time_created"]

    def __init__(self, session, region: Optional[str] = None):
        self.session = session
        self.client = build_database_client(session=session, service="postgresql", region=region)

    # List PostgreSQL DB systems in a compartment.
    def list(self, *, compartment_id: str) -> List[Dict[str, Any]]:
        resp = oci.pagination.list_call_get_all_results(self.client.list_db_systems, compartment_id=compartment_id)
        return oci.util.to_dict(resp.data) or []

    # Get one PostgreSQL DB system by OCID.
    def get(self, *, resource_id: str) -> Dict[str, Any]:
        return oci.util.to_dict(self.client.get_db_system(db_system_id=resource_id).data) or {}

    # Save PostgreSQL rows.
    def save(self, rows: List[Dict[str, Any]]) -> None:
        self.session.save_resources(rows or [], self.TABLE_NAME)

    # No binary download endpoint for PostgreSQL rows.
    def download(self, *, resource_id: str, out_path: str) -> bool:  # pragma: no cover - placeholder
        _ = (resource_id, out_path)
        return False
