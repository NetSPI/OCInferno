"""Config-driven base for the standard OCI enumeration Resource pattern.

Across ~40 service Resource classes the ``__init__`` / ``list`` / ``get`` / ``save``
bodies are identical; only the config varies (OCI SDK client class + service name,
the list/get method names, the get id-parameter, the table + columns). A subclass
declares the config as class attributes and the shared bodies live here once.
Per-service quirks are expressed by overriding one small hook (``_list_items`` /
``_get_item`` / ``_normalize_row``) rather than re-implementing the whole method.

Method signatures intentionally match the long-standing per-service classes so enum
modules / ``run_components`` call them unchanged:
    __init__(session, region=None)
    list(*, compartment_id, **kwargs)   -> list[dict]
    get(*, resource_id, **kwargs)       -> dict
    save(rows)                          -> None  (inherited from ResourceBase)
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

import oci

from ocinferno.core.utils.service_runtime import ResourceBase, _init_client


class OciListResource(ResourceBase):
    """Config-driven base implementing the shared OCI list/get/save bodies.

    Subclasses declare config as class attributes; per-service quirks are handled by
    overriding ``_list_items``/``_get_item``/``_normalize_row`` (the rest stays shared).

    Config attributes:
      CLIENT_CLS         The OCI SDK client class, e.g. ``oci.redis.RedisClusterClient``.
      SERVICE_NAME       Human label passed to ``_init_client`` (error/proxy wiring).
      TABLE_NAME/COLUMNS Workspace-scoped DB table + its columns (COLUMNS also = print cols).
      LIST_METHOD        Client method name for the compartment list, e.g. "list_redis_clusters".
      GET_METHOD         Client method name for a single get, e.g. "get_redis_cluster".
      GET_ID_PARAM       The SDK kwarg name for ``get`` (e.g. "redis_cluster_id"); the
                         public ``get(*, resource_id=...)`` maps onto it.
      LIST_SCOPE_KWARG   The list method's scope kwarg (default "compartment_id").
    """

    CLIENT_CLS: Any = None
    SERVICE_NAME: str = ""
    LIST_METHOD: str = ""
    GET_METHOD: str = ""
    GET_ID_PARAM: str = "resource_id"
    LIST_SCOPE_KWARG: str = "compartment_id"
    COLUMNS: List[str] = []
    # Concise subset of COLUMNS to PRINT in stdout tables (the full COLUMNS set is
    # always saved to the DB). Leave empty to let the framework auto-derive a concise
    # 3-4 column subset from COLUMNS; set explicitly to curate what the operator sees.
    DISPLAY_COLUMNS: List[str] = []

    def __init__(self, session, region: Optional[str] = None) -> None:
        self.session = session
        self.client = self._build_client(session, region)

    def _build_client(self, session, region: Optional[str] = None):
        if self.CLIENT_CLS is None:  # pragma: no cover - misconfiguration guard
            raise NotImplementedError(f"{type(self).__name__} must set CLIENT_CLS (or override _build_client).")
        return _init_client(self.CLIENT_CLS, session=session, service_name=self.SERVICE_NAME or type(self).__name__, region=region)

    # --- SDK-call hooks (override for clients that need extra/renamed kwargs) ---
    def _list_items(self, compartment_id: str, **kwargs):
        """Return the paginated SDK Response for the compartment list."""
        return oci.pagination.list_call_get_all_results(
            getattr(self.client, self.LIST_METHOD), **{self.LIST_SCOPE_KWARG: compartment_id}, **kwargs
        )

    def _get_item(self, resource_id: str, **kwargs):
        """Return the SDK Response for a single get by id."""
        return getattr(self.client, self.GET_METHOD)(**{self.GET_ID_PARAM: resource_id}, **kwargs)

    def _normalize_row(self, row: Dict[str, Any]) -> Dict[str, Any]:
        """Post-process each ``oci.util.to_dict`` row (override for field fixups)."""
        return row

    # --- shared bodies ---
    def list(self, *, compartment_id: str, **kwargs) -> List[Dict[str, Any]]:
        resp = self._list_items(compartment_id, **kwargs)
        rows = oci.util.to_dict(resp.data) or []
        return [self._normalize_row(r) for r in rows if isinstance(r, dict)]

    def get(self, *, resource_id: str, **kwargs) -> Dict[str, Any]:
        if not resource_id:
            return {}
        resp = self._get_item(resource_id, **kwargs)
        row = oci.util.to_dict(resp.data) or {}
        return self._normalize_row(row) if isinstance(row, dict) else {}
