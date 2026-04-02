#!/usr/bin/env python3
from __future__ import annotations

from typing import Any, Dict, List, Optional

import oci
from ocinferno.core.utils.service_runtime import _init_client


def build_tagging_client(session, region: Optional[str] = None):
    """Initialize an Identity client for tagging APIs with shared behavior."""
    client = _init_client(
        oci.identity.IdentityClient,
        session=session,
        service_name="Identity",
    )
    target_region = region or getattr(session, "region", None)
    if target_region:
        try:
            client.base_client.set_region(target_region)
        except Exception:
            pass
    return client


class TaggingTagNamespacesResource:
    TABLE_NAME = "tag_namespaces"
    COLUMNS = ["id", "name", "lifecycle_state", "time_created"]

    def __init__(self, session, region: Optional[str] = None):
        self.session = session
        self.client = build_tagging_client(session=session, region=region)

    # List tag namespaces.
    def list(self, *, compartment_id: str, include_subcompartments: bool = False) -> List[Dict[str, Any]]:
        try:
            resp = oci.pagination.list_call_get_all_results(
                self.client.list_tag_namespaces,
                compartment_id=compartment_id,
                include_subcompartments=bool(include_subcompartments),
            )
        except (TypeError, ValueError):
            resp = oci.pagination.list_call_get_all_results(self.client.list_tag_namespaces, compartment_id=compartment_id)
        return oci.util.to_dict(resp.data) or []

    # Get one tag namespace by OCID.
    def get(self, *, resource_id: str) -> Dict[str, Any]:
        try:
            resp = self.client.get_tag_namespace(tag_namespace_id=resource_id)
        except Exception:
            return {}
        return oci.util.to_dict(resp.data) or {}

    # Save namespace rows.
    def save(self, rows: List[Dict[str, Any]]) -> None:
        self.session.save_resources(rows or [], self.TABLE_NAME)

    # No binary download endpoint for namespace rows.
    def download(self, *, resource_id: str, out_path: str) -> bool:  # pragma: no cover - placeholder
        _ = (resource_id, out_path)
        return False


class TaggingTagDefinitionsResource:
    TABLE_NAME = "tag_definitions"
    COLUMNS = ["id", "name", "tag_namespace_name", "lifecycle_state", "time_created"]

    def __init__(self, session, region: Optional[str] = None):
        self.session = session
        self.client = build_tagging_client(session=session, region=region)

    # List namespaces (helper used by enum flow).
    def list_namespaces(self, *, compartment_id: str, include_subcompartments: bool = False) -> List[Dict[str, Any]]:
        return TaggingTagNamespacesResource(self.session).list(
            compartment_id=compartment_id,
            include_subcompartments=include_subcompartments,
        )

    # List tag definitions for one namespace.
    def list(
        self,
        *,
        compartment_id: str,
        tag_namespace_id: str,
        include_subcompartments: bool = False,
    ) -> List[Dict[str, Any]]:
        list_defs = getattr(self.client, "list_tag_definitions", None)
        if callable(list_defs):
            try:
                resp = oci.pagination.list_call_get_all_results(
                    list_defs,
                    compartment_id=compartment_id,
                    tag_namespace_id=tag_namespace_id,
                    include_subcompartments=bool(include_subcompartments),
                )
            except (TypeError, ValueError):
                resp = oci.pagination.list_call_get_all_results(
                    list_defs,
                    compartment_id=compartment_id,
                    tag_namespace_id=tag_namespace_id,
                )
            return oci.util.to_dict(resp.data) or []

        list_tags = getattr(self.client, "list_tags", None)
        if callable(list_tags):
            try:
                resp = oci.pagination.list_call_get_all_results(list_tags, tag_namespace_id=tag_namespace_id)
            except TypeError:
                resp = oci.pagination.list_call_get_all_results(list_tags, tag_namespace_id)
            return oci.util.to_dict(resp.data) or []
        return []

    # Get one tag definition by OCID (best-effort across SDK variants).
    def get(self, *, resource_id: str) -> Dict[str, Any]:
        get_tag = getattr(self.client, "get_tag", None)
        if callable(get_tag):
            try:
                resp = get_tag(tag_name=resource_id)
                return oci.util.to_dict(resp.data) or {}
            except Exception:
                pass
        return {}

    # Save definition rows.
    def save(self, rows: List[Dict[str, Any]]) -> None:
        self.session.save_resources(rows or [], self.TABLE_NAME)

    # No binary download endpoint for definition rows.
    def download(self, *, resource_id: str, out_path: str) -> bool:  # pragma: no cover - placeholder
        _ = (resource_id, out_path)
        return False


class TaggingTagDefaultsResource:
    TABLE_NAME = "tag_defaults"
    COLUMNS = ["id", "tag_definition_id", "lifecycle_state", "time_created"]

    def __init__(self, session, region: Optional[str] = None):
        self.session = session
        self.client = build_tagging_client(session=session, region=region)

    # List tag defaults.
    def list(self, *, compartment_id: str, include_subcompartments: bool = False) -> List[Dict[str, Any]]:
        try:
            resp = oci.pagination.list_call_get_all_results(
                self.client.list_tag_defaults,
                compartment_id=compartment_id,
                include_subcompartments=bool(include_subcompartments),
            )
        except (TypeError, ValueError):
            resp = oci.pagination.list_call_get_all_results(self.client.list_tag_defaults, compartment_id=compartment_id)
        return oci.util.to_dict(resp.data) or []

    # Get one tag default by OCID.
    def get(self, *, resource_id: str) -> Dict[str, Any]:
        try:
            resp = self.client.get_tag_default(tag_default_id=resource_id)
        except Exception:
            return {}
        return oci.util.to_dict(resp.data) or {}

    # Save default rows.
    def save(self, rows: List[Dict[str, Any]]) -> None:
        self.session.save_resources(rows or [], self.TABLE_NAME)

    # No binary download endpoint for default rows.
    def download(self, *, resource_id: str, out_path: str) -> bool:  # pragma: no cover - placeholder
        _ = (resource_id, out_path)
        return False
