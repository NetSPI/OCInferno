#!/usr/bin/env python3
from __future__ import annotations

from typing import Any, Dict, List, Optional

import oci
from ocinferno.core.resource import OciListResource
from ocinferno.core.utils.service_runtime import _init_client
from ocinferno.core.utils.service_runtime import ResourceBase


def build_tagging_client(session, region: Optional[str] = None):
    """Initialize an Identity client for tagging APIs with shared behavior."""
    return _init_client(
        oci.identity.IdentityClient,
        session=session,
        service_name="Identity",
        region=region,
    )


class TaggingTagNamespacesResource(OciListResource):
    CLIENT_CLS = oci.identity.IdentityClient
    SERVICE_NAME = "Identity"
    TABLE_NAME = "tag_namespaces"
    LIST_METHOD = "list_tag_namespaces"
    GET_METHOD = "get_tag_namespace"
    GET_ID_PARAM = "tag_namespace_id"
    COLUMNS = ["id", "name", "lifecycle_state", "time_created"]

    # ``include_subcompartments`` is unsupported on some older SDK builds; fall back
    # to a plain compartment-scoped call rather than hard-failing (matches the
    # pre-migration try/except behavior).
    def _list_items(self, compartment_id: str, **kwargs):
        include_subcompartments = bool(kwargs.pop("include_subcompartments", False))
        try:
            return oci.pagination.list_call_get_all_results(
                self.client.list_tag_namespaces,
                compartment_id=compartment_id,
                include_subcompartments=include_subcompartments,
                **kwargs,
            )
        except (TypeError, ValueError):
            return oci.pagination.list_call_get_all_results(
                self.client.list_tag_namespaces, compartment_id=compartment_id, **kwargs
            )

    def list(self, *, compartment_id: str, include_subcompartments: bool = False, **kwargs) -> List[Dict[str, Any]]:
        return super().list(compartment_id=compartment_id, include_subcompartments=include_subcompartments, **kwargs)

    # No binary download endpoint for namespace rows.

class TaggingTagDefinitionsResource(ResourceBase):
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

    # No binary download endpoint for definition rows.

class TaggingTagDefaultsResource(OciListResource):
    CLIENT_CLS = oci.identity.IdentityClient
    SERVICE_NAME = "Identity"
    TABLE_NAME = "tag_defaults"
    LIST_METHOD = "list_tag_defaults"
    GET_METHOD = "get_tag_default"
    GET_ID_PARAM = "tag_default_id"
    COLUMNS = ["id", "tag_definition_id", "lifecycle_state", "time_created"]

    # ``include_subcompartments`` is unsupported on some older SDK builds; fall back
    # to a plain compartment-scoped call rather than hard-failing (matches the
    # pre-migration try/except behavior).
    def _list_items(self, compartment_id: str, **kwargs):
        include_subcompartments = bool(kwargs.pop("include_subcompartments", False))
        try:
            return oci.pagination.list_call_get_all_results(
                self.client.list_tag_defaults,
                compartment_id=compartment_id,
                include_subcompartments=include_subcompartments,
                **kwargs,
            )
        except (TypeError, ValueError):
            return oci.pagination.list_call_get_all_results(
                self.client.list_tag_defaults, compartment_id=compartment_id, **kwargs
            )

    def list(self, *, compartment_id: str, include_subcompartments: bool = False, **kwargs) -> List[Dict[str, Any]]:
        return super().list(compartment_id=compartment_id, include_subcompartments=include_subcompartments, **kwargs)

    # No binary download endpoint for default rows.
