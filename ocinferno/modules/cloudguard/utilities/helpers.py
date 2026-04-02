#!/usr/bin/env python3
from __future__ import annotations

from typing import Any, Dict, List, Optional

import oci
from ocinferno.core.utils.service_runtime import _init_client


def build_cloud_guard_client(session, region: Optional[str] = None):
    """Initialize a Cloud Guard client with shared signer/proxy/session behavior."""
    client = _init_client(
        oci.cloud_guard.CloudGuardClient,
        session=session,
        service_name="CloudGuard",
    )
    target_region = region or getattr(session, "region", None)
    if target_region:
        try:
            client.base_client.set_region(target_region)
        except Exception:
            pass
    return client


class CloudGuardTargetsResource:
    TABLE_NAME = "cloud_guard_targets"

    def __init__(self, session, region: Optional[str] = None):
        self.session = session
        self.client = build_cloud_guard_client(session=session, region=region)

    # List targets in a compartment.
    def list(self, *, compartment_id: str) -> List[Dict[str, Any]]:
        resp = oci.pagination.list_call_get_all_results(self.client.list_targets, compartment_id=compartment_id)
        return oci.util.to_dict(resp.data) or []

    # Get one target by OCID.
    def get(self, *, resource_id: str) -> Dict[str, Any]:
        return oci.util.to_dict(self.client.get_target(target_id=resource_id).data) or {}

    # Save target rows.
    def save(self, rows: List[Dict[str, Any]]) -> None:
        self.session.save_resources(rows or [], self.TABLE_NAME)

    # No binary download endpoint for target rows.
    def download(self, *, resource_id: str, out_path: str) -> bool:
        _ = (resource_id, out_path)
        return False


class CloudGuardProblemsResource:
    TABLE_NAME = "cloud_guard_problems"

    def __init__(self, session, region: Optional[str] = None):
        self.session = session
        self.client = build_cloud_guard_client(session=session, region=region)

    # List problems in a compartment.
    def list(self, *, compartment_id: str) -> List[Dict[str, Any]]:
        resp = oci.pagination.list_call_get_all_results(self.client.list_problems, compartment_id=compartment_id)
        return oci.util.to_dict(resp.data) or []

    # Get one problem by OCID.
    def get(self, *, resource_id: str) -> Dict[str, Any]:
        return oci.util.to_dict(self.client.get_problem(problem_id=resource_id).data) or {}

    # Save problem rows.
    def save(self, rows: List[Dict[str, Any]]) -> None:
        self.session.save_resources(rows or [], self.TABLE_NAME)

    # No binary download endpoint for problem rows.
    def download(self, *, resource_id: str, out_path: str) -> bool:
        _ = (resource_id, out_path)
        return False


class CloudGuardRecommendationsResource:
    TABLE_NAME = "cloud_guard_recommendations"

    def __init__(self, session, region: Optional[str] = None):
        self.session = session
        self.client = build_cloud_guard_client(session=session, region=region)

    # List recommendations in a compartment.
    def list(self, *, compartment_id: str) -> List[Dict[str, Any]]:
        resp = oci.pagination.list_call_get_all_results(self.client.list_recommendations, compartment_id=compartment_id)
        return oci.util.to_dict(resp.data) or []

    # Get one recommendation by OCID.
    def get(self, *, resource_id: str) -> Dict[str, Any]:
        resp = self.client.get_recommendation(recommendation_id=resource_id)
        return oci.util.to_dict(resp.data) or {}

    # Save recommendation rows.
    def save(self, rows: List[Dict[str, Any]]) -> None:
        self.session.save_resources(rows or [], self.TABLE_NAME)

    # No binary download endpoint for recommendation rows.
    def download(self, *, resource_id: str, out_path: str) -> bool:
        _ = (resource_id, out_path)
        return False


class CloudGuardDetectorRecipesResource:
    TABLE_NAME = "cloud_guard_detector_recipes"

    def __init__(self, session, region: Optional[str] = None):
        self.session = session
        self.client = build_cloud_guard_client(session=session, region=region)

    # List detector recipes in a compartment.
    def list(self, *, compartment_id: str) -> List[Dict[str, Any]]:
        resp = oci.pagination.list_call_get_all_results(self.client.list_detector_recipes, compartment_id=compartment_id)
        return oci.util.to_dict(resp.data) or []

    # Get one detector recipe by OCID.
    def get(self, *, resource_id: str) -> Dict[str, Any]:
        resp = self.client.get_detector_recipe(detector_recipe_id=resource_id)
        return oci.util.to_dict(resp.data) or {}

    # Save detector-recipe rows.
    def save(self, rows: List[Dict[str, Any]]) -> None:
        self.session.save_resources(rows or [], self.TABLE_NAME)

    # No binary download endpoint for detector-recipe rows.
    def download(self, *, resource_id: str, out_path: str) -> bool:
        _ = (resource_id, out_path)
        return False


class CloudGuardResponderRecipesResource:
    TABLE_NAME = "cloud_guard_responder_recipes"

    def __init__(self, session, region: Optional[str] = None):
        self.session = session
        self.client = build_cloud_guard_client(session=session, region=region)

    # List responder recipes in a compartment.
    def list(self, *, compartment_id: str) -> List[Dict[str, Any]]:
        resp = oci.pagination.list_call_get_all_results(self.client.list_responder_recipes, compartment_id=compartment_id)
        return oci.util.to_dict(resp.data) or []

    # Get one responder recipe by OCID.
    def get(self, *, resource_id: str) -> Dict[str, Any]:
        resp = self.client.get_responder_recipe(responder_recipe_id=resource_id)
        return oci.util.to_dict(resp.data) or {}

    # Save responder-recipe rows.
    def save(self, rows: List[Dict[str, Any]]) -> None:
        self.session.save_resources(rows or [], self.TABLE_NAME)

    # No binary download endpoint for responder-recipe rows.
    def download(self, *, resource_id: str, out_path: str) -> bool:
        _ = (resource_id, out_path)
        return False


class CloudGuardManagedListsResource:
    TABLE_NAME = "cloud_guard_managed_lists"

    def __init__(self, session, region: Optional[str] = None):
        self.session = session
        self.client = build_cloud_guard_client(session=session, region=region)

    # List managed lists in a compartment.
    def list(self, *, compartment_id: str) -> List[Dict[str, Any]]:
        resp = oci.pagination.list_call_get_all_results(self.client.list_managed_lists, compartment_id=compartment_id)
        return oci.util.to_dict(resp.data) or []

    # Get one managed list by OCID.
    def get(self, *, resource_id: str) -> Dict[str, Any]:
        resp = self.client.get_managed_list(managed_list_id=resource_id)
        return oci.util.to_dict(resp.data) or {}

    # Save managed-list rows.
    def save(self, rows: List[Dict[str, Any]]) -> None:
        self.session.save_resources(rows or [], self.TABLE_NAME)

    # No binary download endpoint for managed-list rows.
    def download(self, *, resource_id: str, out_path: str) -> bool:
        _ = (resource_id, out_path)
        return False


class CloudGuardDataSourcesResource:
    TABLE_NAME = "cloud_guard_data_sources"

    def __init__(self, session, region: Optional[str] = None):
        self.session = session
        self.client = build_cloud_guard_client(session=session, region=region)

    # List data sources in a compartment.
    def list(self, *, compartment_id: str) -> List[Dict[str, Any]]:
        resp = oci.pagination.list_call_get_all_results(self.client.list_data_sources, compartment_id=compartment_id)
        return oci.util.to_dict(resp.data) or []

    # Get one data source by OCID.
    def get(self, *, resource_id: str) -> Dict[str, Any]:
        resp = self.client.get_data_source(data_source_id=resource_id)
        return oci.util.to_dict(resp.data) or {}

    # Save data-source rows.
    def save(self, rows: List[Dict[str, Any]]) -> None:
        self.session.save_resources(rows or [], self.TABLE_NAME)

    # No binary download endpoint for data-source rows.
    def download(self, *, resource_id: str, out_path: str) -> bool:
        _ = (resource_id, out_path)
        return False


class CloudGuardSecurityZonesResource:
    TABLE_NAME = "cloud_guard_security_zones"

    def __init__(self, session, region: Optional[str] = None):
        self.session = session
        self.client = build_cloud_guard_client(session=session, region=region)

    # List security zones in a compartment.
    def list(self, *, compartment_id: str) -> List[Dict[str, Any]]:
        resp = oci.pagination.list_call_get_all_results(self.client.list_security_zones, compartment_id=compartment_id)
        return oci.util.to_dict(resp.data) or []

    # Get one security zone by OCID.
    def get(self, *, resource_id: str) -> Dict[str, Any]:
        resp = self.client.get_security_zone(security_zone_id=resource_id)
        return oci.util.to_dict(resp.data) or {}

    # Save security-zone rows.
    def save(self, rows: List[Dict[str, Any]]) -> None:
        self.session.save_resources(rows or [], self.TABLE_NAME)

    # No binary download endpoint for security-zone rows.
    def download(self, *, resource_id: str, out_path: str) -> bool:
        _ = (resource_id, out_path)
        return False


class CloudGuardSecurityRecipesResource:
    TABLE_NAME = "cloud_guard_security_recipes"

    def __init__(self, session, region: Optional[str] = None):
        self.session = session
        self.client = build_cloud_guard_client(session=session, region=region)

    # List security recipes in a compartment.
    def list(self, *, compartment_id: str) -> List[Dict[str, Any]]:
        resp = oci.pagination.list_call_get_all_results(self.client.list_security_recipes, compartment_id=compartment_id)
        return oci.util.to_dict(resp.data) or []

    # Get one security recipe by OCID.
    def get(self, *, resource_id: str) -> Dict[str, Any]:
        resp = self.client.get_security_recipe(security_recipe_id=resource_id)
        return oci.util.to_dict(resp.data) or {}

    # Save security-recipe rows.
    def save(self, rows: List[Dict[str, Any]]) -> None:
        self.session.save_resources(rows or [], self.TABLE_NAME)

    # No binary download endpoint for security-recipe rows.
    def download(self, *, resource_id: str, out_path: str) -> bool:
        _ = (resource_id, out_path)
        return False


class CloudGuardSecurityPoliciesResource:
    TABLE_NAME = "cloud_guard_security_policies"

    def __init__(self, session, region: Optional[str] = None):
        self.session = session
        self.client = build_cloud_guard_client(session=session, region=region)

    # List security policies in a compartment.
    def list(self, *, compartment_id: str) -> List[Dict[str, Any]]:
        resp = oci.pagination.list_call_get_all_results(self.client.list_security_policies, compartment_id=compartment_id)
        return oci.util.to_dict(resp.data) or []

    # Get one security policy by OCID.
    def get(self, *, resource_id: str) -> Dict[str, Any]:
        resp = self.client.get_security_policy(security_policy_id=resource_id)
        return oci.util.to_dict(resp.data) or {}

    # Save security-policy rows.
    def save(self, rows: List[Dict[str, Any]]) -> None:
        self.session.save_resources(rows or [], self.TABLE_NAME)

    # No binary download endpoint for security-policy rows.
    def download(self, *, resource_id: str, out_path: str) -> bool:
        _ = (resource_id, out_path)
        return False
