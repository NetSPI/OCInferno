#!/usr/bin/env python3
from __future__ import annotations

from typing import Any, Dict, List, Optional

import oci
from ocinferno.core.utils.module_helpers import domain_ids_from_db
from ocinferno.core.utils.service_runtime import _init_client


def build_iot_client(session, region: Optional[str] = None):
    """Initialize an IoT client with shared signer/proxy/session behavior."""
    client = _init_client(
        oci.iot.IotClient,
        session=session,
        service_name="IoT",
    )
    target_region = region or getattr(session, "region", None)
    if target_region:
        try:
            client.base_client.set_region(target_region)
        except Exception:
            pass
    return client


class IotDomainsResource:
    TABLE_NAME = "iot_domains"
    COLUMNS = ["id", "display_name", "lifecycle_state", "time_created"]

    def __init__(self, session, region: Optional[str] = None):
        self.session = session
        self.client = build_iot_client(session=session, region=region)

    # List IoT domains in a compartment.
    def list(self, *, compartment_id: str) -> List[Dict[str, Any]]:
        resp = oci.pagination.list_call_get_all_results(self.client.list_iot_domains, compartment_id=compartment_id)
        return oci.util.to_dict(resp.data) or []

    # Get one IoT domain by OCID.
    def get(self, *, resource_id: str) -> Dict[str, Any]:
        return oci.util.to_dict(self.client.get_iot_domain(iot_domain_id=resource_id).data) or {}

    # Save domain rows.
    def save(self, rows: List[Dict[str, Any]]) -> None:
        self.session.save_resources(rows or [], self.TABLE_NAME)

    # No binary download endpoint for domain rows.
    def download(self, *, resource_id: str, out_path: str) -> bool:  # pragma: no cover - placeholder
        _ = (resource_id, out_path)
        return False


class IotDomainGroupsResource:
    TABLE_NAME = "iot_domain_groups"
    COLUMNS = ["id", "display_name", "lifecycle_state", "time_created"]

    def __init__(self, session, region: Optional[str] = None):
        self.session = session
        self.client = build_iot_client(session=session, region=region)

    # List IoT domain groups in a compartment.
    def list(self, *, compartment_id: str) -> List[Dict[str, Any]]:
        resp = oci.pagination.list_call_get_all_results(self.client.list_iot_domain_groups, compartment_id=compartment_id)
        return oci.util.to_dict(resp.data) or []

    # Get one IoT domain group by OCID.
    def get(self, *, resource_id: str) -> Dict[str, Any]:
        return oci.util.to_dict(self.client.get_iot_domain_group(iot_domain_group_id=resource_id).data) or {}

    # Save domain-group rows.
    def save(self, rows: List[Dict[str, Any]]) -> None:
        self.session.save_resources(rows or [], self.TABLE_NAME)

    # No binary download endpoint for domain-group rows.
    def download(self, *, resource_id: str, out_path: str) -> bool:  # pragma: no cover - placeholder
        _ = (resource_id, out_path)
        return False


class IotDigitalTwinModelsResource:
    TABLE_NAME = "iot_digital_twin_models"
    TABLE_DOMAINS = "iot_domains"
    COLUMNS = ["id", "display_name", "lifecycle_state", "time_created", "iot_domain_id"]

    def __init__(self, session, region: Optional[str] = None):
        self.session = session
        self.client = build_iot_client(session=session, region=region)

    # Resolve IoT domain IDs from DB cache and optional filters.
    def resolve_domain_ids(self, *, compartment_id: str, domain_id_filter: str = "") -> List[str]:
        return domain_ids_from_db(
            self.session,
            table_name=self.TABLE_DOMAINS,
            compartment_id=compartment_id,
            domain_id_filter=domain_id_filter,
        )

    # List digital twin models under one domain.
    def list(self, *, iot_domain_id: str) -> List[Dict[str, Any]]:
        resp = oci.pagination.list_call_get_all_results(self.client.list_digital_twin_models, iot_domain_id=iot_domain_id)
        return oci.util.to_dict(resp.data) or []

    # Get one digital twin model by OCID.
    def get(self, *, resource_id: str) -> Dict[str, Any]:
        return oci.util.to_dict(self.client.get_digital_twin_model(digital_twin_model_id=resource_id).data) or {}

    # Save digital-twin model rows.
    def save(self, rows: List[Dict[str, Any]]) -> None:
        self.session.save_resources(rows or [], self.TABLE_NAME)

    # Download the model spec blob.
    def download(self, *, resource_id: str, out_path: str) -> bool:
        try:
            resp = self.client.get_digital_twin_model_spec(digital_twin_model_id=resource_id)
        except Exception:
            return False

        data = getattr(resp, "data", None)
        if data is None:
            return False

        try:
            blob = data.read() if hasattr(data, "read") else data
            if isinstance(blob, str):
                blob = blob.encode("utf-8", errors="ignore")
            if not isinstance(blob, (bytes, bytearray)):
                return False
            with open(out_path, "wb") as handle:
                handle.write(bytes(blob))
            return True
        except Exception:
            return False


class IotDigitalTwinInstancesResource:
    TABLE_NAME = "iot_digital_twin_instances"
    TABLE_DOMAINS = "iot_domains"
    COLUMNS = ["id", "display_name", "lifecycle_state", "time_created", "iot_domain_id"]

    def __init__(self, session, region: Optional[str] = None):
        self.session = session
        self.client = build_iot_client(session=session, region=region)

    # Resolve IoT domain IDs from DB cache and optional filters.
    def resolve_domain_ids(self, *, compartment_id: str, domain_id_filter: str = "") -> List[str]:
        return domain_ids_from_db(
            self.session,
            table_name=self.TABLE_DOMAINS,
            compartment_id=compartment_id,
            domain_id_filter=domain_id_filter,
        )

    # List digital twin instances under one domain.
    def list(self, *, iot_domain_id: str) -> List[Dict[str, Any]]:
        resp = oci.pagination.list_call_get_all_results(self.client.list_digital_twin_instances, iot_domain_id=iot_domain_id)
        return oci.util.to_dict(resp.data) or []

    # Get one digital twin instance by OCID.
    def get(self, *, resource_id: str) -> Dict[str, Any]:
        return oci.util.to_dict(self.client.get_digital_twin_instance(digital_twin_instance_id=resource_id).data) or {}

    # Save digital-twin instance rows.
    def save(self, rows: List[Dict[str, Any]]) -> None:
        self.session.save_resources(rows or [], self.TABLE_NAME)

    # Download the instance content blob.
    def download(self, *, resource_id: str, out_path: str) -> bool:
        try:
            resp = self.client.get_digital_twin_instance_content(digital_twin_instance_id=resource_id)
        except Exception:
            return False

        data = getattr(resp, "data", None)
        if data is None:
            return False

        try:
            blob = data.read() if hasattr(data, "read") else data
            if isinstance(blob, str):
                blob = blob.encode("utf-8", errors="ignore")
            if not isinstance(blob, (bytes, bytearray)):
                return False
            with open(out_path, "wb") as handle:
                handle.write(bytes(blob))
            return True
        except Exception:
            return False


class IotDigitalTwinAdaptersResource:
    TABLE_NAME = "iot_digital_twin_adapters"
    TABLE_DOMAINS = "iot_domains"
    COLUMNS = ["id", "display_name", "lifecycle_state", "time_created", "iot_domain_id"]

    def __init__(self, session, region: Optional[str] = None):
        self.session = session
        self.client = build_iot_client(session=session, region=region)

    # Resolve IoT domain IDs from DB cache and optional filters.
    def resolve_domain_ids(self, *, compartment_id: str, domain_id_filter: str = "") -> List[str]:
        return domain_ids_from_db(
            self.session,
            table_name=self.TABLE_DOMAINS,
            compartment_id=compartment_id,
            domain_id_filter=domain_id_filter,
        )

    # List digital twin adapters under one domain.
    def list(self, *, iot_domain_id: str) -> List[Dict[str, Any]]:
        resp = oci.pagination.list_call_get_all_results(self.client.list_digital_twin_adapters, iot_domain_id=iot_domain_id)
        return oci.util.to_dict(resp.data) or []

    # Get one digital twin adapter by OCID.
    def get(self, *, resource_id: str) -> Dict[str, Any]:
        return oci.util.to_dict(self.client.get_digital_twin_adapter(digital_twin_adapter_id=resource_id).data) or {}

    # Save digital-twin adapter rows.
    def save(self, rows: List[Dict[str, Any]]) -> None:
        self.session.save_resources(rows or [], self.TABLE_NAME)

    # No binary download endpoint for adapter rows.
    def download(self, *, resource_id: str, out_path: str) -> bool:  # pragma: no cover - placeholder
        _ = (resource_id, out_path)
        return False


class IotDigitalTwinRelationshipsResource:
    TABLE_NAME = "iot_digital_twin_relationships"
    TABLE_DOMAINS = "iot_domains"
    COLUMNS = ["id", "display_name", "lifecycle_state", "time_created", "iot_domain_id"]

    def __init__(self, session, region: Optional[str] = None):
        self.session = session
        self.client = build_iot_client(session=session, region=region)

    # Resolve IoT domain IDs from DB cache and optional filters.
    def resolve_domain_ids(self, *, compartment_id: str, domain_id_filter: str = "") -> List[str]:
        return domain_ids_from_db(
            self.session,
            table_name=self.TABLE_DOMAINS,
            compartment_id=compartment_id,
            domain_id_filter=domain_id_filter,
        )

    # List digital twin relationships under one domain.
    def list(self, *, iot_domain_id: str) -> List[Dict[str, Any]]:
        resp = oci.pagination.list_call_get_all_results(self.client.list_digital_twin_relationships, iot_domain_id=iot_domain_id)
        return oci.util.to_dict(resp.data) or []

    # Get one digital twin relationship by OCID.
    def get(self, *, resource_id: str) -> Dict[str, Any]:
        return oci.util.to_dict(self.client.get_digital_twin_relationship(digital_twin_relationship_id=resource_id).data) or {}

    # Save digital-twin relationship rows.
    def save(self, rows: List[Dict[str, Any]]) -> None:
        self.session.save_resources(rows or [], self.TABLE_NAME)

    # No binary download endpoint for relationship rows.
    def download(self, *, resource_id: str, out_path: str) -> bool:  # pragma: no cover - placeholder
        _ = (resource_id, out_path)
        return False
