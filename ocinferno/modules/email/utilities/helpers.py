from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

import oci
from ocinferno.core.utils.service_runtime import _init_client


def build_email_clients(session, region: Optional[str] = None) -> Tuple[Any, Any]:
    """Initialize Email control/data plane clients with shared signer/proxy/session behavior."""
    email_client = _init_client(oci.email.EmailClient, session=session, service_name="EmailDelivery")
    dp_client = _init_client(
        oci.email_data_plane.EmailDPClient,
        session=session,
        service_name="EmailDeliveryDataPlane",
    )

    target_region = region or getattr(session, "region", None)
    if target_region:
        for client in (email_client, dp_client):
            try:
                client.base_client.set_region(target_region)
            except Exception:
                pass
    return email_client, dp_client


class EmailSendersResource:
    TABLE_NAME = "email_senders"
    COLUMNS = ["id", "email_address", "lifecycle_state", "time_created"]

    def __init__(self, session, region: Optional[str] = None):
        self.session = session
        self.email_client, self.dp_client = build_email_clients(session=session, region=region)

    # List sender addresses in a compartment.
    def list(self, *, compartment_id: str) -> List[Dict[str, Any]]:
        resp = oci.pagination.list_call_get_all_results(self.email_client.list_senders, compartment_id=compartment_id)
        return oci.util.to_dict(resp.data) or []

    # Get one sender by OCID.
    def get(self, *, resource_id: str) -> Dict[str, Any]:
        try:
            resp = self.email_client.get_sender(sender_id=resource_id)
        except Exception:
            return {}
        return oci.util.to_dict(resp.data) or {}

    # Save sender rows.
    def save(self, rows: List[Dict[str, Any]]) -> None:
        self.session.save_resources(rows or [], self.TABLE_NAME)

    # No binary download endpoint for sender rows.
    def download(self, *, resource_id: str, out_path: str) -> bool:
        _ = (resource_id, out_path)
        return False


class EmailDomainsResource:
    TABLE_NAME = "email_domains"
    COLUMNS = ["id", "name", "lifecycle_state", "time_created"]

    def __init__(self, session, region: Optional[str] = None):
        self.session = session
        self.email_client, self.dp_client = build_email_clients(session=session, region=region)

    # List email domains in a compartment.
    def list(self, *, compartment_id: str) -> List[Dict[str, Any]]:
        resp = oci.pagination.list_call_get_all_results(self.email_client.list_email_domains, compartment_id=compartment_id)
        return oci.util.to_dict(resp.data) or []

    # Get one domain by OCID.
    def get(self, *, resource_id: str) -> Dict[str, Any]:
        try:
            resp = self.email_client.get_email_domain(email_domain_id=resource_id)
        except Exception:
            return {}
        return oci.util.to_dict(resp.data) or {}

    # Save domain rows.
    def save(self, rows: List[Dict[str, Any]]) -> None:
        self.session.save_resources(rows or [], self.TABLE_NAME)

    # No binary download endpoint for domain rows.
    def download(self, *, resource_id: str, out_path: str) -> bool:
        _ = (resource_id, out_path)
        return False


class EmailDkimsResource:
    TABLE_NAME = "email_domain_dkims"
    COLUMNS = ["id", "name", "lifecycle_state", "email_domain_id"]

    def __init__(self, session, region: Optional[str] = None):
        self.session = session
        self.email_client, self.dp_client = build_email_clients(session=session, region=region)

    # List DKIM entries for one domain.
    def list_for_domain(self, *, email_domain_id: str) -> List[Dict[str, Any]]:
        resp = oci.pagination.list_call_get_all_results(self.email_client.list_dkims, email_domain_id=email_domain_id)
        return oci.util.to_dict(resp.data) or []

    # Compatibility list method alias for SDK-like pattern.
    def list(self, *, email_domain_id: str) -> List[Dict[str, Any]]:
        return self.list_for_domain(email_domain_id=email_domain_id)

    # Get one DKIM by OCID.
    def get(self, *, resource_id: str) -> Dict[str, Any]:
        try:
            resp = self.email_client.get_dkim(dkim_id=resource_id)
        except Exception:
            return {}
        return oci.util.to_dict(resp.data) or {}

    # Save DKIM rows.
    def save(self, rows: List[Dict[str, Any]]) -> None:
        self.session.save_resources(rows or [], self.TABLE_NAME)

    # No binary download endpoint for DKIM rows.
    def download(self, *, resource_id: str, out_path: str) -> bool:
        _ = (resource_id, out_path)
        return False


class EmailSpfsResource:
    TABLE_NAME = "email_domain_spfs"
    COLUMNS = ["id", "lifecycle_state", "email_domain_id", "time_created"]

    def __init__(self, session, region: Optional[str] = None):
        self.session = session
        self.email_client, self.dp_client = build_email_clients(session=session, region=region)

    # List SPF entries for one domain.
    def list_for_domain(self, *, email_domain_id: str) -> List[Dict[str, Any]]:
        resp = oci.pagination.list_call_get_all_results(self.email_client.list_spfs, email_domain_id=email_domain_id)
        return oci.util.to_dict(resp.data) or []

    # Compatibility list method alias for SDK-like pattern.
    def list(self, *, email_domain_id: str) -> List[Dict[str, Any]]:
        return self.list_for_domain(email_domain_id=email_domain_id)

    # Get one SPF record by OCID.
    def get(self, *, resource_id: str) -> Dict[str, Any]:
        try:
            resp = self.email_client.get_spf(spf_id=resource_id)
        except Exception:
            return {}
        return oci.util.to_dict(resp.data) or {}

    # Save SPF rows.
    def save(self, rows: List[Dict[str, Any]]) -> None:
        self.session.save_resources(rows or [], self.TABLE_NAME)

    # No binary download endpoint for SPF rows.
    def download(self, *, resource_id: str, out_path: str) -> bool:
        _ = (resource_id, out_path)
        return False


class EmailReturnPathsResource:
    TABLE_NAME = "email_return_paths"
    COLUMNS = ["id", "name", "lifecycle_state", "time_created"]

    def __init__(self, session, region: Optional[str] = None):
        self.session = session
        self.email_client, self.dp_client = build_email_clients(session=session, region=region)

    # List return paths in a compartment.
    def list(self, *, compartment_id: str) -> List[Dict[str, Any]]:
        resp = oci.pagination.list_call_get_all_results(self.email_client.list_email_return_paths, compartment_id=compartment_id)
        return oci.util.to_dict(resp.data) or []

    # Get one return path by OCID.
    def get(self, *, resource_id: str) -> Dict[str, Any]:
        try:
            resp = self.email_client.get_email_return_path(email_return_path_id=resource_id)
        except Exception:
            return {}
        return oci.util.to_dict(resp.data) or {}

    # Save return-path rows.
    def save(self, rows: List[Dict[str, Any]]) -> None:
        self.session.save_resources(rows or [], self.TABLE_NAME)

    # No binary download endpoint for return-path rows.
    def download(self, *, resource_id: str, out_path: str) -> bool:
        _ = (resource_id, out_path)
        return False


class EmailSuppressionsResource:
    TABLE_NAME = "email_suppressions"
    COLUMNS = ["id", "email_address", "reason", "time_created"]

    def __init__(self, session, region: Optional[str] = None):
        self.session = session
        self.email_client, self.dp_client = build_email_clients(session=session, region=region)

    # List suppressions in a compartment.
    def list(self, *, compartment_id: str) -> List[Dict[str, Any]]:
        resp = oci.pagination.list_call_get_all_results(self.email_client.list_suppressions, compartment_id=compartment_id)
        return oci.util.to_dict(resp.data) or []

    # Get one suppression by OCID.
    def get(self, *, resource_id: str) -> Dict[str, Any]:
        try:
            resp = self.email_client.get_suppression(suppression_id=resource_id)
        except Exception:
            return {}
        return oci.util.to_dict(resp.data) or {}

    # Save suppression rows.
    def save(self, rows: List[Dict[str, Any]]) -> None:
        self.session.save_resources(rows or [], self.TABLE_NAME)

    # No binary download endpoint for suppression rows.
    def download(self, *, resource_id: str, out_path: str) -> bool:
        _ = (resource_id, out_path)
        return False


class EmailConfigurationResource:
    TABLE_NAME = "email_configuration"
    COLUMNS = ["http_submit_endpoint", "smtp_submit_endpoint", "compartment_id"]

    def __init__(self, session, region: Optional[str] = None):
        self.session = session
        self.email_client, self.dp_client = build_email_clients(session=session, region=region)

    # List configuration as a single-row list for consistency.
    def list(self, *, compartment_id: str) -> List[Dict[str, Any]]:
        row = self.get(compartment_id=compartment_id)
        return [row] if row else []

    # Get email configuration for a compartment.
    def get(self, *, compartment_id: str) -> Dict[str, Any]:
        try:
            resp = self.email_client.get_email_configuration(compartment_id=compartment_id)
        except Exception:
            return {}
        return oci.util.to_dict(resp.data) or {}

    # Save configuration rows.
    def save(self, rows: List[Dict[str, Any]]) -> None:
        self.session.save_resources(rows or [], self.TABLE_NAME)

    # No binary download endpoint for configuration rows.
    def download(self, *, resource_id: str, out_path: str) -> bool:
        _ = (resource_id, out_path)
        return False
