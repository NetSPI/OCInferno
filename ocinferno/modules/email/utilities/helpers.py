from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

import oci
from ocinferno.core.resource import OciListResource
from ocinferno.core.utils.service_runtime import _init_client
from ocinferno.core.utils.service_runtime import ResourceBase


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


class _EmailClientMixin:
    """Shared ``_build_client`` for Email Resource classes: builds BOTH the
    control-plane ``EmailClient`` (used for list/get) and the data-plane
    ``EmailDPClient`` (stashed as ``self.dp_client`` for send-mail exploit use;
    not called by any list/get path here) via one ``build_email_clients`` call.
    """

    def _build_client(self, session, region: Optional[str] = None):
        email_client, self.dp_client = build_email_clients(session=session, region=region)
        self.email_client = email_client
        return email_client


class EmailSendersResource(_EmailClientMixin, OciListResource):
    CLIENT_CLS = oci.email.EmailClient
    SERVICE_NAME = "EmailDelivery"
    TABLE_NAME = "email_senders"
    LIST_METHOD = "list_senders"
    GET_METHOD = "get_sender"
    GET_ID_PARAM = "sender_id"
    COLUMNS = ["id", "email_address", "lifecycle_state", "time_created"]

    # No binary download endpoint for sender rows.

class EmailDomainsResource(_EmailClientMixin, OciListResource):
    CLIENT_CLS = oci.email.EmailClient
    SERVICE_NAME = "EmailDelivery"
    TABLE_NAME = "email_domains"
    LIST_METHOD = "list_email_domains"
    GET_METHOD = "get_email_domain"
    GET_ID_PARAM = "email_domain_id"
    COLUMNS = ["id", "name", "lifecycle_state", "time_created"]

    # No binary download endpoint for domain rows.

class EmailDkimsResource(_EmailClientMixin, OciListResource):
    CLIENT_CLS = oci.email.EmailClient
    SERVICE_NAME = "EmailDelivery"
    TABLE_NAME = "email_domain_dkims"
    LIST_METHOD = "list_dkims"
    # DKIMs are listed per-domain, not per-compartment; LIST_SCOPE_KWARG remaps the
    # base list()'s "compartment_id" positional onto the SDK's real scope kwarg.
    LIST_SCOPE_KWARG = "email_domain_id"
    GET_METHOD = "get_dkim"
    GET_ID_PARAM = "dkim_id"
    COLUMNS = ["id", "name", "lifecycle_state", "email_domain_id"]

    # List DKIM entries for one domain (the enum wrapper's call site).
    def list_for_domain(self, *, email_domain_id: str) -> List[Dict[str, Any]]:
        return self.list(compartment_id=email_domain_id)

    # No binary download endpoint for DKIM rows.

class EmailSpfsResource(_EmailClientMixin, OciListResource):
    CLIENT_CLS = oci.email.EmailClient
    SERVICE_NAME = "EmailDelivery"
    TABLE_NAME = "email_domain_spfs"
    LIST_METHOD = "list_spfs"
    LIST_SCOPE_KWARG = "email_domain_id"
    GET_METHOD = "get_spf"
    GET_ID_PARAM = "spf_id"
    COLUMNS = ["id", "lifecycle_state", "email_domain_id", "time_created"]

    # List SPF entries for one domain (the enum wrapper's call site).
    def list_for_domain(self, *, email_domain_id: str) -> List[Dict[str, Any]]:
        return self.list(compartment_id=email_domain_id)

    # No binary download endpoint for SPF rows.

class EmailReturnPathsResource(_EmailClientMixin, OciListResource):
    CLIENT_CLS = oci.email.EmailClient
    SERVICE_NAME = "EmailDelivery"
    TABLE_NAME = "email_return_paths"
    LIST_METHOD = "list_email_return_paths"
    GET_METHOD = "get_email_return_path"
    GET_ID_PARAM = "email_return_path_id"
    COLUMNS = ["id", "name", "lifecycle_state", "time_created"]

    # No binary download endpoint for return-path rows.

class EmailSuppressionsResource(_EmailClientMixin, OciListResource):
    CLIENT_CLS = oci.email.EmailClient
    SERVICE_NAME = "EmailDelivery"
    TABLE_NAME = "email_suppressions"
    LIST_METHOD = "list_suppressions"
    GET_METHOD = "get_suppression"
    GET_ID_PARAM = "suppression_id"
    COLUMNS = ["id", "email_address", "reason", "time_created"]

    # No binary download endpoint for suppression rows.

class EmailConfigurationResource(ResourceBase):
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

    # No binary download endpoint for configuration rows.
