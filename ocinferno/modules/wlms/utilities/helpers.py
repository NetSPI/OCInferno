#!/usr/bin/env python3
from __future__ import annotations

import oci

from ocinferno.core.resource import OciListResource


_WLMS_TIMEOUT = (5, 15)  # (connect, read) seconds — WLMS endpoint may be entirely absent in a region


def _no_retry_list(client, method_name, scope_kwarg, compartment_id, **kwargs):
    """Paginate with NoneRetryStrategy and a short 15s read timeout.

    WLMS endpoints are absent in many regions. Without this, the SDK's default
    circuit-breaker retries and the 60s read timeout combine into a multi-minute hang.
    """
    kwargs.setdefault("timeout", _WLMS_TIMEOUT)
    return oci.pagination.list_call_get_all_results(
        getattr(client, method_name),
        **{scope_kwarg: compartment_id},
        retry_strategy=oci.retry.NoneRetryStrategy(),
        **kwargs,
    )


class WlmsWlsDomainsResource(OciListResource):
    CLIENT_CLS = oci.wlms.WeblogicManagementServiceClient
    SERVICE_NAME = "WebLogic Management"
    TABLE_NAME = "wlms_wls_domains"
    LIST_METHOD = "list_wls_domains"
    GET_METHOD = "get_wls_domain"
    GET_ID_PARAM = "wls_domain_id"
    COLUMNS = [
        "id",
        "display_name",
        "lifecycle_state",
        "time_created",
        "compartment_id",
        "middleware_type",
        "weblogic_version",
        "patch_readiness_status",
        "lifecycle_details",
    ]

    def _list_items(self, compartment_id, **kwargs):
        return _no_retry_list(self.client, self.LIST_METHOD, self.LIST_SCOPE_KWARG, compartment_id, **kwargs)


class WlmsManagedInstancesResource(OciListResource):
    CLIENT_CLS = oci.wlms.WeblogicManagementServiceClient
    SERVICE_NAME = "WebLogic Management"
    TABLE_NAME = "wlms_managed_instances"
    LIST_METHOD = "list_managed_instances"
    GET_METHOD = "get_managed_instance"
    GET_ID_PARAM = "managed_instance_id"
    COLUMNS = [
        "id",
        "display_name",
        "time_created",
        "compartment_id",
        "host_name",
        "server_count",
        "plugin_status",
    ]

    def _list_items(self, compartment_id, **kwargs):
        return _no_retry_list(self.client, self.LIST_METHOD, self.LIST_SCOPE_KWARG, compartment_id, **kwargs)
