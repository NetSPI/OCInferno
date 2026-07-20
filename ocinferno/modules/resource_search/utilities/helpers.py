#!/usr/bin/env python3
from __future__ import annotations

from typing import Any, Dict, List, Optional

import oci
from ocinferno.core.utils.service_runtime import _init_client
from ocinferno.core.utils.service_runtime import ResourceBase


class ResourceSearchInventoryResource(ResourceBase):
    """OCI Search Service inventory -- the closest OCI analog to GCP Cloud Asset
    Inventory. One structured 'query all resources' pass returns every resource
    (OCID, type, compartment) tenancy-wide: a recon force-multiplier and the source
    for an offline OpenGraph build (see process_oracle_cloud_hound_data --from-inventory)."""

    TABLE_NAME = "resource_search_inventory"
    # ResourceSummary.identifier is the OCID (there is no 'id' field).
    COLUMNS = ["identifier", "display_name", "resource_type", "compartment_id",
               "availability_domain", "lifecycle_state", "time_created"]

    def __init__(self, session, region: Optional[str] = None):
        self.session = session
        self.client = _init_client(oci.resource_search.ResourceSearchClient, session=session,
                                   service_name="Resource Search")

    def search_all(self, *, query: str = "query all resources") -> List[Dict[str, Any]]:
        """Run a structured search and return every matching resource summary (paginated)."""
        details = oci.resource_search.models.StructuredSearchDetails(
            query=query,
            type="Structured",
            matching_context_type=oci.resource_search.models.SearchDetails.MATCHING_CONTEXT_TYPE_NONE,
        )
        resp = oci.pagination.list_call_get_all_results(self.client.search_resources, details)
        return oci.util.to_dict(resp.data) or []
