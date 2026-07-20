#!/usr/bin/env python3
from __future__ import annotations

import oci
from ocinferno.core.resource import OciListResource
from ocinferno.core.utils.module_helpers import write_response_stream_to_file


class IotDomainsResource(OciListResource):
    CLIENT_CLS = oci.iot.IotClient
    SERVICE_NAME = "IoT"
    TABLE_NAME = "iot_domains"
    LIST_METHOD = "list_iot_domains"
    GET_METHOD = "get_iot_domain"
    GET_ID_PARAM = "iot_domain_id"
    COLUMNS = ["id", "display_name", "lifecycle_state", "time_created"]

class IotDomainGroupsResource(OciListResource):
    CLIENT_CLS = oci.iot.IotClient
    SERVICE_NAME = "IoT"
    TABLE_NAME = "iot_domain_groups"
    LIST_METHOD = "list_iot_domain_groups"
    GET_METHOD = "get_iot_domain_group"
    GET_ID_PARAM = "iot_domain_group_id"
    COLUMNS = ["id", "display_name", "lifecycle_state", "time_created"]


class _IotDomainScopedResource(OciListResource):
    """Base for digital-twin resources nested under an IoT domain: list/get are scoped
    by iot_domain_id ALONE (no compartment_id), so LIST_SCOPE_KWARG remaps it."""

    CLIENT_CLS = oci.iot.IotClient
    SERVICE_NAME = "IoT"
    LIST_SCOPE_KWARG = "iot_domain_id"


class IotDigitalTwinModelsResource(_IotDomainScopedResource):
    TABLE_NAME = "iot_digital_twin_models"
    LIST_METHOD = "list_digital_twin_models"
    GET_METHOD = "get_digital_twin_model"
    GET_ID_PARAM = "digital_twin_model_id"
    COLUMNS = ["id", "display_name", "lifecycle_state", "time_created", "iot_domain_id"]

    # Download the model spec blob.
    def download(self, *, resource_id: str, out_path: str) -> bool:
        try:
            resp = self.client.get_digital_twin_model_spec(digital_twin_model_id=resource_id)
        except Exception:
            return False
        return write_response_stream_to_file(getattr(resp, "data", None), out_path)


class IotDigitalTwinInstancesResource(_IotDomainScopedResource):
    TABLE_NAME = "iot_digital_twin_instances"
    LIST_METHOD = "list_digital_twin_instances"
    GET_METHOD = "get_digital_twin_instance"
    GET_ID_PARAM = "digital_twin_instance_id"
    COLUMNS = ["id", "display_name", "lifecycle_state", "time_created", "iot_domain_id"]

    # Download the instance content blob.
    def download(self, *, resource_id: str, out_path: str) -> bool:
        try:
            resp = self.client.get_digital_twin_instance_content(digital_twin_instance_id=resource_id)
        except Exception:
            return False
        return write_response_stream_to_file(getattr(resp, "data", None), out_path)


class IotDigitalTwinAdaptersResource(_IotDomainScopedResource):
    TABLE_NAME = "iot_digital_twin_adapters"
    LIST_METHOD = "list_digital_twin_adapters"
    GET_METHOD = "get_digital_twin_adapter"
    GET_ID_PARAM = "digital_twin_adapter_id"
    COLUMNS = ["id", "display_name", "lifecycle_state", "time_created", "iot_domain_id"]

    # No binary download endpoint for adapter rows.

class IotDigitalTwinRelationshipsResource(_IotDomainScopedResource):
    TABLE_NAME = "iot_digital_twin_relationships"
    LIST_METHOD = "list_digital_twin_relationships"
    GET_METHOD = "get_digital_twin_relationship"
    GET_ID_PARAM = "digital_twin_relationship_id"
    COLUMNS = ["id", "display_name", "lifecycle_state", "time_created", "iot_domain_id"]

    # No binary download endpoint for relationship rows.
