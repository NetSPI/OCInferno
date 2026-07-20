#!/usr/bin/env python3
from __future__ import annotations

import oci

from ocinferno.core.resource import OciListResource


class FusionAppsEnvironmentsResource(OciListResource):
    CLIENT_CLS = oci.fusion_apps.FusionApplicationsClient
    SERVICE_NAME = "Fusion Applications"
    TABLE_NAME = "fusion_apps_environments"
    LIST_METHOD = "list_fusion_environments"
    GET_METHOD = "get_fusion_environment"
    GET_ID_PARAM = "fusion_environment_id"
    COLUMNS = [
        "id",
        "display_name",
        "lifecycle_state",
        "fusion_environment_type",
        "time_created",
        "compartment_id",
        "public_url",
        "dns_prefix",
        "fusion_environment_family_id",
        "version",
        "is_break_glass_enabled",
        "lockbox_id",
        "subscription_ids",
    ]


class FusionAppsEnvironmentFamiliesResource(OciListResource):
    CLIENT_CLS = oci.fusion_apps.FusionApplicationsClient
    SERVICE_NAME = "Fusion Applications"
    TABLE_NAME = "fusion_apps_environment_families"
    LIST_METHOD = "list_fusion_environment_families"
    GET_METHOD = "get_fusion_environment_family"
    GET_ID_PARAM = "fusion_environment_family_id"
    COLUMNS = [
        "id",
        "display_name",
        "lifecycle_state",
        "time_created",
        "compartment_id",
        "subscription_ids",
        "is_subscription_update_needed",
    ]
