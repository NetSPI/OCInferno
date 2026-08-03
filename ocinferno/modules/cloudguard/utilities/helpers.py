#!/usr/bin/env python3
from __future__ import annotations

import oci

from ocinferno.core.resource import OciListResource


class CloudGuardTargetsResource(OciListResource):
    CLIENT_CLS = oci.cloud_guard.CloudGuardClient
    SERVICE_NAME = "CloudGuard"
    TABLE_NAME = "cloud_guard_targets"
    LIST_METHOD = "list_targets"
    GET_METHOD = "get_target"
    GET_ID_PARAM = "target_id"


class CloudGuardProblemsResource(OciListResource):
    CLIENT_CLS = oci.cloud_guard.CloudGuardClient
    SERVICE_NAME = "CloudGuard"
    TABLE_NAME = "cloud_guard_problems"
    LIST_METHOD = "list_problems"
    GET_METHOD = "get_problem"
    GET_ID_PARAM = "problem_id"


class CloudGuardRecommendationsResource(OciListResource):
    CLIENT_CLS = oci.cloud_guard.CloudGuardClient
    SERVICE_NAME = "CloudGuard"
    TABLE_NAME = "cloud_guard_recommendations"
    LIST_METHOD = "list_recommendations"
    # CloudGuardClient has no 'get_recommendation' method; --get is disabled via supports_get=False
    # in the Component definition.  GET_METHOD left as the base-class default ("").
    GET_ID_PARAM = "recommendation_id"


class CloudGuardDetectorRecipesResource(OciListResource):
    CLIENT_CLS = oci.cloud_guard.CloudGuardClient
    SERVICE_NAME = "CloudGuard"
    TABLE_NAME = "cloud_guard_detector_recipes"
    LIST_METHOD = "list_detector_recipes"
    GET_METHOD = "get_detector_recipe"
    GET_ID_PARAM = "detector_recipe_id"


class CloudGuardResponderRecipesResource(OciListResource):
    CLIENT_CLS = oci.cloud_guard.CloudGuardClient
    SERVICE_NAME = "CloudGuard"
    TABLE_NAME = "cloud_guard_responder_recipes"
    LIST_METHOD = "list_responder_recipes"
    GET_METHOD = "get_responder_recipe"
    GET_ID_PARAM = "responder_recipe_id"


class CloudGuardManagedListsResource(OciListResource):
    CLIENT_CLS = oci.cloud_guard.CloudGuardClient
    SERVICE_NAME = "CloudGuard"
    TABLE_NAME = "cloud_guard_managed_lists"
    LIST_METHOD = "list_managed_lists"
    GET_METHOD = "get_managed_list"
    GET_ID_PARAM = "managed_list_id"


class CloudGuardDataSourcesResource(OciListResource):
    CLIENT_CLS = oci.cloud_guard.CloudGuardClient
    SERVICE_NAME = "CloudGuard"
    TABLE_NAME = "cloud_guard_data_sources"
    LIST_METHOD = "list_data_sources"
    GET_METHOD = "get_data_source"
    GET_ID_PARAM = "data_source_id"


class CloudGuardSecurityZonesResource(OciListResource):
    CLIENT_CLS = oci.cloud_guard.CloudGuardClient
    SERVICE_NAME = "CloudGuard"
    TABLE_NAME = "cloud_guard_security_zones"
    LIST_METHOD = "list_security_zones"
    GET_METHOD = "get_security_zone"
    GET_ID_PARAM = "security_zone_id"


class CloudGuardSecurityRecipesResource(OciListResource):
    CLIENT_CLS = oci.cloud_guard.CloudGuardClient
    SERVICE_NAME = "CloudGuard"
    TABLE_NAME = "cloud_guard_security_recipes"
    LIST_METHOD = "list_security_recipes"
    GET_METHOD = "get_security_recipe"
    GET_ID_PARAM = "security_recipe_id"


class CloudGuardSecurityPoliciesResource(OciListResource):
    CLIENT_CLS = oci.cloud_guard.CloudGuardClient
    SERVICE_NAME = "CloudGuard"
    TABLE_NAME = "cloud_guard_security_policies"
    LIST_METHOD = "list_security_policies"
    GET_METHOD = "get_security_policy"
    GET_ID_PARAM = "security_policy_id"
