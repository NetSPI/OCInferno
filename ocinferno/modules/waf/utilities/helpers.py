#!/usr/bin/env python3
from __future__ import annotations

import oci

from ocinferno.core.resource import OciListResource


class WebAppFirewallsResource(OciListResource):
    CLIENT_CLS = oci.waf.WafClient
    SERVICE_NAME = "WAF"
    TABLE_NAME = "web_app_firewalls"
    LIST_METHOD = "list_web_app_firewalls"
    GET_METHOD = "get_web_app_firewall"
    GET_ID_PARAM = "web_app_firewall_id"
    COLUMNS = [
        "id",
        "display_name",
        "lifecycle_state",
        "time_created",
        "compartment_id",
        "backend_type",
        "web_app_firewall_policy_id",
        "load_balancer_id",
    ]


class WebAppFirewallPoliciesResource(OciListResource):
    CLIENT_CLS = oci.waf.WafClient
    SERVICE_NAME = "WAF"
    TABLE_NAME = "web_app_firewall_policies"
    LIST_METHOD = "list_web_app_firewall_policies"
    GET_METHOD = "get_web_app_firewall_policy"
    GET_ID_PARAM = "web_app_firewall_policy_id"
    COLUMNS = [
        "id",
        "display_name",
        "lifecycle_state",
        "time_created",
        "compartment_id",
        "actions",
        "request_access_control",
        "response_access_control",
        "request_rate_limiting",
    ]
