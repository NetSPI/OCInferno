#!/usr/bin/env python3
from __future__ import annotations

import oci

from ocinferno.core.resource import OciListResource


class WaasWaasPoliciesResource(OciListResource):
    CLIENT_CLS = oci.waas.WaasClient
    SERVICE_NAME = "WAAS"
    TABLE_NAME = "waas_waas_policies"
    LIST_METHOD = "list_waas_policies"
    GET_METHOD = "get_waas_policy"
    GET_ID_PARAM = "waas_policy_id"
    COLUMNS = [
        "id",
        "display_name",
        "lifecycle_state",
        "time_created",
        "compartment_id",
        "domain",
        "additional_domains",
        "cname",
        "origins",
        "origin_groups",
        # policy_config (incl. certificate_id/is_https_enabled) only appears on the
        # full get_waas_policy response -- list_waas_policies summaries omit it. Run
        # with --get to populate it; config_audit's certificate-attachment check
        # relies on this to distinguish a cert bound to a domain from an unused one.
        "policy_config",
    ]


class WaasCertificatesResource(OciListResource):
    CLIENT_CLS = oci.waas.WaasClient
    SERVICE_NAME = "WAAS"
    TABLE_NAME = "waas_certificates"
    LIST_METHOD = "list_certificates"
    GET_METHOD = "get_certificate"
    GET_ID_PARAM = "certificate_id"
    COLUMNS = [
        "id",
        "display_name",
        "lifecycle_state",
        "time_created",
        "compartment_id",
        "subject_name",
        "issuer_name",
        "time_not_valid_after",
        "is_trust_verification_disabled",
    ]


class WaasCustomProtectionRulesResource(OciListResource):
    CLIENT_CLS = oci.waas.WaasClient
    SERVICE_NAME = "WAAS"
    TABLE_NAME = "waas_custom_protection_rules"
    LIST_METHOD = "list_custom_protection_rules"
    GET_METHOD = "get_custom_protection_rule"
    GET_ID_PARAM = "custom_protection_rule_id"
    COLUMNS = [
        "id",
        "display_name",
        "lifecycle_state",
        "time_created",
        "compartment_id",
        "description",
        "mod_security_rule_ids",
        "template",
    ]


class WaasHttpRedirectsResource(OciListResource):
    CLIENT_CLS = oci.waas.RedirectClient
    SERVICE_NAME = "WAAS"
    TABLE_NAME = "waas_http_redirects"
    LIST_METHOD = "list_http_redirects"
    GET_METHOD = "get_http_redirect"
    GET_ID_PARAM = "http_redirect_id"
    COLUMNS = [
        "id",
        "display_name",
        "lifecycle_state",
        "time_created",
        "compartment_id",
        "domain",
        "target",
        "response_code",
    ]
