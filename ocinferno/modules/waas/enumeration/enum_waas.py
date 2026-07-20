#!/usr/bin/env python3
from __future__ import annotations

from ocinferno.core.utils.enum_framework import Component, run_components
from ocinferno.modules.waas.utilities.helpers import (
    WaasCertificatesResource,
    WaasCustomProtectionRulesResource,
    WaasHttpRedirectsResource,
    WaasWaasPoliciesResource,
)

COMPONENTS = [
    Component("waas_policies", WaasWaasPoliciesResource, help_text="Enumerate WAAS policies (exposes origin server addresses)", cache_table="waas_waas_policies"),
    Component("certificates", WaasCertificatesResource, help_text="Enumerate WAAS certificates", cache_table="waas_certificates"),
    Component("custom_protection_rules", WaasCustomProtectionRulesResource, help_text="Enumerate WAAS custom protection rules", cache_table="waas_custom_protection_rules"),
    Component("http_redirects", WaasHttpRedirectsResource, help_text="Enumerate WAAS HTTP redirects", cache_table="waas_http_redirects"),
]


def run_module(user_args, session):
    return run_components(
        user_args, session, COMPONENTS,
        module_name="enum_waas",
        description="Enumerate WAAS resources",
    )
