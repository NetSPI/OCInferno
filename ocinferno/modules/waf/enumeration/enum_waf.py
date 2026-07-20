#!/usr/bin/env python3
from __future__ import annotations

from ocinferno.core.utils.enum_framework import Component, run_components
from ocinferno.modules.waf.utilities.helpers import (
    WebAppFirewallPoliciesResource,
    WebAppFirewallsResource,
)

COMPONENTS = [
    Component("web_app_firewalls", WebAppFirewallsResource, help_text="Enumerate web-app-firewalls", cache_table="web_app_firewalls"),
    Component("firewall_policies", WebAppFirewallPoliciesResource, help_text="Enumerate firewall-policies", cache_table="web_app_firewall_policies"),
]


def run_module(user_args, session):
    return run_components(
        user_args, session, COMPONENTS,
        module_name="enum_waf",
        description="Enumerate WAF resources",
    )
