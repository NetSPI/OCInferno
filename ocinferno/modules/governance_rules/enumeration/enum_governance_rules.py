#!/usr/bin/env python3
from __future__ import annotations

from ocinferno.core.utils.enum_framework import Component, run_components
from ocinferno.modules.governance_rules.utilities.helpers import (
    GovernanceRulesRulesResource,
    GovernanceRulesTenancyAttachmentsResource,
)

COMPONENTS = [
    Component("rules", GovernanceRulesRulesResource, help_text="Enumerate governance rules", cache_table="governance_rules_rules"),
    Component("tenancy_attachments", GovernanceRulesTenancyAttachmentsResource, help_text="Enumerate tenancy attachments", cache_table="governance_rules_tenancy_attachments"),
]


def run_module(user_args, session):
    return run_components(
        user_args, session, COMPONENTS,
        module_name="enum_governance_rules",
        description="Enumerate Governance Rules resources",
    )
