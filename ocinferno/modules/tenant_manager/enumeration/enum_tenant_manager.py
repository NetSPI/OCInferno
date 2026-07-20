#!/usr/bin/env python3
from __future__ import annotations

from ocinferno.core.utils.enum_framework import Component, run_components
from ocinferno.modules.tenant_manager.utilities.helpers import (
    TenantManagerDomainsResource,
    TenantManagerOrganizationsResource,
    TenantManagerRecipientInvitationsResource,
    TenantManagerSenderInvitationsResource,
)

COMPONENTS = [
    Component("organizations", TenantManagerOrganizationsResource, help_text="Enumerate organizations", cache_table="tenant_manager_organizations"),
    Component("domains", TenantManagerDomainsResource, help_text="Enumerate domains", cache_table="tenant_manager_domains"),
    Component("sender_invitations", TenantManagerSenderInvitationsResource, help_text="Enumerate sender-invitations", cache_table="tenant_manager_sender_invitations"),
    Component("recipient_invitations", TenantManagerRecipientInvitationsResource, help_text="Enumerate recipient-invitations", cache_table="tenant_manager_recipient_invitations"),
]


def run_module(user_args, session):
    return run_components(
        user_args, session, COMPONENTS,
        module_name="enum_tenant_manager",
        description="Enumerate Tenant Manager resources",
    )
