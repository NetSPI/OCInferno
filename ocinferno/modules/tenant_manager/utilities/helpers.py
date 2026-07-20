#!/usr/bin/env python3
from __future__ import annotations

import oci

from ocinferno.core.resource import OciListResource


class TenantManagerOrganizationsResource(OciListResource):
    CLIENT_CLS = oci.tenant_manager_control_plane.OrganizationClient
    SERVICE_NAME = "Tenant Manager"
    TABLE_NAME = "tenant_manager_organizations"
    LIST_METHOD = "list_organizations"
    GET_METHOD = "get_organization"
    GET_ID_PARAM = "organization_id"
    COLUMNS = [
        "id",
        "display_name",
        "lifecycle_state",
        "time_created",
        "compartment_id",
        "parent_name",
        "default_ucm_subscription_id",
        "time_updated",
    ]


class TenantManagerDomainsResource(OciListResource):
    CLIENT_CLS = oci.tenant_manager_control_plane.DomainClient
    SERVICE_NAME = "Tenant Manager"
    TABLE_NAME = "tenant_manager_domains"
    LIST_METHOD = "list_domains"
    GET_METHOD = "get_domain"
    GET_ID_PARAM = "domain_id"
    COLUMNS = [
        "id",
        "domain_name",
        "lifecycle_state",
        "time_created",
        "compartment_id",
        "owner_id",
        "status",
        "txt_record",
    ]


class TenantManagerSenderInvitationsResource(OciListResource):
    CLIENT_CLS = oci.tenant_manager_control_plane.SenderInvitationClient
    SERVICE_NAME = "Tenant Manager"
    TABLE_NAME = "tenant_manager_sender_invitations"
    LIST_METHOD = "list_sender_invitations"
    GET_METHOD = "get_sender_invitation"
    GET_ID_PARAM = "sender_invitation_id"
    COLUMNS = [
        "id",
        "display_name",
        "lifecycle_state",
        "time_created",
        "compartment_id",
        "status",
        "recipient_invitation_id",
        "recipient_tenancy_id",
        "recipient_email_address",
    ]


class TenantManagerRecipientInvitationsResource(OciListResource):
    CLIENT_CLS = oci.tenant_manager_control_plane.RecipientInvitationClient
    SERVICE_NAME = "Tenant Manager"
    TABLE_NAME = "tenant_manager_recipient_invitations"
    LIST_METHOD = "list_recipient_invitations"
    GET_METHOD = "get_recipient_invitation"
    GET_ID_PARAM = "recipient_invitation_id"
    COLUMNS = [
        "id",
        "display_name",
        "lifecycle_state",
        "time_created",
        "compartment_id",
        "status",
        "sender_invitation_id",
        "sender_tenancy_id",
        "recipient_email_address",
    ]
