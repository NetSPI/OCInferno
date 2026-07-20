#!/usr/bin/env python3
from __future__ import annotations

import oci

from ocinferno.core.resource import OciListResource


class BastionBastionsResource(OciListResource):
    """OCI Bastions -- managed jump hosts into private subnets. High value: reveals
    which private VCNs/subnets have an SSH/port-forward ingress path."""

    CLIENT_CLS = oci.bastion.BastionClient
    SERVICE_NAME = "Bastion"
    TABLE_NAME = "bastion_bastions"
    LIST_METHOD = "list_bastions"
    GET_METHOD = "get_bastion"
    GET_ID_PARAM = "bastion_id"
    COLUMNS = ["id", "name", "bastion_type", "lifecycle_state", "target_vcn_id", "target_subnet_id", "time_created"]


class BastionSessionsResource(OciListResource):
    """Active Bastion sessions (managed-SSH / port-forward / dynamic-port-forward).
    Nested under a bastion: list_sessions is scoped by bastion_id ALONE (no
    compartment_id). High value: an active session is a live path onto a private host."""

    CLIENT_CLS = oci.bastion.BastionClient
    SERVICE_NAME = "Bastion"
    TABLE_NAME = "bastion_sessions"
    LIST_METHOD = "list_sessions"
    GET_METHOD = "get_session"
    GET_ID_PARAM = "session_id"
    LIST_SCOPE_KWARG = "bastion_id"
    COLUMNS = ["id", "display_name", "bastion_id", "bastion_name", "lifecycle_state", "target_resource_details", "time_created"]
