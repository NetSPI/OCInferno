#!/usr/bin/env python3
from __future__ import annotations

import oci

from ocinferno.core.resource import OciListResource


class LoadBalancersResource(OciListResource):
    CLIENT_CLS = oci.load_balancer.LoadBalancerClient
    SERVICE_NAME = "Load Balancer"
    TABLE_NAME = "load_balancers"
    LIST_METHOD = "list_load_balancers"
    GET_METHOD = "get_load_balancer"
    GET_ID_PARAM = "load_balancer_id"
    COLUMNS = [
        "id",
        "display_name",
        "lifecycle_state",
        "time_created",
        "compartment_id",
        "ip_addresses",
        "is_private",
        "shape_name",
        "subnet_ids",
        "network_security_group_ids",
        "listeners",
        "backend_sets",
        "certificates",
        "hostnames",
        "routing_policies",
    ]
