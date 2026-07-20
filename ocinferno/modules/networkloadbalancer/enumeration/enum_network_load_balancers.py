#!/usr/bin/env python3
from __future__ import annotations

from ocinferno.core.utils.enum_framework import Component, run_components
from ocinferno.modules.networkloadbalancer.utilities.helpers import NetworkLoadBalancersResource


def _add_extra_args(parser):
    parser.add_argument("--nlb-id", default="", help="Get a specific NLB by OCID (instead of listing the compartment).")


def _list_nlbs(session, args, resource):
    """--nlb-id scopes to a single get(); otherwise list the compartment."""
    nlb_id = (getattr(args, "nlb_id", "") or "").strip()

    def _inner(cid):
        if nlb_id:
            row = resource.get(resource_id=nlb_id) or {}
            return [row] if row else []
        return resource.list(compartment_id=cid)

    return _inner


COMPONENTS = [
    Component(
        "network_load_balancers", NetworkLoadBalancersResource,
        help_text="Enumerate network load balancers", cache_table="network_load_balancers",
        list_fn=_list_nlbs, require_compartment=False,
    ),
]


def run_module(user_args, session):
    return run_components(
        user_args, session, COMPONENTS,
        module_name="enum_network_load_balancers",
        description="Enumerate OCI Network Load Balancers",
        add_extra_args=_add_extra_args,
        require_compartment=False,
    )
