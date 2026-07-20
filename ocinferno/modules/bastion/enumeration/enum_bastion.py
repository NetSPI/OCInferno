#!/usr/bin/env python3
from __future__ import annotations

from ocinferno.core.utils.enum_framework import Component, nested_list_fn, run_components
from ocinferno.modules.bastion.utilities.helpers import (
    BastionBastionsResource,
    BastionSessionsResource,
)

COMPONENTS = [
    Component("bastions", BastionBastionsResource, help_text="Enumerate bastions", cache_table="bastion_bastions"),
    Component("sessions", BastionSessionsResource, help_text="Enumerate bastion sessions", cache_table="bastion_sessions",
              list_fn=nested_list_fn(
                  parent_resource_cls=BastionBastionsResource,
                  parent_id_field="bastion_id",
                  child_takes_compartment=False,
              )),
]


def run_module(user_args, session):
    return run_components(
        user_args, session, COMPONENTS,
        module_name="enum_bastion",
        description="Enumerate Bastion resources",
    )
