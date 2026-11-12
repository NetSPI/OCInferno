#!/usr/bin/env python3
from __future__ import annotations

from ocinferno.core.utils.enum_framework import Component, nested_list_fn, run_components
from ocinferno.modules.dataintegration.utilities.helpers import (
    DataIntegrationDataAssetsResource,
    DataIntegrationWorkspacesResource,
)

COMPONENTS = [
    Component("workspaces", DataIntegrationWorkspacesResource, help_text="Enumerate workspaces", cache_table="data_integration_workspaces"),
    Component("data_assets", DataIntegrationDataAssetsResource, help_text="Enumerate data assets (connection host/endpoint details)",
              cache_table="data_integration_data_assets",
              list_fn=nested_list_fn(
                  parent_resource_cls=DataIntegrationWorkspacesResource,
                  parent_id_field="di_workspace_id",
                  manual_parent_arg="workspace_ids",
                  child_takes_compartment=False,
              )),
]


def _add_extra_args(parser):
    parser.add_argument("--workspace-ids", default="",
                        help="Comma-separated workspace OCIDs to scope data-asset enumeration (default: all in compartment)")


def run_module(user_args, session):
    return run_components(
        user_args, session, COMPONENTS,
        module_name="enum_dataintegration",
        description="Enumerate Data Integration resources",
        add_extra_args=_add_extra_args,
    )
