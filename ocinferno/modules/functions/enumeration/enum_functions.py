#!/usr/bin/env python3
from __future__ import annotations

from ocinferno.core.utils.enum_framework import Component, nested_list_fn, run_components
from ocinferno.core.utils.service_runtime import field_dump_download
from ocinferno.modules.functions.utilities.helpers import (
    FunctionsAppsResource,
    FunctionsFunctionsResource,
)


def _add_extra_args(parser):
    parser.add_argument(
        "--app-ids", action="append", default=[],
        help="Application OCIDs (repeatable, comma-separated supported) to scope function listing.",
    )


COMPONENTS = [
    Component("apps", FunctionsAppsResource, help_text="Enumerate applications", cache_table="functions_apps",
              download_fn=field_dump_download(
                  field="config", service_name="functions", subdir="application-config",
                  filename="config.json")),
    Component("functions", FunctionsFunctionsResource, help_text="Enumerate functions", cache_table="functions_functions",
              list_fn=nested_list_fn(
                  parent_resource_cls=FunctionsAppsResource,
                  parent_id_field="application_id",
                  manual_parent_arg="app_ids",
                  child_takes_compartment=False,
              ),
              download_fn=field_dump_download(
                  field="config", service_name="functions", subdir="function-config",
                  filename="config.json")),
]


def run_module(user_args, session):
    return run_components(
        user_args, session, COMPONENTS,
        module_name="enum_functions",
        description="Enumerate Functions resources",
        add_extra_args=_add_extra_args,
    )
