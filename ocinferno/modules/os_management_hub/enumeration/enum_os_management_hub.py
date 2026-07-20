#!/usr/bin/env python3
from __future__ import annotations

from ocinferno.modules.os_management_hub.utilities.helpers import (
    OsManagementHubManagedInstanceGroupsResource,
    OsManagementHubManagedInstancesResource,
    OsManagementHubScheduledJobsResource,
)
from ocinferno.core.utils.service_runtime import (
    append_cached_component_counts,
    make_parse_args,
    resolve_selected_components,
    run_standard_enum_component,
)


COMPONENTS = [
    ("managed_instances", "managed_instances", "Enumerate managed instances (fleet of hosts you can run commands on)"),
    ("managed_instance_groups", "managed_instance_groups", "Enumerate managed instance groups (fleet handles)"),
    ("scheduled_jobs", "scheduled_jobs", "Enumerate scheduled jobs (command-exec-at-scale surface)"),
]


CACHE_TABLES = {
    "managed_instances": ("osmh_managed_instances", "compartment_id"),
    "managed_instance_groups": ("osmh_managed_instance_groups", "compartment_id"),
    "scheduled_jobs": ("osmh_scheduled_jobs", "compartment_id"),
}


_parse_args = make_parse_args("Enumerate OS Management Hub resources", COMPONENTS)


def run_module(user_args, session):
    args, _ = _parse_args(user_args)

    component_order = [key for key, _suffix, _help in COMPONENTS]
    selected = resolve_selected_components(args, component_order)

    results = []

    if selected.get("managed_instances", False):
        resource = OsManagementHubManagedInstancesResource(session=session)
        results.append(run_standard_enum_component(
            user_args=args, session=session, component_key="managed_instances",
            list_rows=lambda cid: resource.list(compartment_id=cid),
            get_row=lambda row: resource.get(resource_id=row.get("id")),
            save_rows_fn=resource.save,
            print_columns=resource.COLUMNS,
            module_name="enum_os_management_hub",
        ))

    if selected.get("managed_instance_groups", False):
        resource = OsManagementHubManagedInstanceGroupsResource(session=session)
        results.append(run_standard_enum_component(
            user_args=args, session=session, component_key="managed_instance_groups",
            list_rows=lambda cid: resource.list(compartment_id=cid),
            get_row=lambda row: resource.get(resource_id=row.get("id")),
            save_rows_fn=resource.save,
            print_columns=resource.COLUMNS,
            module_name="enum_os_management_hub",
        ))

    if selected.get("scheduled_jobs", False):
        resource = OsManagementHubScheduledJobsResource(session=session)
        results.append(run_standard_enum_component(
            user_args=args, session=session, component_key="scheduled_jobs",
            list_rows=lambda cid: resource.list(compartment_id=cid),
            get_row=lambda row: resource.get(resource_id=row.get("id")),
            save_rows_fn=resource.save,
            print_columns=resource.COLUMNS,
            module_name="enum_os_management_hub",
        ))

    append_cached_component_counts(
        results=results,
        session=session,
        selected=selected,
        component_order=component_order,
        cache_tables=CACHE_TABLES,
    )

    return {"ok": True, "components": results}
