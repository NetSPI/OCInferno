#!/usr/bin/env python3
from __future__ import annotations

from ocinferno.core.utils.enum_framework import Component, component_arg_specs, nested_list_fn, run_components
from ocinferno.core.utils.module_helpers import domain_ids_from_db
from ocinferno.core.utils.service_runtime import parse_wrapper_args, resolve_selected_components, resource_method_download
from ocinferno.modules.iot.utilities.helpers import (
    IotDigitalTwinAdaptersResource,
    IotDigitalTwinInstancesResource,
    IotDigitalTwinModelsResource,
    IotDigitalTwinRelationshipsResource,
    IotDomainGroupsResource,
    IotDomainsResource,
)


_NESTED_KEYS = (
    "digital_twin_models",
    "digital_twin_instances",
    "digital_twin_adapters",
    "digital_twin_relationships",
)

# Both resources implement a --get-adjacent binary download (model spec / instance
# content blob) that was previously never wired into a Component -- --download was
# a silent no-op for either. Same method name ("download") on both classes, but each
# factory call binds its own subdir/filename so the two content types land separately.
_model_spec_download = resource_method_download(
    method="download", service_name="iot", subdir="digital-twin-models",
    filename="model_spec.json", label="IoT digital twin model specs",
)
_instance_content_download = resource_method_download(
    method="download", service_name="iot", subdir="digital-twin-instances",
    filename="instance_content.json", label="IoT digital twin instance content",
)


def _add_extra_args(parser):
    parser.add_argument("--domain-id", default="", help="Domain ID filter for digital twin resources")


def _build_components(domain_ids):
    # Shared once per run_module call (resolved via domain_ids_from_db: manual --domain-id
    # filter -> DB cache; no live-list tier) and fanned out identically across all 4
    # digital-twin resources, instead of each independently re-resolving the same domains.
    nested = nested_list_fn(
        parent_resource_cls=IotDomainsResource,
        parent_id_field="iot_domain_id",
        manual_parent_ids=domain_ids,
        child_takes_compartment=False,
    )
    return [
        Component("domains", IotDomainsResource, help_text="Enumerate domains", cache_table="iot_domains"),
        Component("domain_groups", IotDomainGroupsResource, help_text="Enumerate domain-groups", cache_table="iot_domain_groups"),
        Component("digital_twin_models", IotDigitalTwinModelsResource, help_text="Enumerate digital-twin-models",
                  cache_table="iot_digital_twin_models", list_fn=nested, download_fn=_model_spec_download),
        Component("digital_twin_instances", IotDigitalTwinInstancesResource, help_text="Enumerate digital-twin-instances",
                  cache_table="iot_digital_twin_instances", list_fn=nested, download_fn=_instance_content_download),
        Component("digital_twin_adapters", IotDigitalTwinAdaptersResource, help_text="Enumerate digital-twin-adapters",
                  cache_table="iot_digital_twin_adapters", list_fn=nested),
        Component("digital_twin_relationships", IotDigitalTwinRelationshipsResource, help_text="Enumerate digital-twin-relationships",
                  cache_table="iot_digital_twin_relationships", list_fn=nested),
    ]


# Module-level shape (component keys/help text) for CLI-flag introspection; run_module
# always rebuilds a fresh list bound to the resolved domain_ids for the real run.
COMPONENTS = _build_components([])


def run_module(user_args, session):
    args, _ = parse_wrapper_args(
        user_args,
        description="Enumerate IoT resources",
        components=component_arg_specs(COMPONENTS),
        add_extra_args=_add_extra_args,
    )
    component_order = [c.key for c in COMPONENTS]
    selected = resolve_selected_components(args, component_order)

    domain_ids: list = []
    if any(selected.get(key, False) for key in _NESTED_KEYS):
        compartment_id = getattr(session, "compartment_id", None)
        domain_ids = domain_ids_from_db(
            session,
            table_name="iot_domains",
            compartment_id=compartment_id,
            domain_id_filter=str(getattr(args, "domain_id", "") or "").strip(),
        )

    return run_components(
        user_args, session, _build_components(domain_ids),
        module_name="enum_iot",
        description="Enumerate IoT resources",
        add_extra_args=_add_extra_args,
    )
