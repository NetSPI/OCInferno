#!/usr/bin/env python3
from __future__ import annotations

from ocinferno.core.console import UtilityTools
from ocinferno.core.utils.module_helpers import fill_missing_fields
from ocinferno.modules.iot.utilities.helpers import (
    IotDigitalTwinAdaptersResource,
    IotDigitalTwinInstancesResource,
    IotDigitalTwinModelsResource,
    IotDigitalTwinRelationshipsResource,
    IotDomainGroupsResource,
    IotDomainsResource,
)
from ocinferno.core.utils.service_runtime import (
    append_cached_component_counts,
    parse_wrapper_args,
    resolve_selected_components,
)


COMPONENTS = [
    ("domains", "domains", "Enumerate domains"),
    ("domain_groups", "domain_groups", "Enumerate domain-groups"),
    ("digital_twin_models", "digital_twin_models", "Enumerate digital-twin-models"),
    ("digital_twin_instances", "digital_twin_instances", "Enumerate digital-twin-instances"),
    ("digital_twin_adapters", "digital_twin_adapters", "Enumerate digital-twin-adapters"),
    ("digital_twin_relationships", "digital_twin_relationships", "Enumerate digital-twin-relationships"),
]


CACHE_TABLES = {
    "domains": ("iot_domains", "compartment_id"),
    "domain_groups": ("iot_domain_groups", "compartment_id"),
    "digital_twin_models": ("iot_digital_twin_models", "compartment_id"),
    "digital_twin_instances": ("iot_digital_twin_instances", "compartment_id"),
    "digital_twin_relationships": ("iot_digital_twin_relationships", "compartment_id"),
    "digital_twin_adapters": ("iot_digital_twin_adapters", "compartment_id"),
}


def _component_error_summary(err: Exception) -> str:
    status = getattr(err, "status", None)
    code = getattr(err, "code", None)
    msg = getattr(err, "message", None)
    if status is not None or code is not None:
        return f"status={status}, code={code}, message={msg or str(err)}"
    return f"{type(err).__name__}: {err}"


def _parse_args(user_args):
    def _add_extra_args(parser):
        parser.add_argument("--domain-id", default="", help="Domain ID filter for digital twin resources")

    return parse_wrapper_args(
        user_args=user_args,
        description="Enumerate IoT resources",
        components=COMPONENTS,
        add_extra_args=_add_extra_args,
    )


def run_module(user_args, session):
    args, _ = _parse_args(user_args)

    component_order = [key for key, _suffix, _help in COMPONENTS]
    selected = resolve_selected_components(args, component_order)

    resource_map = {
        "domains": IotDomainsResource(session=session),
        "domain_groups": IotDomainGroupsResource(session=session),
        "digital_twin_models": IotDigitalTwinModelsResource(session=session),
        "digital_twin_instances": IotDigitalTwinInstancesResource(session=session),
        "digital_twin_adapters": IotDigitalTwinAdaptersResource(session=session),
        "digital_twin_relationships": IotDigitalTwinRelationshipsResource(session=session),
    }
    results = []
    for key, _method_suffix, _help_text in COMPONENTS:
        if not selected.get(key, False):
            continue
        try:
            if key in {"domains", "domain_groups"}:
                resource = resource_map[key]
                compartment_id = getattr(session, "compartment_id", None)
                if not compartment_id:
                    raise ValueError("session.compartment_id is not set")

                rows = resource.list(compartment_id=compartment_id) or []
                rows = [row for row in rows if isinstance(row, dict)]
                for row in rows:
                    row.setdefault("compartment_id", compartment_id)

                if args.get:
                    for row in rows:
                        resource_id = row.get("id")
                        if not resource_id:
                            continue
                        meta = resource.get(resource_id=resource_id) or {}
                        fill_missing_fields(row, meta)

                if rows:
                    UtilityTools.print_limited_table(rows, resource.COLUMNS)

                if args.save:
                    resource.save(rows)

                results.append({"ok": True, key: len(rows), "saved": bool(args.save), "get": bool(args.get)})
            else:
                resource = resource_map[key]
                compartment_id = getattr(session, "compartment_id", None)
                if not compartment_id:
                    raise ValueError("session.compartment_id is not set")

                domain_filter = str(getattr(args, "domain_id", "") or "").strip()
                domain_ids = resource.resolve_domain_ids(compartment_id=compartment_id, domain_id_filter=domain_filter)
                rows = []
                for domain_id in domain_ids:
                    listed = resource.list(iot_domain_id=domain_id) or []
                    for row in listed:
                        if not isinstance(row, dict):
                            continue
                        row.setdefault("iot_domain_id", domain_id)
                        row.setdefault("compartment_id", compartment_id)
                        rows.append(row)

                if args.get:
                    for row in rows:
                        resource_id = row.get("id")
                        if not resource_id:
                            continue
                        meta = resource.get(resource_id=resource_id) or {}
                        fill_missing_fields(row, meta)

                if rows:
                    UtilityTools.print_limited_table(rows, resource.COLUMNS)

                if args.save:
                    resource.save(rows)

                results.append({"ok": True, key: len(rows), "saved": bool(args.save), "get": bool(args.get)})
        except Exception as err:
            print(f"[*] enum_iot.{key}: skipped ({_component_error_summary(err)}).")
            results.append({"ok": False, "component": key, "error": _component_error_summary(err)})

    append_cached_component_counts(
        results=results,
        session=session,
        selected=selected,
        component_order=component_order,
        cache_tables=CACHE_TABLES,
    )

    return {"ok": True, "components": results}
