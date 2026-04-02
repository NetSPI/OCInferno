#!/usr/bin/env python3
from __future__ import annotations

import oci
from ocinferno.core.console import UtilityTools
from ocinferno.core.utils.module_helpers import fill_missing_fields
from ocinferno.modules.cloudguard.utilities.helpers import (
    CloudGuardDataSourcesResource,
    CloudGuardDetectorRecipesResource,
    CloudGuardManagedListsResource,
    CloudGuardProblemsResource,
    CloudGuardRecommendationsResource,
    CloudGuardResponderRecipesResource,
    CloudGuardSecurityPoliciesResource,
    CloudGuardSecurityRecipesResource,
    CloudGuardSecurityZonesResource,
    CloudGuardTargetsResource,
)
from ocinferno.core.utils.service_runtime import (
    append_cached_component_counts,
    parse_wrapper_args,
    resolve_selected_components,
)


COMPONENTS = [
    ("targets", "targets", "Enumerate targets"),
    ("problems", "problems", "Enumerate problems"),
    ("recommendations", "recommendations", "Enumerate recommendations"),
    ("detector_recipes", "detector_recipes", "Enumerate detector-recipes"),
    ("responder_recipes", "responder_recipes", "Enumerate responder-recipes"),
    ("managed_lists", "managed_lists", "Enumerate managed-lists"),
    ("data_sources", "data_sources", "Enumerate data-sources"),
    ("security_zones", "security_zones", "Enumerate security-zones"),
    ("security_recipes", "security_recipes", "Enumerate security-recipes"),
    ("security_policies", "security_policies", "Enumerate security-policies"),
]


CACHE_TABLES = {
    "targets": ("cloud_guard_targets", "compartment_id"),
    "problems": ("cloud_guard_problems", "compartment_id"),
    "recommendations": ("cloud_guard_recommendations", "compartment_id"),
    "detector_recipes": ("cloud_guard_detector_recipes", "compartment_id"),
    "responder_recipes": ("cloud_guard_responder_recipes", "compartment_id"),
    "managed_lists": ("cloud_guard_managed_lists", "compartment_id"),
    "data_sources": ("cloud_guard_data_sources", "compartment_id"),
    "security_zones": ("cloud_guard_security_zones", "compartment_id"),
    "security_recipes": ("cloud_guard_security_recipes", "compartment_id"),
    "security_policies": ("cloud_guard_security_policies", "compartment_id"),
}


def _parse_args(user_args):
    return parse_wrapper_args(
        user_args=user_args,
        description="Enumerate CloudGuard resources",
        components=COMPONENTS,
    )


def run_module(user_args, session):
    args, _ = _parse_args(user_args)
    debug = bool(getattr(session, "individual_run_debug", False) or getattr(session, "debug", False))

    component_order = [key for key, _suffix, _help in COMPONENTS]
    selected = resolve_selected_components(args, component_order)
    compartment_id = getattr(session, "compartment_id", None)
    if not compartment_id:
        raise ValueError("session.compartment_id is not set")

    resource_map = {
        "targets": CloudGuardTargetsResource(session=session),
        "problems": CloudGuardProblemsResource(session=session),
        "recommendations": CloudGuardRecommendationsResource(session=session),
        "detector_recipes": CloudGuardDetectorRecipesResource(session=session),
        "responder_recipes": CloudGuardResponderRecipesResource(session=session),
        "managed_lists": CloudGuardManagedListsResource(session=session),
        "data_sources": CloudGuardDataSourcesResource(session=session),
        "security_zones": CloudGuardSecurityZonesResource(session=session),
        "security_recipes": CloudGuardSecurityRecipesResource(session=session),
        "security_policies": CloudGuardSecurityPoliciesResource(session=session),
    }
    results = []
    for key, _method_suffix, _help_text in COMPONENTS:
        if not selected.get(key, False):
            continue
        resource = resource_map[key]
        try:
            rows = resource.list(compartment_id=compartment_id) or []
        except oci.exceptions.ServiceError as err:
            status = getattr(err, "status", None)
            code = getattr(err, "code", None)
            msg = getattr(err, "message", str(err))
            if status in (401, 403, 404):
                # Common in scoped runs where Cloud Guard is disabled/unavailable.
                UtilityTools.dlog(debug, f"list_{key} unavailable for scope", status=status, code=code, msg=msg)
                results.append({"ok": True, key: 0, "saved": False, "get": bool(args.get), "skipped": True})
            else:
                UtilityTools.dlog(True, f"list_{key} failed", status=status, code=code, msg=msg)
                results.append({"ok": False, key: 0, "saved": False, "get": bool(args.get)})
            continue

        rows = [row for row in rows if isinstance(row, dict)]
        for row in rows:
            row.setdefault("compartment_id", compartment_id)

        if args.get:
            for row in rows:
                resource_id = row.get("id")
                if not resource_id:
                    continue
                try:
                    meta = resource.get(resource_id=resource_id) or {}
                except Exception as err:
                    UtilityTools.dlog(debug, f"get_{key} failed", resource_id=resource_id, err=f"{type(err).__name__}: {err}")
                    continue
                fill_missing_fields(row, meta)

        if rows:
            UtilityTools.print_limited_table(rows, ["id", "display_name", "lifecycle_state", "time_created"])

        if args.save:
            resource.save(rows)

        results.append({"ok": True, key: len(rows), "saved": bool(args.save), "get": bool(args.get)})

    append_cached_component_counts(
        results=results,
        session=session,
        selected=selected,
        component_order=component_order,
        cache_tables=CACHE_TABLES,
    )

    return {"ok": True, "components": results}
