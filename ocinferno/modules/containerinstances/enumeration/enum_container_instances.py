#!/usr/bin/env python3
from __future__ import annotations

import argparse
from typing import Any, Dict, List

import oci
from ocinferno.core.console import UtilityTools
from ocinferno.modules.containerinstances.utilities.helpers import ContainerInstancesResource


def _parse_args(user_args):
    parser = argparse.ArgumentParser(
        description="Enumerate OCI Container Instances",
        allow_abbrev=False,
    )
    # --get/--save are runner-level common flags; keep this parser module-specific only.
    args, _ = parser.parse_known_args(list(user_args))
    raw_args = {str(x) for x in (list(user_args) if user_args is not None else [])}
    args.get = "--get" in raw_args
    args.save = "--save" in raw_args
    return args


def run_module(user_args, session) -> Dict[str, Any]:
    args = _parse_args(user_args)
    debug = bool(getattr(session, "debug", False))

    if not getattr(session, "compartment_id", None):
        raise ValueError(
            "session.compartment_id is not set.\n"
            "Select a compartment in the module runner (or run via module_actions prompt)."
        )

    instances_resource = ContainerInstancesResource(session=session)

    try:
        # Resource loop: container instances (list phase).
        instances: List[Dict[str, Any]] = instances_resource.list(compartment_id=session.compartment_id) or []
    except oci.exceptions.ServiceError as e:
        print(f"{UtilityTools.RED}[X] list_container_instances failed: {e.status} {e.message}{UtilityTools.RESET}")
        return {"ok": False, "instances": 0, "saved": False, "get": bool(args.get)}

    if not instances:
        UtilityTools.dlog(debug, "No container instances found", compartment_id=session.compartment_id)
        return {"ok": True, "instances": 0, "saved": False, "get": bool(args.get)}

    # Stamp compartment_id if missing
    for r in instances:
        if isinstance(r, dict) and "compartment_id" not in r:
            r["compartment_id"] = session.compartment_id

    if args.get:
        # Resource loop: container instances (get enrichment phase).
        for r in instances:
            if not isinstance(r, dict):
                continue
            rid = r.get("id")
            if not rid:
                continue
            try:
                meta = instances_resource.get(container_instance_id=rid)
            except oci.exceptions.ServiceError as e:
                UtilityTools.dlog(debug, "get_container_instance failed", id=rid, status=e.status, error_message=e.message)
                continue
            except Exception as e:
                UtilityTools.dlog(debug, "get_container_instance failed", id=rid, err=f"{type(e).__name__}: {e}")
                continue

            if not isinstance(meta, dict):
                continue
            meta["get_run"] = True

            for k, v in meta.items():
                if r.get(k) in (None, "", [], {}, ()):
                    if v not in (None, "", [], {}, ()):
                        r[k] = v

    UtilityTools.print_limited_table(instances, instances_resource.COLUMNS)

    if args.save:
        # Persist component rows for downstream modules/reporting.
        instances_resource.save(instances)

    return {
        "ok": True,
        "cid": session.compartment_id,
        "instances": len(instances),
        "saved": bool(args.save),
        "get": bool(args.get),
    }
