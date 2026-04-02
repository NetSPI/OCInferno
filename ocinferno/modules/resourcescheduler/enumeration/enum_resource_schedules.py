#!/usr/bin/env python3
from __future__ import annotations

import argparse
from typing import Any, Dict, List

import oci
from ocinferno.core.console import UtilityTools
from ocinferno.modules.resourcescheduler.utilities.helpers import ResourceSchedulesResource


def _parse_args(user_args):
    parser = argparse.ArgumentParser(
        description="Enumerate OCI Resource Scheduler Schedules",
        allow_abbrev=False,
    )
    # --get/--save are runner-level common flags; parse module-specific args only.
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

    schedules_resource = ResourceSchedulesResource(session=session)

    try:
        # Resource loop: schedules in the selected compartment.
        schedules: List[Dict[str, Any]] = schedules_resource.list(compartment_id=session.compartment_id) or []
    except oci.exceptions.ServiceError as e:
        status = getattr(e, "status", None)
        code = str(getattr(e, "code", "") or "")
        if status in (401, 403, 404) and code in {"NotAuthorizedOrNotFound", "NotAuthorized", "NotFound"}:
            print("[*] list_schedules skipped in this compartment (not authorized or not found).")
            return {"ok": True, "schedules": 0, "saved": False, "get": bool(args.get), "skipped": True}
        print(f"{UtilityTools.RED}[X] list_schedules failed: {e.status} {e.message}{UtilityTools.RESET}")
        return {"ok": False, "schedules": 0, "saved": False, "get": bool(args.get)}

    if not schedules:
        UtilityTools.dlog(debug, "No resource schedules found", compartment_id=session.compartment_id)
        return {"ok": True, "schedules": 0, "saved": False, "get": bool(args.get)}

    # Stamp compartment_id if missing
    for r in schedules:
        if isinstance(r, dict) and "compartment_id" not in r:
            r["compartment_id"] = session.compartment_id

    if args.get:
        for r in schedules:
            if not isinstance(r, dict):
                continue
            rid = r.get("id")
            if not rid:
                continue
            try:
                meta = schedules_resource.get(schedule_id=rid)
            except oci.exceptions.ServiceError as e:
                UtilityTools.dlog(debug, "get_schedule failed", id=rid, status=e.status, error_message=e.message)
                continue
            except Exception as e:
                UtilityTools.dlog(debug, "get_schedule failed", id=rid, err=f"{type(e).__name__}: {e}")
                continue

            if not isinstance(meta, dict):
                continue
            meta["get_run"] = True

            for k, v in meta.items():
                if r.get(k) in (None, "", [], {}, ()):
                    if v not in (None, "", [], {}, ()):
                        r[k] = v

    UtilityTools.print_limited_table(schedules, schedules_resource.COLUMNS)

    if args.save:
        schedules_resource.save(schedules)

    return {
        "ok": True,
        "cid": session.compartment_id,
        "schedules": len(schedules),
        "saved": bool(args.save),
        "get": bool(args.get),
    }
