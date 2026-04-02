#!/usr/bin/env python3
from __future__ import annotations

import argparse
from typing import Any, Dict, List

import oci
from ocinferno.core.console import UtilityTools
from ocinferno.modules.logging.utilities.helpers import (
    LoggingLogGroupsResource,
    LoggingLogsResource,
)


def _parse_args(user_args):
    parser = argparse.ArgumentParser(description="Enumerate OCI Logging (Log Groups + Logs)", allow_abbrev=False)
    parser.add_argument("--logs", action="store_true", help="List logs for each log group")
    # --get/--save are runner-level common flags; parse module-specific args only.
    args, _ = parser.parse_known_args(list(user_args))
    raw_args = {str(x) for x in (list(user_args) if user_args is not None else [])}
    args.get = "--get" in raw_args
    args.save = "--save" in raw_args
    return args


def run_module(user_args, session) -> Dict[str, Any]:
    args = _parse_args(user_args)
    debug = bool(getattr(args, "debug", False))

    if not getattr(session, "compartment_id", None):
        raise ValueError(
            "session.compartment_id is not set.\n"
            "Select a compartment in the module runner (or run via module_actions prompt)."
        )

    groups_resource = LoggingLogGroupsResource(session=session)
    logs_resource = LoggingLogsResource(session=session)

    # 1) Resource loop: list log groups in the selected compartment.
    try:
        groups: List[Dict[str, Any]] = groups_resource.list(compartment_id=session.compartment_id) or []
    except oci.exceptions.ServiceError as e:
        UtilityTools.dlog(True, "list_log_groups failed",
                          status=getattr(e, "status", None),
                          code=getattr(e, "code", None),
                          msg=str(e))
        return {"ok": False, "log_groups": 0, "logs": 0, "saved": False}
    except Exception as e:
        UtilityTools.dlog(True, "list_log_groups failed", err=f"{type(e).__name__}: {e}")
        return {"ok": False, "log_groups": 0, "logs": 0, "saved": False}

    if not groups:
        UtilityTools.dlog(debug, "No OCI Log Groups found", compartment_id=session.compartment_id)
        return {"ok": True, "log_groups": 0, "logs": 0, "saved": False}

    # Stamp compartment_id if missing
    for g in groups:
        if isinstance(g, dict) and "compartment_id" not in g:
            g["compartment_id"] = session.compartment_id

    # 2) Optional per-group get enrichment (fills missing fields only)
    if args.get:
        for g in groups:
            if not isinstance(g, dict):
                continue
            gid = g.get("id")
            if not gid:
                continue
            try:
                meta = groups_resource.get(log_group_id=gid)
            except oci.exceptions.ServiceError as e:
                UtilityTools.dlog(debug, "get_log_group failed",
                                  log_group_id=gid,
                                  status=getattr(e, "status", None),
                                  code=getattr(e, "code", None))
                continue
            except Exception as e:
                UtilityTools.dlog(debug, "get_log_group failed",
                                  log_group_id=gid,
                                  err=f"{type(e).__name__}: {e}")
                continue

            if not isinstance(meta, dict):
                continue

            meta["get_run"] = True
            changed = False
            for k, v in meta.items():
                if k not in g or g[k] in (None, "", [], {}, ()):
                    if v not in (None, "", [], {}, ()):
                        g[k] = v
                        changed = True
            UtilityTools.dlog(debug, "log group enriched", log_group_id=gid, changed=changed)

    # 3) Resource loop: list logs per discovered log group.
    logs_total = 0
    all_logs: List[Dict[str, Any]] = []

    if args.logs:
        for g in groups:
            if not isinstance(g, dict):
                continue
            gid = g.get("id")
            if not gid:
                continue

            try:
                logs = logs_resource.list(log_group_id=gid) or []
            except Exception as e:
                UtilityTools.dlog(debug, "list_logs failed",
                                  log_group_id=gid,
                                  err=f"{type(e).__name__}: {e}")
                continue

            if isinstance(logs, list):
                logs_total += len(logs)
                g["logs"] = logs  # nested for DB / later analysis

                # also build a flat list for easy table printing
                for r in logs:
                    if isinstance(r, dict):
                        r.setdefault("log_group_id", gid)
                        r.setdefault("compartment_id", session.compartment_id)
                        all_logs.append(r)

        # Optional per-log get enrichment
        if args.get and all_logs:
            for r in all_logs:
                if not isinstance(r, dict):
                    continue
                log_id = r.get("id")
                lgid = r.get("log_group_id")
                if not log_id or not lgid:
                    continue

                try:
                    meta = logs_resource.get(log_group_id=lgid, log_id=log_id)
                except oci.exceptions.ServiceError as e:
                    UtilityTools.dlog(debug, "get_log failed",
                                      log_group_id=lgid,
                                      log_id=log_id,
                                      status=getattr(e, "status", None),
                                      code=getattr(e, "code", None))
                    continue
                except Exception as e:
                    UtilityTools.dlog(debug, "get_log failed",
                                      log_group_id=lgid,
                                      log_id=log_id,
                                      err=f"{type(e).__name__}: {e}")
                    continue

                if not isinstance(meta, dict):
                    continue

                meta["get_run"] = True
                changed = False
                for k, v in meta.items():
                    if k not in r or r[k] in (None, "", [], {}, ()):
                        if v not in (None, "", [], {}, ()):
                            r[k] = v
                            changed = True
                UtilityTools.dlog(debug, "log enriched", log_id=log_id, changed=changed)

    # 4) Print
    UtilityTools.print_limited_table(
        groups,
        groups_resource.COLUMNS,
    )

    if args.logs and all_logs:
        UtilityTools.print_limited_table(all_logs, logs_resource.COLUMNS)

    # 5) Save
    if args.save:
        groups_resource.save(groups)
        if args.logs and all_logs:
            logs_resource.save(all_logs)

    return {
        "ok": True,
        "cid": session.compartment_id,
        "log_groups": len(groups),
        "logs": int(logs_total),
        "saved": bool(args.save),
        "get": bool(args.get),
        "logs_flag": bool(args.logs),
    }
