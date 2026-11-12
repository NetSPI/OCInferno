#!/usr/bin/env python3
from __future__ import annotations

import argparse
import re
from typing import Any, Dict, List

import oci

from ocinferno.core.console import UtilityTools
from ocinferno.core.utils.service_runtime import component_soft_skip_or_error
from ocinferno.modules.logging.utilities.helpers import (
    LoggingLogGroupsResource,
    LoggingLogsResource,
    LoggingSearchResource,
)


def _parse_args(user_args):
    parser = argparse.ArgumentParser(description="Enumerate OCI Logging (Log Groups + Logs)", allow_abbrev=False)
    parser.add_argument("--logs", action="store_true", help="List logs for each log group")
    parser.add_argument("--download", action="store_true",
                        help="Download log content (entries) for each enumerated log stream")
    parser.add_argument("--hours", type=int, default=24, metavar="N",
                        help="How many hours back to search when downloading log content (default: 24)")
    parser.add_argument("--download-timeout", type=int, default=0, metavar="SECS",
                        help="Per-log wall-clock cap in seconds (0 = unlimited)")
    parser.add_argument("--log-type", metavar="TYPE",
                        help="Filter logs by type when downloading (e.g. CUSTOM, SERVICE)")
    parser.add_argument("--log-group-name", metavar="SUBSTR",
                        help="Only enumerate/download logs from groups whose name contains SUBSTR (case-insensitive)")
    parser.add_argument("--start-time", metavar="ISO8601",
                        help="Absolute start of the search window (e.g. 2025-01-01T00:00:00Z); overrides --hours")
    parser.add_argument("--end-time", metavar="ISO8601",
                        help="Absolute end of the search window (default: now)")
    parser.add_argument("--search", metavar="TEXT",
                        help="Keyword filter: only keep entries whose text contains TEXT (case-insensitive)")
    parser.add_argument("--cred-hunt", action="store_true",
                        help="Preset --search for common credential keywords (password, secret, token, key, ...)")
    # --get is a runner-level common flag; parse module-specific args only.
    args, _ = parser.parse_known_args(list(user_args))
    raw_args = {str(x) for x in (list(user_args) if user_args is not None else [])}
    args.get = "--get" in raw_args
    return args


def run_module(user_args, session) -> Dict[str, Any]:
    args = _parse_args(user_args)
    debug = bool(getattr(session, "debug", False))

    # --download implies --logs (need individual log OCIDs to search content)
    if args.download:
        args.logs = True

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
        skip = component_soft_skip_or_error(e, component="log_groups", module_name="enum_logs")
        if skip.get("skipped"):
            return {"ok": True, "log_groups": 0, "logs": 0, "saved": False}
        UtilityTools.dlog(debug, "list_log_groups failed",
                          status=getattr(e, "status", None),
                          code=getattr(e, "code", None),
                          msg=str(e))
        return {"ok": False, "log_groups": 0, "logs": 0, "saved": False}
    except Exception as e:
        UtilityTools.dlog(debug, "list_log_groups failed", err=f"{type(e).__name__}: {e}")
        return {"ok": False, "log_groups": 0, "logs": 0, "saved": False}

    if not groups:
        UtilityTools.dlog(debug, "No OCI Log Groups found", compartment_id=session.compartment_id)
        return {"ok": True, "log_groups": 0, "logs": 0, "saved": False}

    # Apply --log-group-name filter before any further work
    if args.log_group_name:
        needle = args.log_group_name.lower()
        groups = [g for g in groups if needle in str(g.get("display_name") or "").lower()]
        if not groups:
            UtilityTools.dlog(debug, "No log groups match --log-group-name", filter=args.log_group_name)
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
                meta = groups_resource.get(resource_id=gid)
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
        title="Logging - Log Groups",
    )

    if args.logs and all_logs:
        UtilityTools.print_limited_table(all_logs, logs_resource.COLUMNS, title="Logging - Logs")

    # 5) Save
    groups_resource.save(groups)
    if args.logs and all_logs:
        logs_resource.save(all_logs)

    # 6) Optional: download log content for each enumerated log stream
    downloaded_entries = 0
    if args.download and all_logs:
        from datetime import datetime as _dt
        session.download_time_budget = int(getattr(args, "download_timeout", 0) or 0)
        from ocinferno.core.utils.download_budget import DownloadBudget
        budget = DownloadBudget(session, label="Logging content")
        search_resource = LoggingSearchResource(session=session)
        log_type_filter = (args.log_type or "").strip().upper() or None

        # Parse absolute timestamps if provided
        abs_start: Any = None
        abs_end: Any = None
        if args.start_time:
            try:
                abs_start = _dt.fromisoformat(args.start_time.replace("Z", "+00:00"))
            except ValueError:
                UtilityTools.dlog(debug, "Invalid --start-time, ignored", value=args.start_time)
        if args.end_time:
            try:
                abs_end = _dt.fromisoformat(args.end_time.replace("Z", "+00:00"))
            except ValueError:
                UtilityTools.dlog(debug, "Invalid --end-time, ignored", value=args.end_time)

        # Build server-side keyword filter terms
        _CRED_KEYWORDS = [
            "password", "passwd", "secret", "token", "api_key", "apikey",
            "private_key", "access_key", "credential", "auth_token",
        ]
        search_terms: List[str] = []
        if args.cred_hunt:
            search_terms = list(_CRED_KEYWORDS)
        elif args.search:
            search_terms = [args.search.strip()]

        for log_row in all_logs:
            if budget.exceeded():
                break
            # --log-type filter: skip logs that don't match the requested type
            if log_type_filter:
                row_type = str(log_row.get("log_type") or "").strip().upper()
                if row_type and row_type != log_type_filter:
                    continue
            log_id = log_row.get("id")
            log_group_id = log_row.get("log_group_id")
            if not log_id or not log_group_id:
                continue
            display_name = log_row.get("display_name") or log_id
            safe_name = re.sub(r"[^a-zA-Z0-9._-]", "_", display_name)[:80]
            # Shorten the group OCID to its leaf token for the directory name
            group_leaf = log_group_id.rsplit(".", 1)[-1][:32]
            try:
                out_path = session.get_download_save_path(
                    service_name="Logging",
                    filename=f"{safe_name}.jsonl",
                    compartment_id=session.compartment_id,
                    subdirs=["logs", group_leaf],
                )
                written = search_resource.download_log_content(
                    compartment_id=log_row.get("compartment_id") or session.compartment_id,
                    log_group_id=log_group_id,
                    log_id=log_id,
                    hours=max(1, int(getattr(args, "hours", 24) or 24)),
                    out_path=str(out_path),
                    time_start=abs_start,
                    time_end=abs_end,
                    search_terms=search_terms or None,
                )
                downloaded_entries += written
                if written:
                    UtilityTools.dlog(debug, "log content downloaded",
                                      log_id=log_id, entries=written, path=str(out_path))
            except Exception as e:
                UtilityTools.dlog(debug, "log download failed",
                                  log_id=log_id, err=f"{type(e).__name__}: {e}")

    return {
        "ok": True,
        "cid": session.compartment_id,
        "log_groups": len(groups),
        "logs": int(logs_total),
        "saved": True,
        "get": bool(args.get),
        "logs_flag": bool(args.logs),
        "download": bool(args.download),
        "downloaded_entries": downloaded_entries,
    }
