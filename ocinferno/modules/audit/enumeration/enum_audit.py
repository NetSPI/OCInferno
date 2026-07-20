#!/usr/bin/env python3
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from ocinferno.modules.audit.utilities.helpers import AuditEventsResource
from ocinferno.core.utils.service_runtime import (
    SOFT_SKIP_STATUSES,
    append_cached_component_counts,
    parse_wrapper_args,
    resolve_selected_components,
    run_standard_enum_component,
)

# Audit may be unavailable/denied for a given compartment; treat 401/403/404 on
# listing as an empty result rather than an error.
_SOFT_SKIP_STATUSES = SOFT_SKIP_STATUSES


COMPONENTS = [
    ("events", "events", "Enumerate audit events over a time window"),
]


CACHE_TABLES = {
    "events": ("audit_events", "compartment_id"),
}


def _add_extra_args(parser):
    parser.add_argument("--hours", type=int, default=24, help="Look back this many hours (default 24)")
    parser.add_argument("--start-time", dest="start_time", default=None, help="Window start (RFC3339); overrides --hours")
    parser.add_argument("--end-time", dest="end_time", default=None, help="Window end (RFC3339); defaults to now")


def _parse_args(user_args):
    return parse_wrapper_args(
        user_args,
        description="Enumerate Audit events",
        components=COMPONENTS,
        add_extra_args=_add_extra_args,
    )


def _parse_rfc3339(value):
    # Accept a trailing 'Z' (UTC) which datetime.fromisoformat does not handle
    # before 3.11; normalize to +00:00.
    text = str(value).strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    dt = datetime.fromisoformat(text)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def run_module(user_args, session):
    args, _ = _parse_args(user_args)

    component_order = [key for key, _suffix, _help in COMPONENTS]
    selected = resolve_selected_components(args, component_order)
    compartment_id = getattr(session, "compartment_id", None)
    if not compartment_id:
        raise ValueError("session.compartment_id is not set")

    end = _parse_rfc3339(args.end_time) if getattr(args, "end_time", None) else datetime.now(timezone.utc)
    if getattr(args, "start_time", None):
        start = _parse_rfc3339(args.start_time)
    else:
        start = end - timedelta(hours=int(getattr(args, "hours", 24) or 24))

    res = AuditEventsResource(session=session)

    results = []
    for key, _method_suffix, _help_text in COMPONENTS:
        if not selected.get(key, False):
            continue
        results.append(run_standard_enum_component(
            user_args=args, session=session, component_key=key,
            list_rows=lambda cid: res.list(compartment_id=cid, start_time=start, end_time=end),
            get_row=None,
            save_rows_fn=res.save,
            print_columns=res.COLUMNS,
            module_name="enum_audit",
            attach_compartment_id=False,
            soft_skip_statuses=_SOFT_SKIP_STATUSES,
        ))

    append_cached_component_counts(
        results=results,
        session=session,
        selected=selected,
        component_order=component_order,
        cache_tables=CACHE_TABLES,
    )

    return {"ok": True, "components": results}
