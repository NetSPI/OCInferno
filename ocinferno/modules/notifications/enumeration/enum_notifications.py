#!/usr/bin/env python3
from __future__ import annotations

import argparse

import oci
from ocinferno.core.console import UtilityTools
from ocinferno.core.utils.module_helpers import fill_missing_fields
from ocinferno.modules.notifications.utilities.helpers import NotificationSubscriptionsResource, NotificationTopicsResource
from ocinferno.core.utils.service_runtime import (
    append_cached_component_counts,
    parse_wrapper_args,
    resolve_selected_components,
)


COMPONENTS = [
    ("topics", "topics", "Enumerate topics"),
    ("subscriptions", "subscriptions", "Enumerate subscriptions"),
]


CACHE_TABLES = {
    "topics": ("notification_topics", "compartment_id"),
    "subscriptions": ("notification_subscriptions", "compartment_id"),
}


def _parse_args(user_args):
    def _add_extra_args(parser: argparse.ArgumentParser) -> None:
        parser.add_argument("--topic-id", dest="topic_id", default="", help="Filter subscriptions to a specific topic OCID")

    return parse_wrapper_args(
        user_args=user_args,
        description="Enumerate Notifications resources",
        components=COMPONENTS,
        add_extra_args=_add_extra_args,
    )


def run_module(user_args, session):
    args, _ = _parse_args(user_args)
    debug = bool(getattr(session, "individual_run_debug", False) or getattr(session, "debug", False))
    component_order = [key for key, _suffix, _help in COMPONENTS]
    selected = resolve_selected_components(args, component_order)
    compartment_id = getattr(session, "compartment_id", None)
    if not compartment_id:
        raise ValueError("session.compartment_id is not set")
    results = []
    topics_resource = NotificationTopicsResource(session=session)
    subscriptions_resource = NotificationSubscriptionsResource(session=session)

    if selected.get("topics", False):
        try:
            rows = topics_resource.list(compartment_id=compartment_id) or []
        except oci.exceptions.ServiceError as err:
            UtilityTools.dlog(True, "list_topics failed", status=err.status, code=err.code)
            results.append({"ok": False, "topics": 0})
        else:
            rows = [row for row in rows if isinstance(row, dict)]
            for row in rows:
                row.setdefault("compartment_id", compartment_id)

            if args.get:
                for row in rows:
                    topic_id = row.get("id")
                    if not topic_id:
                        continue
                    try:
                        meta = topics_resource.get(resource_id=topic_id) or {}
                    except Exception as err:
                        UtilityTools.dlog(debug, "get_topic failed", topic_id=topic_id, err=f"{type(err).__name__}: {err}")
                        continue
                    fill_missing_fields(row, meta)

            if rows:
                UtilityTools.print_limited_table(rows, topics_resource.COLUMNS)

            if args.save:
                topics_resource.save(rows)

            results.append({"ok": True, "topics": len(rows), "saved": bool(args.save), "get": bool(args.get)})
    if selected.get("subscriptions", False):
        topic_id = (args.topic_id or "").strip() or None
        try:
            rows = subscriptions_resource.list(compartment_id=compartment_id, topic_id=topic_id) or []
        except oci.exceptions.ServiceError as err:
            UtilityTools.dlog(True, "list_subscriptions failed", status=err.status, code=err.code)
            results.append({"ok": False, "subscriptions": 0})
        else:
            rows = [row for row in rows if isinstance(row, dict)]
            for row in rows:
                row.setdefault("compartment_id", compartment_id)

            if args.get:
                for row in rows:
                    subscription_id = row.get("id")
                    if not subscription_id:
                        continue
                    try:
                        meta = subscriptions_resource.get(resource_id=subscription_id) or {}
                    except Exception as err:
                        UtilityTools.dlog(debug, "get_subscription failed", subscription_id=subscription_id, err=f"{type(err).__name__}: {err}")
                        continue
                    fill_missing_fields(row, meta)

            if rows:
                UtilityTools.print_limited_table(rows, subscriptions_resource.COLUMNS)

            if args.save:
                subscriptions_resource.save(rows)

            results.append({"ok": True, "subscriptions": len(rows), "saved": bool(args.save), "get": bool(args.get)})

    append_cached_component_counts(
        results=results,
        session=session,
        selected=selected,
        component_order=component_order,
        cache_tables=CACHE_TABLES,
    )

    return {"ok": True, "components": results}
