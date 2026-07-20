#!/usr/bin/env python3
from __future__ import annotations

import argparse

from ocinferno.modules.notifications.utilities.helpers import NotificationSubscriptionsResource, NotificationTopicsResource
from ocinferno.core.utils.service_runtime import (
    append_cached_component_counts,
    parse_wrapper_args,
    resolve_selected_components,
    run_standard_enum_component,
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
    component_order = [key for key, _suffix, _help in COMPONENTS]
    selected = resolve_selected_components(args, component_order)
    results = []
    topics_resource = NotificationTopicsResource(session=session)
    subscriptions_resource = NotificationSubscriptionsResource(session=session)

    if selected.get("topics", False):
        results.append(run_standard_enum_component(
            user_args=args, session=session, component_key="topics",
            list_rows=lambda cid: topics_resource.list(compartment_id=cid),
            get_row=lambda row: topics_resource.get(resource_id=row.get("id")),
            save_rows_fn=topics_resource.save,
            print_columns=topics_resource.COLUMNS,
            module_name="enum_notifications",
        ))

    if selected.get("subscriptions", False):
        topic_id = (args.topic_id or "").strip() or None
        results.append(run_standard_enum_component(
            user_args=args, session=session, component_key="subscriptions",
            list_rows=lambda cid: subscriptions_resource.list(compartment_id=cid, topic_id=topic_id),
            get_row=lambda row: subscriptions_resource.get(resource_id=row.get("id")),
            save_rows_fn=subscriptions_resource.save,
            print_columns=subscriptions_resource.COLUMNS,
            module_name="enum_notifications",
        ))

    append_cached_component_counts(
        results=results,
        session=session,
        selected=selected,
        component_order=component_order,
        cache_tables=CACHE_TABLES,
    )

    return {"ok": True, "components": results}
