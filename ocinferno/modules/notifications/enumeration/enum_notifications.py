#!/usr/bin/env python3
from __future__ import annotations

import argparse

from ocinferno.core.utils.enum_framework import Component, run_components
from ocinferno.modules.notifications.utilities.helpers import (
    NotificationSubscriptionsResource,
    NotificationTopicsResource,
)


def _add_extra_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--topic-id", dest="topic_id", default="",
                        help="Filter subscriptions to a specific topic OCID")


COMPONENTS = [
    Component("topics", NotificationTopicsResource,
              help_text="Enumerate topics", cache_table="notification_topics"),
    Component("subscriptions", NotificationSubscriptionsResource,
              help_text="Enumerate subscriptions", cache_table="notification_subscriptions",
              list_fn=lambda session, args, resource: (
                  lambda cid: resource.list(
                      compartment_id=cid,
                      topic_id=(args.topic_id or "").strip() or None,
                  )
              )),
]


def run_module(user_args, session):
    return run_components(user_args, session, COMPONENTS,
                         module_name="enum_notifications",
                         description="Enumerate Notifications resources",
                         add_extra_args=_add_extra_args)
