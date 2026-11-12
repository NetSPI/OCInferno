"""Smoke tests for modules migrated to run_components, plus --topic-id passthrough."""
from __future__ import annotations

import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

# resource.py does `from service_runtime import _init_client` so we patch there.
_INIT_CLIENT = "ocinferno.core.resource._init_client"


def _session(saved=None):
    _saved = saved if saved is not None else {}
    return SimpleNamespace(
        compartment_id="ocid1.compartment.oc1..c",
        debug=False,
        individual_run_debug=False,
        active_module_name="",
        download_time_budget=0,
        save_resources=lambda rows, table: _saved.setdefault(table, []).extend(rows),
        get_resource_fields=lambda *a, **kw: [],
        _saved=_saved,
    )


# ---------------------------------------------------------------------------
# enum_databases — only autonomous_databases and db_systems remain
# ---------------------------------------------------------------------------

class TestEnumDatabasesComponents(unittest.TestCase):

    def test_removed_classes_not_importable(self):
        import importlib
        helpers = importlib.import_module("ocinferno.modules.databases.utilities.helpers")
        for removed in ("DatabasesMysqlResource", "DatabasesPostgresResource",
                        "DatabasesCacheClustersResource", "DatabasesCacheUsersResource",
                        "build_database_client"):
            self.assertFalse(
                hasattr(helpers, removed),
                f"{removed} should have been removed from databases.utilities.helpers",
            )

    def test_component_keys(self):
        from ocinferno.modules.databases.enumeration.enum_databases import COMPONENTS
        keys = [c.key for c in COMPONENTS]
        self.assertEqual(keys, ["autonomous_databases", "db_systems"])

    def test_run_module_returns_ok(self):
        from ocinferno.modules.databases.enumeration.enum_databases import run_module
        from ocinferno.modules.databases.utilities.helpers import (
            DatabasesAutonomousResource,
            DatabasesDbSystemsResource,
        )
        sess = _session()
        with (
            patch(_INIT_CLIENT, return_value=MagicMock()),
            patch.object(DatabasesAutonomousResource, "list", return_value=[]),
            patch.object(DatabasesDbSystemsResource, "list", return_value=[]),
        ):
            result = run_module([], sess)
        self.assertTrue(result.get("ok"))


# ---------------------------------------------------------------------------
# enum_os_management_hub — 3 plain components
# ---------------------------------------------------------------------------

class TestEnumOsManagementHub(unittest.TestCase):

    def test_component_keys(self):
        from ocinferno.modules.os_management_hub.enumeration.enum_os_management_hub import COMPONENTS
        keys = [c.key for c in COMPONENTS]
        self.assertEqual(keys, ["managed_instances", "managed_instance_groups", "scheduled_jobs"])

    def test_run_module_returns_ok(self):
        from ocinferno.modules.os_management_hub.enumeration.enum_os_management_hub import run_module
        from ocinferno.modules.os_management_hub.utilities.helpers import (
            OsManagementHubManagedInstanceGroupsResource,
            OsManagementHubManagedInstancesResource,
            OsManagementHubScheduledJobsResource,
        )
        sess = _session()
        with (
            patch(_INIT_CLIENT, return_value=MagicMock()),
            patch.object(OsManagementHubManagedInstancesResource, "list", return_value=[]),
            patch.object(OsManagementHubManagedInstanceGroupsResource, "list", return_value=[]),
            patch.object(OsManagementHubScheduledJobsResource, "list", return_value=[]),
        ):
            result = run_module([], sess)
        self.assertTrue(result.get("ok"))


# ---------------------------------------------------------------------------
# enum_notifications — verify --topic-id is passed through the list_fn lambda
# ---------------------------------------------------------------------------

class TestEnumNotificationsTopicIdPassthrough(unittest.TestCase):

    def test_topic_id_passed_to_list(self):
        from ocinferno.modules.notifications.enumeration.enum_notifications import run_module
        from ocinferno.modules.notifications.utilities.helpers import (
            NotificationSubscriptionsResource,
            NotificationTopicsResource,
        )

        captured_kwargs = {}

        def _fake_list_subs(compartment_id, topic_id=None):
            captured_kwargs["compartment_id"] = compartment_id
            captured_kwargs["topic_id"] = topic_id
            return []

        _NOTIF_INIT = "ocinferno.modules.notifications.utilities.helpers._init_client"
        sess = _session()
        with (
            patch(_INIT_CLIENT, return_value=MagicMock()),
            patch(_NOTIF_INIT, return_value=MagicMock()),
            patch.object(NotificationTopicsResource, "list", return_value=[]),
            patch.object(NotificationSubscriptionsResource, "list", side_effect=_fake_list_subs),
        ):
            run_module(["--subscriptions", "--topic-id", "ocid1.topic.oc1..abc"], sess)

        self.assertEqual(captured_kwargs.get("topic_id"), "ocid1.topic.oc1..abc")

    def test_no_topic_id_passes_none(self):
        from ocinferno.modules.notifications.enumeration.enum_notifications import run_module
        from ocinferno.modules.notifications.utilities.helpers import (
            NotificationSubscriptionsResource,
            NotificationTopicsResource,
        )

        captured_kwargs = {}

        def _fake_list_subs(compartment_id, topic_id=None):
            captured_kwargs["topic_id"] = topic_id
            return []

        _NOTIF_INIT = "ocinferno.modules.notifications.utilities.helpers._init_client"
        sess = _session()
        with (
            patch(_INIT_CLIENT, return_value=MagicMock()),
            patch(_NOTIF_INIT, return_value=MagicMock()),
            patch.object(NotificationTopicsResource, "list", return_value=[]),
            patch.object(NotificationSubscriptionsResource, "list", side_effect=_fake_list_subs),
        ):
            run_module(["--subscriptions"], sess)

        self.assertIsNone(captured_kwargs.get("topic_id"))
