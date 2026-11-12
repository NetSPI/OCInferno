"""Tests for RedisCacheUsersResource method-resolution and fallback logic."""
from __future__ import annotations

import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import oci

from ocinferno.modules.redis.utilities.helpers import RedisCacheUsersResource


def _session():
    return SimpleNamespace(
        compartment_id="ocid1.compartment.oc1..c",
        credentials={"config": {}, "signer": None},
        debug=False,
        config_current_default_region=None,
        region=None,
    )


def _make_resource(client_methods: dict):
    """Build a RedisCacheUsersResource whose OCI client only has the named methods."""
    res = object.__new__(RedisCacheUsersResource)
    res.session = _session()
    client = SimpleNamespace(**client_methods)
    res.client = client
    return res


class TestRedisCacheUsersResourceList(unittest.TestCase):

    def test_list_uses_list_oci_cache_users_when_present(self):
        fake_user = {"id": "ocid1.user.oc1..u1", "name": "alice"}
        mock_fn = MagicMock(return_value=SimpleNamespace(data=[fake_user]))
        res = _make_resource({"list_oci_cache_users": mock_fn})
        with patch("oci.pagination.list_call_get_all_results", side_effect=lambda fn, **kw: fn(**kw)):
            rows = res.list(compartment_id="ocid1.compartment.oc1..c")
        mock_fn.assert_called_once_with(compartment_id="ocid1.compartment.oc1..c")
        self.assertEqual(rows, [fake_user])

    def test_list_falls_back_to_list_cache_users(self):
        fake_user = {"id": "ocid1.user.oc1..u2", "name": "bob"}
        mock_fn = MagicMock(return_value=SimpleNamespace(data=[fake_user]))
        res = _make_resource({"list_cache_users": mock_fn})
        with patch("oci.pagination.list_call_get_all_results", side_effect=lambda fn, **kw: fn(**kw)):
            rows = res.list(compartment_id="ocid1.compartment.oc1..c")
        mock_fn.assert_called_once()
        self.assertEqual(rows, [fake_user])

    def test_list_falls_back_to_list_users(self):
        fake_user = {"id": "ocid1.user.oc1..u3", "name": "carol"}
        mock_fn = MagicMock(return_value=SimpleNamespace(data=[fake_user]))
        res = _make_resource({"list_users": mock_fn})
        with patch("oci.pagination.list_call_get_all_results", side_effect=lambda fn, **kw: fn(**kw)):
            rows = res.list(compartment_id="ocid1.compartment.oc1..c")
        mock_fn.assert_called_once()
        self.assertEqual(rows, [fake_user])

    def test_list_returns_empty_when_no_method_found(self):
        res = _make_resource({})
        rows = res.list(compartment_id="ocid1.compartment.oc1..c")
        self.assertEqual(rows, [])


class TestRedisCacheUsersResourceGet(unittest.TestCase):

    def test_get_uses_oci_cache_user_id_kwarg(self):
        fake_user = {"id": "ocid1.user.oc1..u1", "name": "alice"}
        mock_fn = MagicMock(return_value=SimpleNamespace(data=fake_user))
        res = _make_resource({"get_oci_cache_user": mock_fn})
        row = res.get(resource_id="ocid1.user.oc1..u1")
        mock_fn.assert_called_once_with(oci_cache_user_id="ocid1.user.oc1..u1")
        self.assertEqual(row["id"], "ocid1.user.oc1..u1")

    def test_get_falls_back_to_user_id_kwarg_on_type_error(self):
        fake_user = {"id": "ocid1.user.oc1..u2", "name": "bob"}

        def _get_oci(**kw):
            if "oci_cache_user_id" in kw:
                raise TypeError("unexpected keyword argument")
            return SimpleNamespace(data=fake_user)

        res = _make_resource({"get_oci_cache_user": _get_oci})
        row = res.get(resource_id="ocid1.user.oc1..u2")
        self.assertEqual(row["id"], "ocid1.user.oc1..u2")

    def test_get_returns_empty_on_service_error(self):
        def _raise(**kw):
            raise oci.exceptions.ServiceError(404, "NotFound", {}, "not found")

        res = _make_resource({"get_oci_cache_user": _raise})
        row = res.get(resource_id="ocid1.user.oc1..missing")
        self.assertEqual(row, {})

    def test_get_returns_empty_when_no_method_found(self):
        res = _make_resource({})
        row = res.get(resource_id="ocid1.user.oc1..x")
        self.assertEqual(row, {})
