"""OciListResource config-driven base + run_components declarative loop."""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from ocinferno.core.resource import OciListResource
from ocinferno.core.utils.enum_framework import Component, nested_list_fn, run_components


class _FakeClient:
    def __init__(self):
        self.calls = []

    def list_things(self, **kw):
        self.calls.append(("list", kw))
        return SimpleNamespace(data=[{"id": "t1", "display_name": "one"}, {"id": "t2", "display_name": "two"}])

    def get_thing(self, **kw):
        self.calls.append(("get", kw))
        return SimpleNamespace(data={"id": kw.get("thing_id"), "detail": "deep"})


class ThingResource(OciListResource):
    TABLE_NAME = "things"
    SERVICE_NAME = "Thing"
    LIST_METHOD = "list_things"
    GET_METHOD = "get_thing"
    GET_ID_PARAM = "thing_id"
    COLUMNS = ["id", "display_name", "detail"]

    def _build_client(self, session, region=None):
        return _FakeClient()

    # Skip real oci.pagination in tests; just return the SDK response.
    def _list_items(self, compartment_id, **kw):
        return self.client.list_things(compartment_id=compartment_id, **kw)


def _session():
    saved = {}
    sess = SimpleNamespace(
        compartment_id="ocid1.compartment.oc1..c",
        debug=False, individual_run_debug=False, active_module_name="enum_thing",
        save_resources=lambda rows, table: saved.setdefault(table, []).extend(rows),
        get_resource_fields=lambda *a, **k: [],
    )
    sess._saved = saved
    return sess


def test_base_maps_class_attrs_to_sdk():
    r = ThingResource(session=_session())
    rows = r.list(compartment_id="c1")
    assert rows == [{"id": "t1", "display_name": "one"}, {"id": "t2", "display_name": "two"}]
    assert r.client.calls[0] == ("list", {"compartment_id": "c1"})
    got = r.get(resource_id="t2")
    assert got["id"] == "t2" and got["detail"] == "deep"
    assert ("get", {"thing_id": "t2"}) in r.client.calls
    assert r.get(resource_id="") == {}  # empty id guarded


def test_run_components_lists_and_saves():
    sess = _session()
    comps = [Component("things", ThingResource, cache_table="things")]
    out = run_components([], sess, comps, module_name="enum_thing", description="Enumerate things")
    assert out["ok"] is True
    res = out["components"][0]
    assert res["things"] == 2 and res["saved"] is True
    assert len(sess._saved["things"]) == 2  # persisted


def test_run_components_requires_compartment():
    sess = _session()
    sess.compartment_id = None
    with pytest.raises(ValueError):
        run_components([], sess, [Component("things", ThingResource)], module_name="m", description="d")


def test_run_components_supports_get_false_skips_get():
    sess = _session()
    comps = [Component("things", ThingResource, supports_get=False)]
    out = run_components(["--things", "--get"], sess, comps, module_name="enum_thing", description="d")
    res = out["components"][0]
    # get() never called -> no ("get", ...) recorded on the resource the loop built.
    assert res["things"] == 2 and res["get"] is True  # flag present but get_row was None


def test_run_components_list_fn_override_reads_args():
    """list_fn(session, args, resource) -> callable(cid) lets a component read custom flags."""
    sess = _session()
    seen = {}

    def _list_fn(session, args, resource):
        def _inner(cid):
            seen["cid"] = cid
            return [{"id": "custom"}]
        return _inner

    comps = [Component("things", ThingResource, list_fn=_list_fn, supports_get=False)]
    out = run_components(["--things"], sess, comps, module_name="enum_thing", description="d")
    assert out["components"][0]["things"] == 1
    assert seen["cid"] == "ocid1.compartment.oc1..c"


def test_manual_id_component_runs_without_compartment():
    """require_compartment=False + a list_fn (manual --X-id) lets the component run
    with no compartment set (manual --X-id targeting)."""
    sess = _session()
    sess.compartment_id = None

    def _list_fn(session, args, resource):
        return lambda cid: [{"id": "specific-target"}]

    comps = [Component("things", ThingResource, list_fn=_list_fn, supports_get=False, require_compartment=False)]
    out = run_components([], sess, comps, module_name="enum_thing", description="d", require_compartment=False)
    assert out["components"][0]["things"] == 1  # ran despite compartment_id=None


class _ParentResource(OciListResource):
    TABLE_NAME = "parents"
    COLUMNS = ["id"]

    def _build_client(self, session, region=None):
        return None

    def list(self, *, compartment_id, **kw):
        return [{"id": "p1"}, {"id": "p2"}]


class _ChildResource(OciListResource):
    TABLE_NAME = "children"
    COLUMNS = ["id", "parent_id"]

    def _build_client(self, session, region=None):
        return None

    def list(self, *, compartment_id, **kw):
        pid = kw.get("parent_id")
        return [{"id": f"c-{pid}"}]  # one child per parent


def test_nested_list_fn_fans_out_over_parents_and_stamps_id():
    sess = _session()
    comp = Component("children", _ChildResource, supports_get=False,
                     list_fn=nested_list_fn(parent_resource_cls=_ParentResource, parent_id_field="parent_id"))
    run_components(["--children"], sess, [comp], module_name="enum_x", description="d")
    rows = sess._saved["children"]
    assert {r["id"] for r in rows} == {"c-p1", "c-p2"}       # fanned out over both parents
    assert all(r["parent_id"] in ("p1", "p2") for r in rows)  # parent id stamped


def test_nested_list_fn_manual_parent_ids_skip_parent_list():
    sess = _session()
    comp = Component("children", _ChildResource, supports_get=False,
                     list_fn=nested_list_fn(parent_resource_cls=_ParentResource,
                                            parent_id_field="parent_id", manual_parent_arg="repo_id"))

    def _extra(parser):
        parser.add_argument("--repo-id", default="", dest="repo_id")

    run_components(["--children", "--repo-id", "manual1,manual2"], sess, [comp],
                   module_name="enum_x", description="d", add_extra_args=_extra)
    rows = sess._saved["children"]
    assert {r["parent_id"] for r in rows} == {"manual1", "manual2"}  # used manual ids, not the parent list


class _ParentOnlyChild(OciListResource):
    """Child scoped by the parent id ALONE (e.g. list_functions(application_id))."""
    TABLE_NAME = "children"
    COLUMNS = ["id", "parent_id"]
    LIST_SCOPE_KWARG = "parent_id"

    def _build_client(self, session, region=None):
        return None

    def list(self, *, compartment_id, **kw):
        # child_takes_compartment=False passes the PARENT id in as compartment_id, no extra kwargs.
        assert not kw, "parent-only child must not receive a second scope kwarg"
        return [{"id": f"fn-{compartment_id}"}]


def test_nested_list_fn_parent_only_child_no_duplicate_kwarg():
    sess = _session()
    comp = Component("children", _ParentOnlyChild, supports_get=False,
                     list_fn=nested_list_fn(parent_resource_cls=_ParentResource,
                                            parent_id_field="parent_id", child_takes_compartment=False))
    run_components(["--children"], sess, [comp], module_name="enum_x", description="d")
    rows = sess._saved["children"]
    # fanned out over p1/p2 with the parent id passed as the sole scope; parent_id stamped.
    assert {r["id"] for r in rows} == {"fn-p1", "fn-p2"}
    assert {r["parent_id"] for r in rows} == {"p1", "p2"}
