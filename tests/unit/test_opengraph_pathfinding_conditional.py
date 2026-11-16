"""Unit tests for OpenGraph pathfinding conditional handling and --no-group-hop filter."""
from ocinferno.modules.opengraph.utilities.helpers.pathfinding.model import (
    AttackGraph,
    edge_is_conditional,
)
from ocinferno.modules.opengraph.utilities.helpers.pathfinding.search import (
    _is_group_hop_only,
    shortest_paths,
)

_COND_STMT = "Allow group g to manage policies in tenancy where request.region = 'us-phoenix-1'"
_PLAIN_STMT = "Allow group g to manage policies in tenancy"


def test_edge_is_conditional_detects_where_clause_top_level():
    assert edge_is_conditional({"resolved_statements": [_COND_STMT]}) is True


def test_edge_is_conditional_detects_unresolved_flag():
    assert edge_is_conditional({"has_unresolved_conditionals": True}) is True
    assert edge_is_conditional({"edge_inner_properties": {"has_unresolved_conditionals": True}}) is True


def test_edge_is_conditional_detects_unresolved_statements():
    assert edge_is_conditional({"unresolved_statements": ["x"]}) is True


def test_edge_is_conditional_false_for_plain_grant():
    assert edge_is_conditional({"resolved_statements": [_PLAIN_STMT]}) is False
    assert edge_is_conditional({}) is False
    assert edge_is_conditional(None) is False


def test_edge_is_conditional_reads_inner_json_string():
    props = {"edge_inner_properties": '{"resolved_statements": ["%s"]}' % _COND_STMT}
    assert edge_is_conditional(props) is True


def _graph(exclude_conditional):
    nodes = [
        {"id": "user:a", "kinds": ["OCIUser", "OCIPrincipal"], "properties": {"name": "a"}},
        {"id": "NEW_POLICY@t", "kinds": ["OCINewPolicy", "OCIResource"], "properties": {"name": "np"}},
    ]
    edges = [
        {"start": {"value": "user:a"}, "end": {"value": "NEW_POLICY@t"},
         "kind": "OCI_CAN_CREATE_POLICY",
         "properties": {"resolved_statements": [_COND_STMT]}},
    ]
    return AttackGraph._build(nodes, edges, include_containment=False,
                             exclude_conditional=exclude_conditional, debug=False)


def test_exclude_conditional_drops_conditional_edge():
    # Default: the conditional edge is present in adjacency.
    g_keep = _graph(exclude_conditional=False)
    assert any(dst == "NEW_POLICY@t" for dst, _ in (g_keep.adj.get("user:a") or []))
    # --exclude-conditional: the where-clause edge is skipped entirely.
    g_drop = _graph(exclude_conditional=True)
    assert not (g_drop.adj.get("user:a") or [])


# ---------------------------------------------------------------------------
# --no-group-hop: filter User→Group→priv paths
# ---------------------------------------------------------------------------

def _group_hop_graph():
    """Graph with:
      user:att  --(OCI_GROUP_MEMBER)-->  group:admins  --(OCI_MANAGE)-->  resource:target
      user:att  --(OCI_MANAGE)-->  resource:direct   (direct, no group hop)
    """
    nodes = [
        {"id": "user:att",        "kinds": ["OCIUser", "OCIPrincipal"],  "properties": {"name": "att"}},
        {"id": "group:admins",    "kinds": ["OCIGroup", "OCIResource"],   "properties": {"name": "admins"}},
        {"id": "resource:target", "kinds": ["OCIResource"],              "properties": {"name": "target"}},
        {"id": "resource:direct", "kinds": ["OCIResource"],              "properties": {"name": "direct"}},
    ]
    edges = [
        {"start": {"value": "user:att"},     "end": {"value": "group:admins"},    "kind": "OCI_GROUP_MEMBER", "properties": {}},
        {"start": {"value": "group:admins"}, "end": {"value": "resource:target"}, "kind": "OCI_MANAGE",       "properties": {}},
        {"start": {"value": "user:att"},     "end": {"value": "resource:direct"}, "kind": "OCI_MANAGE",       "properties": {}},
    ]
    return AttackGraph._build(nodes, edges, include_containment=False, exclude_conditional=False, debug=False)


def test_is_group_hop_only_true_for_single_group_hop():
    g = _group_hop_graph()
    assert _is_group_hop_only(g, ["user:att", "group:admins", "resource:target"]) is True


def test_is_group_hop_only_false_for_direct():
    g = _group_hop_graph()
    assert _is_group_hop_only(g, ["user:att", "resource:direct"]) is False


def test_is_group_hop_only_false_for_non_group_intermediate():
    g = _group_hop_graph()
    # intermediate is a plain resource, not a group
    assert _is_group_hop_only(g, ["user:att", "resource:target", "resource:direct"]) is False


def test_is_group_hop_only_false_for_nested_group_chain():
    # User → Group1 → Group2 → target has len=4, NOT filtered by --no-group-hop
    g = _group_hop_graph()
    assert _is_group_hop_only(g, ["user:att", "group:admins", "group:admins", "resource:target"]) is False


def test_no_group_hop_removes_user_via_group_path():
    # user:att reaches resource:target ONLY via group:admins (a group hop).
    # Without --no-group-hop the user path is present; with it, only the group
    # itself (which has a direct path as source) survives.
    g = _group_hop_graph()
    targets = {"resource:target"}
    all_paths = shortest_paths(g, targets, no_direct=False, no_group_hop=False)
    # user:att path should exist in unfiltered results
    assert any(p[0] == "user:att" and p[-1] == "resource:target" for p in all_paths)
    filtered = shortest_paths(g, targets, no_direct=False, no_group_hop=True)
    # user:att path is gone (group hop); group:admins direct path survives
    assert not any(p[0] == "user:att" and p[-1] == "resource:target" for p in filtered)


def test_no_group_hop_keeps_direct_path():
    # user:att reaches resource:direct directly — not a group hop, should survive.
    g = _group_hop_graph()
    targets = {"resource:direct"}
    paths = shortest_paths(g, targets, no_direct=False, no_group_hop=True)
    assert any(p[-1] == "resource:direct" for p in paths)


def test_no_group_hop_with_no_direct_removes_both_trivial_user_paths():
    g = _group_hop_graph()
    # With both flags, user:att should not appear in any path.
    for targets in ({"resource:target"}, {"resource:direct"}):
        paths = shortest_paths(g, targets, no_direct=True, no_group_hop=True)
        assert not any(p[0] == "user:att" for p in paths)
