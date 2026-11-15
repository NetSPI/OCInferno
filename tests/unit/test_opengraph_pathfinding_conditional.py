"""Unit tests for OpenGraph pathfinding conditional handling.

Covers the edge_is_conditional derivation (the fix that connects the graph builder's
rich condition data -- has_unresolved_conditionals / unresolved_statements /
resolved_statements with a `where` clause -- to the pathfinder's --exclude-conditional
and the [conditional] label, which previously keyed only on a flat `conditional` flag
that no builder ever set).
"""
from ocinferno.modules.opengraph.utilities.helpers.pathfinding.model import (
    AttackGraph,
    edge_is_conditional,
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
