"""Unit tests for the OpenGraph edge -> `module run` example post-pass."""
from __future__ import annotations

import json

from ocinferno.modules.opengraph.utilities.edge_command_annotator import annotate_edge_module_commands


def _edge(src, dst, kind, inner=None):
    return {
        "source_id": src, "destination_id": dst, "edge_type": kind,
        "edge_properties": json.dumps({"edge_category": "PERMISSION", "edge_inner_properties": inner or {}}),
    }


def _inner(edge):
    return json.loads(edge["edge_properties"]).get("edge_inner_properties", {})


def test_idd_admin_edge_gets_full_command_and_collapsed_edge():
    nodes = [{
        "node_id": "ocid1.user.oc1..bob", "node_type": "OCIUser",
        "node_properties": json.dumps({"ocid": "ocid1.user.oc1..bob", "name": "bob",
                                       "domain_url": "https://idcs-abc.identity.oraclecloud.com:443"}),
    }]
    edges = [_edge("ocid1.group.oc1..adminrole", "ocid1.user.oc1..bob", "IDD_USER_ADMIN",
                   {"descriptions": ["User Administrator..."]})]
    out, stats = annotate_edge_module_commands(edges, nodes)
    inner = _inner(out[0])
    assert inner["example_command"] == (
        "modules run exploit_add_user_api_key --user-ocid ocid1.user.oc1..bob "
        "--idd --domain-url https://idcs-abc.identity.oraclecloud.com:443 --yes"
    )
    assert inner["authz_source"] == "Identity Domain app-role: User Administrator"
    assert inner["includes_other_edges"] == ["IDD_CREATE_USER_API_KEY"]
    # original inner keys preserved
    assert inner["descriptions"] == ["User Administrator..."]
    assert stats["annotated"] == 1


def test_classic_edge_uses_compartment_from_resource_group_node():
    edges = [_edge("ocid1.group.oc1..g1", "users@ocid1.compartment.oc1..app", "OCI_CREATE_USER_API_KEY")]
    out, _ = annotate_edge_module_commands(edges, [])
    inner = _inner(out[0])
    assert "ocid1.compartment.oc1..app" in inner["example_command"]
    assert "exploit_add_user_api_key" in inner["example_command"]
    assert inner["authz_source"].startswith("OCI IAM policy")
    assert "includes_other_edges" not in inner  # classic edge has no collapsed edges


def test_missing_domain_url_leaves_placeholder():
    # dest node has no domain_url -> template keeps an explicit <DEST_DOMAIN_URL> hint
    nodes = [{"node_id": "ocid1.user.oc1..x", "node_type": "OCIUser", "node_properties": json.dumps({})}]
    edges = [_edge("r", "ocid1.user.oc1..x", "IDD_IDENTITY_ADMIN_USER")]
    out, _ = annotate_edge_module_commands(edges, nodes)
    assert "<DEST_DOMAIN_URL>" in _inner(out[0])["example_command"]


def test_unconfigured_edge_untouched():
    edges = [_edge("a", "b", "OCI_GROUP_MEMBER", {"foo": "bar"})]
    before = edges[0]["edge_properties"]
    out, stats = annotate_edge_module_commands(edges, [])
    assert out[0]["edge_properties"] == before
    assert stats["annotated"] == 0


def test_annotation_lands_in_edge_inner_properties_not_top_level():
    # regression: keys must go into edge_inner_properties (the exporter drops top-level keys)
    edges = [_edge("g", "users@ocid1.compartment.oc1..c", "OCI_CREATE_USER_API_KEY")]
    out, _ = annotate_edge_module_commands(edges, [])
    payload = json.loads(out[0]["edge_properties"])
    assert "example_command" in payload["edge_inner_properties"]
    assert "example_command" not in payload  # not at top level
