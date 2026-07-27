"""Utility-level OpenGraph tests: context membership loading, matching-rules engine,
bundle rule matching, and graph JSON export/split. Each covers a pure helper with no
DB or graph-builder wiring."""
from __future__ import annotations

import json
import pathlib
import tempfile

import pytest

# ---------------------------------------------------------------------------
# OfflineIamContext: membership table loading
# ---------------------------------------------------------------------------
from ocinferno.modules.opengraph.utilities.helpers.context import OfflineIamContext


class _FakeSession:
    workspace_id = 1

    def __init__(self):
        self._tables = {
            "identity_user_group_memberships": [
                {"id": "classic-m1", "user_id": "ocid1.user.oc1..u1", "group_id": "ocid1.group.oc1..g1"},
            ],
            "identity_domain_user_group_memberships": [
                {"id": "idd-m1", "user_id": "ocid1.user.oc1..u2", "group_id": "ocid1.group.oc1..g2"},
            ],
        }

    def get_resource_fields(self, table_name, where_conditions=None, columns=None):
        return list(self._tables.get(table_name, []))


def test_context_loads_classic_and_idd_membership_tables():
    ctx = OfflineIamContext(session=_FakeSession(), lazy=True)
    ctx.load_for_steps({"groups"})
    membership_ids = {str(r.get("id")) for r in ctx.memberships}
    assert membership_ids == {"classic-m1", "idd-m1"}


# ---------------------------------------------------------------------------
# Matching-rules engine: resource-type alias closure + eval_pred
# ---------------------------------------------------------------------------
from ocinferno.modules.opengraph.utilities.helpers.constants import DEFAULT_RESOURCE_FAMILIES
from ocinferno.modules.opengraph.utilities.helpers.matching_rules_engine import (
    OP_EQ,
    OP_NEQ,
    VAR_RESOURCE_TYPE,
    Pred,
    _eval_pred,
    _resource_type_alias_closure,
)


def test_alias_closure_symmetric_from_any_member():
    from_key = _resource_type_alias_closure("fn-function")
    from_value = _resource_type_alias_closure("fnfunction")
    assert from_key == from_value == {"fn-function", "fnfunction", "fnfunc", "fnfnc"}


def test_alias_closure_unrelated_type_has_no_functions_aliases():
    assert _resource_type_alias_closure("computecontainerinstance") == {"computecontainerinstance"}


def test_alias_closure_empty_input():
    assert _resource_type_alias_closure("") == set()
    assert _resource_type_alias_closure(None) == set()


@pytest.mark.parametrize(
    "op, rhs, expected",
    [
        pytest.param(OP_EQ, "fnfunc", True, id="matches-across-synonyms"),
        pytest.param(OP_EQ, ["instance", "fnfunc"], True, id="matches-list-rhs-across-synonyms"),
        pytest.param(OP_NEQ, "fnfunc", False, id="neq-respects-synonyms"),
        pytest.param(OP_EQ, "instance", False, id="no-match-for-unrelated-type"),
    ],
)
def test_eval_pred_resource_type(op, rhs, expected):
    row = {"resource_type": "fnfunction"}
    pred = Pred(var=VAR_RESOURCE_TYPE, op=op, rhs=rhs, tag=None)
    assert _eval_pred(pred=pred, row=row) is expected


def test_execution_family_resolves_to_executions_not_commands():
    assert set(DEFAULT_RESOURCE_FAMILIES["instance-agent-command-execution-family"]) == {
        "instance-agent-command-executions"
    }


def test_command_family_and_execution_family_are_distinct():
    command_members = set(DEFAULT_RESOURCE_FAMILIES["instance-agent-command-family"])
    execution_members = set(DEFAULT_RESOURCE_FAMILIES["instance-agent-command-execution-family"])
    assert command_members.isdisjoint(execution_members)


# ---------------------------------------------------------------------------
# Bundle rule matching (ALLOW_RULE_DEFS bundle.requires_all)
# ---------------------------------------------------------------------------
from ocinferno.modules.opengraph.utilities.allowlist_bundle_graph_builder import (
    _load_bundle_rules,
    _requirement_satisfied,
    bundle_rule_matches,
)


def _bundle_rule():
    return {
        "requires_all": [
            {"permissions_all": {"INSTANCE_CREATE"}, "resource_tokens": {"instances"}},
            {"permissions_all": {"VNIC_CREATE", "VNIC_ATTACH"}, "resource_tokens": {"vnics"}},
            {"permissions_all": {"SUBNET_READ"}, "resource_tokens": {"subnets"}},
        ]
    }


def test_all_requirements_met_matches():
    assert bundle_rule_matches(_bundle_rule(), {
        "instances": {"INSTANCE_CREATE"},
        "vnics": {"VNIC_CREATE", "VNIC_ATTACH"},
        "subnets": {"SUBNET_READ", "SUBNET_ATTACH"},
    }) is True


def test_missing_one_requirement_does_not_match():
    assert bundle_rule_matches(_bundle_rule(), {
        "instances": {"INSTANCE_CREATE"},
        "vnics": {"VNIC_CREATE"},  # missing VNIC_ATTACH
        "subnets": {"SUBNET_READ"},
    }) is False


def test_requirement_satisfied_across_any_of_its_tokens():
    req = {"permissions_all": {"SECRET_BUNDLE_READ"}, "resource_tokens": {"secret-bundles", "vaults"}}
    assert _requirement_satisfied(req, {"vaults": {"SECRET_BUNDLE_READ"}}) is True
    assert _requirement_satisfied(req, {"other": {"SECRET_BUNDLE_READ"}}) is False


def test_empty_rule_never_matches():
    assert bundle_rule_matches({"requires_all": []}, {"instances": {"INSTANCE_CREATE"}}) is False


def test_no_bundle_rules_defined_by_default():
    assert _load_bundle_rules() == []


# ---------------------------------------------------------------------------
# Graph JSON export: streaming writer + size-bounded splitter
# ---------------------------------------------------------------------------
from ocinferno.modules.opengraph.utilities.helpers.graph_export import (
    write_graph_json_with_progress,
    write_split_outputs,
)


def _graph_payload(n_nodes=8, n_edges=6):
    nodes = [{"id": f"n{i}", "kinds": ["OCIUser"], "properties": {"pad": "x" * 40}} for i in range(n_nodes)]
    edges = [{"kind": "E", "start": {"value": f"n{i}"}, "end": {"value": f"n{i+1}"}} for i in range(n_edges)]
    return {"metadata": {"m": 1}, "graph": {"nodes": nodes, "edges": edges},
            "summary": {"nodes": n_nodes, "edges": n_edges}}


def test_streaming_write_matches_payload():
    tmp = pathlib.Path(tempfile.mkdtemp())
    out = tmp / "g.json"
    write_graph_json_with_progress(out, _graph_payload())
    d = json.loads(out.read_text())
    assert len(d["graph"]["nodes"]) == 8 and len(d["graph"]["edges"]) == 6
    assert d["metadata"] == {"m": 1} and "summary" in d


def test_split_produces_self_contained_parts_and_manifest():
    tmp = pathlib.Path(tempfile.mkdtemp())
    res = write_split_outputs(tmp / "g.json", _graph_payload(), max_size_mb=0.0005)
    assert res["part_count"] >= 2
    seen_edges = 0
    for pf in res["parts"]:
        pd = json.loads(pathlib.Path(pf).read_text())
        ids = {n["id"] for n in pd["graph"]["nodes"]}
        for e in pd["graph"]["edges"]:
            assert e["start"]["value"] in ids and e["end"]["value"] in ids
            seen_edges += 1
    assert seen_edges == 6
    man = json.loads(pathlib.Path(res["manifest"]).read_text())
    assert man["part_count"] == res["part_count"] and man["total_edges"] == 6


def test_split_single_part_when_small():
    tmp = pathlib.Path(tempfile.mkdtemp())
    res = write_split_outputs(tmp / "g.json", _graph_payload(), max_size_mb=90.0)
    assert res["part_count"] == 1
